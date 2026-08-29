use std::collections::HashMap;
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{
    E_ACCESSDENIED, E_INVALIDARG, ERROR_CANCELLED, ERROR_READ_FAULT, ERROR_TIMEOUT, FILETIME,
};
use windows::core::{Error, HRESULT, Result};

use crate::device_store::DeviceStore;
use crate::security::{
    AuthenticatedServerConnection, CertificateFingerprint, PinnedTlsClient, PinnedTlsServer,
    TrustedTlsServer,
};

use super::data_object::{
    MAX_VIRTUAL_ITEMS, VirtualFileDescriptor, validate_virtual_descriptor_tree,
};
use super::local_file::LocalFileOffer;
use super::source::ReadAtSource;
use super::transfer::{GeneratedSource, TransferControl};

const MAGIC: [u8; 4] = *b"CFS4";
const PROTOCOL_VERSION: u16 = 2;
const FRAME_HEADER_LEN: usize = 20;
const MANIFEST_HEADER_LEN: usize = 29;
const MANIFEST_ENTRY_FIXED_LEN: usize = 55;
pub const MAX_SECURE_RANGE_BYTES: usize = 256 * 1024;
pub const MAX_SECURE_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_FRAME_PAYLOAD: usize = MAX_SECURE_MANIFEST_BYTES;
const MAX_ACTIVE_TRANSFERS: usize = 64;
const MAX_BEGIN_NONCES: usize = 4_096;
const MAX_TRACKED_RANGES: usize = 4_096;
const DEFAULT_MAX_WORKERS: usize = 32;
const MAX_PAUSE_POLL_INTERVAL: Duration = Duration::from_secs(5);
const HELLO_ROLE_RECEIVER: u8 = 1;
const RESPONSE_BIT: u16 = 0x8000;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProtocolId([u8; 16]);

impl ProtocolId {
    fn random() -> io::Result<Self> {
        Ok(Self(random_bytes()?))
    }

    #[must_use]
    pub fn bytes(self) -> [u8; 16] {
        self.0
    }
}

impl std::fmt::Display for ProtocolId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct OfferManifest {
    pub offer_id: ProtocolId,
    pub entries: Arc<[OfferManifestEntry]>,
    pub ttl: Duration,
}

#[derive(Clone, Debug)]
pub struct OfferManifestEntry {
    pub file_id: ProtocolId,
    pub descriptor: VirtualFileDescriptor,
}

impl OfferManifest {
    pub(crate) fn origin_payload(&self) -> Arc<[u8]> {
        let mut payload = Vec::with_capacity(ClipFerryOrigin::PREFIX.len() + 16);
        payload.extend_from_slice(ClipFerryOrigin::PREFIX);
        payload.extend_from_slice(&self.offer_id.0);
        Arc::from(payload)
    }
}

struct ClipFerryOrigin;

impl ClipFerryOrigin {
    const PREFIX: &'static [u8] = b"ClipFerry.SourceOffer.v1\0";
}

#[derive(Clone)]
pub struct SecureOfferedFile {
    manifest: OfferManifest,
    sources: Arc<HashMap<ProtocolId, Arc<dyn ReadAtSource>>>,
    expires_at: Instant,
}

impl SecureOfferedFile {
    /// Creates an immutable, short-lived offered file backed by a deferred random-access source.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid name, size mismatch, zero lifetime, or unavailable secure
    /// randomness.
    pub fn new(
        descriptor: VirtualFileDescriptor,
        source: Arc<dyn ReadAtSource>,
        ttl: Duration,
    ) -> io::Result<Self> {
        Self::new_tree(vec![(descriptor, Some(source))], ttl)
    }

    /// Creates one bounded virtual directory tree. Directory descriptors have no source; every
    /// ordinary file has an independent deferred random-access source and protocol identifier.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid descriptors, missing or mismatched sources, excessive tree
    /// size, zero lifetime, arithmetic overflow, or unavailable secure randomness.
    pub fn new_tree(
        entries: Vec<(VirtualFileDescriptor, Option<Arc<dyn ReadAtSource>>)>,
        ttl: Duration,
    ) -> io::Result<Self> {
        if ttl.is_zero() || entries.is_empty() || entries.len() > MAX_VIRTUAL_ITEMS {
            return Err(invalid_data("invalid secure offer size or lifetime"));
        }
        let descriptors: Vec<VirtualFileDescriptor> = entries
            .iter()
            .map(|(descriptor, _)| descriptor.clone())
            .collect();
        validate_virtual_descriptor_tree(&descriptors).map_err(invalid_windows)?;
        let offer_id = ProtocolId::random()?;
        let mut manifest_entries = Vec::with_capacity(entries.len());
        let mut sources = HashMap::with_capacity(entries.len());
        for (descriptor, source) in entries {
            if descriptor.is_directory() != source.is_none()
                || source
                    .as_ref()
                    .is_some_and(|source| descriptor.size != source.len())
            {
                return Err(invalid_data(
                    "secure offer source does not match descriptor",
                ));
            }
            let file_id = ProtocolId::random()?;
            if let Some(source) = source {
                sources.insert(file_id, source);
            }
            manifest_entries.push(OfferManifestEntry {
                file_id,
                descriptor,
            });
        }
        let expires_at = Instant::now()
            .checked_add(ttl)
            .ok_or_else(|| invalid_data("secure offer lifetime is too large"))?;
        Ok(Self {
            manifest: OfferManifest {
                offer_id,
                entries: Arc::from(manifest_entries),
                ttl,
            },
            sources: Arc::new(sources),
            expires_at,
        })
    }

    /// Creates a deterministic generated-data offer for security and transport tests.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid arguments or unavailable secure randomness.
    pub fn generated(file_name: Arc<str>, size: u64, ttl: Duration) -> io::Result<Self> {
        let control = Arc::new(TransferControl::default());
        let source: Arc<dyn ReadAtSource> = Arc::new(
            GeneratedSource::new(size, MAX_SECURE_RANGE_BYTES, Duration::ZERO, control)
                .map_err(invalid_windows)?,
        );
        Self::new(VirtualFileDescriptor::basic(file_name, size), source, ttl)
    }

    pub(crate) fn from_local_offer(offer: &LocalFileOffer) -> io::Result<Self> {
        let entries = offer
            .entries()
            .iter()
            .map(|entry| {
                let source = entry.source().map(|source| {
                    let source: Arc<dyn ReadAtSource> = source;
                    source
                });
                (entry.descriptor(), source)
            })
            .collect();
        Self::new_tree(entries, offer.remaining_ttl())
    }

    #[must_use]
    pub fn manifest(&self) -> OfferManifest {
        let mut manifest = self.manifest.clone();
        manifest.ttl = self.expires_at.saturating_duration_since(Instant::now());
        manifest
    }

    fn source(&self, file_id: ProtocolId) -> Option<Arc<dyn ReadAtSource>> {
        self.sources.get(&file_id).cloned()
    }

    fn manifest_entry(&self, file_id: ProtocolId) -> Option<&OfferManifestEntry> {
        self.manifest
            .entries
            .iter()
            .find(|entry| entry.file_id == file_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteTransferState {
    Running,
    Paused,
    Cancelled,
    Completed,
}

impl RemoteTransferState {
    fn encode(self) -> u8 {
        match self {
            Self::Running => 0,
            Self::Paused => 1,
            Self::Cancelled => 2,
            Self::Completed => 3,
        }
    }

    fn decode(value: u8) -> io::Result<Self> {
        match value {
            0 => Ok(Self::Running),
            1 => Ok(Self::Paused),
            2 => Ok(Self::Cancelled),
            3 => Ok(Self::Completed),
            _ => Err(invalid_data("invalid transfer state")),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SecureMetricsSnapshot {
    pub accepted_connections: u64,
    pub tls_failures: u64,
    pub protocol_errors: u64,
    pub denied_requests: u64,
    pub replayed_requests: u64,
    pub begun_transfers: u64,
    pub read_requests: u64,
    pub served_bytes: u64,
    pub unique_bytes: u64,
    pub cancelled_transfers: u64,
    pub active_reads: u64,
    pub max_concurrent_reads: u64,
}

#[derive(Default)]
struct SecureMetrics {
    accepted_connections: AtomicU64,
    tls_failures: AtomicU64,
    protocol_errors: AtomicU64,
    denied_requests: AtomicU64,
    replayed_requests: AtomicU64,
    begun_transfers: AtomicU64,
    read_requests: AtomicU64,
    served_bytes: AtomicU64,
    cancelled_transfers: AtomicU64,
    active_reads: AtomicU64,
    max_concurrent_reads: AtomicU64,
}

impl SecureMetrics {
    fn begin_read(self: &Arc<Self>) -> ActiveRead {
        let current = self.active_reads.fetch_add(1, Ordering::AcqRel) + 1;
        let _ = self.max_concurrent_reads.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |maximum| (current > maximum).then_some(current),
        );
        ActiveRead {
            metrics: Arc::clone(self),
        }
    }

    fn snapshot(&self, unique_bytes: u64) -> SecureMetricsSnapshot {
        SecureMetricsSnapshot {
            accepted_connections: self.accepted_connections.load(Ordering::Relaxed),
            tls_failures: self.tls_failures.load(Ordering::Relaxed),
            protocol_errors: self.protocol_errors.load(Ordering::Relaxed),
            denied_requests: self.denied_requests.load(Ordering::Relaxed),
            replayed_requests: self.replayed_requests.load(Ordering::Relaxed),
            begun_transfers: self.begun_transfers.load(Ordering::Relaxed),
            read_requests: self.read_requests.load(Ordering::Relaxed),
            served_bytes: self.served_bytes.load(Ordering::Relaxed),
            unique_bytes,
            cancelled_transfers: self.cancelled_transfers.load(Ordering::Relaxed),
            active_reads: self.active_reads.load(Ordering::Relaxed),
            max_concurrent_reads: self.max_concurrent_reads.load(Ordering::Relaxed),
        }
    }
}

struct ActiveRead {
    metrics: Arc<SecureMetrics>,
}

impl Drop for ActiveRead {
    fn drop(&mut self) {
        self.metrics.active_reads.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug, Default)]
struct RangeCoverage {
    ranges: Vec<(u64, u64)>,
    unique_bytes: u64,
    saturated: bool,
}

impl RangeCoverage {
    fn note(&mut self, start: u64, length: u64) {
        if self.saturated || length == 0 {
            return;
        }
        let Some(end) = start.checked_add(length) else {
            self.saturated = true;
            return;
        };
        self.ranges.push((start, end));
        self.ranges.sort_unstable_by_key(|range| range.0);
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(self.ranges.len());
        for (range_start, range_end) in self.ranges.drain(..) {
            if let Some(last) = merged.last_mut()
                && range_start <= last.1
            {
                last.1 = last.1.max(range_end);
                continue;
            }
            merged.push((range_start, range_end));
        }
        if merged.len() > MAX_TRACKED_RANGES {
            self.saturated = true;
            self.ranges.clear();
            return;
        }
        self.unique_bytes = merged.iter().map(|(start, end)| end - start).sum();
        self.ranges = merged;
    }
}

struct TransferInner {
    state: RemoteTransferState,
    last_control_sequence: u64,
    coverage: RangeCoverage,
}

struct TransferSession {
    authorized_peer: CertificateFingerprint,
    offer_id: ProtocolId,
    file_id: ProtocolId,
    transfer_id: ProtocolId,
    capability: [u8; 32],
    server_nonce: [u8; 32],
    expires_at: Instant,
    inner: Mutex<TransferInner>,
    changed: Condvar,
}

impl TransferSession {
    fn credentials(&self) -> TransferCredentials {
        TransferCredentials {
            offer_id: self.offer_id,
            file_id: self.file_id,
            transfer_id: self.transfer_id,
            capability: self.capability,
            server_nonce: self.server_nonce,
            expires_at_millis: u64::try_from(
                self.expires_at
                    .saturating_duration_since(Instant::now())
                    .as_millis(),
            )
            .unwrap_or(u64::MAX),
        }
    }
}

struct ServerInner {
    transfers: HashMap<ProtocolId, Arc<TransferSession>>,
    begin_nonces: HashMap<[u8; 32], Instant>,
}

struct ServerState {
    offered: SecureOfferedFile,
    authorized_peer: CertificateFingerprint,
    trust_store: Option<DeviceStore>,
    transfer_ttl: Duration,
    request_timeout: Duration,
    inner: Mutex<ServerInner>,
    metrics: Arc<SecureMetrics>,
}

impl ServerState {
    fn connection_idle_timeout(&self) -> Duration {
        self.transfer_ttl.max(self.request_timeout)
    }

    fn begin_transfer(
        &self,
        peer: CertificateFingerprint,
        offer_id: ProtocolId,
        file_id: ProtocolId,
        nonce: [u8; 32],
    ) -> WireResult<TransferCredentials> {
        self.ensure_peer_allowed(peer)?;
        let now = Instant::now();
        if offer_id != self.offered.manifest.offer_id || now >= self.offered.expires_at {
            return Err(ResponseStatus::Expired);
        }
        if self.offered.source(file_id).is_none() {
            self.metrics.denied_requests.fetch_add(1, Ordering::Relaxed);
            return Err(ResponseStatus::Denied);
        }
        let mut inner = self.inner.lock().map_err(|_| ResponseStatus::Internal)?;
        inner
            .transfers
            .retain(|_, transfer| transfer.expires_at > now);
        inner.begin_nonces.retain(|_, expires_at| *expires_at > now);
        if inner.begin_nonces.contains_key(&nonce) {
            self.metrics
                .replayed_requests
                .fetch_add(1, Ordering::Relaxed);
            return Err(ResponseStatus::Replay);
        }
        let active_transfers = inner
            .transfers
            .values()
            .filter(|transfer| {
                transfer.inner.lock().map_or(true, |state| {
                    matches!(
                        state.state,
                        RemoteTransferState::Running | RemoteTransferState::Paused
                    )
                })
            })
            .count();
        if active_transfers >= MAX_ACTIVE_TRANSFERS
            || inner.transfers.len() >= MAX_BEGIN_NONCES
            || inner.begin_nonces.len() >= MAX_BEGIN_NONCES
        {
            return Err(ResponseStatus::Busy);
        }
        let transfer_id = ProtocolId::random().map_err(|_| ResponseStatus::Internal)?;
        let expires_at = now
            .checked_add(self.transfer_ttl)
            .ok_or(ResponseStatus::Internal)?;
        let session = Arc::new(TransferSession {
            authorized_peer: peer,
            offer_id,
            file_id,
            transfer_id,
            capability: random_bytes().map_err(|_| ResponseStatus::Internal)?,
            server_nonce: random_bytes().map_err(|_| ResponseStatus::Internal)?,
            expires_at,
            inner: Mutex::new(TransferInner {
                state: RemoteTransferState::Running,
                last_control_sequence: 0,
                coverage: RangeCoverage::default(),
            }),
            changed: Condvar::new(),
        });
        inner.begin_nonces.insert(nonce, expires_at);
        inner.transfers.insert(transfer_id, Arc::clone(&session));
        self.metrics.begun_transfers.fetch_add(1, Ordering::Relaxed);
        Ok(session.credentials())
    }

    fn authenticated_session(
        &self,
        peer: CertificateFingerprint,
        credentials: &TransferCredentials,
    ) -> WireResult<Arc<TransferSession>> {
        self.ensure_peer_allowed(peer)?;
        let inner = self.inner.lock().map_err(|_| ResponseStatus::Internal)?;
        let Some(session) = inner.transfers.get(&credentials.transfer_id) else {
            self.metrics.denied_requests.fetch_add(1, Ordering::Relaxed);
            return Err(ResponseStatus::Denied);
        };
        if session.expires_at <= Instant::now() {
            return Err(ResponseStatus::Expired);
        }
        if session.authorized_peer != peer
            || session.offer_id != credentials.offer_id
            || session.file_id != credentials.file_id
            || session.capability != credentials.capability
            || session.server_nonce != credentials.server_nonce
        {
            self.metrics.denied_requests.fetch_add(1, Ordering::Relaxed);
            return Err(ResponseStatus::Denied);
        }
        Ok(Arc::clone(session))
    }

    fn control(
        &self,
        peer: CertificateFingerprint,
        credentials: &TransferCredentials,
        sequence: u64,
        opcode: Opcode,
    ) -> WireResult<TransferStatus> {
        let session = self.authenticated_session(peer, credentials)?;
        let mut inner = session.inner.lock().map_err(|_| ResponseStatus::Internal)?;
        if sequence <= inner.last_control_sequence {
            self.metrics
                .replayed_requests
                .fetch_add(1, Ordering::Relaxed);
            return Err(ResponseStatus::Replay);
        }
        inner.last_control_sequence = sequence;
        match opcode {
            Opcode::Pause if inner.state == RemoteTransferState::Running => {
                inner.state = RemoteTransferState::Paused;
            }
            Opcode::Resume if inner.state == RemoteTransferState::Paused => {
                inner.state = RemoteTransferState::Running;
                session.changed.notify_all();
            }
            Opcode::Cancel
                if matches!(
                    inner.state,
                    RemoteTransferState::Running | RemoteTransferState::Paused
                ) =>
            {
                inner.state = RemoteTransferState::Cancelled;
                self.metrics
                    .cancelled_transfers
                    .fetch_add(1, Ordering::Relaxed);
                session.changed.notify_all();
            }
            Opcode::Complete if inner.state == RemoteTransferState::Running => {
                inner.state = RemoteTransferState::Completed;
                session.changed.notify_all();
            }
            Opcode::Pause | Opcode::Resume | Opcode::Cancel | Opcode::Complete => {}
            _ => return Err(ResponseStatus::Invalid),
        }
        Ok(TransferStatus {
            state: inner.state,
            unique_bytes: inner.coverage.unique_bytes,
        })
    }

    fn status(
        &self,
        peer: CertificateFingerprint,
        credentials: &TransferCredentials,
    ) -> WireResult<TransferStatus> {
        let session = self.authenticated_session(peer, credentials)?;
        let inner = session.inner.lock().map_err(|_| ResponseStatus::Internal)?;
        Ok(TransferStatus {
            state: inner.state,
            unique_bytes: inner.coverage.unique_bytes,
        })
    }

    fn read_range(
        &self,
        peer: CertificateFingerprint,
        credentials: &TransferCredentials,
        offset: u64,
        requested: usize,
    ) -> WireResult<(TransferStatus, Vec<u8>)> {
        if requested > MAX_SECURE_RANGE_BYTES {
            return Err(ResponseStatus::Invalid);
        }
        let session = self.authenticated_session(peer, credentials)?;
        self.metrics.read_requests.fetch_add(1, Ordering::Relaxed);
        let _active = self.metrics.begin_read();
        let mut inner = session.inner.lock().map_err(|_| ResponseStatus::Internal)?;
        while inner.state == RemoteTransferState::Paused {
            if !self.peer_is_allowed(peer) {
                inner.state = RemoteTransferState::Cancelled;
                self.metrics
                    .cancelled_transfers
                    .fetch_add(1, Ordering::Relaxed);
                session.changed.notify_all();
                return Err(ResponseStatus::Denied);
            }
            let now = Instant::now();
            if now >= session.expires_at {
                return Err(ResponseStatus::Expired);
            }
            let remaining = session.expires_at.saturating_duration_since(now);
            let poll_interval = self
                .request_timeout
                .min(MAX_PAUSE_POLL_INTERVAL)
                .min(remaining);
            let (next, wait) = session
                .changed
                .wait_timeout(inner, poll_interval)
                .map_err(|_| ResponseStatus::Internal)?;
            inner = next;
            if wait.timed_out() && inner.state == RemoteTransferState::Paused {
                return Ok((
                    TransferStatus {
                        state: RemoteTransferState::Paused,
                        unique_bytes: inner.coverage.unique_bytes,
                    },
                    Vec::new(),
                ));
            }
        }
        if Instant::now() >= session.expires_at {
            return Err(ResponseStatus::Expired);
        }
        if inner.state == RemoteTransferState::Cancelled {
            return Err(ResponseStatus::Cancelled);
        }
        drop(inner);

        self.ensure_peer_allowed(peer)?;

        let source = self
            .offered
            .source(session.file_id)
            .ok_or(ResponseStatus::Denied)?;
        let descriptor = &self
            .offered
            .manifest_entry(session.file_id)
            .ok_or(ResponseStatus::Denied)?
            .descriptor;
        let available = descriptor.size.saturating_sub(offset);
        let count = usize::try_from(available.min(requested as u64)).unwrap_or(requested);
        let mut bytes = vec![0_u8; count];
        let read = source
            .read_at(offset, &mut bytes)
            .map_err(|_| ResponseStatus::SourceChanged)?;
        bytes.truncate(read);

        let mut inner = session.inner.lock().map_err(|_| ResponseStatus::Internal)?;
        if !self.peer_is_allowed(peer) {
            if matches!(
                inner.state,
                RemoteTransferState::Running | RemoteTransferState::Paused
            ) {
                inner.state = RemoteTransferState::Cancelled;
                self.metrics
                    .cancelled_transfers
                    .fetch_add(1, Ordering::Relaxed);
            }
            session.changed.notify_all();
            return Err(ResponseStatus::Denied);
        }
        if Instant::now() >= session.expires_at {
            return Err(ResponseStatus::Expired);
        }
        if inner.state == RemoteTransferState::Cancelled {
            return Err(ResponseStatus::Cancelled);
        }
        inner.coverage.note(offset, read as u64);
        let status = TransferStatus {
            state: inner.state,
            unique_bytes: inner.coverage.unique_bytes,
        };
        self.metrics
            .served_bytes
            .fetch_add(read as u64, Ordering::Relaxed);
        Ok((status, bytes))
    }

    fn unique_bytes(&self) -> u64 {
        self.inner
            .lock()
            .map(|inner| {
                inner
                    .transfers
                    .values()
                    .filter_map(|transfer| transfer.inner.lock().ok())
                    .map(|state| state.coverage.unique_bytes)
                    .sum()
            })
            .unwrap_or_default()
    }

    fn ensure_peer_allowed(&self, peer: CertificateFingerprint) -> WireResult<()> {
        if !self.peer_is_allowed(peer) {
            self.metrics.denied_requests.fetch_add(1, Ordering::Relaxed);
            self.cancel_peer_transfers(peer);
            return Err(ResponseStatus::Denied);
        }
        Ok(())
    }

    fn peer_is_allowed(&self, peer: CertificateFingerprint) -> bool {
        peer == self.authorized_peer
            && self
                .trust_store
                .as_ref()
                .is_none_or(|store| store.load_peer(peer).is_ok())
    }

    fn cancel_peer_transfers(&self, peer: CertificateFingerprint) {
        let Ok(inner) = self.inner.lock() else {
            return;
        };
        for transfer in inner
            .transfers
            .values()
            .filter(|transfer| transfer.authorized_peer == peer)
        {
            let Ok(mut state) = transfer.inner.lock() else {
                continue;
            };
            if matches!(
                state.state,
                RemoteTransferState::Running | RemoteTransferState::Paused
            ) {
                state.state = RemoteTransferState::Cancelled;
                self.metrics
                    .cancelled_transfers
                    .fetch_add(1, Ordering::Relaxed);
                transfer.changed.notify_all();
            }
        }
    }
}

pub struct SecureOfferServer {
    address: SocketAddr,
    state: Arc<ServerState>,
    stop: Arc<AtomicBool>,
    workers: Arc<AtomicUsize>,
    listener_thread: Option<JoinHandle<()>>,
}

impl SecureOfferServer {
    /// Starts the bounded TLS listener for a single authenticated offer.
    ///
    /// # Errors
    ///
    /// Returns an error when arguments are invalid or the listener/thread cannot start.
    pub fn start(
        listen_address: SocketAddr,
        tls: PinnedTlsServer,
        offered: SecureOfferedFile,
        transfer_ttl: Duration,
        request_timeout: Duration,
    ) -> io::Result<Self> {
        let authorized_peer = tls.expected_peer();
        Self::start_inner(
            listen_address,
            SecureServerTls::Pinned(tls),
            authorized_peer,
            None,
            offered,
            transfer_ttl,
            request_timeout,
        )
    }

    /// Starts a single-offer server that authenticates every currently trusted device but grants
    /// this offer only to the explicitly selected peer. Trust is rechecked for each request.
    ///
    /// # Errors
    ///
    /// Returns an error when arguments are invalid or the listener/thread cannot start.
    pub fn start_trusted(
        listen_address: SocketAddr,
        tls: TrustedTlsServer,
        authorized_peer: CertificateFingerprint,
        offered: SecureOfferedFile,
        transfer_ttl: Duration,
        request_timeout: Duration,
    ) -> io::Result<Self> {
        let trust_store = tls.trust_store();
        let peer = trust_store.load_peer(authorized_peer)?;
        if peer.fingerprint != authorized_peer {
            return Err(invalid_data(
                "authorized peer record does not match its pin",
            ));
        }
        Self::start_inner(
            listen_address,
            SecureServerTls::Trusted(tls),
            authorized_peer,
            Some(trust_store),
            offered,
            transfer_ttl,
            request_timeout,
        )
    }

    fn start_inner(
        listen_address: SocketAddr,
        tls: SecureServerTls,
        authorized_peer: CertificateFingerprint,
        trust_store: Option<DeviceStore>,
        offered: SecureOfferedFile,
        transfer_ttl: Duration,
        request_timeout: Duration,
    ) -> io::Result<Self> {
        if transfer_ttl.is_zero() || request_timeout.is_zero() {
            return Err(invalid_data("secure server timeouts must be non-zero"));
        }
        let listener = TcpListener::bind(listen_address)?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let state = Arc::new(ServerState {
            offered,
            authorized_peer,
            trust_store,
            transfer_ttl,
            request_timeout,
            inner: Mutex::new(ServerInner {
                transfers: HashMap::new(),
                begin_nonces: HashMap::new(),
            }),
            metrics: Arc::new(SecureMetrics::default()),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let workers = Arc::new(AtomicUsize::new(0));
        let thread_state = Arc::clone(&state);
        let thread_stop = Arc::clone(&stop);
        let thread_workers = Arc::clone(&workers);
        let listener_thread = std::thread::Builder::new()
            .name("clipferry-secure-listener".to_owned())
            .spawn(move || {
                secure_accept_loop(listener, tls, thread_state, thread_stop, thread_workers);
            })?;
        Ok(Self {
            address,
            state,
            stop,
            workers,
            listener_thread: Some(listener_thread),
        })
    }

    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    #[must_use]
    pub fn manifest(&self) -> OfferManifest {
        self.state.offered.manifest()
    }

    #[must_use]
    pub fn metrics(&self) -> SecureMetricsSnapshot {
        self.state.metrics.snapshot(self.state.unique_bytes())
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.listener_thread.take() {
            let _ = thread.join();
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.workers.load(Ordering::Acquire) != 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[derive(Clone)]
enum SecureServerTls {
    Pinned(PinnedTlsServer),
    Trusted(TrustedTlsServer),
}

impl SecureServerTls {
    fn accept(&self, socket: TcpStream) -> io::Result<AuthenticatedServerConnection> {
        match self {
            Self::Pinned(tls) => tls.accept_authenticated(socket),
            Self::Trusted(tls) => tls.accept(socket),
        }
    }
}

impl Drop for SecureOfferServer {
    fn drop(&mut self) {
        self.stop();
    }
}

#[allow(clippy::needless_pass_by_value)]
fn secure_accept_loop(
    listener: TcpListener,
    tls: SecureServerTls,
    state: Arc<ServerState>,
    stop: Arc<AtomicBool>,
    workers: Arc<AtomicUsize>,
) {
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((socket, _)) => {
                state
                    .metrics
                    .accepted_connections
                    .fetch_add(1, Ordering::Relaxed);
                if workers.fetch_add(1, Ordering::AcqRel) >= DEFAULT_MAX_WORKERS {
                    workers.fetch_sub(1, Ordering::AcqRel);
                    state
                        .metrics
                        .protocol_errors
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let worker_tls = tls.clone();
                let worker_state = Arc::clone(&state);
                let worker_count = Arc::clone(&workers);
                if std::thread::Builder::new()
                    .name("clipferry-secure-worker".to_owned())
                    .spawn(move || {
                        let _guard = WorkerCountGuard(worker_count);
                        match worker_tls.accept(socket) {
                            Ok(mut authenticated) => {
                                let result = authenticated
                                    .stream
                                    .sock
                                    .set_read_timeout(Some(worker_state.connection_idle_timeout()))
                                    .and_then(|()| {
                                        handle_secure_connection(
                                            &mut authenticated.stream,
                                            &worker_state,
                                            authenticated.peer_fingerprint,
                                        )
                                    });
                                if let Err(error) = result {
                                    if error.kind() == io::ErrorKind::PermissionDenied {
                                        eprintln!("SECURE connection_denied=true");
                                    } else {
                                        eprintln!("SECURE connection_error={error}");
                                        worker_state
                                            .metrics
                                            .protocol_errors
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                            Err(error) => {
                                eprintln!("SECURE tls_error={error}");
                                worker_state
                                    .metrics
                                    .tls_failures
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    })
                    .is_err()
                {
                    workers.fetch_sub(1, Ordering::AcqRel);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => {
                state
                    .metrics
                    .protocol_errors
                    .fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
    }
}

struct WorkerCountGuard(Arc<AtomicUsize>);

impl Drop for WorkerCountGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn handle_secure_connection(
    stream: &mut (impl io::Read + io::Write),
    state: &ServerState,
    peer: CertificateFingerprint,
) -> io::Result<()> {
    state
        .ensure_peer_allowed(peer)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "peer is not authorized"))?;
    let hello = read_frame(stream)?;
    if hello.opcode != Opcode::Hello as u16
        || hello.payload.len() != 33
        || hello.payload[0] != HELLO_ROLE_RECEIVER
        || hello.payload[1..].iter().all(|byte| *byte == 0)
    {
        return Err(invalid_data("invalid secure protocol hello"));
    }
    write_frame(
        stream,
        Frame {
            opcode: response_opcode(Opcode::Hello),
            request_id: hello.request_id,
            payload: random_bytes::<32>()?.to_vec(),
        },
    )?;

    loop {
        let Some(request) = read_frame_optional(stream)? else {
            return Ok(());
        };
        state.ensure_peer_allowed(peer).map_err(|_| {
            io::Error::new(io::ErrorKind::PermissionDenied, "peer trust was revoked")
        })?;
        let opcode = Opcode::try_from(request.opcode)?;
        let response = dispatch_request(state, peer, opcode, &request.payload);
        write_frame(
            stream,
            Frame {
                opcode: response_opcode(opcode),
                request_id: request.request_id,
                payload: response,
            },
        )?;
    }
}

fn dispatch_request(
    state: &ServerState,
    peer: CertificateFingerprint,
    opcode: Opcode,
    payload: &[u8],
) -> Vec<u8> {
    let result = match opcode {
        Opcode::GetOffer => encode_manifest_response(state, payload),
        Opcode::BeginTransfer => encode_begin_response(state, peer, payload),
        Opcode::ReadRange => encode_read_response(state, peer, payload),
        Opcode::Pause | Opcode::Resume | Opcode::Cancel | Opcode::Complete => {
            encode_control_response(state, peer, opcode, payload)
        }
        Opcode::Status => encode_status_response(state, peer, payload),
        Opcode::Hello => Err(ResponseStatus::Invalid),
    };
    result.unwrap_or_else(|status| vec![status.encode()])
}

fn encode_manifest_response(state: &ServerState, payload: &[u8]) -> WireResult<Vec<u8>> {
    if !payload.is_empty() || Instant::now() >= state.offered.expires_at {
        return Err(ResponseStatus::Expired);
    }
    let manifest = state.offered.manifest();
    let mut response = Vec::new();
    response.push(ResponseStatus::Ok.encode());
    response.extend_from_slice(&manifest.offer_id.0);
    response.extend_from_slice(
        &u64::try_from(manifest.ttl.as_millis())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    response.extend_from_slice(
        &u32::try_from(manifest.entries.len())
            .map_err(|_| ResponseStatus::Internal)?
            .to_be_bytes(),
    );
    for entry in manifest.entries.iter() {
        response.extend_from_slice(&entry.file_id.0);
        response.extend_from_slice(&entry.descriptor.size.to_be_bytes());
        response.extend_from_slice(&entry.descriptor.attributes.to_be_bytes());
        let mut time_flags = 0_u8;
        if entry.descriptor.creation_time.is_some() {
            time_flags |= 1;
        }
        if entry.descriptor.last_access_time.is_some() {
            time_flags |= 2;
        }
        if entry.descriptor.last_write_time.is_some() {
            time_flags |= 4;
        }
        response.push(time_flags);
        response.extend_from_slice(&filetime_bits(entry.descriptor.creation_time).to_be_bytes());
        response.extend_from_slice(&filetime_bits(entry.descriptor.last_access_time).to_be_bytes());
        response.extend_from_slice(&filetime_bits(entry.descriptor.last_write_time).to_be_bytes());
        let name = entry.descriptor.file_name.as_bytes();
        let name_length = u16::try_from(name.len()).map_err(|_| ResponseStatus::Internal)?;
        response.extend_from_slice(&name_length.to_be_bytes());
        response.extend_from_slice(name);
        if response.len() > MAX_SECURE_MANIFEST_BYTES {
            return Err(ResponseStatus::Internal);
        }
    }
    Ok(response)
}

fn encode_begin_response(
    state: &ServerState,
    peer: CertificateFingerprint,
    payload: &[u8],
) -> WireResult<Vec<u8>> {
    if payload.len() != 64 {
        return Err(ResponseStatus::Invalid);
    }
    let offer_id = ProtocolId(array_at(payload, 0)?);
    let file_id = ProtocolId(array_at(payload, 16)?);
    let nonce = array_at(payload, 32)?;
    if nonce.iter().all(|byte| *byte == 0) {
        return Err(ResponseStatus::Invalid);
    }
    let credentials = state.begin_transfer(peer, offer_id, file_id, nonce)?;
    let mut response = vec![ResponseStatus::Ok.encode()];
    response.extend_from_slice(&credentials.offer_id.0);
    response.extend_from_slice(&credentials.file_id.0);
    response.extend_from_slice(&credentials.transfer_id.0);
    response.extend_from_slice(&credentials.capability);
    response.extend_from_slice(&credentials.server_nonce);
    response.extend_from_slice(&credentials.expires_at_millis.to_be_bytes());
    Ok(response)
}

fn encode_read_response(
    state: &ServerState,
    peer: CertificateFingerprint,
    payload: &[u8],
) -> WireResult<Vec<u8>> {
    if payload.len() != TransferCredentials::WIRE_LEN + 12 {
        return Err(ResponseStatus::Invalid);
    }
    let credentials = TransferCredentials::decode(payload)?;
    let offset = u64::from_be_bytes(array_at(payload, TransferCredentials::WIRE_LEN)?);
    let requested = u32::from_be_bytes(array_at(payload, TransferCredentials::WIRE_LEN + 8)?);
    let requested = usize::try_from(requested).map_err(|_| ResponseStatus::Invalid)?;
    let (status, bytes) = state.read_range(peer, &credentials, offset, requested)?;
    let mut response = encode_transfer_status(status);
    response.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| ResponseStatus::Internal)?
            .to_be_bytes(),
    );
    response.extend_from_slice(&bytes);
    Ok(response)
}

fn encode_control_response(
    state: &ServerState,
    peer: CertificateFingerprint,
    opcode: Opcode,
    payload: &[u8],
) -> WireResult<Vec<u8>> {
    if payload.len() != TransferCredentials::WIRE_LEN + 8 {
        return Err(ResponseStatus::Invalid);
    }
    let credentials = TransferCredentials::decode(payload)?;
    let sequence = u64::from_be_bytes(array_at(payload, TransferCredentials::WIRE_LEN)?);
    state
        .control(peer, &credentials, sequence, opcode)
        .map(encode_transfer_status)
}

fn encode_status_response(
    state: &ServerState,
    peer: CertificateFingerprint,
    payload: &[u8],
) -> WireResult<Vec<u8>> {
    if payload.len() != TransferCredentials::WIRE_LEN {
        return Err(ResponseStatus::Invalid);
    }
    let credentials = TransferCredentials::decode(payload)?;
    state.status(peer, &credentials).map(encode_transfer_status)
}

fn encode_transfer_status(status: TransferStatus) -> Vec<u8> {
    let mut response = vec![ResponseStatus::Ok.encode(), status.state.encode()];
    response.extend_from_slice(&status.unique_bytes.to_be_bytes());
    response
}

fn filetime_bits(value: Option<FILETIME>) -> u64 {
    value.map_or(0, |time| {
        u64::from(time.dwLowDateTime) | (u64::from(time.dwHighDateTime) << 32)
    })
}

fn filetime_from_bits(value: u64) -> FILETIME {
    FILETIME {
        dwLowDateTime: u32::try_from(value & u64::from(u32::MAX))
            .expect("masked FILETIME low half always fits"),
        dwHighDateTime: u32::try_from(value >> 32).expect("FILETIME high half always fits"),
    }
}

#[derive(Clone, Copy)]
struct TransferCredentials {
    offer_id: ProtocolId,
    file_id: ProtocolId,
    transfer_id: ProtocolId,
    capability: [u8; 32],
    server_nonce: [u8; 32],
    expires_at_millis: u64,
}

impl TransferCredentials {
    const WIRE_LEN: usize = 112;

    fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::WIRE_LEN);
        bytes.extend_from_slice(&self.offer_id.0);
        bytes.extend_from_slice(&self.file_id.0);
        bytes.extend_from_slice(&self.transfer_id.0);
        bytes.extend_from_slice(&self.capability);
        bytes.extend_from_slice(&self.server_nonce);
        bytes
    }

    fn decode(bytes: &[u8]) -> WireResult<Self> {
        if bytes.len() < Self::WIRE_LEN {
            return Err(ResponseStatus::Invalid);
        }
        Ok(Self {
            offer_id: ProtocolId(array_at(bytes, 0)?),
            file_id: ProtocolId(array_at(bytes, 16)?),
            transfer_id: ProtocolId(array_at(bytes, 32)?),
            capability: array_at(bytes, 48)?,
            server_nonce: array_at(bytes, 80)?,
            expires_at_millis: 0,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferStatus {
    pub state: RemoteTransferState,
    pub unique_bytes: u64,
}

#[derive(Clone)]
pub struct SecureOfferClient {
    address: SocketAddr,
    tls: PinnedTlsClient,
    next_request_id: Arc<AtomicU64>,
    connections: Arc<SecureCommandConnections>,
}

#[derive(Default)]
struct SecureCommandConnections {
    control: Mutex<Option<SecureCommandConnection>>,
    data: Mutex<Option<SecureCommandConnection>>,
}

struct SecureCommandConnection {
    stream: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    close_gracefully: bool,
}

impl Drop for SecureCommandConnection {
    fn drop(&mut self) {
        if self.close_gracefully {
            self.stream.conn.send_close_notify();
            let _ = io::Write::flush(&mut self.stream);
        }
        let _ = self.stream.sock.shutdown(Shutdown::Both);
    }
}

impl SecureOfferClient {
    #[must_use]
    pub fn new(address: SocketAddr, tls: PinnedTlsClient) -> Self {
        Self {
            address,
            tls,
            next_request_id: Arc::new(AtomicU64::new(1)),
            connections: Arc::new(SecureCommandConnections::default()),
        }
    }

    /// Fetches and validates the metadata-only offer over the pinned TLS connection.
    ///
    /// # Errors
    ///
    /// Returns an error for TLS, I/O, protocol, expiry, or unsafe file-name failures.
    pub fn fetch_manifest(&self) -> io::Result<OfferManifest> {
        let response = self.command(Opcode::GetOffer, Vec::new())?;
        Self::decode_manifest_response(&response)
    }

    fn decode_manifest_response(response: &[u8]) -> io::Result<OfferManifest> {
        require_ok(response)?;
        if response.len() < MANIFEST_HEADER_LEN {
            return Err(invalid_data("truncated offer manifest"));
        }
        let offer_id = ProtocolId(array_at_io(response, 1)?);
        let ttl_millis = u64::from_be_bytes(array_at_io(response, 17)?);
        if ttl_millis == 0 {
            return Err(invalid_data("expired offer manifest"));
        }
        let item_count = usize::try_from(u32::from_be_bytes(array_at_io(response, 25)?))
            .map_err(invalid_crypto)?;
        if item_count == 0 || item_count > MAX_VIRTUAL_ITEMS {
            return Err(invalid_data("invalid offer item count"));
        }
        let minimum = MANIFEST_HEADER_LEN
            .checked_add(
                item_count
                    .checked_mul(MANIFEST_ENTRY_FIXED_LEN)
                    .ok_or_else(|| invalid_data("offer manifest length overflow"))?,
            )
            .ok_or_else(|| invalid_data("offer manifest length overflow"))?;
        if response.len() < minimum || response.len() > MAX_SECURE_MANIFEST_BYTES {
            return Err(invalid_data("invalid offer manifest length"));
        }
        let mut cursor = MANIFEST_HEADER_LEN;
        let mut entries = Vec::with_capacity(item_count);
        let mut identifiers = std::collections::HashSet::with_capacity(item_count);
        for _ in 0..item_count {
            let file_id = ProtocolId(array_at_io(response, cursor)?);
            cursor += 16;
            if !identifiers.insert(file_id) {
                return Err(invalid_data("duplicate offer file identifier"));
            }
            let size = u64::from_be_bytes(array_at_io(response, cursor)?);
            cursor += 8;
            let attributes = u32::from_be_bytes(array_at_io(response, cursor)?);
            cursor += 4;
            let time_flags = *response
                .get(cursor)
                .ok_or_else(|| invalid_data("truncated offer time flags"))?;
            cursor += 1;
            if time_flags & !0b111 != 0 {
                return Err(invalid_data("invalid offer time flags"));
            }
            let creation = u64::from_be_bytes(array_at_io(response, cursor)?);
            cursor += 8;
            let access = u64::from_be_bytes(array_at_io(response, cursor)?);
            cursor += 8;
            let write = u64::from_be_bytes(array_at_io(response, cursor)?);
            cursor += 8;
            let name_length = usize::from(u16::from_be_bytes(array_at_io(response, cursor)?));
            cursor += 2;
            let name_end = cursor
                .checked_add(name_length)
                .ok_or_else(|| invalid_data("offer file name length overflow"))?;
            let name = response
                .get(cursor..name_end)
                .ok_or_else(|| invalid_data("truncated offer file name"))?;
            let file_name = std::str::from_utf8(name).map_err(invalid_crypto)?;
            entries.push(OfferManifestEntry {
                file_id,
                descriptor: VirtualFileDescriptor {
                    file_name: Arc::from(file_name),
                    size,
                    attributes,
                    creation_time: (time_flags & 1 != 0).then(|| filetime_from_bits(creation)),
                    last_access_time: (time_flags & 2 != 0).then(|| filetime_from_bits(access)),
                    last_write_time: (time_flags & 4 != 0).then(|| filetime_from_bits(write)),
                },
            });
            cursor = name_end;
        }
        if cursor != response.len() {
            return Err(invalid_data("trailing offer manifest bytes"));
        }
        validate_virtual_descriptor_tree(
            &entries
                .iter()
                .map(|entry| entry.descriptor.clone())
                .collect::<Vec<_>>(),
        )
        .map_err(invalid_windows)?;
        Ok(OfferManifest {
            offer_id,
            entries: Arc::from(entries),
            ttl: Duration::from_millis(ttl_millis),
        })
    }

    fn begin_transfer(
        &self,
        manifest: &OfferManifest,
        entry: &OfferManifestEntry,
    ) -> io::Result<TransferCredentials> {
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&manifest.offer_id.0);
        payload.extend_from_slice(&entry.file_id.0);
        payload.extend_from_slice(&random_bytes::<32>()?);
        let response = self.command(Opcode::BeginTransfer, payload)?;
        require_ok(&response)?;
        if response.len() != 121 {
            return Err(invalid_data("invalid BeginTransfer response"));
        }
        let credentials = TransferCredentials {
            offer_id: ProtocolId(array_at_io(&response, 1)?),
            file_id: ProtocolId(array_at_io(&response, 17)?),
            transfer_id: ProtocolId(array_at_io(&response, 33)?),
            capability: array_at_io(&response, 49)?,
            server_nonce: array_at_io(&response, 81)?,
            expires_at_millis: u64::from_be_bytes(array_at_io(&response, 113)?),
        };
        if credentials.offer_id != manifest.offer_id || credentials.file_id != entry.file_id {
            return Err(invalid_data("BeginTransfer identifiers do not match offer"));
        }
        Ok(credentials)
    }

    fn read_range(
        &self,
        credentials: TransferCredentials,
        offset: u64,
        requested: usize,
    ) -> io::Result<(TransferStatus, Vec<u8>)> {
        if requested > MAX_SECURE_RANGE_BYTES {
            return Err(invalid_data("secure range exceeds client limit"));
        }
        let mut payload = credentials.encode();
        payload.extend_from_slice(&offset.to_be_bytes());
        payload.extend_from_slice(
            &u32::try_from(requested)
                .map_err(invalid_crypto)?
                .to_be_bytes(),
        );
        let response = self.command(Opcode::ReadRange, payload)?;
        let status = decode_transfer_status(&response)?;
        if response.len() < 14 {
            return Err(invalid_data("truncated ReadRange response"));
        }
        let length = usize::try_from(u32::from_be_bytes(array_at_io(&response, 10)?))
            .map_err(invalid_crypto)?;
        if response.len() != 14 + length || length > requested {
            return Err(invalid_data("invalid ReadRange payload length"));
        }
        Ok((status, response[14..].to_vec()))
    }

    fn control(
        &self,
        credentials: TransferCredentials,
        sequence: u64,
        opcode: Opcode,
    ) -> io::Result<TransferStatus> {
        let mut payload = credentials.encode();
        payload.extend_from_slice(&sequence.to_be_bytes());
        let response = self.command(opcode, payload)?;
        decode_transfer_status(&response)
    }

    fn status(&self, credentials: TransferCredentials) -> io::Result<TransferStatus> {
        let response = self.command(Opcode::Status, credentials.encode())?;
        decode_transfer_status(&response)
    }

    fn command(&self, opcode: Opcode, payload: Vec<u8>) -> io::Result<Vec<u8>> {
        let connection_slot = if matches!(opcode, Opcode::ReadRange) {
            &self.connections.data
        } else {
            &self.connections.control
        };
        let mut connection = connection_slot
            .lock()
            .map_err(|_| io::Error::other("secure client connection lock poisoned"))?;
        if connection.is_none() {
            *connection = Some(self.connect()?);
        }

        let result = Self::exchange(
            &mut connection
                .as_mut()
                .expect("secure connection was initialized")
                .stream,
            &self.next_request_id,
            opcode,
            payload,
        );
        if result.is_err()
            && let Some(mut failed) = connection.take()
        {
            failed.close_gracefully = false;
        }
        result
    }

    fn connect(&self) -> io::Result<SecureCommandConnection> {
        let mut stream = self.tls.connect(self.address)?;
        let hello_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let mut hello = Vec::with_capacity(33);
        hello.push(HELLO_ROLE_RECEIVER);
        hello.extend_from_slice(&random_bytes::<32>()?);
        write_frame(
            &mut stream,
            Frame {
                opcode: Opcode::Hello as u16,
                request_id: hello_id,
                payload: hello,
            },
        )?;
        let hello_response = read_frame(&mut stream)?;
        if hello_response.opcode != response_opcode(Opcode::Hello)
            || hello_response.request_id != hello_id
            || hello_response.payload.len() != 32
        {
            return Err(invalid_data("invalid secure HelloAck"));
        }
        Ok(SecureCommandConnection {
            stream,
            close_gracefully: true,
        })
    }

    fn exchange(
        stream: &mut (impl io::Read + io::Write),
        next_request_id: &AtomicU64,
        opcode: Opcode,
        payload: Vec<u8>,
    ) -> io::Result<Vec<u8>> {
        let request_id = next_request_id.fetch_add(1, Ordering::Relaxed);
        write_frame(
            stream,
            Frame {
                opcode: opcode as u16,
                request_id,
                payload,
            },
        )?;
        let response = read_frame(stream)?;
        if response.opcode != response_opcode(opcode) || response.request_id != request_id {
            return Err(invalid_data("secure response does not match request"));
        }
        Ok(response.payload)
    }
}

pub struct SecureRemoteSource {
    client: SecureOfferClient,
    manifest: OfferManifest,
    entry: OfferManifestEntry,
    transfer: Mutex<Option<TransferCredentials>>,
    next_control_sequence: AtomicU64,
    completion_sent: AtomicBool,
    read_calls: AtomicU64,
    bytes_read: AtomicU64,
    group_paused: Arc<AtomicBool>,
    group_cancelled: Arc<AtomicBool>,
}

impl SecureRemoteSource {
    #[must_use]
    /// Creates a source for the first ordinary file in a validated manifest.
    ///
    /// # Panics
    ///
    /// Panics when the manifest contains only directory descriptors. Callers handling arbitrary
    /// trees must select an ordinary entry and use [`Self::new_for_entry`].
    pub fn new(client: SecureOfferClient, manifest: OfferManifest) -> Self {
        let entry = manifest
            .entries
            .iter()
            .find(|entry| !entry.descriptor.is_directory())
            .cloned()
            .expect("secure manifest must contain a streamable file");
        Self::new_for_entry(client, manifest, entry)
    }

    #[must_use]
    pub fn new_for_entry(
        client: SecureOfferClient,
        manifest: OfferManifest,
        entry: OfferManifestEntry,
    ) -> Self {
        Self::new_for_entry_in_group(
            client,
            manifest,
            entry,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
    }

    fn new_for_entry_in_group(
        client: SecureOfferClient,
        manifest: OfferManifest,
        entry: OfferManifestEntry,
        group_paused: Arc<AtomicBool>,
        group_cancelled: Arc<AtomicBool>,
    ) -> Self {
        Self {
            client,
            manifest,
            entry,
            transfer: Mutex::new(None),
            next_control_sequence: AtomicU64::new(1),
            completion_sent: AtomicBool::new(false),
            read_calls: AtomicU64::new(0),
            bytes_read: AtomicU64::new(0),
            group_paused,
            group_cancelled,
        }
    }

    fn credentials(&self) -> io::Result<TransferCredentials> {
        let mut transfer = self
            .transfer
            .lock()
            .map_err(|_| io::Error::other("remote transfer lock poisoned"))?;
        if let Some(credentials) = *transfer {
            return Ok(credentials);
        }
        let credentials = self.client.begin_transfer(&self.manifest, &self.entry)?;
        *transfer = Some(credentials);
        drop(transfer);
        if self.group_cancelled.load(Ordering::Acquire) {
            let sequence = self.next_control_sequence.fetch_add(1, Ordering::Relaxed);
            let _ = self.client.control(credentials, sequence, Opcode::Cancel);
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "transfer group was cancelled",
            ));
        }
        if self.group_paused.load(Ordering::Acquire) {
            let sequence = self.next_control_sequence.fetch_add(1, Ordering::Relaxed);
            self.client.control(credentials, sequence, Opcode::Pause)?;
        }
        Ok(credentials)
    }

    /// Pauses this started transfer.
    ///
    /// # Errors
    ///
    /// Returns a TLS, protocol, authentication, expiry, or server-state error.
    pub fn pause(&self) -> io::Result<TransferStatus> {
        self.send_control(Opcode::Pause)
    }

    /// Resumes this started transfer.
    ///
    /// # Errors
    ///
    /// Returns a TLS, protocol, authentication, expiry, or server-state error.
    pub fn resume(&self) -> io::Result<TransferStatus> {
        self.send_control(Opcode::Resume)
    }

    /// Irreversibly cancels this started transfer.
    ///
    /// # Errors
    ///
    /// Returns a TLS, protocol, authentication, expiry, or server-state error.
    pub fn cancel(&self) -> io::Result<TransferStatus> {
        self.send_control(Opcode::Cancel)
    }

    /// Marks this transfer complete after the authenticated manifest length has been read.
    ///
    /// # Errors
    ///
    /// Returns a TLS, protocol, authentication, expiry, or server-state error.
    pub fn complete(&self) -> io::Result<TransferStatus> {
        if self.completion_sent.load(Ordering::Acquire) {
            return self.status();
        }
        let status = self.send_control(Opcode::Complete)?;
        self.completion_sent.store(true, Ordering::Release);
        Ok(status)
    }

    /// Reads the server-authoritative transfer status and unique progress.
    ///
    /// # Errors
    ///
    /// Returns a TLS, protocol, authentication, expiry, or server-state error.
    pub fn status(&self) -> io::Result<TransferStatus> {
        self.client.status(self.credentials()?)
    }

    #[must_use]
    pub fn has_started(&self) -> bool {
        self.transfer
            .lock()
            .is_ok_and(|transfer| transfer.is_some())
    }

    fn send_control(&self, opcode: Opcode) -> io::Result<TransferStatus> {
        let sequence = self.next_control_sequence.fetch_add(1, Ordering::Relaxed);
        self.client.control(self.credentials()?, sequence, opcode)
    }

    #[must_use]
    pub fn read_calls(&self) -> u64 {
        self.read_calls.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn credentials_for_test(&self) -> io::Result<TransferCredentials> {
        self.credentials()
    }
}

#[derive(Default)]
pub struct RemoteTransferRegistry {
    sources: Mutex<Vec<Arc<SecureRemoteSource>>>,
    group_paused: Arc<AtomicBool>,
    group_cancelled: Arc<AtomicBool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferGroupStatus {
    pub state: RemoteTransferState,
    pub started_transfers: usize,
    pub unique_bytes: u64,
    pub read_calls: u64,
    pub bytes_read: u64,
}

impl RemoteTransferRegistry {
    /// Creates and remembers a source for the first ordinary file in a validated manifest.
    ///
    /// # Panics
    ///
    /// Panics when the manifest contains only directory descriptors. Tree-aware callers must use
    /// [`Self::create_source_for_entry`].
    pub fn create_source(
        &self,
        client: SecureOfferClient,
        manifest: OfferManifest,
    ) -> Arc<SecureRemoteSource> {
        let entry = manifest
            .entries
            .iter()
            .find(|entry| !entry.descriptor.is_directory())
            .cloned()
            .expect("secure manifest must contain a streamable file");
        let source = Arc::new(SecureRemoteSource::new_for_entry_in_group(
            client,
            manifest,
            entry,
            Arc::clone(&self.group_paused),
            Arc::clone(&self.group_cancelled),
        ));
        self.remember_source(source)
    }

    pub fn create_source_for_entry(
        &self,
        client: SecureOfferClient,
        manifest: OfferManifest,
        entry: OfferManifestEntry,
    ) -> Arc<SecureRemoteSource> {
        let source = Arc::new(SecureRemoteSource::new_for_entry_in_group(
            client,
            manifest,
            entry,
            Arc::clone(&self.group_paused),
            Arc::clone(&self.group_cancelled),
        ));
        self.remember_source(source)
    }

    fn remember_source(&self, source: Arc<SecureRemoteSource>) -> Arc<SecureRemoteSource> {
        if let Ok(mut sources) = self.sources.lock() {
            sources.push(Arc::clone(&source));
            if sources.len() > MAX_BEGIN_NONCES {
                let excess = sources.len() - MAX_BEGIN_NONCES;
                sources.drain(..excess);
            }
        }
        source
    }

    /// Returns the newest live source that has actually begun a transfer.
    ///
    /// # Errors
    ///
    /// Returns `NotConnected` before the first non-empty stream read, or an internal lock error.
    pub fn latest_started(&self) -> io::Result<Arc<SecureRemoteSource>> {
        let sources = self
            .sources
            .lock()
            .map_err(|_| io::Error::other("remote source registry lock poisoned"))?;
        sources
            .iter()
            .rev()
            .find(|source| source.has_started())
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no transfer has started"))
    }

    fn started_sources(&self) -> io::Result<Vec<Arc<SecureRemoteSource>>> {
        let sources = self
            .sources
            .lock()
            .map_err(|_| io::Error::other("remote source registry lock poisoned"))?;
        let started = sources
            .iter()
            .filter(|source| source.has_started())
            .cloned()
            .collect::<Vec<_>>();
        if started.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no transfer has started",
            ));
        }
        Ok(started)
    }

    /// Pauses every file stream that belongs to the current Explorer paste operation.
    ///
    /// # Errors
    ///
    /// Returns an error before any stream starts or when a TLS/protocol control request fails.
    pub fn pause_all(&self) -> io::Result<TransferGroupStatus> {
        let sources = self.started_sources()?;
        self.group_paused.store(true, Ordering::Release);
        for source in &sources {
            source.pause()?;
        }
        Self::aggregate(&sources)
    }

    /// Resumes every paused file stream in the current Explorer paste operation.
    ///
    /// # Errors
    ///
    /// Returns an error before any stream starts or when a TLS/protocol control request fails.
    pub fn resume_all(&self) -> io::Result<TransferGroupStatus> {
        let sources = self.started_sources()?;
        self.group_paused.store(false, Ordering::Release);
        for source in &sources {
            source.resume()?;
        }
        Self::aggregate(&sources)
    }

    /// Irreversibly cancels all current and not-yet-opened streams in this paste operation.
    ///
    /// # Errors
    ///
    /// Returns an error before any stream starts or when a TLS/protocol control request fails.
    pub fn cancel_all(&self) -> io::Result<TransferGroupStatus> {
        let sources = self.started_sources()?;
        self.group_cancelled.store(true, Ordering::Release);
        self.group_paused.store(false, Ordering::Release);
        for source in &sources {
            source.cancel()?;
        }
        Self::aggregate(&sources)
    }

    /// Returns aggregate progress for all file streams that have started in this paste operation.
    ///
    /// # Errors
    ///
    /// Returns an error before any stream starts or when a TLS/protocol status request fails.
    pub fn status_all(&self) -> io::Result<TransferGroupStatus> {
        let sources = self.started_sources()?;
        Self::aggregate(&sources)
    }

    fn aggregate(sources: &[Arc<SecureRemoteSource>]) -> io::Result<TransferGroupStatus> {
        let mut state = RemoteTransferState::Completed;
        let mut unique_bytes = 0_u64;
        let mut read_calls = 0_u64;
        let mut bytes_read = 0_u64;
        for source in sources {
            let status = source.status()?;
            state = match (state, status.state) {
                (_, RemoteTransferState::Cancelled) | (RemoteTransferState::Cancelled, _) => {
                    RemoteTransferState::Cancelled
                }
                (_, RemoteTransferState::Running) | (RemoteTransferState::Running, _) => {
                    RemoteTransferState::Running
                }
                (_, RemoteTransferState::Paused) | (RemoteTransferState::Paused, _) => {
                    RemoteTransferState::Paused
                }
                _ => RemoteTransferState::Completed,
            };
            unique_bytes = unique_bytes.saturating_add(status.unique_bytes);
            read_calls = read_calls.saturating_add(source.read_calls());
            bytes_read = bytes_read.saturating_add(source.bytes_read());
        }
        Ok(TransferGroupStatus {
            state,
            started_transfers: sources.len(),
            unique_bytes,
            read_calls,
            bytes_read,
        })
    }

    #[must_use]
    pub fn live_sources(&self) -> usize {
        self.sources
            .lock()
            .map(|sources| sources.len())
            .unwrap_or_default()
    }
}

impl ReadAtSource for SecureRemoteSource {
    fn len(&self) -> u64 {
        self.entry.descriptor.size
    }

    fn read_at(&self, offset: u64, destination: &mut [u8]) -> Result<usize> {
        if destination.is_empty() {
            return Ok(0);
        }
        loop {
            if self.group_cancelled.load(Ordering::Acquire) {
                return Err(Error::from_hresult(HRESULT::from_win32(ERROR_CANCELLED.0)));
            }
            if !self.group_paused.load(Ordering::Acquire) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        self.read_calls.fetch_add(1, Ordering::Relaxed);
        let requested = destination.len().min(MAX_SECURE_RANGE_BYTES);
        let credentials = self.credentials().map_err(io_to_windows_error)?;
        let bytes = loop {
            let (status, bytes) = self
                .client
                .read_range(credentials, offset, requested)
                .map_err(io_to_windows_error)?;
            if status.state == RemoteTransferState::Paused && bytes.is_empty() {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            break bytes;
        };
        if bytes.is_empty() && offset < self.entry.descriptor.size {
            return Err(Error::from_hresult(HRESULT::from_win32(ERROR_READ_FAULT.0)));
        }
        if bytes.is_empty()
            && offset >= self.entry.descriptor.size
            && !self.completion_sent.swap(true, Ordering::AcqRel)
        {
            let sequence = self.next_control_sequence.fetch_add(1, Ordering::Relaxed);
            if let Err(error) = self.client.control(credentials, sequence, Opcode::Complete) {
                self.completion_sent.store(false, Ordering::Release);
                return Err(io_to_windows_error(error));
            }
        }
        destination[..bytes.len()].copy_from_slice(&bytes);
        self.bytes_read
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        Ok(bytes.len())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
enum Opcode {
    Hello = 1,
    GetOffer = 2,
    BeginTransfer = 3,
    ReadRange = 4,
    Pause = 5,
    Resume = 6,
    Cancel = 7,
    Status = 8,
    Complete = 9,
}

impl TryFrom<u16> for Opcode {
    type Error = io::Error;

    fn try_from(value: u16) -> io::Result<Self> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::GetOffer),
            3 => Ok(Self::BeginTransfer),
            4 => Ok(Self::ReadRange),
            5 => Ok(Self::Pause),
            6 => Ok(Self::Resume),
            7 => Ok(Self::Cancel),
            8 => Ok(Self::Status),
            9 => Ok(Self::Complete),
            _ => Err(invalid_data("unknown secure protocol opcode")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseStatus {
    Ok,
    Invalid,
    Denied,
    Expired,
    Replay,
    Busy,
    Cancelled,
    Timeout,
    SourceChanged,
    Internal,
}

impl ResponseStatus {
    fn encode(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Invalid => 1,
            Self::Denied => 2,
            Self::Expired => 3,
            Self::Replay => 4,
            Self::Busy => 5,
            Self::Cancelled => 6,
            Self::Timeout => 7,
            Self::SourceChanged => 8,
            Self::Internal => 9,
        }
    }

    fn decode(value: u8) -> io::Result<Self> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Invalid),
            2 => Ok(Self::Denied),
            3 => Ok(Self::Expired),
            4 => Ok(Self::Replay),
            5 => Ok(Self::Busy),
            6 => Ok(Self::Cancelled),
            7 => Ok(Self::Timeout),
            8 => Ok(Self::SourceChanged),
            9 => Ok(Self::Internal),
            _ => Err(invalid_data("invalid secure response status")),
        }
    }
}

type WireResult<T> = std::result::Result<T, ResponseStatus>;

#[derive(Debug)]
struct Frame {
    opcode: u16,
    request_id: u64,
    payload: Vec<u8>,
}

#[allow(clippy::needless_pass_by_value)]
fn write_frame(stream: &mut impl io::Write, frame: Frame) -> io::Result<()> {
    if frame.payload.len() > MAX_FRAME_PAYLOAD {
        return Err(invalid_data("secure frame payload exceeds limit"));
    }
    let payload_length = u32::try_from(frame.payload.len()).map_err(invalid_crypto)?;
    let mut header = [0_u8; FRAME_HEADER_LEN];
    header[..4].copy_from_slice(&MAGIC);
    header[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    header[6..8].copy_from_slice(&frame.opcode.to_be_bytes());
    header[8..16].copy_from_slice(&frame.request_id.to_be_bytes());
    header[16..20].copy_from_slice(&payload_length.to_be_bytes());
    stream.write_all(&header)?;
    stream.write_all(&frame.payload)?;
    stream.flush()
}

fn read_frame(stream: &mut impl io::Read) -> io::Result<Frame> {
    read_frame_optional(stream)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "secure connection closed"))
}

fn read_frame_optional(stream: &mut impl io::Read) -> io::Result<Option<Frame>> {
    let mut header = [0_u8; FRAME_HEADER_LEN];
    if io::Read::read(stream, &mut header[..1])? == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut header[1..])?;
    if header[..4] != MAGIC || u16::from_be_bytes(array_at_io(&header, 4)?) != PROTOCOL_VERSION {
        return Err(invalid_data("invalid secure frame magic or version"));
    }
    let opcode = u16::from_be_bytes(array_at_io(&header, 6)?);
    let request_id = u64::from_be_bytes(array_at_io(&header, 8)?);
    let payload_length =
        usize::try_from(u32::from_be_bytes(array_at_io(&header, 16)?)).map_err(invalid_crypto)?;
    if payload_length > MAX_FRAME_PAYLOAD {
        return Err(invalid_data("secure frame payload exceeds limit"));
    }
    let mut payload = vec![0_u8; payload_length];
    stream.read_exact(&mut payload)?;
    Ok(Some(Frame {
        opcode,
        request_id,
        payload,
    }))
}

fn response_opcode(opcode: Opcode) -> u16 {
    opcode as u16 | RESPONSE_BIT
}

fn require_ok(response: &[u8]) -> io::Result<()> {
    let status = response
        .first()
        .copied()
        .ok_or_else(|| invalid_data("empty secure response"))?;
    match ResponseStatus::decode(status)? {
        ResponseStatus::Ok => Ok(()),
        other => Err(status_error(other)),
    }
}

fn decode_transfer_status(response: &[u8]) -> io::Result<TransferStatus> {
    require_ok(response)?;
    if response.len() < 10 {
        return Err(invalid_data("truncated transfer status"));
    }
    Ok(TransferStatus {
        state: RemoteTransferState::decode(response[1])?,
        unique_bytes: u64::from_be_bytes(array_at_io(response, 2)?),
    })
}

fn status_error(status: ResponseStatus) -> io::Error {
    let (kind, message) = match status {
        ResponseStatus::Invalid => (io::ErrorKind::InvalidData, "invalid request"),
        ResponseStatus::Denied => (io::ErrorKind::PermissionDenied, "request denied"),
        ResponseStatus::Expired => (io::ErrorKind::TimedOut, "offer or transfer expired"),
        ResponseStatus::Replay => (io::ErrorKind::PermissionDenied, "replayed request denied"),
        ResponseStatus::Busy => (io::ErrorKind::WouldBlock, "server is busy"),
        ResponseStatus::Cancelled => (io::ErrorKind::Interrupted, "transfer cancelled"),
        ResponseStatus::Timeout => (io::ErrorKind::TimedOut, "transfer request timed out"),
        ResponseStatus::SourceChanged => (io::ErrorKind::InvalidData, "source file changed"),
        ResponseStatus::Internal => (io::ErrorKind::Other, "server internal error"),
        ResponseStatus::Ok => (io::ErrorKind::Other, "unexpected success status"),
    };
    io::Error::new(kind, message)
}

fn random_bytes<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(invalid_crypto)?;
    Ok(bytes)
}

fn array_at<const N: usize>(bytes: &[u8], start: usize) -> WireResult<[u8; N]> {
    bytes
        .get(start..start + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(ResponseStatus::Invalid)
}

fn array_at_io<const N: usize>(bytes: &[u8], start: usize) -> io::Result<[u8; N]> {
    bytes
        .get(start..start + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| invalid_data("truncated secure protocol field"))
}

fn invalid_crypto(error: impl std::fmt::Display) -> io::Error {
    invalid_data(error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
fn invalid_windows(error: Error) -> io::Error {
    invalid_data(format!(
        "Windows validation failed: {:#010X}",
        error.code().0.cast_unsigned()
    ))
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[allow(clippy::needless_pass_by_value)]
fn io_to_windows_error(error: io::Error) -> Error {
    let hresult = match error.kind() {
        io::ErrorKind::Interrupted => HRESULT::from_win32(ERROR_CANCELLED.0),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => HRESULT::from_win32(ERROR_TIMEOUT.0),
        io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidData => E_ACCESSDENIED,
        io::ErrorKind::InvalidInput => E_INVALIDARG,
        _ => HRESULT::from_win32(ERROR_READ_FAULT.0),
    };
    Error::from_hresult(hresult)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;
    use std::path::PathBuf;

    use rcgen::CertifiedKey;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_DIRECTORY;

    use crate::security::{CertificateFingerprint, TlsIdentity};

    use super::*;
    use crate::clipboard::source::MemorySource;
    use crate::clipboard::transfer::generated_byte;

    struct TestPeers {
        server: PinnedTlsServer,
        client: PinnedTlsClient,
        other_client: PinnedTlsClient,
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(name: &str) -> Self {
            let mut random = [0_u8; 8];
            getrandom::fill(&mut random).unwrap();
            let path = std::env::temp_dir().join(format!(
                "clipferry-secure-{name}-{}-{}",
                std::process::id(),
                u64::from_le_bytes(random)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct TrustedTestPeers {
        _server_directory: TestDirectory,
        _authorized_directory: TestDirectory,
        _other_directory: TestDirectory,
        server_store: DeviceStore,
        server: TrustedTlsServer,
        authorized: PinnedTlsClient,
        other: PinnedTlsClient,
        authorized_fingerprint: CertificateFingerprint,
    }

    fn identity() -> (TlsIdentity, Vec<u8>) {
        let CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(["clipferry.local".to_owned()]).unwrap();
        let certificate = cert.der().as_ref().to_vec();
        let fingerprint = CertificateFingerprint::from_certificate(&certificate);
        let identity = TlsIdentity::from_test_parts(
            CertificateDer::from(certificate.clone()),
            PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
            fingerprint,
        );
        (identity, certificate)
    }

    fn peers() -> TestPeers {
        peers_with_timeout(Duration::from_secs(3))
    }

    fn peers_with_timeout(timeout: Duration) -> TestPeers {
        let (server_identity, server_certificate) = identity();
        let (client_identity, client_certificate) = identity();
        let (other_identity, _) = identity();
        TestPeers {
            server: PinnedTlsServer::new(
                &server_identity,
                client_certificate,
                client_identity.fingerprint(),
                timeout,
            )
            .unwrap(),
            client: PinnedTlsClient::new(
                &client_identity,
                server_certificate.clone(),
                server_identity.fingerprint(),
                timeout,
            )
            .unwrap(),
            other_client: PinnedTlsClient::new(
                &other_identity,
                server_certificate,
                server_identity.fingerprint(),
                timeout,
            )
            .unwrap(),
        }
    }

    fn trusted_peers(timeout: Duration) -> TrustedTestPeers {
        let server_directory = TestDirectory::new("trusted-server");
        let authorized_directory = TestDirectory::new("trusted-authorized");
        let other_directory = TestDirectory::new("trusted-other");
        let server_store = DeviceStore::new(&server_directory.0);
        let authorized_store = DeviceStore::new(&authorized_directory.0);
        let other_store = DeviceStore::new(&other_directory.0);
        let server_identity = server_store.load_or_create_identity().unwrap().identity;
        let authorized_identity = authorized_store.load_or_create_identity().unwrap().identity;
        let other_identity = other_store.load_or_create_identity().unwrap().identity;
        let server_certificate = server_identity.certificate_der().to_vec();
        let server_fingerprint = server_identity.fingerprint();
        let authorized_certificate = authorized_identity.certificate_der().to_vec();
        let authorized_fingerprint = authorized_identity.fingerprint();
        let other_certificate = other_identity.certificate_der().to_vec();
        let other_fingerprint = other_identity.fingerprint();
        server_store
            .trust_peer(
                authorized_certificate,
                authorized_fingerprint,
                "Authorized PC",
            )
            .unwrap();
        server_store
            .trust_peer(other_certificate, other_fingerprint, "Other PC")
            .unwrap();
        let authorized = PinnedTlsClient::new(
            &authorized_identity,
            server_certificate.clone(),
            server_fingerprint,
            timeout,
        )
        .unwrap();
        let other = PinnedTlsClient::new(
            &other_identity,
            server_certificate,
            server_fingerprint,
            timeout,
        )
        .unwrap();
        let server = TrustedTlsServer::new(server_identity, server_store.clone(), timeout).unwrap();
        TrustedTestPeers {
            _server_directory: server_directory,
            _authorized_directory: authorized_directory,
            _other_directory: other_directory,
            server_store,
            server,
            authorized,
            other,
            authorized_fingerprint,
        }
    }

    fn start_generated(size: u64) -> (SecureOfferServer, SecureOfferClient, PinnedTlsClient) {
        start_generated_with_timeouts(size, Duration::from_mins(1), Duration::from_secs(2))
    }

    fn start_generated_with_timeouts(
        size: u64,
        transfer_ttl: Duration,
        request_timeout: Duration,
    ) -> (SecureOfferServer, SecureOfferClient, PinnedTlsClient) {
        let peers = peers();
        let offered = SecureOfferedFile::generated(
            Arc::from("Remote-Secure-Test.bin"),
            size,
            Duration::from_mins(1),
        )
        .unwrap();
        let server = SecureOfferServer::start(
            "127.0.0.1:0".parse().unwrap(),
            peers.server,
            offered,
            transfer_ttl,
            request_timeout,
        )
        .unwrap();
        let client = SecureOfferClient::new(server.address(), peers.client);
        (server, client, peers.other_client)
    }

    #[test]
    fn offer_metadata_is_authenticated_and_content_is_deferred_until_read() {
        let (server, client, _) = start_generated(1024 * 1024);
        let manifest = client.fetch_manifest().unwrap();
        assert_eq!(
            &*manifest.entries[0].descriptor.file_name,
            "Remote-Secure-Test.bin"
        );
        assert_eq!(manifest.entries[0].descriptor.size, 1024 * 1024);
        assert_eq!(server.metrics().begun_transfers, 0);
        assert_eq!(server.metrics().read_requests, 0);

        let source = SecureRemoteSource::new(client, manifest);
        assert_eq!(source.read_calls(), 0);
        let mut bytes = [0_u8; 257];
        let read = source.read_at(7_777, &mut bytes).unwrap();
        assert_eq!(read, bytes.len());
        for (index, byte) in bytes.iter().enumerate() {
            assert_eq!(*byte, generated_byte(7_777 + index as u64));
        }
        assert_eq!(server.metrics().begun_transfers, 1);
        assert_eq!(server.metrics().read_requests, 1);
        assert_eq!(server.metrics().unique_bytes, bytes.len() as u64);
    }

    #[test]
    fn secure_tree_manifest_defers_content_and_supports_independent_out_of_order_streams() {
        let peers = peers();
        let alpha: Arc<dyn ReadAtSource> = Arc::new(MemorySource::new(&b"alpha"[..]));
        let ferry: Arc<dyn ReadAtSource> = Arc::new(MemorySource::new(&b"ferry"[..]));
        let offered = SecureOfferedFile::new_tree(
            vec![
                (
                    VirtualFileDescriptor {
                        file_name: Arc::from("资料-🚢"),
                        size: 0,
                        attributes: FILE_ATTRIBUTE_DIRECTORY.0,
                        creation_time: None,
                        last_access_time: None,
                        last_write_time: None,
                    },
                    None,
                ),
                (
                    VirtualFileDescriptor::basic(Arc::from("资料-🚢\\alpha.txt"), 5),
                    Some(alpha),
                ),
                (
                    VirtualFileDescriptor {
                        file_name: Arc::from("资料-🚢\\空目录"),
                        size: 0,
                        attributes: FILE_ATTRIBUTE_DIRECTORY.0,
                        creation_time: None,
                        last_access_time: None,
                        last_write_time: None,
                    },
                    None,
                ),
                (
                    VirtualFileDescriptor::basic(Arc::from("emoji-🚢.bin"), 5),
                    Some(ferry),
                ),
            ],
            Duration::from_mins(1),
        )
        .unwrap();
        let server = SecureOfferServer::start(
            "127.0.0.1:0".parse().unwrap(),
            peers.server,
            offered,
            Duration::from_mins(1),
            Duration::from_secs(2),
        )
        .unwrap();
        let client = SecureOfferClient::new(server.address(), peers.client);

        let manifest = client.fetch_manifest().unwrap();
        assert_eq!(manifest.entries.len(), 4);
        assert_eq!(server.metrics().begun_transfers, 0);
        assert_eq!(server.metrics().read_requests, 0);
        let Err(directory_error) = client.begin_transfer(&manifest, &manifest.entries[0]) else {
            panic!("directory unexpectedly opened a content transfer");
        };
        assert_eq!(directory_error.kind(), io::ErrorKind::PermissionDenied);

        let registry = RemoteTransferRegistry::default();
        let alpha_source = registry.create_source_for_entry(
            client.clone(),
            manifest.clone(),
            manifest.entries[1].clone(),
        );
        let ferry_source =
            registry.create_source_for_entry(client, manifest.clone(), manifest.entries[3].clone());
        let ferry_thread = std::thread::spawn(move || {
            let mut bytes = [0_u8; 5];
            assert_eq!(ferry_source.read_at(0, &mut bytes).unwrap(), 5);
            bytes
        });
        let alpha_thread = std::thread::spawn(move || {
            let mut bytes = [0_u8; 5];
            assert_eq!(alpha_source.read_at(0, &mut bytes).unwrap(), 5);
            bytes
        });
        assert_eq!(&ferry_thread.join().unwrap(), b"ferry");
        assert_eq!(&alpha_thread.join().unwrap(), b"alpha");

        let status = registry.status_all().unwrap();
        assert_eq!(status.started_transfers, 2);
        assert_eq!(status.unique_bytes, 10);
        assert_eq!(status.read_calls, 2);
        assert_eq!(status.bytes_read, 10);
        assert_eq!(server.metrics().begun_transfers, 2);
        assert_eq!(server.metrics().read_requests, 2);
        assert_eq!(server.metrics().unique_bytes, 10);
    }

    #[test]
    fn completed_file_sessions_remain_observable_after_later_files_begin() {
        let peers = peers();
        let first: Arc<dyn ReadAtSource> = Arc::new(MemorySource::new(&b"first"[..]));
        let second: Arc<dyn ReadAtSource> = Arc::new(MemorySource::new(&b"second"[..]));
        let offered = SecureOfferedFile::new_tree(
            vec![
                (
                    VirtualFileDescriptor::basic(Arc::from("first.txt"), 5),
                    Some(first),
                ),
                (
                    VirtualFileDescriptor::basic(Arc::from("second.txt"), 6),
                    Some(second),
                ),
            ],
            Duration::from_mins(1),
        )
        .unwrap();
        let server = SecureOfferServer::start(
            "127.0.0.1:0".parse().unwrap(),
            peers.server,
            offered,
            Duration::from_mins(1),
            Duration::from_secs(2),
        )
        .unwrap();
        let client = SecureOfferClient::new(server.address(), peers.client);
        let manifest = client.fetch_manifest().unwrap();
        let registry = RemoteTransferRegistry::default();
        let first = registry.create_source_for_entry(
            client.clone(),
            manifest.clone(),
            manifest.entries[0].clone(),
        );
        let second =
            registry.create_source_for_entry(client, manifest.clone(), manifest.entries[1].clone());

        let mut first_bytes = [0_u8; 5];
        assert_eq!(first.read_at(0, &mut first_bytes).unwrap(), 5);
        let mut eof = [0_u8; 1];
        assert_eq!(first.read_at(5, &mut eof).unwrap(), 0);
        assert_eq!(
            first.status().unwrap().state,
            RemoteTransferState::Completed
        );

        let mut second_bytes = [0_u8; 6];
        assert_eq!(second.read_at(0, &mut second_bytes).unwrap(), 6);
        assert_eq!(second.read_at(6, &mut eof).unwrap(), 0);

        let mut reread = [0_u8; 1];
        assert_eq!(first.read_at(0, &mut reread).unwrap(), 1);
        assert_eq!(reread, [b'f']);
        let status = registry.status_all().unwrap();
        assert_eq!(status.state, RemoteTransferState::Completed);
        assert_eq!(status.started_transfers, 2);
        assert_eq!(status.unique_bytes, 11);
        assert_eq!(server.metrics().unique_bytes, 11);
        assert_eq!(server.metrics().denied_requests, 0);
    }

    #[test]
    fn group_pause_resume_and_cancel_apply_to_every_started_file_stream() {
        let peers = peers();
        let first: Arc<dyn ReadAtSource> = Arc::new(MemorySource::new(&b"first"[..]));
        let second: Arc<dyn ReadAtSource> = Arc::new(MemorySource::new(&b"second"[..]));
        let offered = SecureOfferedFile::new_tree(
            vec![
                (
                    VirtualFileDescriptor::basic(Arc::from("first.txt"), 5),
                    Some(first),
                ),
                (
                    VirtualFileDescriptor::basic(Arc::from("second.txt"), 6),
                    Some(second),
                ),
            ],
            Duration::from_mins(1),
        )
        .unwrap();
        let server = SecureOfferServer::start(
            "127.0.0.1:0".parse().unwrap(),
            peers.server,
            offered,
            Duration::from_mins(1),
            Duration::from_secs(2),
        )
        .unwrap();
        let client = SecureOfferClient::new(server.address(), peers.client);
        let manifest = client.fetch_manifest().unwrap();
        let registry = RemoteTransferRegistry::default();
        let first = registry.create_source_for_entry(
            client.clone(),
            manifest.clone(),
            manifest.entries[0].clone(),
        );
        let second =
            registry.create_source_for_entry(client, manifest.clone(), manifest.entries[1].clone());
        let mut byte = [0_u8; 1];
        first.read_at(0, &mut byte).unwrap();
        second.read_at(0, &mut byte).unwrap();

        let paused = registry.pause_all().unwrap();
        assert_eq!(paused.state, RemoteTransferState::Paused);
        assert_eq!(paused.started_transfers, 2);
        let running = registry.resume_all().unwrap();
        assert_eq!(running.state, RemoteTransferState::Running);
        let cancelled = registry.cancel_all().unwrap();
        assert_eq!(cancelled.state, RemoteTransferState::Cancelled);
        assert_eq!(server.metrics().cancelled_transfers, 2);
        let error = first.read_at(1, &mut byte).unwrap_err();
        assert_eq!(error.code(), HRESULT::from_win32(ERROR_CANCELLED.0));
    }

    #[test]
    fn sequential_commands_reuse_bounded_tls_connections() {
        let length = 2_u64 * 1024 * 1024;
        let (server, client, _) = start_generated(length);
        let manifest = client.fetch_manifest().unwrap();
        let source = SecureRemoteSource::new(client, manifest);
        let mut bytes = vec![0_u8; MAX_SECURE_RANGE_BYTES];

        for offset in (0..length).step_by(MAX_SECURE_RANGE_BYTES) {
            assert_eq!(
                source.read_at(offset, &mut bytes).unwrap(),
                MAX_SECURE_RANGE_BYTES
            );
        }
        assert_eq!(source.status().unwrap().unique_bytes, length);
        assert_eq!(source.pause().unwrap().state, RemoteTransferState::Paused);
        assert_eq!(source.resume().unwrap().state, RemoteTransferState::Running);
        assert_eq!(
            source.complete().unwrap().state,
            RemoteTransferState::Completed
        );

        let metrics = server.metrics();
        assert_eq!(metrics.accepted_connections, 2);
        assert_eq!(
            metrics.read_requests,
            length / MAX_SECURE_RANGE_BYTES as u64
        );
        assert_eq!(metrics.protocol_errors, 0);

        drop(source);
        let deadline = Instant::now() + Duration::from_secs(1);
        while server.workers.load(Ordering::Acquire) != 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(server.workers.load(Ordering::Acquire), 0);
        assert_eq!(server.metrics().protocol_errors, 0);
    }

    #[test]
    fn persistent_control_connection_outlives_the_tls_io_timeout() {
        let peers = peers_with_timeout(Duration::from_millis(250));
        let offered = SecureOfferedFile::generated(
            Arc::from("Remote-Secure-Test.bin"),
            4096,
            Duration::from_mins(1),
        )
        .unwrap();
        let server = SecureOfferServer::start(
            "127.0.0.1:0".parse().unwrap(),
            peers.server,
            offered,
            Duration::from_secs(2),
            Duration::from_millis(250),
        )
        .unwrap();
        let client = SecureOfferClient::new(server.address(), peers.client);

        let manifest = client.fetch_manifest().unwrap();
        let source = SecureRemoteSource::new(client, manifest);
        let mut bytes = [0_u8; 256];
        source.read_at(0, &mut bytes).unwrap();
        std::thread::sleep(Duration::from_millis(750));
        assert_eq!(source.status().unwrap().unique_bytes, 256);
        source.read_at(256, &mut bytes).unwrap();

        assert_eq!(server.metrics().accepted_connections, 2);
        assert_eq!(server.metrics().protocol_errors, 0);
    }

    #[test]
    fn repeated_streams_receive_distinct_transfer_ids() {
        let (_server, client, _) = start_generated(4096);
        let manifest = client.fetch_manifest().unwrap();
        let first = SecureRemoteSource::new(client.clone(), manifest.clone());
        let second = SecureRemoteSource::new(client, manifest);
        let first_credentials = first.credentials_for_test().unwrap();
        let second_credentials = second.credentials_for_test().unwrap();
        assert_ne!(
            first_credentials.transfer_id,
            second_credentials.transfer_id
        );
        assert_ne!(first_credentials.capability, second_credentials.capability);
    }

    #[test]
    fn replayed_control_sequence_and_modified_capability_are_denied() {
        let (server, client, _) = start_generated(4096);
        let manifest = client.fetch_manifest().unwrap();
        let source = SecureRemoteSource::new(client.clone(), manifest);
        let credentials = source.credentials_for_test().unwrap();
        assert_eq!(
            client.control(credentials, 1, Opcode::Pause).unwrap().state,
            RemoteTransferState::Paused
        );
        let replay = client.control(credentials, 1, Opcode::Resume).unwrap_err();
        assert_eq!(replay.kind(), io::ErrorKind::PermissionDenied);

        let mut forged = credentials;
        forged.capability[0] ^= 0x80;
        let denied = client.status(forged).unwrap_err();
        assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
        let metrics = server.metrics();
        assert_eq!(metrics.replayed_requests, 1);
        assert_eq!(metrics.denied_requests, 1);
    }

    #[test]
    fn repeated_begin_nonce_is_rejected_as_a_replay() {
        let (server, client, _) = start_generated(4096);
        let manifest = client.fetch_manifest().unwrap();
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&manifest.offer_id.0);
        payload.extend_from_slice(&manifest.entries[0].file_id.0);
        payload.extend_from_slice(&[0xA5; 32]);

        let first = client
            .command(Opcode::BeginTransfer, payload.clone())
            .unwrap();
        require_ok(&first).unwrap();
        let replay = client.command(Opcode::BeginTransfer, payload).unwrap();
        assert_eq!(
            replay.first().copied(),
            Some(ResponseStatus::Replay.encode())
        );
        assert_eq!(server.metrics().begun_transfers, 1);
        assert_eq!(server.metrics().replayed_requests, 1);
    }

    #[test]
    fn pause_resume_cancel_and_unique_progress_are_server_authoritative() {
        let (server, client, _) = start_generated(4096);
        let manifest = client.fetch_manifest().unwrap();
        let source = SecureRemoteSource::new(client, manifest);
        let mut bytes = [0_u8; 256];
        source.read_at(0, &mut bytes).unwrap();
        source.read_at(128, &mut bytes).unwrap();
        assert_eq!(source.status().unwrap().unique_bytes, 384);
        assert_eq!(source.pause().unwrap().state, RemoteTransferState::Paused);
        assert_eq!(source.resume().unwrap().state, RemoteTransferState::Running);
        assert_eq!(
            source.cancel().unwrap().state,
            RemoteTransferState::Cancelled
        );
        let error = source.read_at(0, &mut bytes).unwrap_err();
        assert_eq!(error.code(), HRESULT::from_win32(ERROR_CANCELLED.0));
        assert_eq!(server.metrics().cancelled_transfers, 1);
        assert_eq!(server.metrics().active_reads, 0);
    }

    #[test]
    fn a_long_pause_is_polled_without_returning_false_eof() {
        let (server, client, _) =
            start_generated_with_timeouts(4096, Duration::from_secs(5), Duration::from_millis(25));
        let manifest = client.fetch_manifest().unwrap();
        let source = Arc::new(SecureRemoteSource::new(client, manifest));
        let mut first = [0_u8; 1];
        source.read_at(0, &mut first).unwrap();
        assert_eq!(source.pause().unwrap().state, RemoteTransferState::Paused);

        let worker_source = Arc::clone(&source);
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut bytes = [0_u8; 32];
            sender
                .send(
                    worker_source
                        .read_at(1, &mut bytes)
                        .map(|read| (read, bytes)),
                )
                .unwrap();
        });
        std::thread::sleep(Duration::from_millis(120));
        assert!(receiver.try_recv().is_err());
        assert!(server.metrics().read_requests >= 3);

        assert_eq!(source.resume().unwrap().state, RemoteTransferState::Running);
        let (read, bytes) = receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert_eq!(read, bytes.len());
        assert_eq!(bytes[0], generated_byte(1));
        worker.join().unwrap();
    }

    #[test]
    fn a_paused_read_cannot_outlive_the_transfer_ttl() {
        let (server, client, _) = start_generated_with_timeouts(
            4096,
            Duration::from_millis(100),
            Duration::from_millis(25),
        );
        let manifest = client.fetch_manifest().unwrap();
        let source = Arc::new(SecureRemoteSource::new(client, manifest));
        let mut first = [0_u8; 1];
        source.read_at(0, &mut first).unwrap();
        source.pause().unwrap();

        let worker_source = Arc::clone(&source);
        let worker = std::thread::spawn(move || {
            let mut bytes = [0_u8; 32];
            worker_source.read_at(1, &mut bytes)
        });
        let error = worker.join().unwrap().unwrap_err();
        assert_eq!(error.code(), HRESULT::from_win32(ERROR_TIMEOUT.0));
        assert_eq!(server.metrics().served_bytes, 1);
        assert_eq!(server.metrics().active_reads, 0);
    }

    #[test]
    fn completed_transfer_allows_repeated_eof_and_seeked_rereads() {
        let (server, client, _) = start_generated(32);
        let manifest = client.fetch_manifest().unwrap();
        let registry = RemoteTransferRegistry::default();
        let source = registry.create_source(client, manifest);

        let mut contents = [0_u8; 32];
        assert_eq!(source.read_at(0, &mut contents).unwrap(), contents.len());
        assert_eq!(contents[0], generated_byte(0));
        assert_eq!(contents[31], generated_byte(31));

        let mut byte = [0_u8; 1];
        assert_eq!(source.read_at(32, &mut byte).unwrap(), 0);
        assert_eq!(source.read_at(32, &mut byte).unwrap(), 0);
        assert_eq!(
            source.status().unwrap().state,
            RemoteTransferState::Completed
        );

        let mut reread = [0_u8; 4];
        assert_eq!(source.read_at(7, &mut reread).unwrap(), reread.len());
        assert_eq!(
            reread,
            std::array::from_fn(|index| generated_byte(7 + index as u64))
        );
        assert_eq!(source.status().unwrap().unique_bytes, 32);
        assert_eq!(server.metrics().begun_transfers, 1);
        assert_eq!(server.metrics().denied_requests, 0);

        drop(source);
        assert_eq!(registry.live_sources(), 1);
        assert_eq!(
            registry.latest_started().unwrap().status().unwrap().state,
            RemoteTransferState::Completed
        );
    }

    #[test]
    fn another_client_cannot_reuse_a_transfer_because_mutual_tls_fails_first() {
        let (server, client, other_tls) = start_generated(4096);
        let manifest = client.fetch_manifest().unwrap();
        let source = SecureRemoteSource::new(client, manifest);
        let _credentials = source.credentials_for_test().unwrap();

        let result = other_tls.connect(server.address()).and_then(|mut stream| {
            stream.write_all(b"not a protocol frame")?;
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte)
        });
        assert!(result.is_err());
        let deadline = Instant::now() + Duration::from_secs(2);
        while server.metrics().tls_failures == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(server.metrics().tls_failures >= 1);
    }

    #[test]
    fn trusted_but_offer_unauthorized_device_is_denied_after_mutual_tls() {
        let peers = trusted_peers(Duration::from_secs(3));
        let offered = SecureOfferedFile::generated(
            Arc::from("Remote-Secure-Test.bin"),
            4096,
            Duration::from_mins(1),
        )
        .unwrap();
        let server = SecureOfferServer::start_trusted(
            "127.0.0.1:0".parse().unwrap(),
            peers.server.clone(),
            peers.authorized_fingerprint,
            offered,
            Duration::from_mins(1),
            Duration::from_secs(2),
        )
        .unwrap();
        let authorized = SecureOfferClient::new(server.address(), peers.authorized.clone());
        let other = SecureOfferClient::new(server.address(), peers.other.clone());
        assert_eq!(
            authorized.fetch_manifest().unwrap().entries[0]
                .descriptor
                .size,
            4096
        );
        assert!(other.fetch_manifest().is_err());

        let deadline = Instant::now() + Duration::from_secs(2);
        while server.metrics().denied_requests == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let metrics = server.metrics();
        assert!(metrics.denied_requests >= 1);
        assert_eq!(metrics.tls_failures, 0);
        assert_eq!(metrics.protocol_errors, 0);
        assert_eq!(metrics.begun_transfers, 0);
    }

    #[test]
    fn revocation_interrupts_a_paused_read_on_existing_tls_connections() {
        let peers = trusted_peers(Duration::from_secs(3));
        let offered = SecureOfferedFile::generated(
            Arc::from("Remote-Secure-Test.bin"),
            4096,
            Duration::from_mins(1),
        )
        .unwrap();
        let server = SecureOfferServer::start_trusted(
            "127.0.0.1:0".parse().unwrap(),
            peers.server.clone(),
            peers.authorized_fingerprint,
            offered,
            Duration::from_mins(1),
            Duration::from_millis(100),
        )
        .unwrap();
        let client = SecureOfferClient::new(server.address(), peers.authorized.clone());
        let manifest = client.fetch_manifest().unwrap();
        let source = Arc::new(SecureRemoteSource::new(client, manifest));
        let mut first = [0_u8; 256];
        assert_eq!(source.read_at(0, &mut first).unwrap(), first.len());
        assert_eq!(source.pause().unwrap().state, RemoteTransferState::Paused);

        let reader = Arc::clone(&source);
        let read = std::thread::spawn(move || {
            let mut bytes = [0_u8; 256];
            reader.read_at(256, &mut bytes)
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while server.metrics().active_reads == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(server.metrics().active_reads, 1);
        peers
            .server_store
            .revoke_peer(peers.authorized_fingerprint)
            .unwrap();
        assert!(read.join().unwrap().is_err());
        assert!(source.status().is_err());

        let deadline = Instant::now() + Duration::from_secs(2);
        while (server.metrics().active_reads != 0 || server.metrics().cancelled_transfers == 0)
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(5));
        }
        let metrics = server.metrics();
        assert_eq!(metrics.active_reads, 0);
        assert_eq!(metrics.cancelled_transfers, 1);
        assert!(metrics.denied_requests >= 1);
        assert_eq!(metrics.tls_failures, 0);
        assert_eq!(metrics.protocol_errors, 0);
    }

    #[test]
    fn revoked_peer_cannot_open_a_new_tls_connection() {
        let peers = trusted_peers(Duration::from_secs(3));
        let offered = SecureOfferedFile::generated(
            Arc::from("Remote-Secure-Test.bin"),
            4096,
            Duration::from_mins(1),
        )
        .unwrap();
        let server = SecureOfferServer::start_trusted(
            "127.0.0.1:0".parse().unwrap(),
            peers.server.clone(),
            peers.authorized_fingerprint,
            offered,
            Duration::from_mins(1),
            Duration::from_secs(2),
        )
        .unwrap();
        peers
            .server_store
            .revoke_peer(peers.authorized_fingerprint)
            .unwrap();
        let client = SecureOfferClient::new(server.address(), peers.authorized.clone());
        assert!(client.fetch_manifest().is_err());
        let deadline = Instant::now() + Duration::from_secs(2);
        while server.metrics().tls_failures == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let metrics = server.metrics();
        assert!(metrics.tls_failures >= 1);
        assert_eq!(metrics.begun_transfers, 0);
        assert_eq!(metrics.protocol_errors, 0);
    }

    #[test]
    fn malformed_plaintext_client_never_reaches_the_protocol() {
        let (server, _client, _) = start_generated(4096);
        let mut socket = TcpStream::connect(server.address()).unwrap();
        socket.write_all(b"CFS4 plaintext").unwrap();
        let _ = socket.shutdown(std::net::Shutdown::Both);
        let deadline = Instant::now() + Duration::from_secs(2);
        while server.metrics().tls_failures == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(server.metrics().tls_failures >= 1);
        assert_eq!(server.metrics().begun_transfers, 0);
    }

    #[test]
    fn authenticated_partial_frame_disconnect_does_not_poison_the_server() {
        let (server, client, _) = start_generated(4096);
        let mut stream = client.tls.connect(client.address).unwrap();
        write_frame(
            &mut stream,
            Frame {
                opcode: Opcode::Hello as u16,
                request_id: 77,
                payload: {
                    let mut payload = vec![HELLO_ROLE_RECEIVER];
                    payload.extend_from_slice(&[0x5A; 32]);
                    payload
                },
            },
        )
        .unwrap();
        let hello_ack = read_frame(&mut stream).unwrap();
        assert_eq!(hello_ack.opcode, response_opcode(Opcode::Hello));

        let mut incomplete_header = [0_u8; FRAME_HEADER_LEN];
        incomplete_header[..4].copy_from_slice(&MAGIC);
        incomplete_header[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        incomplete_header[6..8].copy_from_slice(&(Opcode::GetOffer as u16).to_be_bytes());
        stream.write_all(&incomplete_header[..10]).unwrap();
        stream.flush().unwrap();
        drop(stream);

        let deadline = Instant::now() + Duration::from_secs(2);
        while server.metrics().protocol_errors == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(server.metrics().protocol_errors >= 1);
        assert_eq!(
            client.fetch_manifest().unwrap().entries[0].descriptor.size,
            4096
        );
    }

    #[test]
    fn receiver_manifest_decoder_rejects_malicious_metadata_before_exposing_it_to_shell() {
        let (server, _client, _) = start_generated(4096);
        let valid = encode_manifest_response(&server.state, &[]).unwrap();
        let decoded = SecureOfferClient::decode_manifest_response(&valid).unwrap();
        assert_eq!(decoded.entries.len(), 1);

        let mut corpus = Vec::new();
        let mut zero_ttl = valid.clone();
        zero_ttl[17..25].fill(0);
        corpus.push(zero_ttl);

        let mut zero_items = valid.clone();
        zero_items[25..29].fill(0);
        corpus.push(zero_items);

        let time_flags_offset = MANIFEST_HEADER_LEN + 16 + 8 + 4;
        let mut invalid_time_flags = valid.clone();
        invalid_time_flags[time_flags_offset] = 0x80;
        corpus.push(invalid_time_flags);

        let name_length_offset = time_flags_offset + 1 + 24;
        let name_offset = name_length_offset + 2;
        let mut trailing_dot_path = valid.clone();
        *trailing_dot_path.last_mut().unwrap() = b'.';
        corpus.push(trailing_dot_path);

        let mut truncated_name = valid.clone();
        let name_length = u16::from_be_bytes(
            truncated_name[name_length_offset..name_offset]
                .try_into()
                .unwrap(),
        );
        truncated_name[name_length_offset..name_offset]
            .copy_from_slice(&name_length.saturating_add(1).to_be_bytes());
        corpus.push(truncated_name);

        let mut trailing_bytes = valid.clone();
        trailing_bytes.push(0);
        corpus.push(trailing_bytes);

        let mut oversized = valid;
        oversized.resize(MAX_SECURE_MANIFEST_BYTES + 1, 0);
        corpus.push(oversized);

        for malformed in corpus {
            assert!(SecureOfferClient::decode_manifest_response(&malformed).is_err());
        }
    }

    #[test]
    fn malformed_frame_corpus_is_bounded_and_rejected() {
        let mut corpus = Vec::new();

        for length in 1..FRAME_HEADER_LEN {
            corpus.push(vec![0_u8; length]);
        }

        let mut invalid_magic = [0_u8; FRAME_HEADER_LEN];
        invalid_magic[..4].copy_from_slice(b"NOPE");
        invalid_magic[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        corpus.push(invalid_magic.to_vec());

        let mut invalid_version = [0_u8; FRAME_HEADER_LEN];
        invalid_version[..4].copy_from_slice(&MAGIC);
        invalid_version[4..6].copy_from_slice(&PROTOCOL_VERSION.wrapping_add(1).to_be_bytes());
        corpus.push(invalid_version.to_vec());

        let mut oversized = [0_u8; FRAME_HEADER_LEN];
        oversized[..4].copy_from_slice(&MAGIC);
        oversized[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        oversized[16..20]
            .copy_from_slice(&(u32::try_from(MAX_FRAME_PAYLOAD).unwrap() + 1).to_be_bytes());
        corpus.push(oversized.to_vec());

        let mut missing_payload = [0_u8; FRAME_HEADER_LEN];
        missing_payload[..4].copy_from_slice(&MAGIC);
        missing_payload[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        missing_payload[16..20].copy_from_slice(&16_u32.to_be_bytes());
        corpus.push(missing_payload.to_vec());

        for bytes in corpus {
            let error = read_frame(&mut bytes.as_slice()).unwrap_err();
            assert!(matches!(
                error.kind(),
                io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
            ));
        }
    }

    #[test]
    fn secure_frame_parser_survives_a_deterministic_mutation_sweep() {
        let mut state = 0xD1B5_4A32_D192_ED03_u64;
        let mut accepted = 0_usize;
        let mut rejected = 0_usize;

        for case in 0..2048_u64 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let actual_length = usize::try_from(state & 0x0FFF).unwrap();
            let mut bytes = vec![0_u8; FRAME_HEADER_LEN + actual_length];
            bytes[..4].copy_from_slice(&MAGIC);
            bytes[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
            let opcode = u16::try_from(state & u64::from(u16::MAX)).unwrap();
            bytes[6..8].copy_from_slice(&opcode.to_be_bytes());
            bytes[8..16].copy_from_slice(&state.to_be_bytes());
            for (index, byte) in bytes[FRAME_HEADER_LEN..].iter_mut().enumerate() {
                *byte = u8::try_from(
                    state.rotate_left(u32::try_from(index % 64).unwrap()) & u64::from(u8::MAX),
                )
                .unwrap();
            }

            let declared_length = match case % 5 {
                0 => u32::try_from(actual_length).unwrap(),
                1 => u32::try_from(actual_length + 1).unwrap(),
                2 => {
                    bytes[usize::try_from(case).unwrap() % 4] ^= 0x80;
                    u32::try_from(actual_length).unwrap()
                }
                3 => {
                    bytes[4] ^= 0x40;
                    u32::try_from(actual_length).unwrap()
                }
                _ => u32::try_from(MAX_FRAME_PAYLOAD).unwrap() + 1,
            };
            bytes[16..20].copy_from_slice(&declared_length.to_be_bytes());

            match read_frame(&mut bytes.as_slice()) {
                Ok(frame) => {
                    accepted += 1;
                    assert_eq!(frame.payload.len(), actual_length);
                }
                Err(error) => {
                    rejected += 1;
                    assert!(matches!(
                        error.kind(),
                        io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
                    ));
                }
            }
        }

        assert!(accepted > 0);
        assert!(rejected > 0);
    }
}
