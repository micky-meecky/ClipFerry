use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{
    E_ACCESSDENIED, E_INVALIDARG, ERROR_CANCELLED, ERROR_READ_FAULT, ERROR_TIMEOUT, FILETIME,
};
use windows::core::{Error, HRESULT, Result};

use crate::security::{PinnedTlsClient, PinnedTlsServer};

use super::data_object::{VirtualFileDescriptor, validate_virtual_file_name};
use super::local_file::LocalFileOffer;
use super::source::ReadAtSource;
use super::transfer::{GeneratedSource, TransferControl};

const MAGIC: [u8; 4] = *b"CFS4";
const PROTOCOL_VERSION: u16 = 1;
const FRAME_HEADER_LEN: usize = 20;
const MAX_FRAME_PAYLOAD: usize = 128 * 1024;
pub const MAX_SECURE_RANGE_BYTES: usize = 64 * 1024;
const MAX_TRANSFERS: usize = 64;
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
    pub file_id: ProtocolId,
    pub descriptor: VirtualFileDescriptor,
    pub ttl: Duration,
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
    source: Arc<dyn ReadAtSource>,
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
        if ttl.is_zero() || descriptor.size != source.len() {
            return Err(invalid_data("invalid secure offer size or lifetime"));
        }
        validate_virtual_file_name(&descriptor.file_name).map_err(invalid_windows)?;
        let offer_id = ProtocolId::random()?;
        let file_id = ProtocolId::random()?;
        let expires_at = Instant::now()
            .checked_add(ttl)
            .ok_or_else(|| invalid_data("secure offer lifetime is too large"))?;
        Ok(Self {
            manifest: OfferManifest {
                offer_id,
                file_id,
                descriptor,
                ttl,
            },
            source,
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
        let source: Arc<dyn ReadAtSource> = offer.source();
        Self::new(offer.descriptor(), source, offer.remaining_ttl())
    }

    #[must_use]
    pub fn manifest(&self) -> OfferManifest {
        let mut manifest = self.manifest.clone();
        manifest.ttl = self.expires_at.saturating_duration_since(Instant::now());
        manifest
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
    transfer_ttl: Duration,
    request_timeout: Duration,
    inner: Mutex<ServerInner>,
    metrics: Arc<SecureMetrics>,
}

impl ServerState {
    fn begin_transfer(
        &self,
        offer_id: ProtocolId,
        nonce: [u8; 32],
    ) -> WireResult<TransferCredentials> {
        let now = Instant::now();
        if offer_id != self.offered.manifest.offer_id || now >= self.offered.expires_at {
            return Err(ResponseStatus::Expired);
        }
        let mut inner = self.inner.lock().map_err(|_| ResponseStatus::Internal)?;
        inner.transfers.retain(|_, transfer| {
            transfer.expires_at > now
                && transfer
                    .inner
                    .lock()
                    .is_ok_and(|state| state.state != RemoteTransferState::Completed)
        });
        inner.begin_nonces.retain(|_, expires_at| *expires_at > now);
        if inner.begin_nonces.contains_key(&nonce) {
            self.metrics
                .replayed_requests
                .fetch_add(1, Ordering::Relaxed);
            return Err(ResponseStatus::Replay);
        }
        if inner.transfers.len() >= MAX_TRANSFERS || inner.begin_nonces.len() >= MAX_BEGIN_NONCES {
            return Err(ResponseStatus::Busy);
        }
        let transfer_id = ProtocolId::random().map_err(|_| ResponseStatus::Internal)?;
        let expires_at = now
            .checked_add(self.transfer_ttl)
            .ok_or(ResponseStatus::Internal)?;
        let session = Arc::new(TransferSession {
            offer_id,
            file_id: self.offered.manifest.file_id,
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
        credentials: &TransferCredentials,
    ) -> WireResult<Arc<TransferSession>> {
        let inner = self.inner.lock().map_err(|_| ResponseStatus::Internal)?;
        let Some(session) = inner.transfers.get(&credentials.transfer_id) else {
            self.metrics.denied_requests.fetch_add(1, Ordering::Relaxed);
            return Err(ResponseStatus::Denied);
        };
        if session.expires_at <= Instant::now() {
            return Err(ResponseStatus::Expired);
        }
        if session.offer_id != credentials.offer_id
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
        credentials: &TransferCredentials,
        sequence: u64,
        opcode: Opcode,
    ) -> WireResult<TransferStatus> {
        let session = self.authenticated_session(credentials)?;
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

    fn status(&self, credentials: &TransferCredentials) -> WireResult<TransferStatus> {
        let session = self.authenticated_session(credentials)?;
        let inner = session.inner.lock().map_err(|_| ResponseStatus::Internal)?;
        Ok(TransferStatus {
            state: inner.state,
            unique_bytes: inner.coverage.unique_bytes,
        })
    }

    fn read_range(
        &self,
        credentials: &TransferCredentials,
        offset: u64,
        requested: usize,
    ) -> WireResult<(TransferStatus, Vec<u8>)> {
        if requested > MAX_SECURE_RANGE_BYTES {
            return Err(ResponseStatus::Invalid);
        }
        let session = self.authenticated_session(credentials)?;
        self.metrics.read_requests.fetch_add(1, Ordering::Relaxed);
        let _active = self.metrics.begin_read();
        let mut inner = session.inner.lock().map_err(|_| ResponseStatus::Internal)?;
        while inner.state == RemoteTransferState::Paused {
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
        if inner.state == RemoteTransferState::Completed {
            return Err(ResponseStatus::Denied);
        }
        drop(inner);

        let available = self.offered.manifest.descriptor.size.saturating_sub(offset);
        let count = usize::try_from(available.min(requested as u64)).unwrap_or(requested);
        let mut bytes = vec![0_u8; count];
        let read = self
            .offered
            .source
            .read_at(offset, &mut bytes)
            .map_err(|_| ResponseStatus::SourceChanged)?;
        bytes.truncate(read);

        let mut inner = session.inner.lock().map_err(|_| ResponseStatus::Internal)?;
        if Instant::now() >= session.expires_at {
            return Err(ResponseStatus::Expired);
        }
        if inner.state == RemoteTransferState::Cancelled {
            return Err(ResponseStatus::Cancelled);
        }
        if inner.state == RemoteTransferState::Completed {
            return Err(ResponseStatus::Denied);
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
        if transfer_ttl.is_zero() || request_timeout.is_zero() {
            return Err(invalid_data("secure server timeouts must be non-zero"));
        }
        let listener = TcpListener::bind(listen_address)?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let state = Arc::new(ServerState {
            offered,
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

impl Drop for SecureOfferServer {
    fn drop(&mut self) {
        self.stop();
    }
}

#[allow(clippy::needless_pass_by_value)]
fn secure_accept_loop(
    listener: TcpListener,
    tls: PinnedTlsServer,
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
                            Ok(mut stream) => {
                                if let Err(error) =
                                    handle_secure_connection(&mut stream, &worker_state)
                                {
                                    eprintln!("SECURE connection_error={error}");
                                    worker_state
                                        .metrics
                                        .protocol_errors
                                        .fetch_add(1, Ordering::Relaxed);
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
) -> io::Result<()> {
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

    let request = read_frame(stream)?;
    let opcode = Opcode::try_from(request.opcode)?;
    let response = dispatch_request(state, opcode, &request.payload);
    write_frame(
        stream,
        Frame {
            opcode: response_opcode(opcode),
            request_id: request.request_id,
            payload: response,
        },
    )
}

fn dispatch_request(state: &ServerState, opcode: Opcode, payload: &[u8]) -> Vec<u8> {
    let result = match opcode {
        Opcode::GetOffer => encode_manifest_response(state, payload),
        Opcode::BeginTransfer => encode_begin_response(state, payload),
        Opcode::ReadRange => encode_read_response(state, payload),
        Opcode::Pause | Opcode::Resume | Opcode::Cancel | Opcode::Complete => {
            encode_control_response(state, opcode, payload)
        }
        Opcode::Status => encode_status_response(state, payload),
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
    response.extend_from_slice(&manifest.file_id.0);
    response.extend_from_slice(&manifest.descriptor.size.to_be_bytes());
    response.extend_from_slice(&manifest.descriptor.attributes.to_be_bytes());
    let mut time_flags = 0_u8;
    if manifest.descriptor.creation_time.is_some() {
        time_flags |= 1;
    }
    if manifest.descriptor.last_access_time.is_some() {
        time_flags |= 2;
    }
    if manifest.descriptor.last_write_time.is_some() {
        time_flags |= 4;
    }
    response.push(time_flags);
    response.extend_from_slice(&filetime_bits(manifest.descriptor.creation_time).to_be_bytes());
    response.extend_from_slice(&filetime_bits(manifest.descriptor.last_access_time).to_be_bytes());
    response.extend_from_slice(&filetime_bits(manifest.descriptor.last_write_time).to_be_bytes());
    response.extend_from_slice(
        &u64::try_from(manifest.ttl.as_millis())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    let name = manifest.descriptor.file_name.as_bytes();
    let name_length = u16::try_from(name.len()).map_err(|_| ResponseStatus::Internal)?;
    response.extend_from_slice(&name_length.to_be_bytes());
    response.extend_from_slice(name);
    Ok(response)
}

fn encode_begin_response(state: &ServerState, payload: &[u8]) -> WireResult<Vec<u8>> {
    if payload.len() != 48 {
        return Err(ResponseStatus::Invalid);
    }
    let offer_id = ProtocolId(array_at(payload, 0)?);
    let nonce = array_at(payload, 16)?;
    if nonce.iter().all(|byte| *byte == 0) {
        return Err(ResponseStatus::Invalid);
    }
    let credentials = state.begin_transfer(offer_id, nonce)?;
    let mut response = vec![ResponseStatus::Ok.encode()];
    response.extend_from_slice(&credentials.offer_id.0);
    response.extend_from_slice(&credentials.file_id.0);
    response.extend_from_slice(&credentials.transfer_id.0);
    response.extend_from_slice(&credentials.capability);
    response.extend_from_slice(&credentials.server_nonce);
    response.extend_from_slice(&credentials.expires_at_millis.to_be_bytes());
    Ok(response)
}

fn encode_read_response(state: &ServerState, payload: &[u8]) -> WireResult<Vec<u8>> {
    if payload.len() != TransferCredentials::WIRE_LEN + 12 {
        return Err(ResponseStatus::Invalid);
    }
    let credentials = TransferCredentials::decode(payload)?;
    let offset = u64::from_be_bytes(array_at(payload, TransferCredentials::WIRE_LEN)?);
    let requested = u32::from_be_bytes(array_at(payload, TransferCredentials::WIRE_LEN + 8)?);
    let requested = usize::try_from(requested).map_err(|_| ResponseStatus::Invalid)?;
    let (status, bytes) = state.read_range(&credentials, offset, requested)?;
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
    opcode: Opcode,
    payload: &[u8],
) -> WireResult<Vec<u8>> {
    if payload.len() != TransferCredentials::WIRE_LEN + 8 {
        return Err(ResponseStatus::Invalid);
    }
    let credentials = TransferCredentials::decode(payload)?;
    let sequence = u64::from_be_bytes(array_at(payload, TransferCredentials::WIRE_LEN)?);
    state
        .control(&credentials, sequence, opcode)
        .map(encode_transfer_status)
}

fn encode_status_response(state: &ServerState, payload: &[u8]) -> WireResult<Vec<u8>> {
    if payload.len() != TransferCredentials::WIRE_LEN {
        return Err(ResponseStatus::Invalid);
    }
    let credentials = TransferCredentials::decode(payload)?;
    state.status(&credentials).map(encode_transfer_status)
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
}

impl SecureOfferClient {
    #[must_use]
    pub fn new(address: SocketAddr, tls: PinnedTlsClient) -> Self {
        Self {
            address,
            tls,
            next_request_id: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Fetches and validates the metadata-only offer over the pinned TLS connection.
    ///
    /// # Errors
    ///
    /// Returns an error for TLS, I/O, protocol, expiry, or unsafe file-name failures.
    pub fn fetch_manifest(&self) -> io::Result<OfferManifest> {
        let response = self.command(Opcode::GetOffer, Vec::new())?;
        require_ok(&response)?;
        if response.len() < 80 {
            return Err(invalid_data("truncated offer manifest"));
        }
        let offer_id = ProtocolId(array_at_io(&response, 1)?);
        let file_id = ProtocolId(array_at_io(&response, 17)?);
        let size = u64::from_be_bytes(array_at_io(&response, 33)?);
        let attributes = u32::from_be_bytes(array_at_io(&response, 41)?);
        let time_flags = response[45];
        let creation = u64::from_be_bytes(array_at_io(&response, 46)?);
        let access = u64::from_be_bytes(array_at_io(&response, 54)?);
        let write = u64::from_be_bytes(array_at_io(&response, 62)?);
        let ttl_millis = u64::from_be_bytes(array_at_io(&response, 70)?);
        let name_length = usize::from(u16::from_be_bytes(array_at_io(&response, 78)?));
        if response.len() != 80 + name_length {
            return Err(invalid_data("invalid offer file name length"));
        }
        let file_name = std::str::from_utf8(&response[80..]).map_err(invalid_crypto)?;
        validate_virtual_file_name(file_name).map_err(invalid_windows)?;
        Ok(OfferManifest {
            offer_id,
            file_id,
            descriptor: VirtualFileDescriptor {
                file_name: Arc::from(file_name),
                size,
                attributes,
                creation_time: (time_flags & 1 != 0).then(|| filetime_from_bits(creation)),
                last_access_time: (time_flags & 2 != 0).then(|| filetime_from_bits(access)),
                last_write_time: (time_flags & 4 != 0).then(|| filetime_from_bits(write)),
            },
            ttl: Duration::from_millis(ttl_millis),
        })
    }

    fn begin_transfer(&self, manifest: &OfferManifest) -> io::Result<TransferCredentials> {
        let mut payload = Vec::with_capacity(48);
        payload.extend_from_slice(&manifest.offer_id.0);
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
        if credentials.offer_id != manifest.offer_id || credentials.file_id != manifest.file_id {
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

        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        write_frame(
            &mut stream,
            Frame {
                opcode: opcode as u16,
                request_id,
                payload,
            },
        )?;
        let response = read_frame(&mut stream)?;
        if response.opcode != response_opcode(opcode) || response.request_id != request_id {
            return Err(invalid_data("secure response does not match request"));
        }
        Ok(response.payload)
    }
}

pub struct SecureRemoteSource {
    client: SecureOfferClient,
    manifest: OfferManifest,
    transfer: Mutex<Option<TransferCredentials>>,
    next_control_sequence: AtomicU64,
    completion_sent: AtomicBool,
    read_calls: AtomicU64,
    bytes_read: AtomicU64,
}

impl SecureRemoteSource {
    #[must_use]
    pub fn new(client: SecureOfferClient, manifest: OfferManifest) -> Self {
        Self {
            client,
            manifest,
            transfer: Mutex::new(None),
            next_control_sequence: AtomicU64::new(1),
            completion_sent: AtomicBool::new(false),
            read_calls: AtomicU64::new(0),
            bytes_read: AtomicU64::new(0),
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
        let credentials = self.client.begin_transfer(&self.manifest)?;
        *transfer = Some(credentials);
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
}

impl RemoteTransferRegistry {
    pub fn create_source(
        &self,
        client: SecureOfferClient,
        manifest: OfferManifest,
    ) -> Arc<SecureRemoteSource> {
        let source = Arc::new(SecureRemoteSource::new(client, manifest));
        if let Ok(mut sources) = self.sources.lock() {
            sources.push(Arc::clone(&source));
            if sources.len() > MAX_TRANSFERS {
                let excess = sources.len() - MAX_TRANSFERS;
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
        self.manifest.descriptor.size
    }

    fn read_at(&self, offset: u64, destination: &mut [u8]) -> Result<usize> {
        if destination.is_empty() {
            return Ok(0);
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
            if status.state == RemoteTransferState::Completed {
                return Err(Error::from_hresult(E_ACCESSDENIED));
            }
            break bytes;
        };
        if bytes.is_empty() && offset < self.manifest.descriptor.size {
            return Err(Error::from_hresult(HRESULT::from_win32(ERROR_READ_FAULT.0)));
        }
        if bytes.is_empty()
            && offset >= self.manifest.descriptor.size
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
    let mut header = [0_u8; FRAME_HEADER_LEN];
    stream.read_exact(&mut header)?;
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
    Ok(Frame {
        opcode,
        request_id,
        payload,
    })
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
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;

    use rcgen::CertifiedKey;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

    use crate::security::{CertificateFingerprint, TlsIdentity};

    use super::*;
    use crate::clipboard::transfer::generated_byte;

    struct TestPeers {
        server: PinnedTlsServer,
        client: PinnedTlsClient,
        other_client: PinnedTlsClient,
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
        let (server_identity, server_certificate) = identity();
        let (client_identity, client_certificate) = identity();
        let (other_identity, _) = identity();
        let timeout = Duration::from_secs(3);
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
        assert_eq!(&*manifest.descriptor.file_name, "Remote-Secure-Test.bin");
        assert_eq!(manifest.descriptor.size, 1024 * 1024);
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
        let mut payload = Vec::with_capacity(48);
        payload.extend_from_slice(&manifest.offer_id.0);
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
    fn eof_completes_the_transfer_and_registry_retains_observable_status() {
        let (_server, client, _) = start_generated(32);
        let manifest = client.fetch_manifest().unwrap();
        let registry = RemoteTransferRegistry::default();
        let source = registry.create_source(client, manifest);
        let mut byte = [0_u8; 1];
        assert_eq!(source.read_at(32, &mut byte).unwrap(), 0);
        assert_eq!(
            source.status().unwrap().state,
            RemoteTransferState::Completed
        );
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
        assert_eq!(client.fetch_manifest().unwrap().descriptor.size, 4096);
    }
}
