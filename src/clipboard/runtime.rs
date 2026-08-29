use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::ffi::c_void;
use std::fmt::Write as _;
use std::io::{BufRead as _, Write as _};

use sha2::{Digest as _, Sha256};

use windows::Win32::Foundation::{
    CLIPBRD_E_CANT_OPEN, E_INVALIDARG, E_UNEXPECTED, HINSTANCE, HWND, LPARAM, LRESULT, S_OK, WPARAM,
};
use windows::Win32::System::Com::IDataObject;
use windows::Win32::System::DataExchange::{
    AddClipboardFormatListener, RemoveClipboardFormatListener,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Ole::{OleInitialize, OleSetClipboard, OleUninitialize};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::Shell::IDataObjectAsyncCapability;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, HWND_MESSAGE,
    KillTimer, MSG, PostThreadMessageW, RegisterClassW, SetTimer, TranslateMessage,
    UnregisterClassW, WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLIPBOARDUPDATE, WM_QUIT, WM_TIMER,
    WNDCLASSW,
};
use windows::core::{Error, HRESULT, Interface, Result, w};

use super::data_object::VirtualFileDataObject;
use super::local_file::{
    CaptureFormats, ClipboardCapture, FileSnapshot, LocalFileOffer, LocalOfferRegistry,
    capture_single_file_from_clipboard,
};
use super::loopback::{
    DEFAULT_MAX_WORKERS, LOOPBACK_FILE_ID, LOOPBACK_TEST_FILE_NAME, LoopbackControlClient,
    LoopbackServer, LoopbackServerConfig, TcpRangeSource,
};
use super::probe::ProbeState;
use super::secure_transfer::{
    RemoteTransferRegistry, SecureMetricsSnapshot, SecureOfferClient, SecureOfferServer,
    SecureOfferedFile, SecureRemoteSource, TransferStatus,
};
use super::source::{MemorySource, ReadAtSource};
use super::transfer::{GeneratedSource, TransferControl};
use super::{TEST_FILE_CONTENT, TEST_FILE_NAME};
use crate::security::{CertificateFingerprint, PinnedTlsServer, TrustedTlsServer};

#[derive(Clone, Copy, Debug, Default)]
pub struct ClipboardProbeOptions {
    pub lifetime: Option<Duration>,
}

#[derive(Clone, Copy, Debug)]
pub struct PauseProbeOptions {
    pub size_bytes: u64,
    pub chunk_bytes: usize,
    pub chunk_delay: Duration,
    pub lifetime: Option<Duration>,
    pub async_mode: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct LoopbackProbeOptions {
    pub size_bytes: u64,
    pub range_bytes: usize,
    pub fragment_bytes: usize,
    pub range_delay: Duration,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub lifetime: Option<Duration>,
    pub async_mode: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct FileCaptureProbeOptions {
    pub offer_ttl: Duration,
    pub lifetime: Option<Duration>,
    pub async_mode: bool,
}

pub struct SecureSourceProbeOptions {
    pub listen_address: SocketAddr,
    pub source_path: PathBuf,
    pub offer_ttl: Duration,
    pub transfer_ttl: Duration,
    pub io_timeout: Duration,
    pub lifetime: Option<Duration>,
    pub tls: SecureSourceTls,
}

pub enum SecureSourceTls {
    Pinned(PinnedTlsServer),
    Trusted {
        tls: TrustedTlsServer,
        authorized_peer: CertificateFingerprint,
    },
}

pub struct SecureReceiverProbeOptions {
    pub client: SecureOfferClient,
    pub lifetime: Option<Duration>,
    pub async_mode: bool,
}

pub struct SecureFetchProbeOptions {
    pub client: SecureOfferClient,
    pub output_path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecureFetchResult {
    pub bytes: u64,
    pub sha256: [u8; 32],
    pub status: TransferStatus,
}

pub const PAUSE_TEST_FILE_NAME: &str = "RemoteClipboard-Pause-Test.bin";

struct OleApartment;

const CLIPBOARD_WINDOW_CLASS: windows::core::PCWSTR = w!("ClipFerryClipboardWindow");

struct ClipboardWindow {
    handle: HWND,
    instance: HINSTANCE,
}

impl ClipboardWindow {
    fn create() -> Result<Self> {
        let module = unsafe { GetModuleHandleW(None) }?;
        let instance = HINSTANCE(module.0);
        let window_class = WNDCLASSW {
            lpfnWndProc: Some(clipboard_window_procedure),
            hInstance: instance,
            lpszClassName: CLIPBOARD_WINDOW_CLASS,
            ..Default::default()
        };
        let atom = unsafe { RegisterClassW(&raw const window_class) };
        if atom == 0 {
            return Err(Error::from_thread());
        }

        let handle_result = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                CLIPBOARD_WINDOW_CLASS,
                w!("ClipFerry Clipboard"),
                WINDOW_STYLE::default(),
                0,
                0,
                0,
                0,
                Some(HWND_MESSAGE),
                None,
                Some(instance),
                None,
            )
        };
        let handle = match handle_result {
            Ok(handle) => handle,
            Err(error) => {
                let _ = unsafe { UnregisterClassW(CLIPBOARD_WINDOW_CLASS, Some(instance)) };
                return Err(error);
            }
        };
        if let Err(error) = unsafe { AddClipboardFormatListener(handle) } {
            let _ = unsafe { DestroyWindow(handle) };
            let _ = unsafe { UnregisterClassW(CLIPBOARD_WINDOW_CLASS, Some(instance)) };
            return Err(error);
        }

        Ok(Self { handle, instance })
    }
}

impl Drop for ClipboardWindow {
    fn drop(&mut self) {
        let _ = unsafe { RemoveClipboardFormatListener(self.handle) };
        let _ = unsafe { DestroyWindow(self.handle) };
        let _ = unsafe { UnregisterClassW(CLIPBOARD_WINDOW_CLASS, Some(self.instance)) };
    }
}

unsafe extern "system" fn clipboard_window_procedure(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}

impl OleApartment {
    fn initialize() -> Result<Self> {
        unsafe { OleInitialize(None) }?;
        Ok(Self)
    }
}

impl Drop for OleApartment {
    fn drop(&mut self) {
        unsafe { OleUninitialize() };
    }
}

struct ClipboardLease {
    object: IDataObject,
    probe: Arc<ProbeState>,
    window: ClipboardWindow,
    _apartment: OleApartment,
}

impl ClipboardLease {
    fn register(
        file_name: Arc<str>,
        source: Arc<dyn ReadAtSource>,
        async_mode: bool,
    ) -> Result<Self> {
        let apartment = OleApartment::initialize()?;
        let window = ClipboardWindow::create()?;
        let probe = Arc::new(ProbeState::default());
        let object = VirtualFileDataObject::create(file_name, source, Arc::clone(&probe))?;
        if async_mode {
            let capability: IDataObjectAsyncCapability = object.cast()?;
            unsafe { capability.SetAsyncMode(true) }?;
        }
        ole_set_clipboard_with_retry(&object)?;

        if probe.read_calls() != 0 {
            return Err(Error::from_hresult(E_UNEXPECTED));
        }
        probe.record(
            "OleSetClipboard",
            format_args!(
                "registered=true deferred_reads={} async_mode={async_mode}",
                probe.read_calls()
            ),
        );
        Ok(Self {
            object,
            probe,
            window,
            _apartment: apartment,
        })
    }

    fn is_current(&self) -> bool {
        self.current_status() == S_OK
    }

    fn current_status(&self) -> HRESULT {
        unsafe { ole_is_current_clipboard_raw(Interface::as_raw(&self.object)) }
    }
}

#[link(name = "ole32")]
unsafe extern "system" {
    #[link_name = "OleIsCurrentClipboard"]
    fn ole_is_current_clipboard_raw(data_object: *mut c_void) -> HRESULT;
}

impl Drop for ClipboardLease {
    fn drop(&mut self) {
        let current = self.is_current();
        let status = self.current_status();
        self.probe.record(
            "ClipboardLease::drop",
            format_args!(
                "was_current={current} status={:#010X} read_calls={}",
                status.0.cast_unsigned(),
                self.probe.read_calls()
            ),
        );
        if current {
            let _ = unsafe { OleSetClipboard(None::<&IDataObject>) };
        }
    }
}

struct CapturedClipboardLease {
    object: IDataObject,
    probe: Arc<ProbeState>,
    offer: Arc<LocalFileOffer>,
}

impl CapturedClipboardLease {
    fn register(offer: Arc<LocalFileOffer>, async_mode: bool) -> Result<Self> {
        let probe = Arc::new(ProbeState::quiet());
        let concrete_source = offer.source();
        let source: Arc<dyn ReadAtSource> = concrete_source.clone();
        let object = VirtualFileDataObject::create_with_descriptor(
            offer.descriptor(),
            source,
            Arc::clone(&probe),
            offer.origin_payload(),
        )?;
        if async_mode {
            let capability: IDataObjectAsyncCapability = object.cast()?;
            unsafe { capability.SetAsyncMode(true) }?;
        }
        ole_set_clipboard_with_retry(&object)?;
        if concrete_source.read_calls() != 0 || concrete_source.bytes_read() != 0 {
            return Err(Error::from_hresult(E_UNEXPECTED));
        }
        probe.record(
            "OleSetClipboard",
            format_args!("captured_offer=true deferred_reads=0 async_mode={async_mode}"),
        );
        Ok(Self {
            object,
            probe,
            offer,
        })
    }

    fn current_status(&self) -> HRESULT {
        unsafe { ole_is_current_clipboard_raw(Interface::as_raw(&self.object)) }
    }

    fn is_current(&self) -> bool {
        self.current_status() == S_OK
    }
}

impl Drop for CapturedClipboardLease {
    fn drop(&mut self) {
        let status = self.current_status();
        let source = self.offer.source();
        self.probe.record(
            "CapturedClipboardLease::drop",
            format_args!(
                "was_current={} status={:#010X} read_calls={} bytes_read={}",
                status == S_OK,
                status.0.cast_unsigned(),
                source.read_calls(),
                source.bytes_read()
            ),
        );
        if status == S_OK {
            let _ = unsafe { OleSetClipboard(None::<&IDataObject>) };
        }
    }
}

fn ole_set_clipboard_with_retry(object: &IDataObject) -> Result<()> {
    const BACKOFF: [Duration; 8] = [
        Duration::from_millis(5),
        Duration::from_millis(10),
        Duration::from_millis(20),
        Duration::from_millis(40),
        Duration::from_millis(80),
        Duration::from_millis(120),
        Duration::from_millis(160),
        Duration::from_millis(200),
    ];
    let mut last_error = Error::from_hresult(E_UNEXPECTED);
    for (index, delay) in BACKOFF.into_iter().enumerate() {
        match unsafe { OleSetClipboard(object) } {
            Ok(()) => return Ok(()),
            Err(error) if error.code() == CLIPBRD_E_CANT_OPEN => last_error = error,
            Err(error) => return Err(error),
        }
        if index + 1 != BACKOFF.len() {
            std::thread::sleep(delay);
        }
    }
    Err(last_error)
}

struct FileCaptureSession {
    offer_ttl: Duration,
    async_mode: bool,
    registry: LocalOfferRegistry,
    lease: Option<CapturedClipboardLease>,
    accepted: u64,
    rejected: u64,
    ignored: u64,
}

impl FileCaptureSession {
    fn new(options: FileCaptureProbeOptions) -> Self {
        Self {
            offer_ttl: options.offer_ttl,
            async_mode: options.async_mode,
            registry: LocalOfferRegistry::default(),
            lease: None,
            accepted: 0,
            rejected: 0,
            ignored: 0,
        }
    }

    fn handle_clipboard_update(&mut self, window: HWND, formats: CaptureFormats) {
        if let Some(current) = self.lease.as_ref()
            && current.is_current()
        {
            current.probe.record(
                "WM_CLIPBOARDUPDATE",
                format_args!("current=true loop_suppressed=true"),
            );
            return;
        }

        self.registry.revoke_current();
        self.lease.take();
        match capture_single_file_from_clipboard(window, formats) {
            Ok(ClipboardCapture::Candidate { path, sequence }) => {
                self.accept_candidate(&path, sequence);
            }
            Ok(ClipboardCapture::Rejected(reason)) => {
                self.rejected = self.rejected.saturating_add(1);
                println!("CAPTURE accepted=false reason={reason}");
            }
            Ok(ClipboardCapture::PrivateOffer) => {
                self.ignored = self.ignored.saturating_add(1);
                println!("CAPTURE ignored=true reason=private-origin");
            }
            Ok(ClipboardCapture::NotFileClipboard) => {
                self.ignored = self.ignored.saturating_add(1);
                println!("CAPTURE ignored=true reason=not-file-clipboard");
            }
            Err(error) => {
                self.rejected = self.rejected.saturating_add(1);
                eprintln!("CAPTURE accepted=false reason=clipboard-read {error}");
            }
        }
        let _ = std::io::stdout().flush();
    }

    fn accept_candidate(&mut self, path: &std::path::Path, sequence: u32) {
        let snapshot = match FileSnapshot::capture(path) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.rejected = self.rejected.saturating_add(1);
                eprintln!("CAPTURE accepted=false {error}");
                return;
            }
        };
        let offer = match self.registry.publish(snapshot, self.offer_ttl) {
            Ok(offer) => offer,
            Err(error) => {
                self.rejected = self.rejected.saturating_add(1);
                eprintln!(
                    "CAPTURE accepted=false reason=offer-create error={:#010X}",
                    error.code().0.cast_unsigned()
                );
                return;
            }
        };
        match CapturedClipboardLease::register(Arc::clone(&offer), self.async_mode) {
            Ok(next_lease) => {
                self.accepted = self.accepted.saturating_add(1);
                println!(
                    "CAPTURE accepted=true sequence={} offer={:?} file_id={:?} file={} size={} content_reads=0 ttl_ms={}",
                    sequence,
                    offer.offer_id(),
                    offer.file_id(),
                    offer.file_name(),
                    offer.size(),
                    offer.remaining_ttl().as_millis()
                );
                self.lease = Some(next_lease);
            }
            Err(error) => {
                self.rejected = self.rejected.saturating_add(1);
                self.registry.revoke_current();
                eprintln!(
                    "CAPTURE accepted=false reason=clipboard-register error={:#010X}",
                    error.code().0.cast_unsigned()
                );
            }
        }
    }

    fn summary(&self) -> CaptureSummary {
        let Some(current) = self.lease.as_ref() else {
            return CaptureSummary {
                current: false,
                accepted: self.accepted,
                rejected: self.rejected,
                ignored: self.ignored,
                ..CaptureSummary::default()
            };
        };
        let source = current.offer.source();
        CaptureSummary {
            current: current.is_current(),
            accepted: self.accepted,
            rejected: self.rejected,
            ignored: self.ignored,
            offer_age_ms: current.offer.age().as_millis(),
            read_calls: source.read_calls(),
            bytes_read: source.bytes_read(),
            events: current.probe.event_count(),
            dropped_events: current.probe.dropped_events(),
        }
    }
}

#[derive(Default)]
struct CaptureSummary {
    current: bool,
    accepted: u64,
    rejected: u64,
    ignored: u64,
    offer_age_ms: u128,
    read_calls: u64,
    bytes_read: u64,
    events: u64,
    dropped_events: u64,
}

/// Registers the fixed virtual-file probe and pumps its clipboard apartment.
///
/// # Errors
///
/// Returns a COM or Win32 error if OLE initialization, clipboard registration,
/// message-window setup, or message processing fails.
pub fn run_clipboard_probe(options: ClipboardProbeOptions) -> Result<()> {
    let lease = ClipboardLease::register(
        Arc::<str>::from(TEST_FILE_NAME),
        Arc::new(MemorySource::new(TEST_FILE_CONTENT)),
        false,
    )?;
    println!(
        "READY file={} size={} deferred_reads={} lifetime={}",
        TEST_FILE_NAME,
        TEST_FILE_CONTENT.len(),
        lease.probe.read_calls(),
        options.lifetime.map_or_else(
            || "infinite".to_owned(),
            |duration| format!("{}s", duration.as_secs())
        )
    );

    let timer = options.lifetime.map(set_exit_timer).transpose()?;
    message_loop(timer, &lease)?;
    if let Some(timer) = timer {
        let _ = unsafe { KillTimer(None, timer) };
    }

    let current_status = lease.current_status();
    println!(
        "STOP current_clipboard={} status={:#010X} read_calls={} events={} dropped_events={}",
        current_status == S_OK,
        current_status.0.cast_unsigned(),
        lease.probe.read_calls(),
        lease.probe.event_count(),
        lease.probe.dropped_events()
    );
    Ok(())
}

/// Captures a real single-file `CF_HDROP` clipboard, validates it, and republishes it as a
/// local virtual-file offer without reading file content before Explorer requests a stream.
///
/// # Errors
///
/// Returns a COM, Win32, clipboard, timer, or thread-start error if the probe cannot run.
pub fn run_file_capture_probe(options: FileCaptureProbeOptions) -> Result<()> {
    if options.offer_ttl.is_zero() {
        return Err(Error::from_hresult(E_INVALIDARG));
    }
    let _apartment = OleApartment::initialize()?;
    let window = ClipboardWindow::create()?;
    let formats = CaptureFormats::register()?;
    let mut session = FileCaptureSession::new(options);

    println!(
        "READY mode=file-capture waiting_for=CF_HDROP offer_ttl={}s async_mode={} lifetime={}",
        options.offer_ttl.as_secs(),
        options.async_mode,
        options.lifetime.map_or_else(
            || "infinite".to_owned(),
            |duration| format!("{}s", duration.as_secs())
        )
    );
    println!("CONTROL commands=status,quit");
    let _ = std::io::stdout().flush();
    spawn_capture_control_input(unsafe { GetCurrentThreadId() })?;
    let timer = options.lifetime.map(set_exit_timer).transpose()?;

    loop {
        let mut message = MSG::default();
        let status = unsafe { GetMessageW(&raw mut message, None, 0, 0) }.0;
        if status == -1 {
            return Err(Error::from_thread());
        }
        if status == 0 || message.message == WM_QUIT {
            break;
        }
        if message.message == WM_TIMER && timer == Some(message.wParam.0) {
            break;
        }
        if message.hwnd == window.handle && message.message == WM_CLIPBOARDUPDATE {
            session.handle_clipboard_update(window.handle, formats);
        }
        unsafe {
            let _ = TranslateMessage(&raw const message);
            DispatchMessageW(&raw const message);
        }
    }

    if let Some(timer) = timer {
        let _ = unsafe { KillTimer(None, timer) };
    }
    let summary = session.summary();
    println!(
        "STOP current_clipboard={current} accepted={accepted} rejected={rejected} ignored={ignored} offer_age_ms={offer_age_ms} read_calls={read_calls} bytes_read={bytes_read} events={events} dropped_events={dropped_events}",
        current = summary.current,
        accepted = summary.accepted,
        rejected = summary.rejected,
        ignored = summary.ignored,
        offer_age_ms = summary.offer_age_ms,
        read_calls = summary.read_calls,
        bytes_read = summary.bytes_read,
        events = summary.events,
        dropped_events = summary.dropped_events
    );
    Ok(())
}

/// Registers a throttled generated file and accepts pause/resume/cancel commands on stdin.
///
/// # Errors
///
/// Returns a COM, Win32, or thread-start error if the probe cannot be registered or pumped.
pub fn run_pause_probe(options: PauseProbeOptions) -> Result<()> {
    let control = Arc::new(TransferControl::default());
    let source: Arc<dyn ReadAtSource> = Arc::new(GeneratedSource::new(
        options.size_bytes,
        options.chunk_bytes,
        options.chunk_delay,
        Arc::clone(&control),
    )?);
    let lease = ClipboardLease::register(
        Arc::<str>::from(PAUSE_TEST_FILE_NAME),
        source,
        options.async_mode,
    )?;
    println!(
        "READY file={} size={} chunk={} delay_ms={} async_mode={} deferred_reads={} lifetime={}",
        PAUSE_TEST_FILE_NAME,
        options.size_bytes,
        options.chunk_bytes,
        options.chunk_delay.as_millis(),
        options.async_mode,
        lease.probe.read_calls(),
        options.lifetime.map_or_else(
            || "infinite".to_owned(),
            |duration| format!("{}s", duration.as_secs())
        )
    );
    println!("CONTROL commands=pause,resume,cancel,status,stop,quit");
    let _ = std::io::stdout().flush();

    let main_thread_id = unsafe { GetCurrentThreadId() };
    spawn_control_input(Arc::clone(&control), main_thread_id)?;
    let timer = options.lifetime.map(set_exit_timer).transpose()?;
    let loop_result = message_loop(timer, &lease);
    // A timed or externally posted shutdown can occur while Explorer is blocked in Read.
    // Always wake that call before releasing the clipboard object so shutdown cannot hang.
    control.cancel()?;
    loop_result?;
    if let Some(timer) = timer {
        let _ = unsafe { KillTimer(None, timer) };
    }

    let current_status = lease.current_status();
    println!(
        "STOP current_clipboard={} status={:#010X} control_state={} bytes_served={} chunks={} read_calls={} events={} dropped_events={}",
        current_status == S_OK,
        current_status.0.cast_unsigned(),
        control.state()?,
        control.bytes_served(),
        control.chunk_calls(),
        lease.probe.read_calls(),
        lease.probe.event_count(),
        lease.probe.dropped_events()
    );
    Ok(())
}

/// Registers a virtual file whose bytes are fetched from a bounded `127.0.0.1` range server.
///
/// # Errors
///
/// Returns a protocol, socket, COM, Win32, or thread-start error if setup or pumping fails.
pub fn run_loopback_probe(options: LoopbackProbeOptions) -> Result<()> {
    let control = Arc::new(TransferControl::default());
    let server = LoopbackServer::start(
        LoopbackServerConfig {
            length: options.size_bytes,
            file_id: LOOPBACK_FILE_ID,
            max_range_bytes: options.range_bytes,
            fragment_bytes: options.fragment_bytes,
            range_delay: options.range_delay,
            socket_timeout: options.io_timeout,
            max_workers: DEFAULT_MAX_WORKERS,
        },
        Arc::clone(&control),
    )?;
    let tcp_source = Arc::new(TcpRangeSource::new(
        server.address(),
        LOOPBACK_FILE_ID,
        options.size_bytes,
        options.range_bytes,
        options.connect_timeout,
        options.io_timeout,
    )?);
    let source: Arc<dyn ReadAtSource> = tcp_source.clone();
    let lease = ClipboardLease::register(
        Arc::<str>::from(LOOPBACK_TEST_FILE_NAME),
        source,
        options.async_mode,
    )?;
    if server.metrics().read_requests != 0 {
        return Err(Error::from_hresult(E_UNEXPECTED));
    }
    println!(
        "READY file={} size={} address={} range={} fragment={} delay_ms={} io_timeout_ms={} async_mode={} deferred_reads={} network_reads=0 lifetime={}",
        LOOPBACK_TEST_FILE_NAME,
        options.size_bytes,
        server.address(),
        options.range_bytes,
        options.fragment_bytes,
        options.range_delay.as_millis(),
        options.io_timeout.as_millis(),
        options.async_mode,
        lease.probe.read_calls(),
        options.lifetime.map_or_else(
            || "infinite".to_owned(),
            |duration| format!("{}s", duration.as_secs())
        )
    );
    println!("CONTROL transport=tcp commands=pause,resume,cancel,status,stop,quit");
    let _ = std::io::stdout().flush();

    let main_thread_id = unsafe { GetCurrentThreadId() };
    spawn_loopback_control_input(
        Arc::new(LoopbackControlClient::new(tcp_source)),
        main_thread_id,
    )?;
    let timer = options.lifetime.map(set_exit_timer).transpose()?;
    let loop_result = message_loop(timer, &lease);
    control.cancel()?;
    loop_result?;
    if let Some(timer) = timer {
        let _ = unsafe { KillTimer(None, timer) };
    }

    let current_status = lease.current_status();
    let metrics = server.metrics();
    println!(
        "STOP current_clipboard={} status={:#010X} control_state={} connections={} network_reads={} served_bytes={} unique_bytes={} ranges={} coverage_saturated={} max_concurrent_reads={} protocol_errors={} read_calls={} events={} dropped_events={}",
        current_status == S_OK,
        current_status.0.cast_unsigned(),
        control.state()?,
        metrics.connections,
        metrics.read_requests,
        metrics.served_bytes,
        metrics.unique_bytes,
        metrics.retained_ranges,
        metrics.coverage_saturated,
        metrics.max_concurrent_reads,
        metrics.protocol_errors,
        lease.probe.read_calls(),
        lease.probe.event_count(),
        lease.probe.dropped_events()
    );
    Ok(())
}

/// Serves one captured local file through the stage-4 pinned mutual-TLS protocol.
///
/// # Errors
///
/// Returns an I/O, source validation, TLS, protocol, or worker-start error.
pub fn run_secure_source_probe(options: SecureSourceProbeOptions) -> std::io::Result<()> {
    let snapshot = FileSnapshot::capture(&options.source_path)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let mut registry = LocalOfferRegistry::default();
    let local_offer = registry
        .publish(snapshot, options.offer_ttl)
        .map_err(windows_to_io)?;
    let offered = SecureOfferedFile::from_local_offer(&local_offer)?;
    let mut server = match options.tls {
        SecureSourceTls::Pinned(tls) => SecureOfferServer::start(
            options.listen_address,
            tls,
            offered,
            options.transfer_ttl,
            options.io_timeout,
        )?,
        SecureSourceTls::Trusted {
            tls,
            authorized_peer,
        } => SecureOfferServer::start_trusted(
            options.listen_address,
            tls,
            authorized_peer,
            offered,
            options.transfer_ttl,
            options.io_timeout,
        )?,
    };
    let manifest = server.manifest();
    println!(
        "READY mode=secure-source tls=1.3 mtls=true address={} offer={} file_id={} file={} size={} content_reads=0 lifetime={}",
        server.address(),
        manifest.offer_id,
        manifest.file_id,
        manifest.descriptor.file_name,
        manifest.descriptor.size,
        options.lifetime.map_or_else(
            || "infinite".to_owned(),
            |duration| format!("{}s", duration.as_secs())
        )
    );
    println!("CONTROL commands=status,quit");
    let _ = std::io::stdout().flush();

    wait_for_secure_source_control(&server, options.lifetime)?;
    server.stop();
    print_secure_server_stop(server.metrics());
    Ok(())
}

/// Downloads one authenticated offer through the same range protocol used by the virtual stream.
/// The target is published by rename only after completion, so failures leave no final file.
///
/// # Errors
///
/// Returns an I/O, TLS, protocol, source, or destination error.
pub fn run_secure_fetch_probe(
    options: SecureFetchProbeOptions,
) -> std::io::Result<SecureFetchResult> {
    if options.output_path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "secure fetch output already exists",
        ));
    }
    let manifest = options.client.fetch_manifest()?;
    let source = SecureRemoteSource::new(options.client, manifest.clone());
    let temporary_path = unique_partial_path(&options.output_path)?;
    let mut temporary = PartialFileGuard::create(temporary_path)?;
    let mut offset = 0_u64;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 256 * 1024];
    loop {
        let read = source.read_at(offset, &mut buffer).map_err(windows_to_io)?;
        if read == 0 {
            break;
        }
        temporary.file.write_all(&buffer[..read])?;
        digest.update(&buffer[..read]);
        offset = offset
            .checked_add(read as u64)
            .ok_or_else(|| std::io::Error::other("download offset overflow"))?;
    }
    if offset != manifest.descriptor.size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "download size differs from authenticated manifest",
        ));
    }
    let status = source.complete()?;
    temporary.file.flush()?;
    temporary.file.sync_all()?;
    temporary.commit(&options.output_path)?;
    Ok(SecureFetchResult {
        bytes: offset,
        sha256: digest.finalize().into(),
        status,
    })
}

/// Registers the authenticated remote manifest as a virtual file and lazily starts one secure
/// transfer per `FILECONTENTS` stream.
///
/// # Errors
///
/// Returns a TLS, protocol, COM, clipboard, timer, or thread-start error.
pub fn run_secure_receiver_probe(options: &SecureReceiverProbeOptions) -> Result<()> {
    let manifest = options
        .client
        .fetch_manifest()
        .map_err(io_to_windows_error)?;
    let _apartment = OleApartment::initialize()?;
    let window = ClipboardWindow::create()?;
    let registry = Arc::new(RemoteTransferRegistry::default());
    let source_factory = {
        let client = options.client.clone();
        let manifest = manifest.clone();
        let registry = Arc::clone(&registry);
        Arc::new(move || {
            let source = registry.create_source(client.clone(), manifest.clone());
            let source: Arc<dyn ReadAtSource> = source;
            source
        }) as Arc<dyn Fn() -> Arc<dyn ReadAtSource> + Send + Sync>
    };
    let probe = Arc::new(ProbeState::quiet());
    let object = VirtualFileDataObject::create_with_source_factory(
        manifest.descriptor.clone(),
        source_factory,
        Arc::clone(&probe),
        manifest.origin_payload(),
    )?;
    if options.async_mode {
        let capability: IDataObjectAsyncCapability = object.cast()?;
        unsafe { capability.SetAsyncMode(true) }?;
    }
    ole_set_clipboard_with_retry(&object)?;
    let lease = RemoteClipboardLease {
        object,
        window,
        probe,
        registry: Arc::clone(&registry),
    };
    println!(
        "READY mode=secure-receiver tls=1.3 mtls=true offer={} file_id={} file={} size={} content_reads=0 async_mode={} lifetime={}",
        manifest.offer_id,
        manifest.file_id,
        manifest.descriptor.file_name,
        manifest.descriptor.size,
        options.async_mode,
        options.lifetime.map_or_else(
            || "infinite".to_owned(),
            |duration| format!("{}s", duration.as_secs())
        )
    );
    println!("CONTROL commands=pause,resume,cancel,status,quit");
    let _ = std::io::stdout().flush();
    let main_thread_id = unsafe { GetCurrentThreadId() };
    spawn_secure_receiver_control(Arc::clone(&registry), main_thread_id)?;
    let timer = options.lifetime.map(set_exit_timer).transpose()?;
    remote_message_loop(timer, &lease)?;
    if let Some(timer) = timer {
        let _ = unsafe { KillTimer(None, timer) };
    }
    let current_status = lease.current_status();
    let latest = registry.latest_started().ok();
    let transfer_state = match latest.as_ref() {
        None => "not-started".to_owned(),
        Some(source) => source.status().map_or_else(
            |error| format!("unavailable({})", error.kind()),
            |status| format!("{:?}", status.state),
        ),
    };
    println!(
        "STOP current_clipboard={} status={:#010X} live_sources={} read_calls={} bytes_read={} transfer_state={}",
        current_status == S_OK,
        current_status.0.cast_unsigned(),
        registry.live_sources(),
        latest.as_ref().map_or(0, |source| source.read_calls()),
        latest.as_ref().map_or(0, |source| source.bytes_read()),
        transfer_state
    );
    Ok(())
}

struct RemoteClipboardLease {
    object: IDataObject,
    window: ClipboardWindow,
    probe: Arc<ProbeState>,
    registry: Arc<RemoteTransferRegistry>,
}

impl RemoteClipboardLease {
    fn current_status(&self) -> HRESULT {
        unsafe { ole_is_current_clipboard_raw(Interface::as_raw(&self.object)) }
    }
}

impl Drop for RemoteClipboardLease {
    fn drop(&mut self) {
        let status = self.current_status();
        self.probe.record(
            "RemoteClipboardLease::drop",
            format_args!(
                "was_current={} status={:#010X} live_sources={}",
                status == S_OK,
                status.0.cast_unsigned(),
                self.registry.live_sources()
            ),
        );
        if status == S_OK {
            let _ = unsafe { OleSetClipboard(None::<&IDataObject>) };
        }
    }
}

fn remote_message_loop(exit_timer: Option<usize>, lease: &RemoteClipboardLease) -> Result<()> {
    loop {
        let mut message = MSG::default();
        let status = unsafe { GetMessageW(&raw mut message, None, 0, 0) }.0;
        if status == -1 {
            return Err(Error::from_thread());
        }
        if status == 0 || message.message == WM_QUIT {
            return Ok(());
        }
        if message.message == WM_TIMER && exit_timer == Some(message.wParam.0) {
            return Ok(());
        }
        if message.hwnd == lease.window.handle && message.message == WM_CLIPBOARDUPDATE {
            let status = lease.current_status();
            lease.probe.record(
                "WM_CLIPBOARDUPDATE",
                format_args!(
                    "current={} status={:#010X}",
                    status == S_OK,
                    status.0.cast_unsigned()
                ),
            );
        }
        unsafe {
            let _ = TranslateMessage(&raw const message);
            DispatchMessageW(&raw const message);
        }
    }
}

fn spawn_secure_receiver_control(
    registry: Arc<RemoteTransferRegistry>,
    main_thread_id: u32,
) -> Result<()> {
    std::thread::Builder::new()
        .name("clipferry-secure-control".to_owned())
        .spawn(move || {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let Ok(line) = line else {
                    eprintln!("CONTROL input_error=true");
                    break;
                };
                let command = line.trim().to_ascii_lowercase();
                if command == "quit" {
                    if let Ok(source) = registry.latest_started() {
                        let _ = source.cancel();
                    }
                    let _ = unsafe {
                        PostThreadMessageW(main_thread_id, WM_QUIT, WPARAM(0), LPARAM(0))
                    };
                    break;
                }
                let source = match registry.latest_started() {
                    Ok(source) => source,
                    Err(error) => {
                        if !command.is_empty() {
                            eprintln!("CONTROL state=not-started command={command} error={error}");
                        }
                        continue;
                    }
                };
                let result = match command.as_str() {
                    "pause" => source.pause(),
                    "resume" => source.resume(),
                    "cancel" => source.cancel(),
                    "status" => source.status(),
                    "" => continue,
                    _ => {
                        eprintln!("CONTROL unknown={command:?}");
                        continue;
                    }
                };
                match result {
                    Ok(status) => println!(
                        "CONTROL state={:?} unique_bytes={} read_calls={} bytes_read={}",
                        status.state,
                        status.unique_bytes,
                        source.read_calls(),
                        source.bytes_read()
                    ),
                    Err(error) => eprintln!("CONTROL command={command} error={error}"),
                }
                let _ = std::io::stdout().flush();
            }
        })
        .map_err(|_| Error::from_hresult(E_UNEXPECTED))?;
    Ok(())
}

fn wait_for_secure_source_control(
    server: &SecureOfferServer,
    lifetime: Option<Duration>,
) -> std::io::Result<()> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("clipferry-secure-source-control".to_owned())
        .spawn(move || {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                match line {
                    Ok(line) => {
                        if sender.send(line).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        })?;
    let deadline = lifetime.map(|duration| Instant::now() + duration);
    loop {
        let timeout = deadline.map_or(Duration::from_secs(1), |deadline| {
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(1))
        });
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Ok(());
        }
        match receiver.recv_timeout(timeout) {
            Ok(line) => match line.trim().to_ascii_lowercase().as_str() {
                "status" => print_secure_server_status(server.metrics()),
                "quit" => return Ok(()),
                "" => {}
                command => eprintln!("CONTROL unknown={command:?}"),
            },
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
        }
        let _ = std::io::stdout().flush();
    }
}

fn print_secure_server_status(metrics: SecureMetricsSnapshot) {
    print_secure_server_metrics("CONTROL", metrics);
}

fn print_secure_server_stop(metrics: SecureMetricsSnapshot) {
    print_secure_server_metrics("STOP", metrics);
}

fn print_secure_server_metrics(prefix: &str, metrics: SecureMetricsSnapshot) {
    println!(
        "{prefix} tls_connections={} tls_failures={} begun_transfers={} network_reads={} served_bytes={} unique_bytes={} active_reads={} denied={} replays={} cancelled={} protocol_errors={}",
        metrics.accepted_connections,
        metrics.tls_failures,
        metrics.begun_transfers,
        metrics.read_requests,
        metrics.served_bytes,
        metrics.unique_bytes,
        metrics.active_reads,
        metrics.denied_requests,
        metrics.replayed_requests,
        metrics.cancelled_transfers,
        metrics.protocol_errors
    );
}

struct PartialFileGuard {
    path: PathBuf,
    file: std::fs::File,
    committed: bool,
}

impl PartialFileGuard {
    fn create(path: PathBuf) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        Ok(Self {
            path,
            file,
            committed: false,
        })
    }

    fn commit(&mut self, output_path: &std::path::Path) -> std::io::Result<()> {
        std::fs::rename(&self.path, output_path)?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for PartialFileGuard {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn unique_partial_path(output_path: &std::path::Path) -> std::io::Result<PathBuf> {
    let parent = output_path
        .parent()
        .ok_or_else(|| std::io::Error::other("secure fetch output has no parent directory"))?;
    let file_name = output_path
        .file_name()
        .ok_or_else(|| std::io::Error::other("secure fetch output has no file name"))?
        .to_string_lossy();
    let mut nonce = [0_u8; 8];
    getrandom::fill(&mut nonce).map_err(|error| std::io::Error::other(error.to_string()))?;
    let suffix = nonce
        .iter()
        .fold(String::with_capacity(16), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        });
    Ok(parent.join(format!(".{file_name}.clipferry-{suffix}.part")))
}

#[allow(clippy::needless_pass_by_value)]
fn windows_to_io(error: Error) -> std::io::Error {
    std::io::Error::other(format!(
        "Windows error {:#010X}: {error}",
        error.code().0.cast_unsigned()
    ))
}

#[allow(clippy::needless_pass_by_value)]
fn io_to_windows_error(error: std::io::Error) -> Error {
    use windows::Win32::Foundation::{
        E_ACCESSDENIED, ERROR_CANCELLED, ERROR_READ_FAULT, ERROR_TIMEOUT,
    };
    let hresult = match error.kind() {
        std::io::ErrorKind::Interrupted => HRESULT::from_win32(ERROR_CANCELLED.0),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
            HRESULT::from_win32(ERROR_TIMEOUT.0)
        }
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::InvalidData => E_ACCESSDENIED,
        std::io::ErrorKind::InvalidInput => E_INVALIDARG,
        _ => HRESULT::from_win32(ERROR_READ_FAULT.0),
    };
    Error::from_hresult(hresult)
}

fn spawn_control_input(control: Arc<TransferControl>, main_thread_id: u32) -> Result<()> {
    std::thread::Builder::new()
        .name("clipferry-probe-control".to_owned())
        .spawn(move || {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let Ok(line) = line else {
                    eprintln!("CONTROL input_error=true");
                    break;
                };
                let command = line.trim().to_ascii_lowercase();
                let state = match command.as_str() {
                    "pause" => control.pause(),
                    "resume" => control.resume(),
                    "cancel" | "quit" => control.cancel(),
                    "status" | "stop" => control.state(),
                    "" => continue,
                    _ => {
                        eprintln!("CONTROL unknown={command:?}");
                        continue;
                    }
                };
                match state {
                    Ok(state) => println!(
                        "CONTROL state={state} bytes_served={} chunks={}",
                        control.bytes_served(),
                        control.chunk_calls()
                    ),
                    Err(error) => eprintln!(
                        "CONTROL error={:#010X} command={command}",
                        error.code().0.cast_unsigned()
                    ),
                }
                let _ = std::io::stdout().flush();
                if command == "quit" || command == "stop" {
                    let _ = unsafe {
                        PostThreadMessageW(main_thread_id, WM_QUIT, WPARAM(0), LPARAM(0))
                    };
                    break;
                }
            }
        })
        .map_err(|_| Error::from_hresult(E_UNEXPECTED))?;
    Ok(())
}

fn spawn_capture_control_input(main_thread_id: u32) -> Result<()> {
    std::thread::Builder::new()
        .name("clipferry-capture-control".to_owned())
        .spawn(move || {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let Ok(line) = line else {
                    eprintln!("CONTROL input_error=true");
                    break;
                };
                match line.trim().to_ascii_lowercase().as_str() {
                    "status" => println!("CONTROL state=running"),
                    "quit" => {
                        let _ = unsafe {
                            PostThreadMessageW(main_thread_id, WM_QUIT, WPARAM(0), LPARAM(0))
                        };
                        break;
                    }
                    "" => continue,
                    command => eprintln!("CONTROL unknown={command:?}"),
                }
                let _ = std::io::stdout().flush();
            }
        })
        .map_err(|_| Error::from_hresult(E_UNEXPECTED))?;
    Ok(())
}

fn spawn_loopback_control_input(
    client: Arc<LoopbackControlClient>,
    main_thread_id: u32,
) -> Result<()> {
    std::thread::Builder::new()
        .name("clipferry-loopback-control".to_owned())
        .spawn(move || {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let Ok(line) = line else {
                    eprintln!("CONTROL input_error=true");
                    break;
                };
                let command = line.trim().to_ascii_lowercase();
                let state = match command.as_str() {
                    "pause" => client.pause(),
                    "resume" => client.resume(),
                    "cancel" | "quit" => client.cancel(),
                    "status" | "stop" => client.state(),
                    "" => continue,
                    _ => {
                        eprintln!("CONTROL unknown={command:?}");
                        continue;
                    }
                };
                match state {
                    Ok(state) => println!("CONTROL transport=tcp state={state}"),
                    Err(error) => eprintln!(
                        "CONTROL transport=tcp error={:#010X} command={command}",
                        error.code().0.cast_unsigned()
                    ),
                }
                let _ = std::io::stdout().flush();
                if command == "quit" || command == "stop" {
                    let _ = unsafe {
                        PostThreadMessageW(main_thread_id, WM_QUIT, WPARAM(0), LPARAM(0))
                    };
                    break;
                }
            }
        })
        .map_err(|_| Error::from_hresult(E_UNEXPECTED))?;
    Ok(())
}

fn set_exit_timer(lifetime: Duration) -> Result<usize> {
    let milliseconds = lifetime.as_millis();
    let milliseconds = u32::try_from(milliseconds)
        .map_err(|_| Error::from_hresult(E_INVALIDARG))?
        .max(1);
    let timer = unsafe { SetTimer(None, 0, milliseconds, None) };
    if timer == 0 {
        Err(Error::from_thread())
    } else {
        Ok(timer)
    }
}

fn message_loop(exit_timer: Option<usize>, lease: &ClipboardLease) -> Result<()> {
    loop {
        let mut message = MSG::default();
        let status = unsafe { GetMessageW(&raw mut message, None, 0, 0) }.0;
        if status == -1 {
            return Err(Error::from_thread());
        }
        if status == 0 || message.message == WM_QUIT {
            return Ok(());
        }
        if message.message == WM_TIMER && exit_timer == Some(message.wParam.0) {
            return Ok(());
        }
        if message.hwnd == lease.window.handle && message.message == WM_CLIPBOARDUPDATE {
            let status = lease.current_status();
            lease.probe.record(
                "WM_CLIPBOARDUPDATE",
                format_args!(
                    "current={} status={:#010X}",
                    status == S_OK,
                    status.0.cast_unsigned()
                ),
            );
        }
        unsafe {
            let _ = TranslateMessage(&raw const message);
            DispatchMessageW(&raw const message);
        }
    }
}
