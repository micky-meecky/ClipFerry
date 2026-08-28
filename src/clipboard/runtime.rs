use std::sync::Arc;
use std::time::Duration;

use std::ffi::c_void;
use std::io::{BufRead as _, Write as _};

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
use super::source::{MemorySource, ReadAtSource};
use super::transfer::{GeneratedSource, TransferControl};
use super::{TEST_FILE_CONTENT, TEST_FILE_NAME};

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
