use std::ffi::c_void;
use std::fs::{self, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

use windows::Win32::Foundation::{E_UNEXPECTED, HINSTANCE, HWND, LPARAM, LRESULT, S_OK, WPARAM};
use windows::Win32::System::Com::IDataObject;
use windows::Win32::System::DataExchange::{
    AddClipboardFormatListener, GetClipboardSequenceNumber, RemoveClipboardFormatListener,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Ole::{OleInitialize, OleSetClipboard, OleUninitialize};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::Shell::IDataObjectAsyncCapability;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, HWND_MESSAGE,
    KillTimer, MSG, PostThreadMessageW, RegisterClassW, SetTimer, TranslateMessage,
    UnregisterClassW, WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_CLIPBOARDUPDATE, WM_QUIT, WM_TIMER,
    WNDCLASSW,
};
use windows_core::{Error, HRESULT, Interface, Result as WindowsResult, w};

use super::data_object::{SourceFactory, VirtualFileDataObject, VirtualFileEntry};
use super::local_file::{
    CaptureError, CaptureFormats, CaptureRejection, ClipboardCapture, FileTreeSnapshot,
    LocalOfferRegistry, capture_files_from_clipboard,
};
use super::probe::ProbeState;
use super::runtime::ole_set_clipboard_with_retry;
use super::secure_transfer::{
    OfferManifest, RemoteTransferRegistry, SecureOfferClient, SecureOfferServer, SecureOfferedFile,
    SecureRecoveryPolicy,
};
use super::source::ReadAtSource;
use crate::app_settings::{AppSettings, validate_private_endpoint};
use crate::device_store::DeviceStore;
use crate::security::{CertificateFingerprint, PinnedTlsClient, TrustedTlsServer};

const PRODUCT_WINDOW_CLASS: windows_core::PCWSTR = w!("ClipFerryProductClipboardWindow");
const PRODUCT_EVENT_MESSAGE: u32 = WM_APP + 40;
const PRODUCT_COMMAND_MESSAGE: u32 = WM_APP + 41;
const PRODUCT_TIMER_ID: usize = 0x4346;
const PRODUCT_TIMER_MS: u32 = 1000;
const OFFER_MAGIC: &[u8; 8] = b"CFOFFER1";
const OFFER_ACK: &[u8; 8] = b"CFACK001";
const OFFER_FRAME_SIZE: usize = 8 + 1 + 16 + 2;
const TLS_TIMEOUT: Duration = Duration::from_secs(10);
const OFFER_TTL: Duration = Duration::from_mins(15);
const TRANSFER_TTL: Duration = Duration::from_hours(1);
const RECOVERY_WINDOW: Duration = Duration::from_mins(3);
const ANNOUNCEMENT_WINDOW: Duration = Duration::from_mins(1);
const MAX_LIVE_SOURCE_OFFERS: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductTransferState {
    AwaitingPaste,
    Running,
    Paused,
    Cancelled,
    Completed,
    Failed,
}

impl ProductTransferState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AwaitingPaste => "等待粘贴",
            Self::Running => "传输中",
            Self::Paused => "已暂停",
            Self::Cancelled => "已取消",
            Self::Completed => "已完成",
            Self::Failed => "失败",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductManifestSummary {
    pub direction: &'static str,
    pub primary_name: String,
    pub items: usize,
    pub files: usize,
    pub directories: usize,
    pub total_size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductTransferSnapshot {
    pub state: ProductTransferState,
    pub transferred: u64,
    pub total_size: u64,
    pub bytes_per_second: u64,
    pub average_bytes_per_second: u64,
    pub started_files: usize,
    pub total_files: usize,
    pub current_file_name: Option<String>,
    pub current_file_transferred: u64,
    pub current_file_size: u64,
    pub reconnect_attempts: u64,
    pub recovered_commands: u64,
    pub recovery_active: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductSnapshot {
    pub listener_running: bool,
    pub local_endpoint: SocketAddr,
    pub active_peer_label: String,
    pub active_peer: CertificateFingerprint,
    pub auto_receive: bool,
    pub pending_offer: bool,
    pub last_manifest: Option<ProductManifestSummary>,
    pub transfer: Option<ProductTransferSnapshot>,
    pub transfer_generation: u64,
    pub last_error: Option<String>,
}

impl ProductSnapshot {
    fn initial(settings: &AppSettings, peer_label: String) -> Self {
        Self {
            listener_running: false,
            local_endpoint: settings.local_endpoint,
            active_peer_label: peer_label,
            active_peer: settings.active_peer,
            auto_receive: settings.auto_receive,
            pending_offer: false,
            last_manifest: None,
            transfer: None,
            transfer_generation: 0,
            last_error: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductCommand {
    AcceptPending,
    Pause,
    Resume,
    Cancel,
}

pub struct ProductRuntime {
    snapshot: Arc<Mutex<ProductSnapshot>>,
    command_sender: mpsc::Sender<WorkerCommand>,
    worker_thread_id: u32,
    worker: Option<JoinHandle<()>>,
}

impl ProductRuntime {
    /// Starts the authenticated offer inbox and the OLE clipboard worker.
    ///
    /// # Errors
    ///
    /// Returns an error when settings, trust, TLS, listener, COM, or worker startup fails.
    pub fn start(store: DeviceStore, settings: AppSettings) -> io::Result<Self> {
        let peer = store.load_peer(settings.active_peer)?;
        let snapshot = Arc::new(Mutex::new(ProductSnapshot::initial(
            &settings,
            peer.label.clone(),
        )));
        let (command_sender, command_receiver) = mpsc::channel();
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let thread_snapshot = Arc::clone(&snapshot);
        let worker = std::thread::Builder::new()
            .name("clipferry-product-clipboard".to_owned())
            .spawn(move || {
                let result = run_worker(
                    store,
                    settings,
                    &thread_snapshot,
                    &command_receiver,
                    &ready_sender,
                );
                if let Err(error) = result {
                    if let Ok(mut snapshot) = thread_snapshot.lock() {
                        snapshot.listener_running = false;
                        snapshot.last_error = Some(format!("后台服务已停止：{error}"));
                    }
                    let _ = ready_sender.try_send(Err(error));
                }
            })?;
        let worker_thread_id = match ready_receiver.recv_timeout(Duration::from_secs(15)) {
            Ok(Ok(thread_id)) => thread_id,
            Ok(Err(error)) => {
                let _ = worker.join();
                return Err(error);
            }
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "product clipboard worker did not start",
                ));
            }
        };
        Ok(Self {
            snapshot,
            command_sender,
            worker_thread_id,
            worker: Some(worker),
        })
    }

    #[must_use]
    pub fn snapshot(&self) -> ProductSnapshot {
        self.snapshot.lock().map_or_else(
            |poisoned| poisoned.into_inner().clone(),
            |value| value.clone(),
        )
    }

    /// Queues a bounded product control command on the clipboard STA.
    ///
    /// # Errors
    ///
    /// Returns an error if the worker stopped or its message queue cannot be woken.
    pub fn command(&self, command: ProductCommand) -> io::Result<()> {
        self.command_sender
            .send(WorkerCommand::Control(command))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "product worker stopped"))?;
        post_worker_message(self.worker_thread_id, PRODUCT_COMMAND_MESSAGE)
    }

    pub fn stop(&mut self) {
        if self.worker.is_none() {
            return;
        }
        let _ = self.command_sender.send(WorkerCommand::Stop);
        let _ = post_worker_message(self.worker_thread_id, PRODUCT_COMMAND_MESSAGE);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for ProductRuntime {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Clone, Copy, Debug)]
struct OfferAnnouncement {
    endpoint: SocketAddr,
    peer: CertificateFingerprint,
}

enum WorkerEvent {
    RemoteOffer(OfferAnnouncement),
    AnnouncementResult(io::Result<()>),
}

enum WorkerCommand {
    Control(ProductCommand),
    Stop,
}

struct ProductWindow {
    handle: HWND,
    instance: HINSTANCE,
}

impl ProductWindow {
    fn create() -> WindowsResult<Self> {
        // SAFETY: retrieving the current module does not transfer ownership.
        let module = unsafe { GetModuleHandleW(None) }?;
        let instance = HINSTANCE(module.0);
        let class = WNDCLASSW {
            lpfnWndProc: Some(product_window_procedure),
            hInstance: instance,
            lpszClassName: PRODUCT_WINDOW_CLASS,
            ..Default::default()
        };
        // SAFETY: the class definition and constant name remain valid for the call.
        if unsafe { RegisterClassW(&raw const class) } == 0 {
            return Err(Error::from_thread());
        }
        // SAFETY: the registered class creates a message-only window owned by this thread.
        let handle = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                PRODUCT_WINDOW_CLASS,
                w!("ClipFerry Product Clipboard"),
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
        }?;
        // SAFETY: the live message-only window can receive clipboard notifications.
        if let Err(error) = unsafe { AddClipboardFormatListener(handle) } {
            let _ = unsafe { DestroyWindow(handle) };
            let _ = unsafe { UnregisterClassW(PRODUCT_WINDOW_CLASS, Some(instance)) };
            return Err(error);
        }
        Ok(Self { handle, instance })
    }
}

impl Drop for ProductWindow {
    fn drop(&mut self) {
        // SAFETY: this guard owns the listener registration, window and class.
        let _ = unsafe { RemoveClipboardFormatListener(self.handle) };
        let _ = unsafe { DestroyWindow(self.handle) };
        let _ = unsafe { UnregisterClassW(PRODUCT_WINDOW_CLASS, Some(self.instance)) };
    }
}

unsafe extern "system" fn product_window_procedure(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // SAFETY: all messages are intentionally handled by the owning message loop.
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}

struct OleApartment;

impl OleApartment {
    fn initialize() -> WindowsResult<Self> {
        // SAFETY: the worker is a dedicated STA and balances this call in Drop.
        unsafe { OleInitialize(None) }?;
        Ok(Self)
    }
}

impl Drop for OleApartment {
    fn drop(&mut self) {
        // SAFETY: balances the successful initialization on the same worker thread.
        unsafe { OleUninitialize() };
    }
}

struct ProductRemoteLease {
    object: IDataObject,
    registry: Arc<RemoteTransferRegistry>,
    manifest: OfferManifest,
    _probe: Arc<ProbeState>,
}

impl ProductRemoteLease {
    fn register(client: &SecureOfferClient) -> WindowsResult<Self> {
        let manifest = client.fetch_manifest().map_err(io_to_windows)?;
        let registry = Arc::new(RemoteTransferRegistry::default());
        let entries = manifest
            .entries
            .iter()
            .map(|entry| {
                let descriptor = entry.descriptor.clone();
                if descriptor.is_directory() {
                    return VirtualFileEntry::directory(descriptor);
                }
                let client = client.clone();
                let manifest = manifest.clone();
                let entry = entry.clone();
                let registry = Arc::clone(&registry);
                let source_factory: SourceFactory = Arc::new(move || {
                    let source = registry.create_source_for_entry(
                        client.clone(),
                        manifest.clone(),
                        entry.clone(),
                    );
                    let source: Arc<dyn ReadAtSource> = source;
                    source
                });
                VirtualFileEntry::file(descriptor, source_factory)
            })
            .collect();
        let probe = Arc::new(ProbeState::quiet());
        let object = VirtualFileDataObject::create_with_entries(
            entries,
            Arc::clone(&probe),
            manifest.origin_payload(),
        )?;
        let capability: IDataObjectAsyncCapability = object.cast()?;
        // SAFETY: the object implements the capability and remains alive in this lease.
        unsafe { capability.SetAsyncMode(true) }?;
        ole_set_clipboard_with_retry(&object)?;
        Ok(Self {
            object,
            registry,
            manifest,
            _probe: probe,
        })
    }

    fn is_current(&self) -> bool {
        self.current_status() == S_OK
    }

    fn current_status(&self) -> HRESULT {
        // SAFETY: the COM pointer remains owned by this lease.
        unsafe { ole_is_current_clipboard_raw(Interface::as_raw(&self.object)) }
    }
}

#[link(name = "ole32")]
unsafe extern "system" {
    #[link_name = "OleIsCurrentClipboard"]
    fn ole_is_current_clipboard_raw(data_object: *mut c_void) -> HRESULT;
}

impl Drop for ProductRemoteLease {
    fn drop(&mut self) {
        if self.is_current() {
            // SAFETY: only clear the clipboard while this lease still owns the current object.
            let _ = unsafe { OleSetClipboard(None::<&IDataObject>) };
        }
    }
}

struct LiveSourceOffer {
    server: SecureOfferServer,
    manifest: OfferManifest,
}

struct ProductSession {
    store: DeviceStore,
    settings: AppSettings,
    formats: CaptureFormats,
    snapshot: Arc<Mutex<ProductSnapshot>>,
    event_sender: mpsc::Sender<WorkerEvent>,
    worker_thread_id: u32,
    registry: LocalOfferRegistry,
    sources: Vec<LiveSourceOffer>,
    pending: Option<OfferAnnouncement>,
    remote: Option<ProductRemoteLease>,
    active_direction: Option<TransferDirection>,
    last_clipboard_sequence: Option<u32>,
    log_path: std::path::PathBuf,
    last_sample_at: Instant,
    last_sample_bytes: u64,
    smoothed_speed: u64,
    transfer_started_at: Option<Instant>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransferDirection {
    Source,
    Remote,
}

impl ProductSession {
    fn handle_clipboard_update(&mut self, window: HWND) {
        // SAFETY: this reads the process-wide clipboard sequence without taking ownership.
        let observed_sequence = unsafe { GetClipboardSequenceNumber() };
        // Claim the notification before any clipboard read. Successful captures, explicit policy
        // rejections, and transient read failures must all be deduplicated uniformly.
        if !claim_clipboard_sequence(&mut self.last_clipboard_sequence, observed_sequence) {
            return;
        }
        if self
            .remote
            .as_ref()
            .is_some_and(ProductRemoteLease::is_current)
        {
            return;
        }
        match capture_files_from_clipboard(window, self.formats) {
            Ok(ClipboardCapture::Candidates { paths, sequence }) => {
                if sequence != 0 {
                    self.last_clipboard_sequence = Some(sequence);
                }
                if let Err(error) = self.publish_paths(&paths) {
                    self.set_error(format!("本机文件清单发布失败：{error}"));
                }
            }
            Ok(ClipboardCapture::Rejected(reason)) => {
                self.set_error(format!("本机文件剪贴板未发送：{}", reason.user_message()));
            }
            Ok(ClipboardCapture::NotFileClipboard | ClipboardCapture::PrivateOffer) => {}
            Err(error) => self.set_error(format!("读取本机剪贴板失败：{error}")),
        }
    }

    fn publish_paths(&mut self, paths: &[std::path::PathBuf]) -> io::Result<()> {
        let tree = FileTreeSnapshot::capture(paths).map_err(|error| {
            let message = match error {
                CaptureError::Rejected(CaptureRejection::AlternateDataStream) =>
                    "所选内容包含 NTFS 附加数据流（通常是 Windows 的下载来源标记）。当前虚拟粘贴无法在目标端安全保留该标记，因此已停止发送；请先确认来源并在文件属性中解除锁定后重试。".to_owned(),
                other => other.to_string(),
            };
            io::Error::other(message)
        })?;
        let offer = self
            .registry
            .publish_tree(&tree, OFFER_TTL)
            .map_err(windows_to_io)?;
        let offered = SecureOfferedFile::from_local_offer(&offer)?;
        let identity = self.store.load_identity()?;
        let tls = TrustedTlsServer::new(identity, self.store.clone(), TLS_TIMEOUT)?;
        let transfer_endpoint = SocketAddr::new(self.settings.local_endpoint.ip(), 0);
        let server = SecureOfferServer::start_trusted(
            transfer_endpoint,
            tls,
            self.settings.active_peer,
            offered,
            TRANSFER_TTL,
            TLS_TIMEOUT,
        )?;
        let manifest = server.manifest();
        let summary = summarize_manifest("发送", &manifest);
        let total_size = summary.total_size;
        let total_files = summary.files;
        if self.sources.len() == MAX_LIVE_SOURCE_OFFERS {
            self.sources.remove(0);
        }
        let endpoint = server.address();
        self.sources.push(LiveSourceOffer { server, manifest });
        self.active_direction = Some(TransferDirection::Source);
        let _ = append_product_log(
            &self.log_path,
            &format!(
                "offer_published endpoint={} items={} files={} total_size={}",
                endpoint, summary.items, summary.files, summary.total_size
            ),
        );
        self.update_snapshot(|snapshot| {
            snapshot.last_manifest = Some(summary);
            snapshot.transfer_generation = snapshot.transfer_generation.wrapping_add(1);
            snapshot.transfer = Some(ProductTransferSnapshot {
                state: ProductTransferState::AwaitingPaste,
                transferred: 0,
                total_size,
                bytes_per_second: 0,
                average_bytes_per_second: 0,
                started_files: 0,
                total_files,
                current_file_name: None,
                current_file_transferred: 0,
                current_file_size: 0,
                reconnect_attempts: 0,
                recovered_commands: 0,
                recovery_active: false,
            });
            snapshot.last_error = None;
        });
        self.last_sample_at = Instant::now();
        self.last_sample_bytes = 0;
        self.smoothed_speed = 0;
        self.transfer_started_at = None;
        self.spawn_announcement(endpoint)?;
        Ok(())
    }

    fn spawn_announcement(&self, endpoint: SocketAddr) -> io::Result<()> {
        let store = self.store.clone();
        let settings = self.settings.clone();
        let sender = self.event_sender.clone();
        let worker_thread_id = self.worker_thread_id;
        std::thread::Builder::new()
            .name("clipferry-offer-announce".to_owned())
            .spawn(move || {
                let result = send_announcement_recovering(&store, &settings, endpoint);
                let _ = sender.send(WorkerEvent::AnnouncementResult(result));
                let _ = post_worker_message(worker_thread_id, PRODUCT_EVENT_MESSAGE);
            })?;
        Ok(())
    }

    fn handle_event(&mut self, event: WorkerEvent) {
        match event {
            WorkerEvent::RemoteOffer(announcement) => {
                if announcement.peer != self.settings.active_peer {
                    self.set_error("收到非活动设备的 Offer，已拒绝".to_owned());
                    return;
                }
                self.pending = Some(announcement);
                self.update_snapshot(|snapshot| snapshot.pending_offer = true);
                if self.settings.auto_receive
                    && let Err(error) = self.accept_pending()
                {
                    self.set_error(format!("自动接收远端清单失败：{error}"));
                }
            }
            WorkerEvent::AnnouncementResult(Ok(())) => {
                self.update_snapshot(|snapshot| snapshot.last_error = None);
            }
            WorkerEvent::AnnouncementResult(Err(error)) => {
                self.set_error(format!("无法通知对端设备：{error}"));
            }
        }
    }

    fn handle_command(&mut self, command: ProductCommand) {
        let result = match command {
            ProductCommand::AcceptPending => self.accept_pending(),
            ProductCommand::Pause => self.control_remote(RemoteTransferRegistry::pause_all),
            ProductCommand::Resume => self.control_remote(RemoteTransferRegistry::resume_all),
            ProductCommand::Cancel => self.cancel_remote(),
        };
        if let Err(error) = result {
            self.set_error(format!("传输控制失败：{error}"));
        }
        self.refresh_progress();
    }

    fn accept_pending(&mut self) -> io::Result<()> {
        let announcement = self
            .pending
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "当前没有待接收清单"))?;
        validate_private_endpoint(announcement.endpoint)?;
        let client = build_offer_client(&self.store, &self.settings, announcement.endpoint)?;
        let remote = ProductRemoteLease::register(&client).map_err(windows_to_io)?;
        let summary = summarize_manifest("接收", &remote.manifest);
        let total_size = summary.total_size;
        let total_files = summary.files;
        self.remote = Some(remote);
        self.active_direction = Some(TransferDirection::Remote);
        let _ = append_product_log(
            &self.log_path,
            &format!(
                "offer_received endpoint={} items={} files={} total_size={} auto_receive={}",
                announcement.endpoint,
                summary.items,
                summary.files,
                summary.total_size,
                self.settings.auto_receive
            ),
        );
        self.pending = None;
        self.last_sample_at = Instant::now();
        self.last_sample_bytes = 0;
        self.smoothed_speed = 0;
        self.transfer_started_at = None;
        self.update_snapshot(|snapshot| {
            snapshot.pending_offer = false;
            snapshot.last_manifest = Some(summary);
            snapshot.transfer_generation = snapshot.transfer_generation.wrapping_add(1);
            snapshot.transfer = Some(ProductTransferSnapshot {
                state: ProductTransferState::AwaitingPaste,
                transferred: 0,
                total_size,
                bytes_per_second: 0,
                average_bytes_per_second: 0,
                started_files: 0,
                total_files,
                current_file_name: None,
                current_file_transferred: 0,
                current_file_size: 0,
                reconnect_attempts: 0,
                recovered_commands: 0,
                recovery_active: false,
            });
            snapshot.last_error = None;
        });
        Ok(())
    }

    fn control_remote(
        &mut self,
        operation: impl FnOnce(
            &RemoteTransferRegistry,
        ) -> io::Result<super::secure_transfer::TransferGroupStatus>,
    ) -> io::Result<()> {
        let remote = self
            .remote
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "当前没有远端剪贴板"))?;
        let _ = operation(&remote.registry)?;
        Ok(())
    }

    fn cancel_remote(&mut self) -> io::Result<()> {
        let remote = self
            .remote
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "当前没有远端剪贴板"))?;
        if remote.registry.local_progress().started_transfers == 0 {
            self.remote.take();
            self.active_direction = None;
            self.update_snapshot(|snapshot| {
                if let Some(transfer) = snapshot.transfer.as_mut() {
                    transfer.state = ProductTransferState::Cancelled;
                    transfer.bytes_per_second = 0;
                }
            });
            return Ok(());
        }
        let _ = remote.registry.cancel_all()?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn refresh_progress(&mut self) {
        if self.active_direction.is_none() {
            return;
        }
        let now = Instant::now();
        let mut bytes = 0_u64;
        let mut state = ProductTransferState::AwaitingPaste;
        let mut started_files = 0_usize;
        let mut total_files = 0_usize;
        let mut total_size = 0_u64;
        let mut current_file_name = None;
        let mut current_file_transferred = 0_u64;
        let mut current_file_size = 0_u64;
        let mut reconnect_attempts = 0_u64;
        let mut recovered_commands = 0_u64;
        let mut recovery_active = false;
        if self.active_direction == Some(TransferDirection::Remote)
            && let Some(remote) = self.remote.as_ref()
        {
            let progress = remote.registry.local_progress();
            let summary = summarize_manifest("接收", &remote.manifest);
            bytes = progress.bytes_read.min(summary.total_size);
            started_files = progress.started_transfers;
            total_files = summary.files;
            total_size = summary.total_size;
            if let Some((name, transferred, size)) = remote.registry.current_file_progress() {
                current_file_name = Some(name);
                current_file_transferred = transferred;
                current_file_size = size;
            }
            let recovery = remote.registry.recovery_snapshot();
            reconnect_attempts = recovery.reconnect_attempts;
            recovered_commands = recovery.recovered_commands;
            recovery_active = recovery.active_recoveries != 0;
            state = if progress.cancelled {
                ProductTransferState::Cancelled
            } else if progress.paused {
                ProductTransferState::Paused
            } else if total_files != 0 && progress.completed_transfers == total_files {
                ProductTransferState::Completed
            } else if progress.started_transfers != 0 {
                ProductTransferState::Running
            } else {
                ProductTransferState::AwaitingPaste
            };
        } else if self.active_direction == Some(TransferDirection::Source)
            && let Some(source) = self.sources.last()
        {
            let metrics = source.server.metrics();
            let summary = summarize_manifest("发送", &source.manifest);
            bytes = metrics.unique_bytes.min(summary.total_size);
            started_files = usize::try_from(metrics.begun_transfers).unwrap_or(usize::MAX);
            total_files = summary.files;
            total_size = summary.total_size;
            state = if metrics.cancelled_transfers != 0 {
                ProductTransferState::Cancelled
            } else if total_size != 0 && bytes == total_size {
                ProductTransferState::Completed
            } else if metrics.begun_transfers != 0 {
                ProductTransferState::Running
            } else {
                ProductTransferState::AwaitingPaste
            };
        }
        let elapsed = now.saturating_duration_since(self.last_sample_at);
        let raw_speed = if elapsed.is_zero() || bytes < self.last_sample_bytes {
            0
        } else {
            let scaled = u128::from(bytes - self.last_sample_bytes).saturating_mul(1000)
                / elapsed.as_millis().max(1);
            u64::try_from(scaled).unwrap_or(u64::MAX)
        };
        if state == ProductTransferState::Running && bytes != 0 {
            self.transfer_started_at.get_or_insert(self.last_sample_at);
            if raw_speed != 0 {
                self.smoothed_speed = if self.smoothed_speed == 0 {
                    raw_speed
                } else {
                    self.smoothed_speed
                        .saturating_mul(3)
                        .saturating_add(raw_speed)
                        / 4
                };
            }
        } else if state != ProductTransferState::Paused {
            self.smoothed_speed = 0;
        }
        let average_speed = self.transfer_started_at.map_or(0, |started_at| {
            let milliseconds = now.saturating_duration_since(started_at).as_millis().max(1);
            u64::try_from(u128::from(bytes).saturating_mul(1000) / milliseconds).unwrap_or(u64::MAX)
        });
        let speed = if state == ProductTransferState::Running {
            self.smoothed_speed
        } else {
            0
        };
        self.last_sample_at = now;
        self.last_sample_bytes = bytes;
        self.update_snapshot(|snapshot| {
            if snapshot.transfer.is_some() {
                snapshot.transfer = Some(ProductTransferSnapshot {
                    state,
                    transferred: bytes,
                    total_size,
                    bytes_per_second: speed,
                    average_bytes_per_second: average_speed,
                    started_files,
                    total_files,
                    current_file_name,
                    current_file_transferred,
                    current_file_size,
                    reconnect_attempts,
                    recovered_commands,
                    recovery_active,
                });
            }
        });
    }

    fn set_error(&self, error: String) {
        let _ = append_product_log(&self.log_path, &format!("product_error error={error}"));
        self.update_snapshot(|snapshot| snapshot.last_error = Some(error));
        let _ = crate::tray::show_runtime_error_existing();
    }

    fn update_snapshot(&self, update: impl FnOnce(&mut ProductSnapshot)) {
        match self.snapshot.lock() {
            Ok(mut snapshot) => update(&mut snapshot),
            Err(mut poisoned) => update(poisoned.get_mut()),
        }
    }
}

fn claim_clipboard_sequence(last_sequence: &mut Option<u32>, observed_sequence: u32) -> bool {
    if observed_sequence == 0 {
        return true;
    }
    if *last_sequence == Some(observed_sequence) {
        return false;
    }
    *last_sequence = Some(observed_sequence);
    true
}

fn run_worker(
    store: DeviceStore,
    settings: AppSettings,
    snapshot: &Arc<Mutex<ProductSnapshot>>,
    command_receiver: &mpsc::Receiver<WorkerCommand>,
    ready_sender: &mpsc::SyncSender<io::Result<u32>>,
) -> io::Result<()> {
    let _apartment = OleApartment::initialize().map_err(windows_to_io)?;
    let window = ProductWindow::create().map_err(windows_to_io)?;
    let formats = CaptureFormats::register().map_err(windows_to_io)?;
    // SAFETY: this call reads the current dedicated worker thread identifier.
    let thread_id = unsafe { GetCurrentThreadId() };
    let (event_sender, event_receiver) = mpsc::channel();
    let log_path = store.root().join("logs").join("clipferry.log");
    let mut inbox = OfferInbox::start(store.clone(), &settings, event_sender.clone(), thread_id)?;
    if let Ok(mut value) = snapshot.lock() {
        value.listener_running = true;
    }
    let _ = append_product_log(
        &log_path,
        &format!(
            "product_start listener={} peer={} auto_receive={}",
            settings.local_endpoint, settings.active_peer, settings.auto_receive
        ),
    );
    ready_sender
        .send(Ok(thread_id))
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "tray abandoned worker startup"))?;
    // SAFETY: a thread timer posts WM_TIMER into this worker's queue.
    let timer = unsafe { SetTimer(None, PRODUCT_TIMER_ID, PRODUCT_TIMER_MS, None) };
    if timer == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut session = ProductSession {
        store,
        settings,
        formats,
        snapshot: Arc::clone(snapshot),
        event_sender,
        worker_thread_id: thread_id,
        registry: LocalOfferRegistry::default(),
        sources: Vec::new(),
        pending: None,
        remote: None,
        active_direction: None,
        last_clipboard_sequence: None,
        log_path: log_path.clone(),
        last_sample_at: Instant::now(),
        last_sample_bytes: 0,
        smoothed_speed: 0,
        transfer_started_at: None,
    };
    let mut stopping = false;
    while !stopping {
        let mut message = MSG::default();
        // SAFETY: the worker owns its message queue and the writable MSG structure.
        let status = unsafe { GetMessageW(&raw mut message, None, 0, 0) }.0;
        if status == -1 {
            return Err(io::Error::last_os_error());
        }
        if status == 0 || message.message == WM_QUIT {
            break;
        }
        match message.message {
            WM_CLIPBOARDUPDATE if message.hwnd == window.handle => {
                session.handle_clipboard_update(window.handle);
            }
            PRODUCT_EVENT_MESSAGE => {
                for event in event_receiver.try_iter() {
                    session.handle_event(event);
                }
            }
            PRODUCT_COMMAND_MESSAGE => {
                for command in command_receiver.try_iter() {
                    match command {
                        WorkerCommand::Control(command) => session.handle_command(command),
                        WorkerCommand::Stop => {
                            stopping = true;
                            break;
                        }
                    }
                }
            }
            WM_TIMER if message.wParam.0 == timer => session.refresh_progress(),
            _ => unsafe {
                let _ = TranslateMessage(&raw const message);
                DispatchMessageW(&raw const message);
            },
        }
    }
    if let Some(remote) = session.remote.as_ref() {
        let _ = remote.registry.cancel_all();
    }
    session.remote.take();
    session.sources.clear();
    inbox.stop();
    // SAFETY: balances the live timer on this worker thread.
    let _ = unsafe { KillTimer(None, timer) };
    if let Ok(mut value) = snapshot.lock() {
        value.listener_running = false;
    }
    let _ = append_product_log(&log_path, "product_stop clean=true");
    Ok(())
}

struct OfferInbox {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl OfferInbox {
    fn start(
        store: DeviceStore,
        settings: &AppSettings,
        event_sender: mpsc::Sender<WorkerEvent>,
        worker_thread_id: u32,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(settings.local_endpoint)?;
        let address = listener.local_addr()?;
        let identity = store.load_identity()?;
        let tls = TrustedTlsServer::new(identity, store, TLS_TIMEOUT)?;
        let active_peer = settings.active_peer;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let worker = std::thread::Builder::new()
            .name("clipferry-offer-inbox".to_owned())
            .spawn(move || {
                while !thread_stop.load(Ordering::Acquire) {
                    let Ok((socket, _)) = listener.accept() else {
                        continue;
                    };
                    if thread_stop.load(Ordering::Acquire) {
                        break;
                    }
                    let Ok(mut connection) = tls.accept(socket) else {
                        continue;
                    };
                    if connection.peer_fingerprint != active_peer {
                        continue;
                    }
                    let result = read_announcement(&mut connection.stream).and_then(|endpoint| {
                        event_sender
                            .send(WorkerEvent::RemoteOffer(OfferAnnouncement {
                                endpoint,
                                peer: connection.peer_fingerprint,
                            }))
                            .map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::BrokenPipe,
                                    "clipboard worker stopped",
                                )
                            })?;
                        connection.stream.write_all(OFFER_ACK)?;
                        connection.stream.flush()?;
                        Ok(())
                    });
                    if result.is_ok() {
                        let _ = post_worker_message(worker_thread_id, PRODUCT_EVENT_MESSAGE);
                    }
                }
            })?;
        Ok(Self {
            address,
            stop,
            worker: Some(worker),
        })
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_secs(1));
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for OfferInbox {
    fn drop(&mut self) {
        self.stop();
    }
}

fn send_announcement(
    store: &DeviceStore,
    settings: &AppSettings,
    endpoint: SocketAddr,
) -> io::Result<()> {
    let mut stream = build_pinned_tls(store, settings)?.connect(settings.peer_endpoint)?;
    stream.write_all(&encode_announcement(endpoint)?)?;
    stream.flush()?;
    let mut acknowledgement = [0_u8; OFFER_ACK.len()];
    stream.read_exact(&mut acknowledgement)?;
    if &acknowledgement != OFFER_ACK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "peer returned an invalid offer acknowledgement",
        ));
    }
    let _ = stream.sock.shutdown(Shutdown::Both);
    Ok(())
}

fn send_announcement_recovering(
    store: &DeviceStore,
    settings: &AppSettings,
    endpoint: SocketAddr,
) -> io::Result<()> {
    let deadline = Instant::now() + ANNOUNCEMENT_WINDOW;
    let mut delay = Duration::from_millis(100);
    loop {
        match send_announcement(store, settings, endpoint) {
            Ok(()) => return Ok(()),
            Err(error)
                if is_recoverable_announcement_error(&error) && Instant::now() < deadline =>
            {
                std::thread::sleep(delay.min(deadline.saturating_duration_since(Instant::now())));
                delay = delay.saturating_mul(2).min(Duration::from_secs(2));
            }
            Err(error) => return Err(error),
        }
    }
}

fn is_recoverable_announcement_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::TimedOut
            | io::ErrorKind::UnexpectedEof
    ) || matches!(
        error.raw_os_error(),
        Some(10050 | 10051 | 10052 | 10053 | 10054 | 10060 | 10061 | 10064 | 10065)
    )
}

fn build_offer_client(
    store: &DeviceStore,
    settings: &AppSettings,
    endpoint: SocketAddr,
) -> io::Result<SecureOfferClient> {
    let tls = build_pinned_tls(store, settings)?;
    Ok(SecureOfferClient::with_recovery_policy(
        endpoint,
        tls,
        SecureRecoveryPolicy {
            max_elapsed: RECOVERY_WINDOW,
            connect_attempt_timeout: Duration::from_secs(2),
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
        },
    ))
}

fn build_pinned_tls(store: &DeviceStore, settings: &AppSettings) -> io::Result<PinnedTlsClient> {
    let identity = store.load_identity()?;
    let peer = store.load_peer(settings.active_peer)?;
    PinnedTlsClient::new(
        &identity,
        peer.into_certificate_der(),
        settings.active_peer,
        TLS_TIMEOUT,
    )
}

fn encode_announcement(endpoint: SocketAddr) -> io::Result<[u8; OFFER_FRAME_SIZE]> {
    validate_private_endpoint(endpoint)?;
    let mut frame = [0_u8; OFFER_FRAME_SIZE];
    frame[..8].copy_from_slice(OFFER_MAGIC);
    match endpoint.ip() {
        IpAddr::V4(ip) => {
            frame[8] = 4;
            frame[9..13].copy_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            frame[8] = 6;
            frame[9..25].copy_from_slice(&ip.octets());
        }
    }
    frame[25..27].copy_from_slice(&endpoint.port().to_be_bytes());
    Ok(frame)
}

fn read_announcement(stream: &mut impl io::Read) -> io::Result<SocketAddr> {
    let mut frame = [0_u8; OFFER_FRAME_SIZE];
    stream.read_exact(&mut frame)?;
    if &frame[..8] != OFFER_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid offer announcement magic",
        ));
    }
    let ip = match frame[8] {
        4 => IpAddr::V4(std::net::Ipv4Addr::new(
            frame[9], frame[10], frame[11], frame[12],
        )),
        6 => {
            let octets: [u8; 16] = frame[9..25]
                .try_into()
                .map_err(|_| io::Error::other("invalid IPv6 offer endpoint"))?;
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid offer endpoint address family",
            ));
        }
    };
    let port = u16::from_be_bytes([frame[25], frame[26]]);
    let endpoint = SocketAddr::new(ip, port);
    validate_private_endpoint(endpoint)?;
    Ok(endpoint)
}

fn summarize_manifest(direction: &'static str, manifest: &OfferManifest) -> ProductManifestSummary {
    let files = manifest
        .entries
        .iter()
        .filter(|entry| !entry.descriptor.is_directory())
        .count();
    let total_size = manifest
        .entries
        .iter()
        .map(|entry| entry.descriptor.size)
        .sum();
    let primary_name = manifest.entries.first().map_or_else(
        || "（空清单）".to_owned(),
        |entry| entry.descriptor.file_name.to_string(),
    );
    ProductManifestSummary {
        direction,
        primary_name,
        items: manifest.entries.len(),
        files,
        directories: manifest.entries.len().saturating_sub(files),
        total_size,
    }
}

fn post_worker_message(thread_id: u32, message: u32) -> io::Result<()> {
    // SAFETY: private messages carry no pointers and target the known product worker thread.
    unsafe { PostThreadMessageW(thread_id, message, WPARAM(0), LPARAM(0)) }
        .map_err(|error| io::Error::other(error.to_string()))
}

fn append_product_log(path: &std::path::Path, message: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{timestamp} {message}")
}

#[allow(clippy::needless_pass_by_value)]
fn windows_to_io(error: Error) -> io::Error {
    io::Error::other(format!(
        "{} ({:#010X})",
        error,
        error.code().0.cast_unsigned()
    ))
}

#[allow(clippy::needless_pass_by_value)]
fn io_to_windows(error: io::Error) -> Error {
    if let Some(code) = error.raw_os_error() {
        Error::from_hresult(HRESULT::from_win32(code.cast_unsigned()))
    } else {
        Error::new(E_UNEXPECTED, error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    static NEXT_TEST_STORE: AtomicU64 = AtomicU64::new(1);

    struct TestStore {
        store: DeviceStore,
        root: std::path::PathBuf,
    }

    impl TestStore {
        fn new(label: &str) -> Self {
            let id = NEXT_TEST_STORE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "clipferry-product-{label}-{}-{id}",
                std::process::id()
            ));
            std::fs::create_dir_all(&root).unwrap();
            Self {
                store: DeviceStore::new(&root),
                root,
            }
        }
    }

    impl Drop for TestStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn offer_announcement_round_trips_private_ipv4_and_ipv6() {
        for endpoint in ["192.168.1.9:49152", "[fd00::9]:49152"] {
            let endpoint: SocketAddr = endpoint.parse().unwrap();
            let encoded = encode_announcement(endpoint).unwrap();
            assert_eq!(
                read_announcement(&mut encoded.as_slice()).unwrap(),
                endpoint
            );
        }
    }

    #[test]
    fn offer_announcement_rejects_public_zero_port_and_bad_magic() {
        assert!(encode_announcement("8.8.8.8:45233".parse().unwrap()).is_err());
        assert!(encode_announcement("192.168.1.9:0".parse().unwrap()).is_err());
        let mut frame = encode_announcement("192.168.1.9:45233".parse().unwrap()).unwrap();
        frame[0] ^= 0xff;
        assert!(read_announcement(&mut frame.as_slice()).is_err());
    }

    #[test]
    fn public_snapshot_layout_stays_small() {
        assert!(std::mem::size_of::<ProductSnapshot>() < 512);
    }

    #[test]
    fn clipboard_sequence_is_claimed_before_success_rejection_or_read_failure() {
        let mut last = None;
        assert!(claim_clipboard_sequence(&mut last, 41));
        assert_eq!(last, Some(41));
        assert!(!claim_clipboard_sequence(&mut last, 41));
        assert!(claim_clipboard_sequence(&mut last, 42));
        assert_eq!(last, Some(42));
        assert!(claim_clipboard_sequence(&mut last, 0));
    }

    #[test]
    fn authenticated_offer_inbox_accepts_only_the_selected_peer() {
        let first = TestStore::new("first");
        let second = TestStore::new("second");
        let first_identity = first.store.load_or_create_identity().unwrap().identity;
        let second_identity = second.store.load_or_create_identity().unwrap().identity;
        first
            .store
            .trust_peer(
                second_identity.certificate_der().to_vec(),
                second_identity.fingerprint(),
                "second",
            )
            .unwrap();
        second
            .store
            .trust_peer(
                first_identity.certificate_der().to_vec(),
                first_identity.fingerprint(),
                "first",
            )
            .unwrap();
        let receiver_settings = AppSettings {
            local_endpoint: "127.0.0.1:0".parse().unwrap(),
            active_peer: first_identity.fingerprint(),
            peer_endpoint: "127.0.0.1:45234".parse().unwrap(),
            auto_receive: true,
        };
        let (sender, receiver) = mpsc::channel();
        // SAFETY: the numeric id is used only for an ignored best-effort wake message in this test.
        let thread_id = unsafe { GetCurrentThreadId() };
        let mut inbox =
            OfferInbox::start(second.store.clone(), &receiver_settings, sender, thread_id).unwrap();
        let sender_settings = AppSettings {
            local_endpoint: "127.0.0.1:45234".parse().unwrap(),
            active_peer: second_identity.fingerprint(),
            peer_endpoint: inbox.address,
            auto_receive: true,
        };
        let source_tls = TrustedTlsServer::new(
            first.store.load_identity().unwrap(),
            first.store.clone(),
            TLS_TIMEOUT,
        )
        .unwrap();
        let offered =
            SecureOfferedFile::generated(Arc::<str>::from("product-smoke.bin"), 4096, OFFER_TTL)
                .unwrap();
        let mut source_server = SecureOfferServer::start_trusted(
            "127.0.0.1:0".parse().unwrap(),
            source_tls,
            second_identity.fingerprint(),
            offered,
            TRANSFER_TTL,
            TLS_TIMEOUT,
        )
        .unwrap();
        let transfer_endpoint = source_server.address();
        send_announcement(&first.store, &sender_settings, transfer_endpoint).unwrap();
        let event = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
        let WorkerEvent::RemoteOffer(announcement) = event else {
            panic!("expected a remote offer event");
        };
        assert_eq!(announcement.endpoint, transfer_endpoint);
        assert_eq!(announcement.peer, first_identity.fingerprint());
        let client =
            build_offer_client(&second.store, &receiver_settings, announcement.endpoint).unwrap();
        let manifest = client.fetch_manifest().unwrap();
        assert_eq!(manifest.entries.len(), 1);
        assert_eq!(
            manifest.entries[0].descriptor.file_name.as_ref(),
            "product-smoke.bin"
        );
        assert_eq!(manifest.entries[0].descriptor.size, 4096);
        let source = super::super::secure_transfer::SecureRemoteSource::new(client, manifest);
        let mut bytes = [0_u8; 32];
        assert_eq!(source.read_at(1024, &mut bytes).unwrap(), bytes.len());
        assert!(bytes.iter().any(|byte| *byte != 0));
        inbox.stop();
        source_server.stop();
    }

    #[test]
    fn product_runtime_starts_and_stops_its_listener_and_clipboard_sta() {
        let first = TestStore::new("runtime-first");
        let second = TestStore::new("runtime-second");
        let first_identity = first.store.load_or_create_identity().unwrap().identity;
        let second_identity = second.store.load_or_create_identity().unwrap().identity;
        second
            .store
            .trust_peer(
                first_identity.certificate_der().to_vec(),
                first_identity.fingerprint(),
                "first",
            )
            .unwrap();
        first
            .store
            .trust_peer(
                second_identity.certificate_der().to_vec(),
                second_identity.fingerprint(),
                "second",
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_endpoint = listener.local_addr().unwrap();
        drop(listener);
        let settings = AppSettings {
            local_endpoint,
            active_peer: first_identity.fingerprint(),
            peer_endpoint: "127.0.0.1:45234".parse().unwrap(),
            auto_receive: false,
        };
        let mut runtime = ProductRuntime::start(second.store.clone(), settings).unwrap();
        let snapshot = runtime.snapshot();
        assert!(snapshot.listener_running);
        assert_eq!(snapshot.active_peer, first_identity.fingerprint());
        assert!(!snapshot.pending_offer);
        runtime.stop();
        assert!(!runtime.snapshot().listener_running);
    }
}
