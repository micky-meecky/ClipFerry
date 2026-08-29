use std::ffi::c_void;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use windows::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, GetLastError, HANDLE,
    HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM,
};
use windows::Win32::System::Console::FreeConsole;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, REG_SZ, RRF_RT_REG_SZ, RegCloseKey, RegCreateKeyW, RegDeleteValueW,
    RegGetValueW, RegSetValueExW,
};
use windows::Win32::System::Threading::{CREATE_NEW_CONSOLE, CreateMutexW};
use windows::Win32::UI::Shell::{
    NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW, Shell_NotifyIconW,
    ShellExecuteW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CREATESTRUCTW, CreateIconFromResourceEx, CreatePopupMenu, CreateWindowExW,
    DefWindowProcW, DestroyIcon, DestroyMenu, DestroyWindow, DispatchMessageW, FindWindowExW,
    GWLP_USERDATA, GetCursorPos, GetMessageW, GetSystemMetrics, GetWindowLongPtrW, HICON,
    HWND_MESSAGE, IDI_APPLICATION, LR_DEFAULTCOLOR, LoadIconW, MB_ICONERROR, MB_ICONINFORMATION,
    MB_OK, MENU_ITEM_FLAGS, MF_CHECKED, MF_DISABLED, MF_SEPARATOR, MF_STRING, MSG, MessageBoxW,
    PostMessageW, PostQuitMessage, RegisterClassW, RegisterWindowMessageW, SM_CXSMICON,
    SM_CYSMICON, SW_SHOWNORMAL, SetForegroundWindow, SetWindowLongPtrW, TPM_RETURNCMD,
    TPM_RIGHTBUTTON, TrackPopupMenu, TranslateMessage, UnregisterClassW, WINDOW_EX_STYLE,
    WINDOW_STYLE, WM_APP, WM_COMMAND, WM_DESTROY, WM_ENDSESSION, WM_LBUTTONDBLCLK, WM_NCCREATE,
    WM_QUERYENDSESSION, WM_RBUTTONUP, WNDCLASSW,
};
use windows_core::{PCWSTR, w};

use crate::device_store::DeviceStore;

const TRAY_WINDOW_CLASS: PCWSTR = w!("ClipFerryTrayWindow");
const TRAY_CALLBACK_MESSAGE: u32 = WM_APP + 1;
const TRAY_SHOW_STATUS_MESSAGE: u32 = WM_APP + 2;
const TRAY_EXIT_MESSAGE: u32 = WM_APP + 3;
const TRAY_ICON_ID: u32 = 1;
const SINGLE_INSTANCE_NAME: PCWSTR = w!("Local\\ClipFerry.Tray.v1");
const RUN_KEY: PCWSTR = w!("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
const RUN_VALUE: PCWSTR = w!("ClipFerry");
const ICON_BYTES: &[u8] = include_bytes!("../assets/brand/clipferry.ico");

const COMMAND_STATUS: usize = 1001;
const COMMAND_PAIR: usize = 1002;
const COMMAND_MANAGE_PEERS: usize = 1003;
const COMMAND_PAUSE: usize = 1004;
const COMMAND_RESUME: usize = 1005;
const COMMAND_CANCEL: usize = 1006;
const COMMAND_AUTOSTART: usize = 1007;
const COMMAND_LOG: usize = 1008;
const COMMAND_EXIT: usize = 1009;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AutostartState {
    Disabled,
    Enabled,
    Stale,
}

impl AutostartState {
    const fn label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Enabled => "enabled",
            Self::Stale => "stale",
        }
    }
}

struct SingleInstance(HANDLE);

impl SingleInstance {
    fn acquire() -> io::Result<Option<Self>> {
        // SAFETY: the mutex uses a process-lifetime constant name and no security descriptor.
        let handle =
            unsafe { CreateMutexW(None, false, SINGLE_INSTANCE_NAME) }.map_err(windows_error)?;
        // SAFETY: GetLastError reads thread-local status immediately after CreateMutexW.
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            // SAFETY: `handle` was returned by CreateMutexW and is owned here.
            let _ = unsafe { CloseHandle(handle) };
            return Ok(None);
        }
        Ok(Some(Self(handle)))
    }
}

impl Drop for SingleInstance {
    fn drop(&mut self) {
        // SAFETY: the guard uniquely owns the mutex handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct OwnedIcon {
    handle: HICON,
    owned: bool,
}

impl OwnedIcon {
    fn load() -> io::Result<Self> {
        if let Ok(image) = best_icon_image(ICON_BYTES) {
            // SAFETY: `image` is a validated, in-bounds ICO image resource and remains live for
            // the duration of the call. Windows creates an independent HICON on success.
            if let Ok(handle) = unsafe {
                CreateIconFromResourceEx(
                    image,
                    true,
                    0x0003_0000,
                    GetSystemMetrics(SM_CXSMICON),
                    GetSystemMetrics(SM_CYSMICON),
                    LR_DEFAULTCOLOR,
                )
            } {
                return Ok(Self {
                    handle,
                    owned: true,
                });
            }
        }
        // SAFETY: IDI_APPLICATION is a predefined shared system resource.
        let handle = unsafe { LoadIconW(None, IDI_APPLICATION) }.map_err(windows_error)?;
        Ok(Self {
            handle,
            owned: false,
        })
    }
}

impl Drop for OwnedIcon {
    fn drop(&mut self) {
        if self.owned {
            // SAFETY: owned icons are returned by CreateIconFromResourceEx exactly once.
            let _ = unsafe { DestroyIcon(self.handle) };
        }
    }
}

struct TrayState {
    store: DeviceStore,
    log_path: PathBuf,
    icon: OwnedIcon,
    taskbar_created: u32,
}

impl TrayState {
    fn new() -> io::Result<Self> {
        let store = DeviceStore::current_user()?;
        let stored = store.load_or_create_identity()?;
        let log_path = store.root().join("logs").join("clipferry.log");
        append_log(
            &log_path,
            &format!(
                "tray_start created_identity={} fingerprint={}",
                stored.created,
                stored.identity.fingerprint()
            ),
        )?;
        // SAFETY: the static string is valid for the duration of the registration call.
        let taskbar_created = unsafe { RegisterWindowMessageW(w!("TaskbarCreated")) };
        if taskbar_created == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            store,
            log_path,
            icon: OwnedIcon::load()?,
            taskbar_created,
        })
    }

    fn snapshot(&self) -> io::Result<String> {
        let identity = self.store.load_identity()?;
        let peers = self.store.list_peers()?;
        let peer_lines = if peers.is_empty() {
            "暂无（可从托盘菜单开始配对）".to_owned()
        } else {
            peers
                .iter()
                .map(|peer| format!("• {}  {}", peer.label, peer.fingerprint))
                .collect::<Vec<_>>()
                .join("\r\n")
        };
        let autostart = query_autostart()?.label();
        Ok(format!(
            "ClipFerry 正在后台运行\r\n\r\n本机设备\r\n{}\r\n\r\n已配对设备（{}）\r\n{}\r\n\r\n连接状态：等待已配对设备\r\n最近远端清单：暂无\r\n活动传输：暂无\r\n开机自启动：{}",
            identity.fingerprint(),
            peers.len(),
            peer_lines,
            autostart
        ))
    }

    fn add_icon(&self, window: HWND) -> io::Result<()> {
        let data = self.notify_data(window);
        // SAFETY: data is fully initialized and references a live hidden window and icon.
        if unsafe { Shell_NotifyIconW(NIM_ADD, &raw const data) }.as_bool() {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn delete_icon(&self, window: HWND) {
        let data = self.notify_data(window);
        // SAFETY: deleting a missing icon is harmless; the data identifies our own tray icon.
        let _ = unsafe { Shell_NotifyIconW(NIM_DELETE, &raw const data) };
    }

    fn notify_data(&self, window: HWND) -> NOTIFYICONDATAW {
        let mut data = NOTIFYICONDATAW {
            cbSize: u32::try_from(size_of::<NOTIFYICONDATAW>()).unwrap_or(u32::MAX),
            hWnd: window,
            uID: TRAY_ICON_ID,
            uFlags: NIF_ICON | NIF_MESSAGE | NIF_TIP,
            uCallbackMessage: TRAY_CALLBACK_MESSAGE,
            hIcon: self.icon.handle,
            ..Default::default()
        };
        copy_wide_to_fixed("ClipFerry · 剪贴摆渡", &mut data.szTip);
        data
    }

    fn handle_command(&mut self, window: HWND, command: usize) {
        let result = match command {
            COMMAND_STATUS => self.show_status(window),
            COMMAND_PAIR => Self::spawn_console("pair-wizard"),
            COMMAND_MANAGE_PEERS => Self::spawn_console("trust-wizard"),
            COMMAND_PAUSE | COMMAND_RESUME | COMMAND_CANCEL => {
                show_information(window, "当前没有活动传输。", "ClipFerry");
                Ok(())
            }
            COMMAND_AUTOSTART => self.toggle_autostart(window),
            COMMAND_LOG => self.open_log(),
            COMMAND_EXIT => {
                let _ = append_log(&self.log_path, "tray_exit requested=true");
                // SAFETY: this ends the message loop owned by the current tray thread.
                unsafe { PostQuitMessage(0) };
                Ok(())
            }
            _ => Ok(()),
        };
        if let Err(error) = result {
            let _ = append_log(&self.log_path, &format!("tray_command_error error={error}"));
            show_error(window, &format!("操作失败：{error}"));
        }
    }

    fn show_status(&self, window: HWND) -> io::Result<()> {
        let snapshot = self.snapshot()?;
        show_information(window, &snapshot, "ClipFerry 状态");
        Ok(())
    }

    fn toggle_autostart(&self, window: HWND) -> io::Result<()> {
        let enable = query_autostart()? != AutostartState::Enabled;
        write_autostart(enable)?;
        append_log(
            &self.log_path,
            if enable {
                "autostart enabled=true"
            } else {
                "autostart enabled=false"
            },
        )?;
        show_information(
            window,
            if enable {
                "已启用当前 Windows 用户登录后自动启动，不需要管理员权限。"
            } else {
                "已关闭开机自启动。"
            },
            "ClipFerry",
        );
        Ok(())
    }

    fn spawn_console(command: &str) -> io::Result<()> {
        let executable = std::env::current_exe()?;
        Command::new(executable)
            .arg(command)
            .creation_flags(CREATE_NEW_CONSOLE.0)
            .spawn()?;
        Ok(())
    }

    fn open_log(&self) -> io::Result<()> {
        append_log(&self.log_path, "diagnostics_open requested=true")?;
        let path = wide_null(self.log_path.as_os_str());
        // SAFETY: path is null terminated and ShellExecuteW copies it during the call.
        let result = unsafe {
            ShellExecuteW(
                None,
                w!("open"),
                PCWSTR(path.as_ptr()),
                None,
                None,
                SW_SHOWNORMAL,
            )
        };
        if result.0 as isize <= 32 {
            return Err(io::Error::other(format!(
                "Windows 无法打开诊断日志（ShellExecute={}）",
                result.0 as isize
            )));
        }
        Ok(())
    }

    fn show_menu(&mut self, window: HWND) -> io::Result<()> {
        let menu = PopupMenu::new()?;
        menu.append("ClipFerry · 后台运行", 0, MF_STRING | MF_DISABLED)?;
        menu.separator()?;
        menu.append("查看状态", COMMAND_STATUS, MF_STRING)?;
        menu.append("配对新设备…", COMMAND_PAIR, MF_STRING)?;
        menu.append("管理已配对设备…", COMMAND_MANAGE_PEERS, MF_STRING)?;
        menu.separator()?;
        menu.append("暂停传输", COMMAND_PAUSE, MF_STRING | MF_DISABLED)?;
        menu.append("继续传输", COMMAND_RESUME, MF_STRING | MF_DISABLED)?;
        menu.append("取消传输", COMMAND_CANCEL, MF_STRING | MF_DISABLED)?;
        menu.separator()?;
        let autostart_flags = if query_autostart()? == AutostartState::Enabled {
            MF_STRING | MF_CHECKED
        } else {
            MF_STRING
        };
        menu.append("随 Windows 启动", COMMAND_AUTOSTART, autostart_flags)?;
        menu.append("打开诊断日志", COMMAND_LOG, MF_STRING)?;
        menu.separator()?;
        menu.append("退出 ClipFerry", COMMAND_EXIT, MF_STRING)?;

        let mut point = POINT::default();
        // SAFETY: point is a live writable structure.
        unsafe { GetCursorPos(&raw mut point) }.map_err(windows_error)?;
        // SAFETY: the hidden window owns the popup-menu interaction.
        let _ = unsafe { SetForegroundWindow(window) };
        // SAFETY: menu, owner window and cursor coordinates remain valid during the call.
        let selected = unsafe {
            TrackPopupMenu(
                menu.handle,
                TPM_RIGHTBUTTON | TPM_RETURNCMD,
                point.x,
                point.y,
                None,
                window,
                None,
            )
        };
        let command = usize::try_from(selected.0).unwrap_or_default();
        if command != 0 {
            self.handle_command(window, command);
        }
        Ok(())
    }
}

struct PopupMenu {
    handle: windows::Win32::UI::WindowsAndMessaging::HMENU,
}

impl PopupMenu {
    fn new() -> io::Result<Self> {
        // SAFETY: no parameters and ownership is transferred to the returned guard.
        let handle = unsafe { CreatePopupMenu() }.map_err(windows_error)?;
        Ok(Self { handle })
    }

    fn append(&self, label: &str, command: usize, flags: MENU_ITEM_FLAGS) -> io::Result<()> {
        let label = wide_null(label.as_ref());
        // SAFETY: the menu is live and the null-terminated label remains valid during the call.
        unsafe { AppendMenuW(self.handle, flags, command, PCWSTR(label.as_ptr())) }
            .map_err(windows_error)
    }

    fn separator(&self) -> io::Result<()> {
        // SAFETY: separators ignore the identifier and label.
        unsafe { AppendMenuW(self.handle, MF_SEPARATOR, 0, PCWSTR::null()) }.map_err(windows_error)
    }
}

impl Drop for PopupMenu {
    fn drop(&mut self) {
        // SAFETY: the guard uniquely owns the popup menu.
        let _ = unsafe { DestroyMenu(self.handle) };
    }
}

struct TrayWindow {
    handle: HWND,
    instance: HINSTANCE,
    state: Box<TrayState>,
    class_registered: bool,
}

impl TrayWindow {
    fn create() -> io::Result<Self> {
        let mut state = Box::new(TrayState::new()?);
        // SAFETY: retrieving the current module does not transfer ownership.
        let module = unsafe { GetModuleHandleW(None) }.map_err(windows_error)?;
        let instance = HINSTANCE(module.0);
        let class = WNDCLASSW {
            lpfnWndProc: Some(tray_window_procedure),
            hInstance: instance,
            hIcon: state.icon.handle,
            lpszClassName: TRAY_WINDOW_CLASS,
            ..Default::default()
        };
        // SAFETY: the class structure and constant class name are valid.
        if unsafe { RegisterClassW(&raw const class) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let state_pointer = (&raw mut *state).cast::<c_void>();
        // SAFETY: the boxed state has a stable address until after the window is destroyed.
        let handle = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                TRAY_WINDOW_CLASS,
                w!("ClipFerry"),
                WINDOW_STYLE::default(),
                0,
                0,
                0,
                0,
                Some(HWND_MESSAGE),
                None,
                Some(instance),
                Some(state_pointer.cast_const()),
            )
        }
        .map_err(|error| {
            // SAFETY: registration succeeded in this function.
            let _ = unsafe { UnregisterClassW(TRAY_WINDOW_CLASS, Some(instance)) };
            windows_error(error)
        })?;
        if let Err(error) = state.add_icon(handle) {
            // SAFETY: handle and class are owned by this partially constructed window.
            let _ = unsafe { DestroyWindow(handle) };
            let _ = unsafe { UnregisterClassW(TRAY_WINDOW_CLASS, Some(instance)) };
            return Err(error);
        }
        Ok(Self {
            handle,
            instance,
            state,
            class_registered: true,
        })
    }

    fn run_loop(&self) -> io::Result<()> {
        debug_assert!(!self.handle.0.is_null());
        loop {
            let mut message = MSG::default();
            // SAFETY: message is writable and the thread owns this message loop.
            let result = unsafe { GetMessageW(&raw mut message, None, 0, 0) }.0;
            if result == -1 {
                return Err(io::Error::last_os_error());
            }
            if result == 0 {
                return Ok(());
            }
            // SAFETY: GetMessageW initialized the message.
            unsafe {
                let _ = TranslateMessage(&raw const message);
                DispatchMessageW(&raw const message);
            }
        }
    }
}

impl Drop for TrayWindow {
    fn drop(&mut self) {
        self.state.delete_icon(self.handle);
        // SAFETY: the window was created by this guard and state stays live through destruction.
        let _ = unsafe { DestroyWindow(self.handle) };
        if self.class_registered {
            // SAFETY: this guard registered the class and no window remains after DestroyWindow.
            let _ = unsafe { UnregisterClassW(TRAY_WINDOW_CLASS, Some(self.instance)) };
            self.class_registered = false;
        }
        let _ = append_log(&self.state.log_path, "tray_stop clean=true");
    }
}

unsafe extern "system" fn tray_window_procedure(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_NCCREATE {
        let create = lparam.0 as *const CREATESTRUCTW;
        if !create.is_null() {
            // SAFETY: WM_NCCREATE guarantees lParam points to CREATESTRUCTW, whose lpCreateParams
            // is the stable TrayState pointer passed to CreateWindowExW.
            let state = unsafe { (*create).lpCreateParams } as isize;
            // SAFETY: window creation is in progress and GWLP_USERDATA stores the pointer value.
            unsafe { SetWindowLongPtrW(window, GWLP_USERDATA, state) };
        }
    }
    // SAFETY: reading the application-owned pointer does not dereference it yet.
    let state_pointer = unsafe { GetWindowLongPtrW(window, GWLP_USERDATA) } as *mut TrayState;
    if !state_pointer.is_null() {
        // SAFETY: the pointer belongs to the boxed TrayState and outlives the window.
        let state = unsafe { &mut *state_pointer };
        if message == state.taskbar_created {
            let _ = state.add_icon(window);
            return LRESULT(0);
        }
        if message == TRAY_CALLBACK_MESSAGE {
            let event = u32::try_from(lparam.0).unwrap_or_default();
            match event {
                WM_RBUTTONUP => {
                    if let Err(error) = state.show_menu(window) {
                        show_error(window, &format!("无法打开托盘菜单：{error}"));
                    }
                }
                WM_LBUTTONDBLCLK => {
                    if let Err(error) = state.show_status(window) {
                        show_error(window, &format!("无法读取状态：{error}"));
                    }
                }
                _ => {}
            }
            return LRESULT(0);
        }
        if message == TRAY_SHOW_STATUS_MESSAGE {
            if let Err(error) = state.show_status(window) {
                show_error(window, &format!("无法读取状态：{error}"));
            }
            return LRESULT(0);
        }
        if message == TRAY_EXIT_MESSAGE {
            let _ = append_log(&state.log_path, "tray_exit requested=external");
            // SAFETY: this ends the message loop owned by the tray thread.
            unsafe { PostQuitMessage(0) };
            return LRESULT(0);
        }
        if message == WM_COMMAND {
            state.handle_command(window, wparam.0 & 0xffff);
            return LRESULT(0);
        }
    }
    match message {
        WM_QUERYENDSESSION => LRESULT(1),
        WM_ENDSESSION if wparam.0 != 0 => {
            // SAFETY: this requests orderly termination of the current thread's message loop.
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        WM_DESTROY => {
            // SAFETY: the window is ending, so stop the owning message loop.
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        _ => {
            // SAFETY: unhandled messages are delegated to the system default procedure.
            unsafe { DefWindowProcW(window, message, wparam, lparam) }
        }
    }
}

/// Runs the per-user native tray process.
///
/// # Errors
///
/// Returns a user-facing error when identity initialization, single-instance acquisition,
/// hidden-window setup, tray registration, or the message loop fails.
pub fn run(detach_console: bool) -> Result<(), String> {
    if detach_console {
        // SAFETY: detaching the inherited console is process-local and expected for tray mode.
        let _ = unsafe { FreeConsole() };
    }
    let result = run_inner();
    if let Err(error) = &result {
        show_error(HWND::default(), &format!("ClipFerry 无法启动：{error}"));
    }
    result.map_err(|error| error.to_string())
}

fn run_inner() -> io::Result<()> {
    let Some(_single_instance) = SingleInstance::acquire()? else {
        post_to_existing(TRAY_SHOW_STATUS_MESSAGE)?;
        return Ok(());
    };
    let tray = TrayWindow::create()?;
    tray.run_loop()
}

/// Asks the already-running tray instance to show its native status dialog.
///
/// # Errors
///
/// Returns an error if no instance window exists or the message cannot be posted.
pub fn show_existing_status() -> Result<(), String> {
    post_to_existing(TRAY_SHOW_STATUS_MESSAGE).map_err(|error| error.to_string())
}

/// Requests an orderly exit from the already-running tray instance.
///
/// # Errors
///
/// Returns an error if no instance window exists or the message cannot be posted.
pub fn exit_existing() -> Result<(), String> {
    post_to_existing(TRAY_EXIT_MESSAGE).map_err(|error| error.to_string())
}

fn post_to_existing(message: u32) -> io::Result<()> {
    // SAFETY: the search is restricted to message-only windows with our private class name.
    let window =
        unsafe { FindWindowExW(Some(HWND_MESSAGE), None, TRAY_WINDOW_CLASS, PCWSTR::null()) }
            .map_err(|_| {
                io::Error::new(io::ErrorKind::NotFound, "ClipFerry tray is not running")
            })?;
    // SAFETY: the message contains no pointers and targets the discovered private window.
    unsafe { PostMessageW(Some(window), message, WPARAM(0), LPARAM(0)) }.map_err(windows_error)
}

/// Returns an externally stable autostart state label.
///
/// # Errors
///
/// Returns an error if the current executable or per-user Run registry value cannot be read.
pub fn autostart_status() -> Result<&'static str, String> {
    query_autostart()
        .map(AutostartState::label)
        .map_err(|error| error.to_string())
}

/// Enables or disables current-user startup without elevation.
///
/// # Errors
///
/// Returns an error if the current executable cannot be resolved or HKCU cannot be modified.
pub fn set_autostart(enabled: bool) -> Result<(), String> {
    write_autostart(enabled).map_err(|error| error.to_string())
}

fn query_autostart() -> io::Result<AutostartState> {
    let expected = autostart_command()?;
    let mut bytes = 0_u32;
    // SAFETY: querying with no data buffer asks Windows for the required REG_SZ size.
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            RUN_KEY,
            RUN_VALUE,
            RRF_RT_REG_SZ,
            None,
            None,
            Some(&raw mut bytes),
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(AutostartState::Disabled);
    }
    check_win32(status)?;
    if bytes == 0 || bytes > 64 * 1024 || !bytes.is_multiple_of(2) {
        return Ok(AutostartState::Stale);
    }
    let mut data = vec![0_u8; usize::try_from(bytes).map_err(io::Error::other)?];
    // SAFETY: the buffer has exactly the size Windows reported and remains live through the call.
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            RUN_KEY,
            RUN_VALUE,
            RRF_RT_REG_SZ,
            None,
            Some(data.as_mut_ptr().cast()),
            Some(&raw mut bytes),
        )
    };
    check_win32(status)?;
    let units = data
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .take_while(|unit| *unit != 0)
        .collect::<Vec<_>>();
    let actual = String::from_utf16(&units)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "autostart value is not UTF-16"))?;
    Ok(if actual == expected {
        AutostartState::Enabled
    } else {
        AutostartState::Stale
    })
}

fn write_autostart(enabled: bool) -> io::Result<()> {
    let mut key = HKEY::default();
    // SAFETY: this opens/creates the current user's standard Run key with no custom security.
    check_win32(unsafe { RegCreateKeyW(HKEY_CURRENT_USER, RUN_KEY, &raw mut key) })?;
    let key = RegistryKey(key);
    if enabled {
        let command = wide_null(autostart_command()?.as_ref());
        // SAFETY: command is valid UTF-16 including its terminating NUL; bytes borrow it only for
        // the registry call.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                command.as_ptr().cast::<u8>(),
                command.len().saturating_mul(size_of::<u16>()),
            )
        };
        // SAFETY: key is live and owned, value name is static, and data is a complete REG_SZ.
        check_win32(unsafe { RegSetValueExW(key.0, RUN_VALUE, None, REG_SZ, Some(bytes)) })
    } else {
        // SAFETY: key is live and deleting a missing value is normalized below.
        let status = unsafe { RegDeleteValueW(key.0, RUN_VALUE) };
        if status == ERROR_FILE_NOT_FOUND {
            Ok(())
        } else {
            check_win32(status)
        }
    }
}

struct RegistryKey(HKEY);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        // SAFETY: the guard uniquely owns the registry key returned by RegCreateKeyW.
        let _ = unsafe { RegCloseKey(self.0) };
    }
}

fn autostart_command() -> io::Result<String> {
    let executable = std::env::current_exe()?;
    quote_tray_command(&executable)
}

fn quote_tray_command(executable: &Path) -> io::Result<String> {
    let text = executable.as_os_str().to_string_lossy();
    if text.contains('"') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the executable path contains a quote",
        ));
    }
    Ok(format!("\"{text}\" tray"))
}

fn append_log(path: &Path, message: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "time_unix={timestamp} {message}")
}

fn best_icon_image(bytes: &[u8]) -> io::Result<&[u8]> {
    if bytes.len() < 6 || bytes[0..2] != [0, 0] || bytes[2..4] != [1, 0] {
        return Err(invalid_data("invalid ICO header"));
    }
    let count = usize::from(u16::from_le_bytes([bytes[4], bytes[5]]));
    if count == 0 || count > 256 || bytes.len() < 6 + count * 16 {
        return Err(invalid_data("invalid ICO directory"));
    }
    let mut best = None;
    for index in 0..count {
        let entry = 6 + index * 16;
        let width = if bytes[entry] == 0 {
            256_u32
        } else {
            u32::from(bytes[entry])
        };
        let height = if bytes[entry + 1] == 0 {
            256_u32
        } else {
            u32::from(bytes[entry + 1])
        };
        let size = usize::try_from(u32::from_le_bytes([
            bytes[entry + 8],
            bytes[entry + 9],
            bytes[entry + 10],
            bytes[entry + 11],
        ]))
        .map_err(io::Error::other)?;
        let offset = usize::try_from(u32::from_le_bytes([
            bytes[entry + 12],
            bytes[entry + 13],
            bytes[entry + 14],
            bytes[entry + 15],
        ]))
        .map_err(io::Error::other)?;
        let end = offset
            .checked_add(size)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| invalid_data("ICO image is out of bounds"))?;
        let score = width.saturating_mul(height);
        if best.is_none_or(|(best_score, _, _)| score > best_score) {
            best = Some((score, offset, end));
        }
    }
    let (_, start, end) = best.ok_or_else(|| invalid_data("ICO has no image"))?;
    Ok(&bytes[start..end])
}

fn copy_wide_to_fixed(text: &str, output: &mut [u16]) {
    output.fill(0);
    let content_length = output.len().saturating_sub(1);
    for (target, value) in output
        .iter_mut()
        .take(content_length)
        .zip(text.encode_utf16())
    {
        *target = value;
    }
}

fn wide_null(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn show_information(window: HWND, message: &str, title: &str) {
    show_message(window, message, title, MB_OK | MB_ICONINFORMATION);
}

fn show_error(window: HWND, message: &str) {
    show_message(window, message, "ClipFerry", MB_OK | MB_ICONERROR);
}

fn show_message(
    window: HWND,
    message: &str,
    title: &str,
    style: windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_STYLE,
) {
    let message = wide_null(message.as_ref());
    let title = wide_null(title.as_ref());
    // SAFETY: both strings are null terminated and remain live for the modal call.
    let _ = unsafe {
        MessageBoxW(
            if window.0.is_null() {
                None
            } else {
                Some(window)
            },
            PCWSTR(message.as_ptr()),
            PCWSTR(title.as_ptr()),
            style,
        )
    };
}

fn check_win32(status: windows::Win32::Foundation::WIN32_ERROR) -> io::Result<()> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(
            i32::try_from(status.0).unwrap_or(i32::MAX),
        ))
    }
}

fn windows_error(error: windows_core::Error) -> io::Error {
    io::Error::other(error)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Exercises deterministic tray assets and state formatting without creating UI or mutating HKCU.
///
/// # Errors
///
/// Returns an error if the embedded icon or command-line quoting invariant is invalid.
pub fn self_test() -> Result<(), String> {
    let icon = best_icon_image(ICON_BYTES).map_err(|error| error.to_string())?;
    if icon.len() < 40 {
        return Err("embedded icon image is unexpectedly short".to_owned());
    }
    let quoted = quote_tray_command(Path::new(r"C:\Program Files\ClipFerry\clipferry.exe"))
        .map_err(|error| error.to_string())?;
    if quoted != r#""C:\Program Files\ClipFerry\clipferry.exe" tray"# {
        return Err("autostart command quoting is invalid".to_owned());
    }
    println!(
        "TRAY_SELFTEST passed=true icon_bytes={} autostart_command={quoted:?}",
        icon.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ICON_BYTES, best_icon_image, copy_wide_to_fixed, quote_tray_command};
    use std::path::Path;

    #[test]
    fn embedded_ico_directory_selects_an_in_bounds_image() {
        let image = best_icon_image(ICON_BYTES).unwrap();
        assert!(image.len() >= 40);
        assert!(
            ICON_BYTES
                .windows(image.len())
                .any(|window| window == image)
        );
    }

    #[test]
    fn autostart_command_quotes_the_executable_and_uses_tray_mode() {
        let command =
            quote_tray_command(Path::new(r"C:\Program Files\ClipFerry\clipferry.exe")).unwrap();
        assert_eq!(
            command,
            r#""C:\Program Files\ClipFerry\clipferry.exe" tray"#
        );
        assert!(quote_tray_command(Path::new("C:\\bad\"path\\clipferry.exe")).is_err());
    }

    #[test]
    fn fixed_wide_text_is_null_terminated_and_truncated() {
        let mut output = [0xFFFF; 5];
        copy_wide_to_fixed("ClipFerry", &mut output);
        assert_eq!(output, ['C' as u16, 'l' as u16, 'i' as u16, 'p' as u16, 0]);
    }
}
