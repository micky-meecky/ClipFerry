use std::ffi::{OsStr, c_void};
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    CLEARTYPE_QUALITY, CLIP_DEFAULT_PRECIS, COLOR_WINDOW, CreateFontW, DEFAULT_CHARSET,
    DEFAULT_PITCH, DeleteObject, FF_DONTCARE, GetSysColorBrush, HDC, HFONT, HGDIOBJ,
    OUT_DEFAULT_PRECIS, SetBkMode, TRANSPARENT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{
    ICC_PROGRESS_CLASS, INITCOMMONCONTROLSEX, InitCommonControlsEx, PBM_SETPOS, PBM_SETRANGE32,
    PBM_SETSTATE, PBST_ERROR, PBST_NORMAL, PBST_PAUSED, PROGRESS_CLASSW,
};
use windows::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows::Win32::UI::WindowsAndMessaging::{
    BS_PUSHBUTTON, CREATESTRUCTW, CW_USEDEFAULT, CreateWindowExW, DefWindowProcW, DestroyWindow,
    GWLP_USERDATA, GetWindowLongPtrW, HICON, HMENU, IDC_ARROW, IsDialogMessageW, IsWindowVisible,
    LoadCursorW, MSG, PostMessageW, RegisterClassW, SC_MINIMIZE, SW_HIDE, SW_RESTORE,
    SW_SHOWNOACTIVATE, SendMessageW, SetForegroundWindow, SetWindowLongPtrW, SetWindowTextW,
    ShowWindow, UnregisterClassW, WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLOSE, WM_COMMAND,
    WM_CTLCOLORSTATIC, WM_NCCREATE, WM_NCDESTROY, WM_SETFONT, WM_SYSCOMMAND, WNDCLASSW, WS_CAPTION,
    WS_CHILD, WS_CLIPCHILDREN, WS_EX_APPWINDOW, WS_MINIMIZEBOX, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
};
use windows_core::{PCWSTR, w};

use crate::clipboard::{ProductSnapshot, ProductTransferState};

const TRANSFER_WINDOW_CLASS: PCWSTR = w!("ClipFerryTransferWindow");
const CONTROL_PAUSE: usize = 1;
const CONTROL_RESUME: usize = 2;
const CONTROL_CANCEL: usize = 3;

#[derive(Clone, Copy)]
pub struct TransferWindowCommands {
    pub pause: usize,
    pub resume: usize,
    pub cancel: usize,
}

struct ProcedureState {
    command_target: HWND,
    commands: TransferWindowCommands,
    hidden_by_user: Arc<AtomicBool>,
    primary_is_close: Arc<AtomicBool>,
}

struct Controls {
    heading: HWND,
    state: HWND,
    progress: HWND,
    amount: HWND,
    speed: HWND,
    current_file: HWND,
    recovery: HWND,
    pause: HWND,
    resume: HWND,
    cancel: HWND,
}

pub struct TransferWindow {
    handle: HWND,
    instance: HINSTANCE,
    procedure_state: Box<ProcedureState>,
    controls: Controls,
    body_font: HFONT,
    heading_font: HFONT,
    hidden_by_user: Arc<AtomicBool>,
    primary_is_close: Arc<AtomicBool>,
    generation: Option<u64>,
}

impl TransferWindow {
    pub fn create(
        command_target: HWND,
        icon: HICON,
        commands: TransferWindowCommands,
    ) -> io::Result<Self> {
        let controls = INITCOMMONCONTROLSEX {
            dwSize: u32::try_from(size_of::<INITCOMMONCONTROLSEX>()).unwrap_or(u32::MAX),
            dwICC: ICC_PROGRESS_CLASS,
        };
        // SAFETY: the structure is fully initialized and only requests the progress class.
        if !unsafe { InitCommonControlsEx(&raw const controls) }.as_bool() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: retrieving the current module does not transfer ownership.
        let module = unsafe { GetModuleHandleW(None) }.map_err(windows_error)?;
        let instance = HINSTANCE(module.0);
        // SAFETY: IDC_ARROW and COLOR_WINDOW are shared system resources.
        let cursor = unsafe { LoadCursorW(None, IDC_ARROW) }.map_err(windows_error)?;
        let background = unsafe { GetSysColorBrush(COLOR_WINDOW) };
        let class = WNDCLASSW {
            lpfnWndProc: Some(transfer_window_procedure),
            hInstance: instance,
            hIcon: icon,
            hCursor: cursor,
            hbrBackground: background,
            lpszClassName: TRANSFER_WINDOW_CLASS,
            ..Default::default()
        };
        // SAFETY: the class fields and static class name remain valid for the call.
        if unsafe { RegisterClassW(&raw const class) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let hidden_by_user = Arc::new(AtomicBool::new(false));
        let primary_is_close = Arc::new(AtomicBool::new(false));
        let mut procedure_state = Box::new(ProcedureState {
            command_target,
            commands,
            hidden_by_user: Arc::clone(&hidden_by_user),
            primary_is_close: Arc::clone(&primary_is_close),
        });
        let state_pointer = (&raw mut *procedure_state).cast::<c_void>();
        let style = WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN;
        // SAFETY: the registered class is live and the boxed procedure state has a stable address.
        let handle = match unsafe {
            CreateWindowExW(
                WS_EX_APPWINDOW,
                TRANSFER_WINDOW_CLASS,
                w!("ClipFerry 文件接收"),
                style,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                680,
                370,
                None,
                None,
                Some(instance),
                Some(state_pointer.cast_const()),
            )
        } {
            Ok(handle) => handle,
            Err(error) => {
                // SAFETY: registration succeeded above and no class window was created.
                let _ = unsafe { UnregisterClassW(TRANSFER_WINDOW_CLASS, Some(instance)) };
                return Err(windows_error(error));
            }
        };
        let body_font = match create_font(-17, 400) {
            Ok(font) => font,
            Err(error) => {
                let _ = unsafe { DestroyWindow(handle) };
                let _ = unsafe { UnregisterClassW(TRANSFER_WINDOW_CLASS, Some(instance)) };
                return Err(error);
            }
        };
        let heading_font = match create_font(-21, 600) {
            Ok(font) => font,
            Err(error) => {
                let _ = unsafe { DeleteObject(HGDIOBJ(body_font.0)) };
                let _ = unsafe { DestroyWindow(handle) };
                let _ = unsafe { UnregisterClassW(TRANSFER_WINDOW_CLASS, Some(instance)) };
                return Err(error);
            }
        };
        let child_result = Self::create_controls(handle, instance, body_font, heading_font);
        let child_controls = match child_result {
            Ok(controls) => controls,
            Err(error) => {
                // SAFETY: the partially initialized top-level window owns all created children.
                let _ = unsafe { DestroyWindow(handle) };
                let _ = unsafe { DeleteObject(HGDIOBJ(body_font.0)) };
                let _ = unsafe { DeleteObject(HGDIOBJ(heading_font.0)) };
                let _ = unsafe { UnregisterClassW(TRANSFER_WINDOW_CLASS, Some(instance)) };
                return Err(error);
            }
        };
        Ok(Self {
            handle,
            instance,
            procedure_state,
            controls: child_controls,
            body_font,
            heading_font,
            hidden_by_user,
            primary_is_close,
            generation: None,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn create_controls(
        parent: HWND,
        instance: HINSTANCE,
        body_font: HFONT,
        heading_font: HFONT,
    ) -> io::Result<Controls> {
        let heading = create_child(
            parent,
            instance,
            w!("STATIC"),
            "等待接收文件",
            28,
            22,
            624,
            28,
            0,
        )?;
        let state = create_child(
            parent,
            instance,
            w!("STATIC"),
            "等待传输开始",
            28,
            58,
            624,
            24,
            0,
        )?;
        let progress = create_child(parent, instance, PROGRESS_CLASSW, "", 28, 92, 624, 18, 0)?;
        let amount = create_child(
            parent,
            instance,
            w!("STATIC"),
            "0 B / 0 B",
            28,
            122,
            624,
            24,
            0,
        )?;
        let speed = create_child(
            parent,
            instance,
            w!("STATIC"),
            "当前速度：0 B/s",
            28,
            188,
            624,
            24,
            0,
        )?;
        let current_file = create_child(
            parent,
            instance,
            w!("STATIC"),
            "当前文件：尚未开始",
            28,
            158,
            624,
            24,
            0,
        )?;
        let recovery = create_child(
            parent,
            instance,
            w!("STATIC"),
            "网络状态：稳定",
            28,
            218,
            624,
            24,
            0,
        )?;
        let pause = create_child(
            parent,
            instance,
            w!("BUTTON"),
            "暂停",
            352,
            276,
            92,
            34,
            CONTROL_PAUSE,
        )?;
        let resume = create_child(
            parent,
            instance,
            w!("BUTTON"),
            "继续",
            456,
            276,
            92,
            34,
            CONTROL_RESUME,
        )?;
        let cancel = create_child(
            parent,
            instance,
            w!("BUTTON"),
            "取消",
            560,
            276,
            92,
            34,
            CONTROL_CANCEL,
        )?;
        set_control_font(heading, heading_font);
        for control in [
            state,
            amount,
            speed,
            current_file,
            recovery,
            pause,
            resume,
            cancel,
        ] {
            set_control_font(control, body_font);
        }
        // SAFETY: the progress bar is live and accepts a 0..1000 integer range.
        unsafe {
            SendMessageW(
                progress,
                PBM_SETRANGE32,
                Some(WPARAM(0)),
                Some(LPARAM(1000)),
            );
        }
        Ok(Controls {
            heading,
            state,
            progress,
            amount,
            speed,
            current_file,
            recovery,
            pause,
            resume,
            cancel,
        })
    }

    #[allow(clippy::too_many_lines)]
    pub fn update(&mut self, snapshot: &ProductSnapshot) -> io::Result<()> {
        let Some((manifest, transfer)) = snapshot
            .last_manifest
            .as_ref()
            .filter(|manifest| manifest.direction == "接收")
            .zip(snapshot.transfer.as_ref())
        else {
            return Ok(());
        };
        if !should_present_generation(
            self.generation,
            snapshot.transfer_generation,
            transfer.state,
        ) {
            return Ok(());
        }
        if self.generation != Some(snapshot.transfer_generation) {
            self.generation = Some(snapshot.transfer_generation);
            self.hidden_by_user.store(false, Ordering::Release);
        }
        let tenths = progress_tenths(transfer.transferred, transfer.total_size, transfer.state);
        set_text(
            self.handle,
            &format!("ClipFerry · 从“{}”接收", snapshot.active_peer_label),
        )?;
        set_text(
            self.controls.heading,
            &format!(
                "{} · {} 个文件 / {} 个目录",
                truncate(&manifest.primary_name, 72),
                manifest.files,
                manifest.directories
            ),
        )?;
        set_text(
            self.controls.state,
            &format!(
                "{} · {}.{}%",
                transfer.state.label(),
                tenths / 10,
                tenths % 10
            ),
        )?;
        set_text(
            self.controls.amount,
            &format!(
                "已传输：{} / {}",
                format_bytes(transfer.transferred),
                format_bytes(transfer.total_size)
            ),
        )?;
        set_text(
            self.controls.speed,
            &format!(
                "当前速度：{}/s    平均速度：{}/s    剩余：{}",
                format_bytes(transfer.bytes_per_second),
                format_bytes(transfer.average_bytes_per_second),
                format_remaining(transfer)
            ),
        )?;
        set_text(
            self.controls.current_file,
            &format!(
                "当前文件：{}    {} / {}    文件 {}/{}",
                transfer
                    .current_file_name
                    .as_deref()
                    .map_or_else(|| "尚未开始".to_owned(), |name| truncate(name, 52)),
                format_bytes(transfer.current_file_transferred),
                format_bytes(transfer.current_file_size),
                transfer.started_files.min(transfer.total_files),
                transfer.total_files
            ),
        )?;
        let recovery = if transfer.recovery_active {
            format!(
                "网络状态：正在重连 · 已尝试 {} 次 · 已恢复 {} 次命令",
                transfer.reconnect_attempts, transfer.recovered_commands
            )
        } else if transfer.reconnect_attempts != 0 {
            format!(
                "网络状态：已恢复 · 共尝试 {} 次 · 已恢复 {} 次命令",
                transfer.reconnect_attempts, transfer.recovered_commands
            )
        } else {
            "网络状态：稳定".to_owned()
        };
        set_text(self.controls.recovery, &recovery)?;
        let terminal = matches!(
            transfer.state,
            ProductTransferState::Completed
                | ProductTransferState::Cancelled
                | ProductTransferState::Failed
        );
        self.primary_is_close.store(terminal, Ordering::Release);
        set_text(
            self.controls.cancel,
            match transfer.state {
                ProductTransferState::Completed => "完成",
                ProductTransferState::Cancelled | ProductTransferState::Failed => "关闭",
                _ => "取消",
            },
        )?;
        // SAFETY: the controls are live and the message parameters are bounded integers.
        unsafe {
            SendMessageW(
                self.controls.progress,
                PBM_SETPOS,
                Some(WPARAM(usize::from(tenths))),
                Some(LPARAM(0)),
            );
            let progress_state = match transfer.state {
                ProductTransferState::Paused => PBST_PAUSED,
                ProductTransferState::Cancelled | ProductTransferState::Failed => PBST_ERROR,
                _ => PBST_NORMAL,
            };
            SendMessageW(
                self.controls.progress,
                PBM_SETSTATE,
                Some(WPARAM(progress_state as usize)),
                Some(LPARAM(0)),
            );
            let _ = EnableWindow(
                self.controls.pause,
                transfer.state == ProductTransferState::Running,
            );
            let _ = EnableWindow(
                self.controls.resume,
                transfer.state == ProductTransferState::Paused,
            );
            let _ = EnableWindow(self.controls.cancel, true);
        }
        if matches!(
            transfer.state,
            ProductTransferState::Running | ProductTransferState::Paused
        ) && !self.hidden_by_user.load(Ordering::Acquire)
            && !unsafe { IsWindowVisible(self.handle) }.as_bool()
        {
            // SAFETY: showing without activation preserves the user's Explorer paste focus.
            let _ = unsafe { ShowWindow(self.handle, SW_SHOWNOACTIVATE) };
        }
        Ok(())
    }

    pub fn show(&self) {
        self.hidden_by_user.store(false, Ordering::Release);
        // SAFETY: this is a live top-level window explicitly requested from the tray menu.
        unsafe {
            let _ = ShowWindow(self.handle, SW_RESTORE);
            let _ = SetForegroundWindow(self.handle);
        }
    }

    pub fn is_dialog_message(&self, message: &MSG) -> bool {
        // SAFETY: the transfer window and message are live on the same GUI thread.
        unsafe { IsDialogMessageW(self.handle, message) }.as_bool()
    }
}

impl Drop for TransferWindow {
    fn drop(&mut self) {
        // Keep the boxed procedure state alive until after the window procedure finishes.
        let _ = &self.procedure_state;
        // SAFETY: this guard owns the top-level window and registered class.
        let _ = unsafe { DestroyWindow(self.handle) };
        let _ = unsafe { DeleteObject(HGDIOBJ(self.body_font.0)) };
        let _ = unsafe { DeleteObject(HGDIOBJ(self.heading_font.0)) };
        let _ = unsafe { UnregisterClassW(TRANSFER_WINDOW_CLASS, Some(self.instance)) };
    }
}

unsafe extern "system" fn transfer_window_procedure(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_NCCREATE {
        let create = lparam.0 as *const CREATESTRUCTW;
        if !create.is_null() {
            // SAFETY: WM_NCCREATE provides the CREATESTRUCTW passed to CreateWindowExW.
            let state = unsafe { (*create).lpCreateParams } as isize;
            // SAFETY: GWLP_USERDATA stores the stable boxed ProcedureState pointer.
            unsafe { SetWindowLongPtrW(window, GWLP_USERDATA, state) };
        }
    }
    // SAFETY: reading application-owned window data does not dereference it yet.
    let state = unsafe { GetWindowLongPtrW(window, GWLP_USERDATA) } as *mut ProcedureState;
    if !state.is_null() {
        // SAFETY: the boxed ProcedureState outlives the window.
        let state = unsafe { &*state };
        match message {
            WM_COMMAND => {
                let control = wparam.0 & 0xffff;
                if control == CONTROL_CANCEL && state.primary_is_close.load(Ordering::Acquire) {
                    state.hidden_by_user.store(true, Ordering::Release);
                    // SAFETY: terminal action only hides the live transfer window.
                    let _ = unsafe { ShowWindow(window, SW_HIDE) };
                    return LRESULT(0);
                }
                let command = match control {
                    CONTROL_PAUSE => Some(state.commands.pause),
                    CONTROL_RESUME => Some(state.commands.resume),
                    CONTROL_CANCEL => Some(state.commands.cancel),
                    _ => None,
                };
                if let Some(command) = command {
                    // SAFETY: this posts a pointer-free command to the tray's hidden window.
                    let _ = unsafe {
                        PostMessageW(
                            Some(state.command_target),
                            WM_COMMAND,
                            WPARAM(command),
                            LPARAM(0),
                        )
                    };
                    if control == CONTROL_CANCEL {
                        state.hidden_by_user.store(true, Ordering::Release);
                        // SAFETY: cancellation continues in the tray worker after this window hides.
                        let _ = unsafe { ShowWindow(window, SW_HIDE) };
                    }
                }
                return LRESULT(0);
            }
            WM_CLOSE => {
                state.hidden_by_user.store(true, Ordering::Release);
                // SAFETY: hiding preserves the active transfer and its controls.
                let _ = unsafe { ShowWindow(window, SW_HIDE) };
                return LRESULT(0);
            }
            WM_SYSCOMMAND
                if u32::try_from(wparam.0).unwrap_or_default() & 0xfff0 == SC_MINIMIZE =>
            {
                state.hidden_by_user.store(true, Ordering::Release);
                // SAFETY: minimize-to-tray is implemented by hiding this top-level window.
                let _ = unsafe { ShowWindow(window, SW_HIDE) };
                return LRESULT(0);
            }
            WM_NCDESTROY => {
                // SAFETY: the procedure state is no longer read after non-client destruction.
                unsafe { SetWindowLongPtrW(window, GWLP_USERDATA, 0) };
            }
            WM_CTLCOLORSTATIC => {
                let device_context = HDC(wparam.0 as *mut c_void);
                // SAFETY: WM_CTLCOLORSTATIC provides a live device context for this paint pass.
                let _ = unsafe { SetBkMode(device_context, TRANSPARENT) };
                // SAFETY: the system color brush is shared and matches the window background.
                let brush = unsafe { GetSysColorBrush(COLOR_WINDOW) };
                return LRESULT(brush.0 as isize);
            }
            _ => {}
        }
    }
    // SAFETY: unhandled messages use the system default procedure.
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}

#[allow(clippy::too_many_arguments)]
fn create_child(
    parent: HWND,
    instance: HINSTANCE,
    class_name: PCWSTR,
    text: &str,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    identifier: usize,
) -> io::Result<HWND> {
    let text = wide_null(text.as_ref());
    let mut style = WS_CHILD | WS_VISIBLE;
    if identifier != 0 {
        style |= WS_TABSTOP | WINDOW_STYLE(BS_PUSHBUTTON as u32);
    }
    let menu = (identifier != 0).then_some(HMENU(identifier as *mut c_void));
    // SAFETY: parent and instance are live; text is null terminated for the duration of the call.
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class_name,
            PCWSTR(text.as_ptr()),
            style,
            x,
            y,
            width,
            height,
            Some(parent),
            menu,
            Some(instance),
            None,
        )
    }
    .map_err(windows_error)
}

fn set_text(window: HWND, text: &str) -> io::Result<()> {
    let text = wide_null(text.as_ref());
    // SAFETY: the window is live and text is null terminated for the call.
    unsafe { SetWindowTextW(window, PCWSTR(text.as_ptr())) }.map_err(windows_error)
}

fn create_font(height: i32, weight: i32) -> io::Result<HFONT> {
    // SAFETY: all scalar parameters are bounded and the face name is a static UTF-16 string.
    let font = unsafe {
        CreateFontW(
            height,
            0,
            0,
            0,
            weight,
            0,
            0,
            0,
            DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY,
            u32::from(DEFAULT_PITCH.0 | FF_DONTCARE.0),
            w!("Segoe UI"),
        )
    };
    if font.0.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(font)
    }
}

fn set_control_font(control: HWND, font: HFONT) {
    // SAFETY: both handles remain live until after the parent window is destroyed.
    unsafe {
        SendMessageW(
            control,
            WM_SETFONT,
            Some(WPARAM(font.0 as usize)),
            Some(LPARAM(1)),
        );
    }
}

fn progress_tenths(transferred: u64, total: u64, state: ProductTransferState) -> u16 {
    if total == 0 {
        return u16::from(state == ProductTransferState::Completed) * 1000;
    }
    u16::try_from(
        transferred
            .min(total)
            .saturating_mul(1000)
            .checked_div(total)
            .unwrap_or_default(),
    )
    .unwrap_or(1000)
}

fn should_present_generation(
    displayed_generation: Option<u64>,
    incoming_generation: u64,
    incoming_state: ProductTransferState,
) -> bool {
    displayed_generation.is_none()
        || displayed_generation == Some(incoming_generation)
        || incoming_state != ProductTransferState::AwaitingPaste
}

fn format_remaining(transfer: &crate::clipboard::ProductTransferSnapshot) -> String {
    if transfer.state == ProductTransferState::Completed {
        return "已完成".to_owned();
    }
    if transfer.state == ProductTransferState::Paused {
        return "已暂停".to_owned();
    }
    if transfer.bytes_per_second == 0 {
        return "计算中".to_owned();
    }
    let seconds = transfer
        .total_size
        .saturating_sub(transfer.transferred)
        .div_ceil(transfer.bytes_per_second);
    if seconds >= 3600 {
        format!("{} 小时 {} 分", seconds / 3600, seconds % 3600 / 60)
    } else if seconds >= 60 {
        format!("{} 分 {} 秒", seconds / 60, seconds % 60)
    } else {
        format!("{seconds} 秒")
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    if bytes >= GIB {
        format_scaled_bytes(bytes, GIB, 2, "GiB")
    } else if bytes >= MIB {
        format_scaled_bytes(bytes, MIB, 1, "MiB")
    } else if bytes >= KIB {
        format_scaled_bytes(bytes, KIB, 1, "KiB")
    } else {
        format!("{bytes} B")
    }
}

fn format_scaled_bytes(bytes: u64, unit: u64, decimals: u32, suffix: &str) -> String {
    let factor = 10_u64.pow(decimals);
    let fraction = u128::from(bytes % unit) * u128::from(factor) / u128::from(unit);
    format!(
        "{}.{:0width$} {suffix}",
        bytes / unit,
        fraction,
        width = decimals as usize
    )
}

fn truncate(text: &str, max_chars: usize) -> String {
    let mut characters = text.chars();
    let prefix = characters.by_ref().take(max_chars).collect::<String>();
    if characters.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn windows_error(error: windows_core::Error) -> io::Error {
    io::Error::other(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_and_remaining_time_are_bounded() {
        assert_eq!(progress_tenths(50, 100, ProductTransferState::Running), 500);
        assert_eq!(
            progress_tenths(200, 100, ProductTransferState::Running),
            1000
        );
        assert_eq!(progress_tenths(0, 0, ProductTransferState::Completed), 1000);
        let transfer = crate::clipboard::ProductTransferSnapshot {
            state: ProductTransferState::Running,
            transferred: 50,
            total_size: 100,
            bytes_per_second: 10,
            average_bytes_per_second: 8,
            started_files: 1,
            total_files: 1,
            current_file_name: Some("file.bin".to_owned()),
            current_file_transferred: 50,
            current_file_size: 100,
            reconnect_attempts: 0,
            recovered_commands: 0,
            recovery_active: false,
        };
        assert_eq!(format_remaining(&transfer), "5 秒");
    }

    #[test]
    fn truncation_preserves_unicode_boundaries() {
        assert_eq!(truncate("你好-ClipFerry", 2), "你好…");
        assert_eq!(truncate("文件", 4), "文件");
    }

    #[test]
    fn an_unpasted_offer_does_not_replace_the_visible_transfer_result() {
        assert!(!should_present_generation(
            Some(7),
            8,
            ProductTransferState::AwaitingPaste
        ));
        assert!(should_present_generation(
            Some(7),
            8,
            ProductTransferState::Running
        ));
        assert!(should_present_generation(
            Some(7),
            7,
            ProductTransferState::Completed
        ));
    }

    #[test]
    fn native_window_constructs_and_renders_an_awaiting_receiver() {
        let mut window = TransferWindow::create(
            HWND::default(),
            HICON::default(),
            TransferWindowCommands {
                pause: 1,
                resume: 2,
                cancel: 3,
            },
        )
        .unwrap();
        let snapshot = ProductSnapshot {
            listener_running: true,
            local_endpoint: "127.0.0.1:45233".parse().unwrap(),
            active_peer_label: "测试设备".to_owned(),
            active_peer: crate::security::CertificateFingerprint::from_bytes([7; 32]),
            auto_receive: true,
            pending_offer: false,
            last_manifest: Some(crate::clipboard::ProductManifestSummary {
                direction: "接收",
                primary_name: "测试文件夹".to_owned(),
                items: 2,
                files: 1,
                directories: 1,
                total_size: 100,
            }),
            transfer: Some(crate::clipboard::ProductTransferSnapshot {
                state: ProductTransferState::AwaitingPaste,
                transferred: 0,
                total_size: 100,
                bytes_per_second: 0,
                average_bytes_per_second: 0,
                started_files: 0,
                total_files: 1,
                current_file_name: None,
                current_file_transferred: 0,
                current_file_size: 0,
                reconnect_attempts: 0,
                recovered_commands: 0,
                recovery_active: false,
            }),
            transfer_generation: 1,
            last_error: None,
        };
        window.update(&snapshot).unwrap();
        assert!(!unsafe { IsWindowVisible(window.handle) }.as_bool());
    }
}
