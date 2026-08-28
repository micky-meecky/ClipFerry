use std::sync::Arc;
use std::time::Duration;

use std::ffi::c_void;

use windows::Win32::Foundation::{
    E_INVALIDARG, E_UNEXPECTED, HINSTANCE, HWND, LPARAM, LRESULT, S_OK, WPARAM,
};
use windows::Win32::System::Com::IDataObject;
use windows::Win32::System::DataExchange::{
    AddClipboardFormatListener, RemoveClipboardFormatListener,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Ole::{OleInitialize, OleSetClipboard, OleUninitialize};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, HWND_MESSAGE,
    KillTimer, MSG, RegisterClassW, SetTimer, TranslateMessage, UnregisterClassW, WINDOW_EX_STYLE,
    WINDOW_STYLE, WM_CLIPBOARDUPDATE, WM_QUIT, WM_TIMER, WNDCLASSW,
};
use windows::core::{Error, HRESULT, Interface, Result, w};

use super::data_object::VirtualFileDataObject;
use super::probe::ProbeState;
use super::source::MemorySource;
use super::{TEST_FILE_CONTENT, TEST_FILE_NAME};

#[derive(Clone, Copy, Debug, Default)]
pub struct ClipboardProbeOptions {
    pub lifetime: Option<Duration>,
}

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
    fn register_test_file() -> Result<Self> {
        let apartment = OleApartment::initialize()?;
        let window = ClipboardWindow::create()?;
        let probe = Arc::new(ProbeState::default());
        let object = VirtualFileDataObject::create(
            Arc::<str>::from(TEST_FILE_NAME),
            Arc::new(MemorySource::new(TEST_FILE_CONTENT)),
            Arc::clone(&probe),
        )?;
        unsafe { OleSetClipboard(&object) }?;

        if probe.read_calls() != 0 {
            return Err(Error::from_hresult(E_UNEXPECTED));
        }
        probe.record(
            "OleSetClipboard",
            format_args!("registered=true deferred_reads={}", probe.read_calls()),
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

/// Registers the fixed virtual-file probe and pumps its clipboard apartment.
///
/// # Errors
///
/// Returns a COM or Win32 error if OLE initialization, clipboard registration,
/// message-window setup, or message processing fails.
pub fn run_clipboard_probe(options: ClipboardProbeOptions) -> Result<()> {
    let lease = ClipboardLease::register_test_file()?;
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
