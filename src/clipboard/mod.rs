mod data_object;
mod format_enum;
mod local_file;
mod loopback;
mod probe;
mod product;
mod runtime;
pub mod secure_transfer;
mod source;
mod stream;
mod transfer;

pub use probe::ProbeState;
pub use product::{
    ProductCommand, ProductManifestSummary, ProductRuntime, ProductSnapshot,
    ProductTransferSnapshot, ProductTransferState,
};
pub use runtime::{
    ClipboardProbeOptions, FileCaptureProbeOptions, LoopbackProbeOptions, PauseProbeOptions,
    SecureFetchProbeOptions, SecureFetchResult, SecureReceiverProbeOptions,
    SecureSourceProbeOptions, SecureSourceTls, run_clipboard_probe, run_file_capture_probe,
    run_loopback_probe, run_pause_probe, run_secure_fetch_probe, run_secure_receiver_probe,
    run_secure_source_probe,
};

pub const TEST_FILE_NAME: &str = "RemoteClipboard-Test.txt";
pub const TEST_FILE_CONTENT: &[u8] = b"ClipFerry virtual file stream test.\r\n";

pub(crate) fn catch_com_result<T>(
    operation: impl FnOnce() -> windows::core::Result<T>,
) -> windows::core::Result<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)).unwrap_or_else(|_| {
        Err(windows::core::Error::from_hresult(
            windows::Win32::Foundation::E_UNEXPECTED,
        ))
    })
}

pub(crate) fn catch_com_hresult(
    operation: impl FnOnce() -> windows::core::HRESULT,
) -> windows::core::HRESULT {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation))
        .unwrap_or(windows::Win32::Foundation::E_UNEXPECTED)
}
