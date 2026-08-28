use std::ffi::{OsString, c_void};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::os::windows::ffi::OsStringExt as _;
use std::os::windows::fs::{FileExt as _, OpenOptionsExt as _};
use std::os::windows::io::AsRawHandle as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{
    E_INVALIDARG, E_UNEXPECTED, ERROR_FILE_INVALID, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA,
    ERROR_NOT_SUPPORTED, ERROR_TIMEOUT, FILETIME, HANDLE, HGLOBAL, HWND,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_COMPRESSED, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_EA, FILE_ATTRIBUTE_ENCRYPTED, FILE_ATTRIBUTE_INTEGRITY_STREAM,
    FILE_ATTRIBUTE_NO_SCRUB_DATA, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_PINNED,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SPARSE_FILE, FILE_ATTRIBUTE_UNPINNED,
    FILE_ATTRIBUTE_VIRTUAL, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_STREAM_INFO, FILE_TYPE_DISK, FileStreamInfo, GetFileAttributesW,
    GetFileInformationByHandle, GetFileInformationByHandleEx, GetFileType, INVALID_FILE_ATTRIBUTES,
};
use windows::Win32::System::Com::CoCreateGuid;
use windows::Win32::System::DataExchange::{
    CloseClipboard, GetClipboardData, GetClipboardSequenceNumber, IsClipboardFormatAvailable,
    OpenClipboard, RegisterClipboardFormatW,
};
use windows::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};
use windows::Win32::System::Ole::{CF_HDROP, DROPEFFECT_COPY, DROPEFFECT_MOVE};
use windows::Win32::UI::Shell::{CFSTR_PREFERREDDROPEFFECT, DragQueryFileW, HDROP};
use windows::core::{Error, GUID, HRESULT, PCWSTR, Result, w};

use super::data_object::{VirtualFileDescriptor, validate_virtual_file_name};
use super::source::ReadAtSource;

const MAX_CAPTURE_PATH_U16: usize = 32_767;
const PRIVATE_ORIGIN_FORMAT: PCWSTR = w!("ClipFerry.SourceOffer.v1");
const PRIVATE_ORIGIN_PREFIX: &[u8] = b"ClipFerry.SourceOffer.v1\0";

#[derive(Clone, Copy, Debug)]
pub struct CaptureFormats {
    preferred_effect: u32,
    private_origin: u32,
}

impl CaptureFormats {
    pub fn register() -> Result<Self> {
        let preferred_effect = unsafe { RegisterClipboardFormatW(CFSTR_PREFERREDDROPEFFECT) };
        let private_origin = unsafe { RegisterClipboardFormatW(PRIVATE_ORIGIN_FORMAT) };
        if preferred_effect == 0 || private_origin == 0 {
            return Err(Error::from_thread());
        }
        Ok(Self {
            preferred_effect,
            private_origin,
        })
    }
}

#[derive(Debug)]
pub enum ClipboardCapture {
    Candidate { path: PathBuf, sequence: u32 },
    NotFileClipboard,
    PrivateOffer,
    Rejected(CaptureRejection),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureRejection {
    MissingCopyEffect,
    CutOperation,
    MultipleItems,
    InvalidPath,
    NonUnicodeName,
    Directory,
    ReparsePoint,
    Encrypted,
    Sparse,
    OfflinePlaceholder,
    Compressed,
    AlternateDataStream,
    UnsupportedMetadata,
    NonDiskFile,
}

impl fmt::Display for CaptureRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::MissingCopyEffect => "missing-copy-effect",
            Self::CutOperation => "cut-operation",
            Self::MultipleItems => "multiple-items",
            Self::InvalidPath => "invalid-path",
            Self::NonUnicodeName => "non-unicode-name",
            Self::Directory => "directory",
            Self::ReparsePoint => "reparse-point",
            Self::Encrypted => "efs-encrypted",
            Self::Sparse => "sparse-file",
            Self::OfflinePlaceholder => "offline-or-cloud-placeholder",
            Self::Compressed => "compressed-file",
            Self::AlternateDataStream => "alternate-data-stream",
            Self::UnsupportedMetadata => "unsupported-file-metadata",
            Self::NonDiskFile => "non-disk-file",
        };
        formatter.write_str(text)
    }
}

#[derive(Debug)]
pub enum CaptureError {
    Windows(Error),
    Rejected(CaptureRejection),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Windows(error) => write!(formatter, "{error} ({:#010X})", error.code().0),
            Self::Rejected(reason) => write!(formatter, "rejected: {reason}"),
        }
    }
}

impl From<Error> for CaptureError {
    fn from(error: Error) -> Self {
        Self::Windows(error)
    }
}

pub fn capture_single_file_from_clipboard(
    owner: HWND,
    formats: CaptureFormats,
) -> std::result::Result<ClipboardCapture, CaptureError> {
    let _clipboard = ClipboardGuard::open(owner)?;
    let sequence = unsafe { GetClipboardSequenceNumber() };
    if unsafe { IsClipboardFormatAvailable(formats.private_origin) }.is_ok()
        && read_private_origin(formats.private_origin)
    {
        return Ok(ClipboardCapture::PrivateOffer);
    }
    if unsafe { IsClipboardFormatAvailable(u32::from(CF_HDROP.0)) }.is_err() {
        return Ok(ClipboardCapture::NotFileClipboard);
    }
    if unsafe { IsClipboardFormatAvailable(formats.preferred_effect) }.is_err() {
        return Ok(ClipboardCapture::Rejected(
            CaptureRejection::MissingCopyEffect,
        ));
    }
    let effect = read_drop_effect(formats.preferred_effect)?;
    if let Err(reason) = validate_drop_effect(effect) {
        return Ok(ClipboardCapture::Rejected(reason));
    }

    let handle = unsafe { GetClipboardData(u32::from(CF_HDROP.0)) }?;
    let drop = HDROP(handle.0);
    let count = unsafe { DragQueryFileW(drop, u32::MAX, None) };
    if count != 1 {
        return Ok(ClipboardCapture::Rejected(CaptureRejection::MultipleItems));
    }
    let length = usize::try_from(unsafe { DragQueryFileW(drop, 0, None) })
        .map_err(|_| CaptureError::Rejected(CaptureRejection::InvalidPath))?;
    if length == 0 || length > MAX_CAPTURE_PATH_U16 {
        return Ok(ClipboardCapture::Rejected(CaptureRejection::InvalidPath));
    }
    let mut buffer = vec![0_u16; length + 1];
    let copied = usize::try_from(unsafe { DragQueryFileW(drop, 0, Some(&mut buffer)) })
        .map_err(|_| CaptureError::Rejected(CaptureRejection::InvalidPath))?;
    if copied != length || buffer[length] != 0 {
        return Ok(ClipboardCapture::Rejected(CaptureRejection::InvalidPath));
    }
    let path = PathBuf::from(OsString::from_wide(&buffer[..length]));
    if !path.is_absolute() {
        return Ok(ClipboardCapture::Rejected(CaptureRejection::InvalidPath));
    }
    Ok(ClipboardCapture::Candidate { path, sequence })
}

fn validate_drop_effect(effect: u32) -> std::result::Result<(), CaptureRejection> {
    if effect & DROPEFFECT_MOVE.0 != 0 {
        return Err(CaptureRejection::CutOperation);
    }
    if effect & DROPEFFECT_COPY.0 == 0 {
        return Err(CaptureRejection::MissingCopyEffect);
    }
    Ok(())
}

struct ClipboardGuard;

impl ClipboardGuard {
    fn open(owner: HWND) -> Result<Self> {
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
            match unsafe { OpenClipboard(Some(owner)) } {
                Ok(()) => return Ok(Self),
                Err(error) => last_error = error,
            }
            if index + 1 != BACKOFF.len() {
                std::thread::sleep(delay);
            }
        }
        Err(last_error)
    }
}

impl Drop for ClipboardGuard {
    fn drop(&mut self) {
        let _ = unsafe { CloseClipboard() };
    }
}

fn read_drop_effect(format: u32) -> Result<u32> {
    let handle = unsafe { GetClipboardData(format) }?;
    let global = HGLOBAL(handle.0);
    if unsafe { GlobalSize(global) } < size_of::<u32>() {
        return Err(Error::from_hresult(E_INVALIDARG));
    }
    let pointer = unsafe { GlobalLock(global) };
    if pointer.is_null() {
        return Err(Error::from_thread());
    }
    let effect = unsafe { pointer.cast::<u32>().read_unaligned() };
    let _ = unsafe { GlobalUnlock(global) };
    Ok(effect)
}

fn read_private_origin(format: u32) -> bool {
    let Ok(handle) = (unsafe { GetClipboardData(format) }) else {
        return false;
    };
    let global = HGLOBAL(handle.0);
    let expected_length = PRIVATE_ORIGIN_PREFIX.len() + 16;
    if unsafe { GlobalSize(global) } != expected_length {
        return false;
    }
    let pointer = unsafe { GlobalLock(global) };
    if pointer.is_null() {
        return false;
    }
    let payload = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), expected_length) };
    let valid = is_private_origin_payload(payload);
    let _ = unsafe { GlobalUnlock(global) };
    valid
}

fn is_private_origin_payload(payload: &[u8]) -> bool {
    payload.len() == PRIVATE_ORIGIN_PREFIX.len() + 16 && payload.starts_with(PRIVATE_ORIGIN_PREFIX)
}

const fn size_of<T>() -> usize {
    std::mem::size_of::<T>()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    volume_serial: u32,
    file_index: u64,
}

#[derive(Clone, Debug)]
pub struct FileSnapshot {
    path: PathBuf,
    file_name: Arc<str>,
    size: u64,
    attributes: u32,
    creation_time: FILETIME,
    last_access_time: FILETIME,
    last_write_time: FILETIME,
    identity: FileIdentity,
}

impl FileSnapshot {
    pub fn capture(path: &Path) -> std::result::Result<Self, CaptureError> {
        if !path.is_absolute() {
            return Err(CaptureError::Rejected(CaptureRejection::InvalidPath));
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(CaptureError::Rejected(CaptureRejection::NonUnicodeName))?;
        validate_virtual_file_name(file_name).map_err(CaptureError::Windows)?;

        // Opening a directory for ordinary file reads fails with ACCESS_DENIED
        // before a handle-based attribute check is possible. A bounded
        // preflight gives callers the intended policy error; the handle check
        // below remains authoritative for replacement races.
        let wide = path_wide(path).map_err(CaptureError::Windows)?;
        let path_attributes = unsafe { GetFileAttributesW(PCWSTR(wide.as_ptr())) };
        if path_attributes == INVALID_FILE_ATTRIBUTES {
            return Err(CaptureError::Windows(Error::from_thread()));
        }
        reject_attributes(path_attributes).map_err(CaptureError::Rejected)?;

        let file = open_snapshot_handle(path).map_err(CaptureError::Windows)?;
        let information = information_for(&file).map_err(CaptureError::Windows)?;
        reject_attributes(information.dwFileAttributes).map_err(CaptureError::Rejected)?;
        let file_type = unsafe { GetFileType(file_handle(&file)) };
        if file_type != FILE_TYPE_DISK {
            return Err(CaptureError::Rejected(CaptureRejection::NonDiskFile));
        }
        if has_named_data_stream(&file).map_err(CaptureError::Windows)? {
            return Err(CaptureError::Rejected(
                CaptureRejection::AlternateDataStream,
            ));
        }

        Ok(Self::from_information(
            path.to_path_buf(),
            Arc::<str>::from(file_name),
            information,
        ))
    }

    fn from_information(
        path: PathBuf,
        file_name: Arc<str>,
        information: BY_HANDLE_FILE_INFORMATION,
    ) -> Self {
        Self {
            path,
            file_name,
            size: file_size(&information),
            attributes: information.dwFileAttributes,
            creation_time: information.ftCreationTime,
            last_access_time: information.ftLastAccessTime,
            last_write_time: information.ftLastWriteTime,
            identity: file_identity(&information),
        }
    }

    #[must_use]
    #[cfg(test)]
    pub fn file_name(&self) -> &Arc<str> {
        &self.file_name
    }

    #[must_use]
    #[cfg(test)]
    pub fn size(&self) -> u64 {
        self.size
    }

    fn descriptor(&self) -> VirtualFileDescriptor {
        VirtualFileDescriptor {
            file_name: Arc::clone(&self.file_name),
            size: self.size,
            attributes: self.attributes,
            creation_time: Some(self.creation_time),
            last_access_time: Some(self.last_access_time),
            last_write_time: Some(self.last_write_time),
        }
    }

    fn matches(&self, information: &BY_HANDLE_FILE_INFORMATION) -> bool {
        self.size == file_size(information)
            && self.attributes == information.dwFileAttributes
            && self.identity == file_identity(information)
            && filetime_eq(self.creation_time, information.ftCreationTime)
            && filetime_eq(self.last_write_time, information.ftLastWriteTime)
    }
}

fn reject_attributes(attributes: u32) -> std::result::Result<(), CaptureRejection> {
    if attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
        return Err(CaptureRejection::Directory);
    }
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(CaptureRejection::ReparsePoint);
    }
    if attributes & FILE_ATTRIBUTE_ENCRYPTED.0 != 0 {
        return Err(CaptureRejection::Encrypted);
    }
    if attributes & FILE_ATTRIBUTE_SPARSE_FILE.0 != 0 {
        return Err(CaptureRejection::Sparse);
    }
    if attributes
        & (FILE_ATTRIBUTE_OFFLINE.0
            | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS.0
            | FILE_ATTRIBUTE_RECALL_ON_OPEN.0)
        != 0
    {
        return Err(CaptureRejection::OfflinePlaceholder);
    }
    if attributes & FILE_ATTRIBUTE_COMPRESSED.0 != 0 {
        return Err(CaptureRejection::Compressed);
    }
    if attributes
        & (FILE_ATTRIBUTE_EA.0
            | FILE_ATTRIBUTE_INTEGRITY_STREAM.0
            | FILE_ATTRIBUTE_NO_SCRUB_DATA.0
            | FILE_ATTRIBUTE_PINNED.0
            | FILE_ATTRIBUTE_UNPINNED.0
            | FILE_ATTRIBUTE_VIRTUAL.0)
        != 0
    {
        return Err(CaptureRejection::UnsupportedMetadata);
    }
    Ok(())
}

fn open_snapshot_handle(path: &Path) -> Result<File> {
    open_file(
        path,
        FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0,
    )
}

fn open_stable_handle(path: &Path) -> Result<File> {
    open_file(path, FILE_SHARE_READ.0)
}

fn open_file(path: &Path, share_mode: u32) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(share_mode)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0);
    options.open(path).map_err(|error| io_error(&error))
}

fn file_handle(file: &File) -> HANDLE {
    HANDLE(file.as_raw_handle())
}

fn information_for(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(file_handle(file), &raw mut information) }?;
    Ok(information)
}

fn file_size(information: &BY_HANDLE_FILE_INFORMATION) -> u64 {
    (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow)
}

fn file_identity(information: &BY_HANDLE_FILE_INFORMATION) -> FileIdentity {
    FileIdentity {
        volume_serial: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    }
}

fn filetime_eq(left: FILETIME, right: FILETIME) -> bool {
    left.dwLowDateTime == right.dwLowDateTime && left.dwHighDateTime == right.dwHighDateTime
}

fn has_named_data_stream(file: &File) -> Result<bool> {
    // Query by the already-validated handle so a rename/replacement race cannot
    // make the ADS policy inspect a different path target.
    const BUFFER_SIZE: usize = 64 * 1024;
    const NAME_OFFSET: usize = std::mem::offset_of!(FILE_STREAM_INFO, StreamName);
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    if let Err(error) = unsafe {
        GetFileInformationByHandleEx(
            file_handle(file),
            FileStreamInfo,
            buffer.as_mut_ptr().cast::<c_void>(),
            u32::try_from(buffer.len()).expect("the fixed stream-info buffer fits in u32"),
        )
    } {
        if error.code() == HRESULT::from_win32(ERROR_MORE_DATA.0)
            || error.code() == HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0)
        {
            // A default unnamed stream fits in a few dozen bytes. Overflow is
            // therefore already enough evidence to conservatively reject.
            return Ok(true);
        }
        return Err(error);
    }

    let mut cursor = 0_usize;
    loop {
        let header_end = cursor
            .checked_add(NAME_OFFSET)
            .ok_or_else(|| Error::from_hresult(E_INVALIDARG))?;
        let structure_end = cursor
            .checked_add(size_of::<FILE_STREAM_INFO>())
            .ok_or_else(|| Error::from_hresult(E_INVALIDARG))?;
        if header_end > buffer.len() || structure_end > buffer.len() {
            return Err(Error::from_hresult(E_INVALIDARG));
        }
        let entry = unsafe {
            buffer
                .as_ptr()
                .add(cursor)
                .cast::<FILE_STREAM_INFO>()
                .read_unaligned()
        };
        let name_bytes = usize::try_from(entry.StreamNameLength)
            .map_err(|_| Error::from_hresult(E_INVALIDARG))?;
        if name_bytes % size_of::<u16>() != 0 {
            return Err(Error::from_hresult(E_INVALIDARG));
        }
        let entry_end = header_end
            .checked_add(name_bytes)
            .ok_or_else(|| Error::from_hresult(E_INVALIDARG))?;
        if entry_end > buffer.len() {
            return Err(Error::from_hresult(E_INVALIDARG));
        }
        let name_length = name_bytes / size_of::<u16>();
        let mut name = Vec::with_capacity(name_length);
        for index in 0..name_length {
            let character_offset = header_end + index * size_of::<u16>();
            name.push(u16::from_ne_bytes([
                buffer[character_offset],
                buffer[character_offset + 1],
            ]));
        }
        if String::from_utf16_lossy(&name) != "::$DATA" {
            return Ok(true);
        }
        if entry.NextEntryOffset == 0 {
            return Ok(false);
        }
        let next = usize::try_from(entry.NextEntryOffset)
            .map_err(|_| Error::from_hresult(E_INVALIDARG))?;
        if next < NAME_OFFSET {
            return Err(Error::from_hresult(E_INVALIDARG));
        }
        cursor = cursor
            .checked_add(next)
            .ok_or_else(|| Error::from_hresult(E_INVALIDARG))?;
    }
}

fn path_wide(path: &Path) -> Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt as _;

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(Error::from_hresult(E_INVALIDARG));
    }
    wide.push(0);
    Ok(wide)
}

fn io_error(error: &std::io::Error) -> Error {
    error.raw_os_error().map_or_else(
        || Error::from_hresult(E_UNEXPECTED),
        |code| Error::from_hresult(HRESULT::from_win32(code.cast_unsigned())),
    )
}

fn source_changed_error() -> Error {
    Error::from_hresult(HRESULT::from_win32(ERROR_FILE_INVALID.0))
}

fn offer_unavailable_error() -> Error {
    Error::from_hresult(HRESULT::from_win32(ERROR_TIMEOUT.0))
}

struct StableFileContext {
    file: File,
    snapshot: Arc<FileSnapshot>,
}

impl StableFileContext {
    fn open(snapshot: Arc<FileSnapshot>) -> Result<Self> {
        let file = open_stable_handle(&snapshot.path)?;
        let information = information_for(&file)?;
        reject_attributes(information.dwFileAttributes)
            .map_err(|_| Error::from_hresult(HRESULT::from_win32(ERROR_NOT_SUPPORTED.0)))?;
        if unsafe { GetFileType(file_handle(&file)) } != FILE_TYPE_DISK
            || !snapshot.matches(&information)
        {
            return Err(source_changed_error());
        }
        if has_named_data_stream(&file)? {
            return Err(Error::from_hresult(HRESULT::from_win32(
                ERROR_NOT_SUPPORTED.0,
            )));
        }
        Ok(Self { file, snapshot })
    }

    fn verify(&self) -> Result<()> {
        let information = information_for(&self.file)?;
        if self.snapshot.matches(&information) {
            Ok(())
        } else {
            Err(source_changed_error())
        }
    }
}

enum StableFileState {
    Unstarted,
    Active(Arc<StableFileContext>),
    Failed(HRESULT),
}

pub struct StableFileSource {
    snapshot: Arc<FileSnapshot>,
    expires_at: Instant,
    revoked: AtomicBool,
    state: Mutex<StableFileState>,
    read_calls: AtomicU64,
    bytes_read: AtomicU64,
}

impl StableFileSource {
    fn new(snapshot: Arc<FileSnapshot>, expires_at: Instant) -> Self {
        Self {
            snapshot,
            expires_at,
            revoked: AtomicBool::new(false),
            state: Mutex::new(StableFileState::Unstarted),
            read_calls: AtomicU64::new(0),
            bytes_read: AtomicU64::new(0),
        }
    }

    fn context(&self) -> Result<Arc<StableFileContext>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::from_hresult(E_UNEXPECTED))?;
        match &*state {
            StableFileState::Active(context) => return Ok(Arc::clone(context)),
            StableFileState::Failed(code) => return Err(Error::from_hresult(*code)),
            StableFileState::Unstarted => {}
        }
        if self.revoked.load(Ordering::Acquire) || Instant::now() >= self.expires_at {
            let error = offer_unavailable_error();
            *state = StableFileState::Failed(error.code());
            return Err(error);
        }
        match StableFileContext::open(Arc::clone(&self.snapshot)) {
            Ok(context) => {
                let context = Arc::new(context);
                *state = StableFileState::Active(Arc::clone(&context));
                Ok(context)
            }
            Err(error) => {
                *state = StableFileState::Failed(error.code());
                Err(error)
            }
        }
    }

    fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn read_calls(&self) -> u64 {
        self.read_calls.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read.load(Ordering::Relaxed)
    }
}

impl ReadAtSource for StableFileSource {
    fn len(&self) -> u64 {
        self.snapshot.size
    }

    fn read_at(&self, offset: u64, destination: &mut [u8]) -> Result<usize> {
        if destination.is_empty() {
            return Ok(0);
        }
        self.read_calls.fetch_add(1, Ordering::Relaxed);
        let context = self.context()?;
        context.verify()?;
        if offset >= self.snapshot.size {
            return Ok(0);
        }
        let available = self.snapshot.size - offset;
        let length = destination
            .len()
            .min(usize::try_from(available).unwrap_or(usize::MAX));
        let read = context
            .file
            .seek_read(&mut destination[..length], offset)
            .map_err(|error| io_error(&error))?;
        self.bytes_read
            .fetch_add(u64::try_from(read).unwrap_or(u64::MAX), Ordering::Relaxed);
        if read != length {
            return Err(source_changed_error());
        }
        if offset.saturating_add(read as u64) >= self.snapshot.size {
            context.verify()?;
        }
        Ok(read)
    }
}

pub struct LocalFileOffer {
    offer_id: GUID,
    file_id: GUID,
    created_at: Instant,
    expires_at: Instant,
    snapshot: Arc<FileSnapshot>,
    source: Arc<StableFileSource>,
    origin_payload: Arc<[u8]>,
}

impl LocalFileOffer {
    fn create(snapshot: FileSnapshot, ttl: Duration) -> Result<Self> {
        if ttl.is_zero() {
            return Err(Error::from_hresult(E_INVALIDARG));
        }
        let offer_id = unsafe { CoCreateGuid() }?;
        let file_id = unsafe { CoCreateGuid() }?;
        let created_at = Instant::now();
        let expires_at = created_at
            .checked_add(ttl)
            .ok_or_else(|| Error::from_hresult(E_INVALIDARG))?;
        let snapshot = Arc::new(snapshot);
        let source = Arc::new(StableFileSource::new(Arc::clone(&snapshot), expires_at));
        let mut origin_payload = Vec::with_capacity(PRIVATE_ORIGIN_PREFIX.len() + 16);
        origin_payload.extend_from_slice(PRIVATE_ORIGIN_PREFIX);
        origin_payload.extend_from_slice(&offer_id.to_u128().to_be_bytes());
        Ok(Self {
            offer_id,
            file_id,
            created_at,
            expires_at,
            snapshot,
            source,
            origin_payload: Arc::from(origin_payload),
        })
    }

    #[must_use]
    pub fn offer_id(&self) -> GUID {
        self.offer_id
    }

    #[must_use]
    pub fn file_id(&self) -> GUID {
        self.file_id
    }

    #[must_use]
    pub fn file_name(&self) -> &str {
        &self.snapshot.file_name
    }

    #[must_use]
    pub fn size(&self) -> u64 {
        self.snapshot.size
    }

    #[must_use]
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    #[must_use]
    pub fn remaining_ttl(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }

    #[must_use]
    pub fn descriptor(&self) -> VirtualFileDescriptor {
        self.snapshot.descriptor()
    }

    #[must_use]
    pub fn source(&self) -> Arc<StableFileSource> {
        Arc::clone(&self.source)
    }

    #[must_use]
    pub fn origin_payload(&self) -> Arc<[u8]> {
        Arc::clone(&self.origin_payload)
    }

    fn revoke(&self) {
        self.source.revoke();
    }
}

#[derive(Default)]
pub struct LocalOfferRegistry {
    current: Option<Arc<LocalFileOffer>>,
}

impl LocalOfferRegistry {
    pub fn publish(
        &mut self,
        snapshot: FileSnapshot,
        ttl: Duration,
    ) -> Result<Arc<LocalFileOffer>> {
        let offer = Arc::new(LocalFileOffer::create(snapshot, ttl)?);
        if let Some(previous) = self.current.replace(Arc::clone(&offer)) {
            previous.revoke();
        }
        Ok(offer)
    }

    pub fn revoke_current(&mut self) {
        if let Some(current) = self.current.take() {
            current.revoke();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write as _;
    use std::sync::{Arc, Barrier};

    use windows::Win32::Foundation::{ERROR_FILE_INVALID, ERROR_TIMEOUT};
    use windows::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_COMPRESSED, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_ENCRYPTED,
        FILE_ATTRIBUTE_INTEGRITY_STREAM, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_SPARSE_FILE,
    };
    use windows::Win32::System::Ole::{DROPEFFECT_COPY, DROPEFFECT_MOVE};
    use windows::core::HRESULT;

    use super::{
        CaptureError, CaptureRejection, FileSnapshot, LocalOfferRegistry, PRIVATE_ORIGIN_PREFIX,
        StableFileSource, is_private_origin_payload, reject_attributes, validate_drop_effect,
    };
    use crate::clipboard::source::ReadAtSource;

    struct TestFile {
        directory: std::path::PathBuf,
        path: std::path::PathBuf,
    }

    impl TestFile {
        fn create(name: &str, bytes: &[u8]) -> Self {
            let directory = std::env::temp_dir().join(format!(
                "clipferry-local-file-{}-{}",
                std::process::id(),
                unsafe { windows::Win32::System::Com::CoCreateGuid() }
                    .unwrap()
                    .to_u128()
            ));
            std::fs::create_dir(&directory).unwrap();
            let path = directory.join(name);
            std::fs::write(&path, bytes).unwrap();
            Self { directory, path }
        }
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn unsupported_attribute_policy_is_explicit() {
        assert_eq!(
            reject_attributes(FILE_ATTRIBUTE_DIRECTORY.0),
            Err(CaptureRejection::Directory)
        );
        assert_eq!(
            reject_attributes(FILE_ATTRIBUTE_REPARSE_POINT.0),
            Err(CaptureRejection::ReparsePoint)
        );
        assert_eq!(
            reject_attributes(FILE_ATTRIBUTE_ENCRYPTED.0),
            Err(CaptureRejection::Encrypted)
        );
        assert_eq!(
            reject_attributes(FILE_ATTRIBUTE_SPARSE_FILE.0),
            Err(CaptureRejection::Sparse)
        );
        assert_eq!(
            reject_attributes(FILE_ATTRIBUTE_OFFLINE.0),
            Err(CaptureRejection::OfflinePlaceholder)
        );
        assert_eq!(
            reject_attributes(FILE_ATTRIBUTE_COMPRESSED.0),
            Err(CaptureRejection::Compressed)
        );
        assert_eq!(
            reject_attributes(FILE_ATTRIBUTE_INTEGRITY_STREAM.0),
            Err(CaptureRejection::UnsupportedMetadata)
        );
        assert_eq!(reject_attributes(0), Ok(()));
    }

    #[test]
    fn only_an_explicit_copy_effect_is_accepted() {
        assert_eq!(validate_drop_effect(DROPEFFECT_COPY.0), Ok(()));
        assert_eq!(
            validate_drop_effect(DROPEFFECT_MOVE.0),
            Err(CaptureRejection::CutOperation)
        );
        assert_eq!(
            validate_drop_effect(DROPEFFECT_COPY.0 | DROPEFFECT_MOVE.0),
            Err(CaptureRejection::CutOperation)
        );
        assert_eq!(
            validate_drop_effect(0),
            Err(CaptureRejection::MissingCopyEffect)
        );
    }

    #[test]
    fn capture_reads_metadata_but_no_content() {
        let file = TestFile::create("metadata.bin", b"abcdef");
        let snapshot = FileSnapshot::capture(&file.path).unwrap();
        let source = StableFileSource::new(
            Arc::new(snapshot.clone()),
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        );

        assert_eq!(snapshot.size(), 6);
        assert_eq!(snapshot.file_name().as_ref(), "metadata.bin");
        assert_eq!(snapshot.descriptor().attributes, snapshot.attributes);
        assert_eq!(source.read_calls(), 0);
        assert_eq!(source.bytes_read(), 0);
    }

    #[test]
    fn private_origin_requires_the_exact_versioned_payload_shape() {
        let mut payload = PRIVATE_ORIGIN_PREFIX.to_vec();
        payload.extend_from_slice(&[0xA5; 16]);
        assert!(is_private_origin_payload(&payload));
        assert!(!is_private_origin_payload(PRIVATE_ORIGIN_PREFIX));
        payload[0] ^= 1;
        assert!(!is_private_origin_payload(&payload));
    }

    #[test]
    fn directory_capture_reports_the_explicit_policy_rejection() {
        let file = TestFile::create("inside.bin", b"payload");
        assert!(matches!(
            FileSnapshot::capture(&file.directory),
            Err(CaptureError::Rejected(CaptureRejection::Directory))
        ));
    }

    #[test]
    fn alternate_data_stream_is_rejected() {
        let file = TestFile::create("motw.bin", b"payload");
        let stream_path =
            std::path::PathBuf::from(format!("{}:Zone.Identifier", file.path.display()));
        match std::fs::write(&stream_path, b"[ZoneTransfer]\r\nZoneId=3\r\n") {
            Ok(()) => assert!(matches!(
                FileSnapshot::capture(&file.path),
                Err(CaptureError::Rejected(
                    CaptureRejection::AlternateDataStream
                ))
            )),
            Err(error) => eprintln!("ADS test not supported on this volume: {error}"),
        }
    }

    #[test]
    fn alternate_data_stream_added_after_capture_is_rejected_before_content() {
        let file = TestFile::create("late-motw.bin", b"payload");
        let snapshot = FileSnapshot::capture(&file.path).unwrap();
        let stream_path =
            std::path::PathBuf::from(format!("{}:Zone.Identifier", file.path.display()));
        if std::fs::write(&stream_path, b"[ZoneTransfer]\r\nZoneId=3\r\n").is_err() {
            return;
        }
        let source = StableFileSource::new(
            Arc::new(snapshot),
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        );
        let mut bytes = [0_u8; 8];

        assert!(source.read_at(0, &mut bytes).is_err());
        assert_eq!(source.read_calls(), 1);
        assert_eq!(source.bytes_read(), 0);
    }

    #[test]
    fn source_change_before_first_read_fails_terminally() {
        let file = TestFile::create("changed.bin", b"before");
        let snapshot = FileSnapshot::capture(&file.path).unwrap();
        std::fs::write(&file.path, b"after-longer").unwrap();
        let source = StableFileSource::new(
            Arc::new(snapshot),
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        );
        let mut bytes = [0_u8; 16];

        let error = source.read_at(0, &mut bytes).unwrap_err();
        assert_eq!(error.code(), HRESULT::from_win32(ERROR_FILE_INVALID.0));
        let second = source.read_at(0, &mut bytes).unwrap_err();
        assert_eq!(second.code(), HRESULT::from_win32(ERROR_FILE_INVALID.0));
        assert_eq!(source.read_calls(), 2);
        assert_eq!(source.bytes_read(), 0);
    }

    #[test]
    fn stable_handle_uses_explicit_offsets_and_blocks_write_rename_and_delete() {
        let file = TestFile::create("stable.bin", b"0123456789abcdef");
        let snapshot = FileSnapshot::capture(&file.path).unwrap();
        let source = Arc::new(StableFileSource::new(
            Arc::new(snapshot),
            std::time::Instant::now() + std::time::Duration::from_secs(2),
        ));
        let barrier = Arc::new(Barrier::new(3));
        let read = |offset| {
            let source = Arc::clone(&source);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let mut bytes = [0_u8; 4];
                barrier.wait();
                source.read_at(offset, &mut bytes).unwrap();
                bytes
            })
        };
        let first = read(0);
        let second = read(8);
        barrier.wait();

        assert_eq!(&first.join().unwrap(), b"0123");
        assert_eq!(&second.join().unwrap(), b"89ab");
        assert!(OpenOptions::new().write(true).open(&file.path).is_err());
        assert!(std::fs::rename(&file.path, file.directory.join("renamed.bin")).is_err());
        assert!(std::fs::remove_file(&file.path).is_err());
        assert_eq!(source.read_calls(), 2);
        assert_eq!(source.bytes_read(), 8);
    }

    #[test]
    fn expired_and_replaced_unstarted_offers_cannot_begin() {
        let first = TestFile::create("first.bin", b"first");
        let second = TestFile::create("second.bin", b"second");
        let mut registry = LocalOfferRegistry::default();
        let expired = registry
            .publish(
                FileSnapshot::capture(&first.path).unwrap(),
                std::time::Duration::from_millis(1),
            )
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let mut bytes = [0_u8; 8];
        assert_eq!(
            expired.source().read_at(0, &mut bytes).unwrap_err().code(),
            HRESULT::from_win32(ERROR_TIMEOUT.0)
        );

        let old = registry
            .publish(
                FileSnapshot::capture(&first.path).unwrap(),
                std::time::Duration::from_secs(1),
            )
            .unwrap();
        let current = registry
            .publish(
                FileSnapshot::capture(&second.path).unwrap(),
                std::time::Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            old.source().read_at(0, &mut bytes).unwrap_err().code(),
            HRESULT::from_win32(ERROR_TIMEOUT.0)
        );
        assert_eq!(current.source().read_at(0, &mut bytes).unwrap(), 6);
        assert_eq!(&bytes[..6], b"second");
    }

    #[test]
    fn an_active_offer_can_finish_after_registry_replacement() {
        let first = TestFile::create("active.bin", b"active-content");
        let second = TestFile::create("replacement.bin", b"replacement");
        let mut registry = LocalOfferRegistry::default();
        let active = registry
            .publish(
                FileSnapshot::capture(&first.path).unwrap(),
                std::time::Duration::from_secs(1),
            )
            .unwrap();
        let source = active.source();
        let mut prefix = [0_u8; 6];
        assert_eq!(source.read_at(0, &mut prefix).unwrap(), 6);
        registry
            .publish(
                FileSnapshot::capture(&second.path).unwrap(),
                std::time::Duration::from_secs(1),
            )
            .unwrap();
        let mut suffix = [0_u8; 8];
        assert_eq!(source.read_at(6, &mut suffix).unwrap(), 8);
        assert_eq!(&prefix, b"active");
        assert_eq!(&suffix, b"-content");
    }

    #[test]
    fn open_writer_from_before_transfer_prevents_a_mixed_snapshot() {
        let file = TestFile::create("writer.bin", b"stable");
        let snapshot = FileSnapshot::capture(&file.path).unwrap();
        let mut writer = OpenOptions::new().write(true).open(&file.path).unwrap();
        let source = StableFileSource::new(
            Arc::new(snapshot),
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        );
        writer.write_all(b"changed").unwrap();
        let mut bytes = [0_u8; 8];

        assert!(source.read_at(0, &mut bytes).is_err());
    }
}
