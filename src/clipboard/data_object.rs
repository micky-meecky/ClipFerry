#![allow(clippy::inline_always, clippy::ref_as_ptr)]

use std::mem::{ManuallyDrop, size_of};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use windows::Win32::Foundation::{
    DATA_S_SAMEFORMATETC, DV_E_DVASPECT, DV_E_DVTARGETDEVICE, DV_E_FORMATETC, DV_E_LINDEX,
    DV_E_TYMED, E_NOTIMPL, E_POINTER, FILETIME, GlobalFree, OLE_E_ADVISENOTSUPPORTED, S_OK,
};
use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
use windows::Win32::System::Com::{
    DATADIR_GET, DVASPECT_CONTENT, FORMATETC, IAdviseSink, IBindCtx, IDataObject, IDataObject_Impl,
    IEnumFORMATETC, IEnumSTATDATA, IStream, STGMEDIUM, STGMEDIUM_0, TYMED_HGLOBAL, TYMED_ISTREAM,
};
use windows::Win32::System::DataExchange::RegisterClipboardFormatW;
use windows::Win32::System::Memory::{
    GMEM_MOVEABLE, GMEM_ZEROINIT, GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock,
};
use windows::Win32::System::Ole::{DROPEFFECT_COPY, ReleaseStgMedium};
use windows::Win32::UI::Shell::{
    CFSTR_FILECONTENTS, CFSTR_FILEDESCRIPTORW, CFSTR_LOGICALPERFORMEDDROPEFFECT,
    CFSTR_PASTESUCCEEDED, CFSTR_PERFORMEDDROPEFFECT, CFSTR_PREFERREDDROPEFFECT, FD_ACCESSTIME,
    FD_ATTRIBUTES, FD_CREATETIME, FD_FILESIZE, FD_UNICODE, FD_WRITESTIME, FILEDESCRIPTORW,
    FILEGROUPDESCRIPTORW, IDataObjectAsyncCapability, IDataObjectAsyncCapability_Impl,
};
use windows::core::{BOOL, Error, HRESULT, Ref, Result, implement, w};

use super::format_enum::FormatEnumerator;
use super::probe::ProbeState;
use super::source::ReadAtSource;
use super::stream::VirtualStream;
use super::{catch_com_hresult, catch_com_result};

#[derive(Clone, Copy, Debug)]
struct ClipboardFormats {
    descriptor: u16,
    contents: u16,
    preferred_effect: u16,
    origin: u16,
    performed_effect: u16,
    logical_performed_effect: u16,
    paste_succeeded: u16,
}

impl ClipboardFormats {
    fn register() -> Result<Self> {
        Ok(Self {
            descriptor: register_format(CFSTR_FILEDESCRIPTORW)?,
            contents: register_format(CFSTR_FILECONTENTS)?,
            preferred_effect: register_format(CFSTR_PREFERREDDROPEFFECT)?,
            origin: register_format(w!("ClipFerry.SourceOffer.v1"))?,
            performed_effect: register_format(CFSTR_PERFORMEDDROPEFFECT)?,
            logical_performed_effect: register_format(CFSTR_LOGICALPERFORMEDDROPEFFECT)?,
            paste_succeeded: register_format(CFSTR_PASTESUCCEEDED)?,
        })
    }

    fn enumerated(self) -> [FORMATETC; 4] {
        [
            format_etc(self.descriptor, -1, TYMED_HGLOBAL.0.cast_unsigned()),
            format_etc(self.contents, 0, TYMED_ISTREAM.0.cast_unsigned()),
            format_etc(self.preferred_effect, -1, TYMED_HGLOBAL.0.cast_unsigned()),
            format_etc(self.origin, -1, TYMED_HGLOBAL.0.cast_unsigned()),
        ]
    }

    fn is_feedback(self, format: u16) -> bool {
        format == self.performed_effect
            || format == self.logical_performed_effect
            || format == self.paste_succeeded
    }
}

fn register_format(name: windows::core::PCWSTR) -> Result<u16> {
    let format = unsafe { RegisterClipboardFormatW(name) };
    if format == 0 {
        return Err(Error::from_thread());
    }
    u16::try_from(format).map_err(|_| Error::from_hresult(DV_E_FORMATETC))
}

fn format_etc(format: u16, index: i32, medium: u32) -> FORMATETC {
    FORMATETC {
        cfFormat: format,
        ptd: ptr::null_mut(),
        dwAspect: DVASPECT_CONTENT.0,
        lindex: index,
        tymed: medium,
    }
}

#[implement(IDataObject, IDataObjectAsyncCapability)]
pub struct VirtualFileDataObject {
    formats: ClipboardFormats,
    descriptor: VirtualFileDescriptor,
    origin_payload: Arc<[u8]>,
    source_factory: Arc<dyn Fn() -> Arc<dyn ReadAtSource> + Send + Sync>,
    probe: Arc<ProbeState>,
    async_mode: AtomicBool,
    in_operation: AtomicBool,
}

#[derive(Clone, Debug)]
pub struct VirtualFileDescriptor {
    pub file_name: Arc<str>,
    pub size: u64,
    pub attributes: u32,
    pub creation_time: Option<FILETIME>,
    pub last_access_time: Option<FILETIME>,
    pub last_write_time: Option<FILETIME>,
}

impl VirtualFileDescriptor {
    #[must_use]
    pub fn basic(file_name: Arc<str>, size: u64) -> Self {
        Self {
            file_name,
            size,
            attributes: FILE_ATTRIBUTE_NORMAL.0,
            creation_time: None,
            last_access_time: None,
            last_write_time: None,
        }
    }
}

impl VirtualFileDataObject {
    pub fn create(
        file_name: Arc<str>,
        source: Arc<dyn ReadAtSource>,
        probe: Arc<ProbeState>,
    ) -> Result<IDataObject> {
        let descriptor = VirtualFileDescriptor::basic(file_name, source.len());
        Self::create_with_descriptor(
            descriptor,
            source,
            probe,
            Arc::<[u8]>::from(&b"ClipFerry\0"[..]),
        )
    }

    pub fn create_with_descriptor(
        descriptor: VirtualFileDescriptor,
        source: Arc<dyn ReadAtSource>,
        probe: Arc<ProbeState>,
        origin_payload: Arc<[u8]>,
    ) -> Result<IDataObject> {
        if descriptor.size != source.len() {
            return Err(Error::from_hresult(
                windows::Win32::Foundation::E_INVALIDARG,
            ));
        }
        let source_factory: Arc<dyn Fn() -> Arc<dyn ReadAtSource> + Send + Sync> =
            Arc::new(move || Arc::clone(&source));
        Self::create_with_source_factory(descriptor, source_factory, probe, origin_payload)
    }

    pub(crate) fn create_with_source_factory(
        descriptor: VirtualFileDescriptor,
        source_factory: Arc<dyn Fn() -> Arc<dyn ReadAtSource> + Send + Sync>,
        probe: Arc<ProbeState>,
        origin_payload: Arc<[u8]>,
    ) -> Result<IDataObject> {
        if origin_payload.is_empty() {
            return Err(Error::from_hresult(
                windows::Win32::Foundation::E_INVALIDARG,
            ));
        }
        validate_virtual_file_name(&descriptor.file_name)?;
        let formats = ClipboardFormats::register()?;
        let object: IDataObject = Self {
            formats,
            descriptor,
            origin_payload,
            source_factory,
            probe,
            async_mode: AtomicBool::new(false),
            in_operation: AtomicBool::new(false),
        }
        .into();
        Ok(object)
    }

    fn validate(&self, format: &FORMATETC) -> HRESULT {
        if !format.ptd.is_null() {
            return DV_E_DVTARGETDEVICE;
        }
        if format.dwAspect != DVASPECT_CONTENT.0 {
            return DV_E_DVASPECT;
        }

        let (expected_index, expected_medium) = if format.cfFormat == self.formats.descriptor
            || format.cfFormat == self.formats.preferred_effect
            || format.cfFormat == self.formats.origin
        {
            (-1, TYMED_HGLOBAL.0.cast_unsigned())
        } else if format.cfFormat == self.formats.contents {
            (0, TYMED_ISTREAM.0.cast_unsigned())
        } else {
            return DV_E_FORMATETC;
        };

        if format.lindex != expected_index {
            return DV_E_LINDEX;
        }
        if format.tymed & expected_medium == 0 {
            return DV_E_TYMED;
        }
        S_OK
    }

    fn medium_for(&self, format: &FORMATETC) -> Result<STGMEDIUM> {
        if format.cfFormat == self.formats.descriptor {
            return self.file_descriptor_medium();
        }
        if format.cfFormat == self.formats.contents {
            let source = (self.source_factory)();
            if source.len() != self.descriptor.size {
                return Err(Error::from_hresult(
                    windows::Win32::Foundation::E_UNEXPECTED,
                ));
            }
            let stream = VirtualStream::create(
                source,
                Arc::clone(&self.descriptor.file_name),
                0,
                Arc::clone(&self.probe),
            );
            return Ok(stream_medium(stream));
        }
        if format.cfFormat == self.formats.preferred_effect {
            return hglobal_medium(&DROPEFFECT_COPY.0.to_ne_bytes());
        }
        if format.cfFormat == self.formats.origin {
            return hglobal_medium(&self.origin_payload);
        }
        Err(Error::from_hresult(DV_E_FORMATETC))
    }

    fn file_descriptor_medium(&self) -> Result<STGMEDIUM> {
        let file_size = self.descriptor.size;
        let file_size_high =
            u32::try_from(file_size >> 32).expect("the high half of a u64 always fits in a u32");
        let file_size_low = u32::try_from(file_size & u64::from(u32::MAX))
            .expect("the low half of a u64 always fits in a u32");
        let mut flags = (FD_ATTRIBUTES.0 | FD_FILESIZE.0 | FD_UNICODE.0).cast_unsigned();
        if self.descriptor.creation_time.is_some() {
            flags |= FD_CREATETIME.0.cast_unsigned();
        }
        if self.descriptor.last_access_time.is_some() {
            flags |= FD_ACCESSTIME.0.cast_unsigned();
        }
        if self.descriptor.last_write_time.is_some() {
            flags |= FD_WRITESTIME.0.cast_unsigned();
        }
        let mut descriptor = FILEDESCRIPTORW {
            dwFlags: flags,
            dwFileAttributes: self.descriptor.attributes,
            nFileSizeHigh: file_size_high,
            nFileSizeLow: file_size_low,
            ftCreationTime: self.descriptor.creation_time.unwrap_or_default(),
            ftLastAccessTime: self.descriptor.last_access_time.unwrap_or_default(),
            ftLastWriteTime: self.descriptor.last_write_time.unwrap_or_default(),
            ..Default::default()
        };
        let mut file_name = [0_u16; 260];
        write_file_name(&mut file_name, &self.descriptor.file_name)?;
        descriptor.cFileName = file_name;
        let group = FILEGROUPDESCRIPTORW {
            cItems: 1,
            fgd: [descriptor],
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const group).cast::<u8>(),
                size_of::<FILEGROUPDESCRIPTORW>(),
            )
        };
        hglobal_medium(bytes)
    }
}

impl IDataObject_Impl for VirtualFileDataObject_Impl {
    fn GetData(&self, format_ptr: *const FORMATETC) -> Result<STGMEDIUM> {
        catch_com_result(|| {
            if format_ptr.is_null() {
                return Err(Error::from_hresult(E_POINTER));
            }
            let format = unsafe { format_ptr.read() };
            self.probe.record(
                "IDataObject::GetData",
                format_args!(
                    "format={} index={} aspect={} tymed={}",
                    format.cfFormat, format.lindex, format.dwAspect, format.tymed
                ),
            );
            let validation = self.validate(&format);
            validation.ok()?;
            self.medium_for(&format)
        })
    }

    fn GetDataHere(&self, format: *const FORMATETC, medium: *mut STGMEDIUM) -> Result<()> {
        catch_com_result(|| {
            if format.is_null() || medium.is_null() {
                return Err(Error::from_hresult(E_POINTER));
            }
            Err(Error::from_hresult(E_NOTIMPL))
        })
    }

    fn QueryGetData(&self, format_ptr: *const FORMATETC) -> HRESULT {
        catch_com_hresult(|| {
            if format_ptr.is_null() {
                return E_POINTER;
            }
            let format = unsafe { format_ptr.read() };
            let result = self.validate(&format);
            self.probe.record(
                "IDataObject::QueryGetData",
                format_args!(
                    "format={} index={} aspect={} tymed={} result={:#010X}",
                    format.cfFormat,
                    format.lindex,
                    format.dwAspect,
                    format.tymed,
                    result.0.cast_unsigned()
                ),
            );
            result
        })
    }

    fn GetCanonicalFormatEtc(&self, input: *const FORMATETC, output: *mut FORMATETC) -> HRESULT {
        catch_com_hresult(|| {
            if input.is_null() || output.is_null() {
                return E_POINTER;
            }
            unsafe { output.write(FORMATETC::default()) };
            DATA_S_SAMEFORMATETC
        })
    }

    fn SetData(
        &self,
        format_ptr: *const FORMATETC,
        medium_ptr: *const STGMEDIUM,
        release: BOOL,
    ) -> Result<()> {
        catch_com_result(|| {
            if format_ptr.is_null() || medium_ptr.is_null() {
                return Err(Error::from_hresult(E_POINTER));
            }
            let format = unsafe { format_ptr.read() };
            if !format.ptd.is_null() {
                return Err(Error::from_hresult(DV_E_DVTARGETDEVICE));
            }
            if !self.formats.is_feedback(format.cfFormat) {
                return Err(Error::from_hresult(DV_E_FORMATETC));
            }
            if format.dwAspect != DVASPECT_CONTENT.0 {
                return Err(Error::from_hresult(DV_E_DVASPECT));
            }
            if format.lindex != -1 {
                return Err(Error::from_hresult(DV_E_LINDEX));
            }
            if format.tymed & TYMED_HGLOBAL.0.cast_unsigned() == 0 {
                return Err(Error::from_hresult(DV_E_TYMED));
            }
            let mut medium = unsafe { medium_ptr.read() };
            if medium.tymed != TYMED_HGLOBAL.0.cast_unsigned() {
                return Err(Error::from_hresult(DV_E_TYMED));
            }
            let global = unsafe { medium.u.hGlobal };
            if global.0.is_null() || unsafe { GlobalSize(global) } < size_of::<u32>() {
                return Err(Error::from_hresult(DV_E_TYMED));
            }
            let locked = unsafe { GlobalLock(global) };
            if locked.is_null() {
                return Err(Error::from_thread());
            }
            let effect = unsafe { locked.cast::<u32>().read_unaligned() };
            let _ = unsafe { GlobalUnlock(global) };
            self.probe.record(
                "IDataObject::SetData",
                format_args!(
                    "format={} effect={} release={}",
                    format.cfFormat,
                    effect,
                    release.as_bool()
                ),
            );
            if release.as_bool() {
                unsafe { ReleaseStgMedium(&raw mut medium) };
            }
            Ok(())
        })
    }

    fn EnumFormatEtc(&self, direction: u32) -> Result<IEnumFORMATETC> {
        catch_com_result(|| {
            self.probe.record(
                "IDataObject::EnumFormatEtc",
                format_args!("direction={direction}"),
            );
            if direction != DATADIR_GET.0.cast_unsigned() {
                return Err(Error::from_hresult(E_NOTIMPL));
            }
            Ok(FormatEnumerator::create(
                self.formats.enumerated(),
                Arc::clone(&self.probe),
            ))
        })
    }

    fn DAdvise(
        &self,
        _format: *const FORMATETC,
        _flags: u32,
        _sink: Ref<IAdviseSink>,
    ) -> Result<u32> {
        catch_com_result(|| Err(Error::from_hresult(OLE_E_ADVISENOTSUPPORTED)))
    }

    fn DUnadvise(&self, _connection: u32) -> Result<()> {
        catch_com_result(|| Err(Error::from_hresult(OLE_E_ADVISENOTSUPPORTED)))
    }

    fn EnumDAdvise(&self) -> Result<IEnumSTATDATA> {
        catch_com_result(|| Err(Error::from_hresult(OLE_E_ADVISENOTSUPPORTED)))
    }
}

impl IDataObjectAsyncCapability_Impl for VirtualFileDataObject_Impl {
    fn SetAsyncMode(&self, async_mode: BOOL) -> Result<()> {
        catch_com_result(|| {
            self.async_mode
                .store(async_mode.as_bool(), Ordering::Release);
            self.probe.record(
                "IDataObjectAsyncCapability::SetAsyncMode",
                format_args!("enabled={}", async_mode.as_bool()),
            );
            Ok(())
        })
    }

    fn GetAsyncMode(&self) -> Result<BOOL> {
        catch_com_result(|| {
            let enabled = self.async_mode.load(Ordering::Acquire);
            self.probe.record(
                "IDataObjectAsyncCapability::GetAsyncMode",
                format_args!("enabled={enabled}"),
            );
            Ok(enabled.into())
        })
    }

    fn StartOperation(&self, _reserved: Ref<IBindCtx>) -> Result<()> {
        catch_com_result(|| {
            self.in_operation.store(true, Ordering::Release);
            self.probe
                .record("IDataObjectAsyncCapability::StartOperation", "started=true");
            Ok(())
        })
    }

    fn InOperation(&self) -> Result<BOOL> {
        catch_com_result(|| {
            let active = self.in_operation.load(Ordering::Acquire);
            self.probe.record(
                "IDataObjectAsyncCapability::InOperation",
                format_args!("active={active}"),
            );
            Ok(active.into())
        })
    }

    fn EndOperation(&self, result: HRESULT, _reserved: Ref<IBindCtx>, effects: u32) -> Result<()> {
        catch_com_result(|| {
            self.in_operation.store(false, Ordering::Release);
            self.probe.record(
                "IDataObjectAsyncCapability::EndOperation",
                format_args!(
                    "result={:#010X} effects={effects}",
                    result.0.cast_unsigned()
                ),
            );
            Ok(())
        })
    }
}

fn write_file_name(destination: &mut [u16; 260], name: &str) -> Result<()> {
    validate_virtual_file_name(name)?;
    let encoded: Vec<u16> = name.encode_utf16().collect();
    destination[..encoded.len()].copy_from_slice(&encoded);
    destination[encoded.len()] = 0;
    Ok(())
}

pub(crate) fn validate_virtual_file_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.contains(['<', '>', ':', '"', '/', '\\', '|', '?', '*'])
        || name.ends_with([' ', '.'])
        || name.chars().any(char::is_control)
        || is_reserved_dos_name(name)
    {
        return Err(Error::from_hresult(DV_E_FORMATETC));
    }
    let encoded: Vec<u16> = name.encode_utf16().collect();
    if encoded.len() >= 260 {
        return Err(Error::from_hresult(DV_E_FORMATETC));
    }
    Ok(())
}

fn is_reserved_dos_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name);
    if stem.eq_ignore_ascii_case("CON")
        || stem.eq_ignore_ascii_case("PRN")
        || stem.eq_ignore_ascii_case("AUX")
        || stem.eq_ignore_ascii_case("NUL")
        || stem.eq_ignore_ascii_case("CLOCK$")
    {
        return true;
    }
    matches!(
        stem.to_ascii_uppercase().as_str(),
        "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

fn hglobal_medium(bytes: &[u8]) -> Result<STGMEDIUM> {
    let allocation_size = bytes.len().max(1);
    let global = unsafe { GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, allocation_size) }?;
    let destination = unsafe { GlobalLock(global) };
    if destination.is_null() {
        let error = Error::from_thread();
        let _ = unsafe { GlobalFree(Some(global)) };
        return Err(error);
    }
    if !bytes.is_empty() {
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), destination.cast::<u8>(), bytes.len()) };
    }
    let _ = unsafe { GlobalUnlock(global) };

    Ok(STGMEDIUM {
        tymed: TYMED_HGLOBAL.0.cast_unsigned(),
        u: STGMEDIUM_0 { hGlobal: global },
        pUnkForRelease: ManuallyDrop::new(None),
    })
}

fn stream_medium(stream: IStream) -> STGMEDIUM {
    STGMEDIUM {
        tymed: TYMED_ISTREAM.0.cast_unsigned(),
        u: STGMEDIUM_0 {
            pstm: ManuallyDrop::new(Some(stream)),
        },
        pUnkForRelease: ManuallyDrop::new(None),
    }
}

#[cfg(test)]
#[allow(clippy::borrow_as_ptr)]
mod tests {
    use std::ffi::c_void;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use windows::Win32::Foundation::{
        DV_E_DVASPECT, DV_E_DVTARGETDEVICE, DV_E_FORMATETC, DV_E_LINDEX, DV_E_TYMED, E_POINTER,
        FILETIME, S_FALSE, S_OK,
    };
    use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
    use windows::Win32::System::Com::{
        DATADIR_GET, FORMATETC, IBindCtx, IStream, TYMED_HGLOBAL, TYMED_ISTREAM,
    };
    use windows::Win32::System::Memory::{GlobalLock, GlobalUnlock};
    use windows::Win32::System::Ole::ReleaseStgMedium;
    use windows::Win32::UI::Shell::{
        FD_ACCESSTIME, FD_ATTRIBUTES, FD_CREATETIME, FD_FILESIZE, FD_UNICODE, FD_WRITESTIME,
        FILEDESCRIPTORW, FILEGROUPDESCRIPTORW, IDataObjectAsyncCapability,
    };
    use windows::core::Interface;

    use super::{
        ClipboardFormats, VirtualFileDataObject, VirtualFileDescriptor, format_etc, write_file_name,
    };
    use crate::clipboard::probe::ProbeState;
    use crate::clipboard::source::{MemorySource, ReadAtSource};

    struct DropTrackedSource {
        drops: Arc<AtomicUsize>,
    }

    impl Drop for DropTrackedSource {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl ReadAtSource for DropTrackedSource {
        fn len(&self) -> u64 {
            1
        }

        fn read_at(&self, offset: u64, destination: &mut [u8]) -> windows::core::Result<usize> {
            if offset != 0 || destination.is_empty() {
                return Ok(0);
            }
            destination[0] = b'x';
            Ok(1)
        }
    }

    fn object() -> (
        windows::Win32::System::Com::IDataObject,
        Arc<ProbeState>,
        ClipboardFormats,
    ) {
        let probe = Arc::new(ProbeState::default());
        let object = VirtualFileDataObject::create(
            Arc::<str>::from("test.txt"),
            Arc::new(MemorySource::new(&b"hello"[..])),
            Arc::clone(&probe),
        )
        .unwrap();
        let formats = ClipboardFormats::register().unwrap();
        (object, probe, formats)
    }

    #[test]
    fn content_is_deferred_until_stream_read() {
        let (object, probe, formats) = object();
        let descriptor = format_etc(formats.descriptor, -1, TYMED_HGLOBAL.0.cast_unsigned());
        let mut descriptor_medium = unsafe { object.GetData(&descriptor) }.unwrap();
        assert_eq!(probe.read_calls(), 0);
        unsafe { ReleaseStgMedium(&mut descriptor_medium) };

        let contents = format_etc(formats.contents, 0, TYMED_ISTREAM.0.cast_unsigned());
        let mut contents_medium = unsafe { object.GetData(&contents) }.unwrap();
        assert_eq!(probe.read_calls(), 0);
        let stream: IStream = unsafe {
            let stream = &*contents_medium.u.pstm;
            stream.as_ref().unwrap().clone()
        };
        let mut bytes = [0_u8; 5];
        let mut read = 0;
        assert_eq!(
            unsafe { stream.Read(bytes.as_mut_ptr().cast::<c_void>(), 5, Some(&mut read)) },
            S_OK
        );
        assert_eq!(&bytes, b"hello");
        assert_eq!(probe.read_calls(), 1);
        unsafe { ReleaseStgMedium(&mut contents_medium) };
    }

    #[test]
    fn query_get_data_checks_index_and_medium() {
        let (object, _, formats) = object();
        let valid = format_etc(formats.contents, 0, TYMED_ISTREAM.0.cast_unsigned());
        assert_eq!(unsafe { object.QueryGetData(&valid) }, S_OK);

        let invalid_index = format_etc(formats.contents, 1, TYMED_ISTREAM.0.cast_unsigned());
        assert_eq!(unsafe { object.QueryGetData(&invalid_index) }, DV_E_LINDEX);

        let mut invalid_device = valid;
        invalid_device.ptd = std::ptr::dangling_mut();
        assert_eq!(
            unsafe { object.QueryGetData(&invalid_device) },
            DV_E_DVTARGETDEVICE
        );

        let mut invalid_aspect = valid;
        invalid_aspect.dwAspect = 0;
        assert_eq!(
            unsafe { object.QueryGetData(&invalid_aspect) },
            DV_E_DVASPECT
        );

        let invalid_medium = format_etc(formats.contents, 0, TYMED_HGLOBAL.0.cast_unsigned());
        assert_eq!(unsafe { object.QueryGetData(&invalid_medium) }, DV_E_TYMED);

        let unknown_format = format_etc(1, -1, TYMED_HGLOBAL.0.cast_unsigned());
        assert_eq!(
            unsafe { object.QueryGetData(&unknown_format) },
            DV_E_FORMATETC
        );
    }

    #[test]
    fn null_format_pointers_are_rejected_by_the_com_vtable() {
        let (object, _, _) = object();
        let vtable = Interface::vtable(&object);
        let raw = Interface::as_raw(&object);
        let mut output = FORMATETC::default();

        assert_eq!(
            unsafe { (vtable.QueryGetData)(raw, std::ptr::null()) },
            E_POINTER
        );
        assert_eq!(
            unsafe { (vtable.GetCanonicalFormatEtc)(raw, std::ptr::null(), &raw mut output) },
            E_POINTER
        );
    }

    #[test]
    fn file_descriptor_hglobal_has_the_expected_name_size_and_flags() {
        let (object, _, formats) = object();
        let format = format_etc(formats.descriptor, -1, TYMED_HGLOBAL.0.cast_unsigned());
        let mut medium = unsafe { object.GetData(&format) }.unwrap();
        let global = unsafe { medium.u.hGlobal };
        let locked = unsafe { GlobalLock(global) };
        assert!(!locked.is_null());

        let group = locked.cast::<FILEGROUPDESCRIPTORW>();
        let item_count = unsafe { std::ptr::addr_of!((*group).cItems).read_unaligned() };
        assert_eq!(item_count, 1);
        let descriptor = unsafe {
            std::ptr::addr_of!((*group).fgd)
                .cast::<FILEDESCRIPTORW>()
                .read_unaligned()
        };
        let flags = unsafe { std::ptr::addr_of!(descriptor.dwFlags).read_unaligned() };
        let size_high = unsafe { std::ptr::addr_of!(descriptor.nFileSizeHigh).read_unaligned() };
        let size_low = unsafe { std::ptr::addr_of!(descriptor.nFileSizeLow).read_unaligned() };
        let file_name = unsafe { std::ptr::addr_of!(descriptor.cFileName).read_unaligned() };
        assert_ne!(flags & FD_ATTRIBUTES.0.cast_unsigned(), 0);
        assert_ne!(flags & FD_FILESIZE.0.cast_unsigned(), 0);
        assert_ne!(flags & FD_UNICODE.0.cast_unsigned(), 0);
        assert_eq!(size_high, 0);
        assert_eq!(size_low, 5);
        let name_length = file_name
            .iter()
            .position(|character| *character == 0)
            .unwrap();
        assert_eq!(
            String::from_utf16(&file_name[..name_length]).unwrap(),
            "test.txt"
        );

        let _ = unsafe { GlobalUnlock(global) };
        unsafe { ReleaseStgMedium(&mut medium) };
    }

    #[test]
    fn captured_descriptor_preserves_times_and_private_offer_identity() {
        let probe = Arc::new(ProbeState::default());
        let source: Arc<dyn ReadAtSource> = Arc::new(MemorySource::new(&b"captured"[..]));
        let creation = FILETIME {
            dwLowDateTime: 11,
            dwHighDateTime: 12,
        };
        let access = FILETIME {
            dwLowDateTime: 21,
            dwHighDateTime: 22,
        };
        let write = FILETIME {
            dwLowDateTime: 31,
            dwHighDateTime: 32,
        };
        let object = VirtualFileDataObject::create_with_descriptor(
            VirtualFileDescriptor {
                file_name: Arc::<str>::from("captured.bin"),
                size: 8,
                attributes: FILE_ATTRIBUTE_NORMAL.0,
                creation_time: Some(creation),
                last_access_time: Some(access),
                last_write_time: Some(write),
            },
            source,
            probe,
            Arc::<[u8]>::from(&b"private-offer-123"[..]),
        )
        .unwrap();
        let formats = ClipboardFormats::register().unwrap();
        let descriptor_format = format_etc(formats.descriptor, -1, TYMED_HGLOBAL.0.cast_unsigned());
        let mut descriptor_medium = unsafe { object.GetData(&descriptor_format) }.unwrap();
        let descriptor_global = unsafe { descriptor_medium.u.hGlobal };
        let locked = unsafe { GlobalLock(descriptor_global) };
        let descriptor = unsafe {
            std::ptr::addr_of!((*locked.cast::<FILEGROUPDESCRIPTORW>()).fgd)
                .cast::<FILEDESCRIPTORW>()
                .read_unaligned()
        };
        let flags = descriptor.dwFlags;
        assert_ne!(flags & FD_CREATETIME.0.cast_unsigned(), 0);
        assert_ne!(flags & FD_ACCESSTIME.0.cast_unsigned(), 0);
        assert_ne!(flags & FD_WRITESTIME.0.cast_unsigned(), 0);
        let actual_creation =
            unsafe { std::ptr::addr_of!(descriptor.ftCreationTime).read_unaligned() };
        let actual_access =
            unsafe { std::ptr::addr_of!(descriptor.ftLastAccessTime).read_unaligned() };
        let actual_write =
            unsafe { std::ptr::addr_of!(descriptor.ftLastWriteTime).read_unaligned() };
        assert_eq!(actual_creation, creation);
        assert_eq!(actual_access, access);
        assert_eq!(actual_write, write);
        let _ = unsafe { GlobalUnlock(descriptor_global) };
        unsafe { ReleaseStgMedium(&mut descriptor_medium) };

        let origin_format = format_etc(formats.origin, -1, TYMED_HGLOBAL.0.cast_unsigned());
        let mut origin_medium = unsafe { object.GetData(&origin_format) }.unwrap();
        let origin_global = unsafe { origin_medium.u.hGlobal };
        let locked = unsafe { GlobalLock(origin_global) };
        let payload = unsafe { std::slice::from_raw_parts(locked.cast::<u8>(), 17) };
        assert_eq!(payload, b"private-offer-123");
        let _ = unsafe { GlobalUnlock(origin_global) };
        unsafe { ReleaseStgMedium(&mut origin_medium) };
    }

    #[test]
    fn preferred_drop_effect_hglobal_requests_a_copy() {
        let (object, _, formats) = object();
        let format = format_etc(
            formats.preferred_effect,
            -1,
            TYMED_HGLOBAL.0.cast_unsigned(),
        );
        let mut medium = unsafe { object.GetData(&format) }.unwrap();
        let global = unsafe { medium.u.hGlobal };
        let locked = unsafe { GlobalLock(global) };
        assert!(!locked.is_null());
        assert_eq!(unsafe { locked.cast::<u32>().read_unaligned() }, 1);

        let _ = unsafe { GlobalUnlock(global) };
        unsafe { ReleaseStgMedium(&mut medium) };
    }

    #[test]
    fn shell_feedback_set_data_accepts_hglobal_without_taking_unrequested_ownership() {
        let (object, probe, formats) = object();
        let format = format_etc(
            formats.performed_effect,
            -1,
            TYMED_HGLOBAL.0.cast_unsigned(),
        );
        let mut medium = super::hglobal_medium(&1_u32.to_ne_bytes()).unwrap();

        unsafe { object.SetData(&raw const format, &raw const medium, false) }.unwrap();
        let global = unsafe { medium.u.hGlobal };
        assert!(unsafe { windows::Win32::System::Memory::GlobalSize(global) } >= 4);
        assert!(
            probe
                .events()
                .iter()
                .any(|event| event.contains("IDataObject::SetData") && event.contains("effect=1"))
        );

        unsafe { ReleaseStgMedium(&mut medium) };
    }

    #[test]
    fn rejected_set_data_leaves_release_true_medium_owned_by_the_caller() {
        let (object, _, _) = object();
        let format = format_etc(1, -1, TYMED_HGLOBAL.0.cast_unsigned());
        let mut medium = super::hglobal_medium(&1_u32.to_ne_bytes()).unwrap();

        let error =
            unsafe { object.SetData(&raw const format, &raw const medium, true) }.unwrap_err();
        assert_eq!(error.code(), DV_E_FORMATETC);
        let global = unsafe { medium.u.hGlobal };
        assert!(unsafe { windows::Win32::System::Memory::GlobalSize(global) } >= 4);

        unsafe { ReleaseStgMedium(&mut medium) };
    }

    #[test]
    fn async_capability_tracks_operation_lifecycle() {
        let (object, _, _) = object();
        let capability: IDataObjectAsyncCapability = object.cast().unwrap();

        assert!(!unsafe { capability.GetAsyncMode() }.unwrap().as_bool());
        unsafe { capability.SetAsyncMode(true) }.unwrap();
        assert!(unsafe { capability.GetAsyncMode() }.unwrap().as_bool());
        assert!(!unsafe { capability.InOperation() }.unwrap().as_bool());
        unsafe { capability.StartOperation(None::<&IBindCtx>) }.unwrap();
        assert!(unsafe { capability.InOperation() }.unwrap().as_bool());
        unsafe { capability.EndOperation(S_OK, None::<&IBindCtx>, 1) }.unwrap();
        assert!(!unsafe { capability.InOperation() }.unwrap().as_bool());
    }

    #[test]
    fn stream_medium_keeps_the_source_alive_until_release() {
        let drops = Arc::new(AtomicUsize::new(0));
        let object = VirtualFileDataObject::create(
            Arc::<str>::from("owned.txt"),
            Arc::new(DropTrackedSource {
                drops: Arc::clone(&drops),
            }),
            Arc::new(ProbeState::default()),
        )
        .unwrap();
        let formats = ClipboardFormats::register().unwrap();
        let contents = format_etc(formats.contents, 0, TYMED_ISTREAM.0.cast_unsigned());
        let mut medium = unsafe { object.GetData(&contents) }.unwrap();

        drop(object);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        unsafe { ReleaseStgMedium(&mut medium) };
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn independently_opened_streams_have_independent_positions() {
        let (object, _, formats) = object();
        let contents = format_etc(formats.contents, 0, TYMED_ISTREAM.0.cast_unsigned());
        let mut first_medium = unsafe { object.GetData(&contents) }.unwrap();
        let mut second_medium = unsafe { object.GetData(&contents) }.unwrap();
        let first_stream = unsafe { (*first_medium.u.pstm).as_ref().unwrap().clone() };
        let second_stream = unsafe { (*second_medium.u.pstm).as_ref().unwrap().clone() };

        let mut first_bytes = [0_u8; 5];
        let mut second_bytes = [0_u8; 5];
        let mut read = 0;
        assert_eq!(
            unsafe { first_stream.Read(first_bytes.as_mut_ptr().cast(), 2, Some(&mut read)) },
            S_OK
        );
        assert_eq!(read, 2);
        assert_eq!(
            unsafe { second_stream.Read(second_bytes.as_mut_ptr().cast(), 5, Some(&mut read)) },
            S_OK
        );
        assert_eq!(read, 5);
        assert_eq!(
            unsafe { first_stream.Read(first_bytes[2..].as_mut_ptr().cast(), 3, Some(&mut read)) },
            S_OK
        );
        assert_eq!(&first_bytes, b"hello");
        assert_eq!(&second_bytes, b"hello");

        unsafe { ReleaseStgMedium(&mut first_medium) };
        unsafe { ReleaseStgMedium(&mut second_medium) };
    }

    #[test]
    fn file_names_reject_paths_controls_trailing_dots_and_truncation() {
        let mut destination = [0_u16; 260];
        assert!(write_file_name(&mut destination, "valid name.txt").is_ok());
        for invalid in [
            "",
            "..\\escape.txt",
            "nested/file.txt",
            "bad.",
            "bad ",
            "bad\n",
            "name:stream.bin",
            "wild*.bin",
            "question?.bin",
            "CON",
            "nul.txt",
            "Com1.log",
            "LPT9",
        ] {
            assert!(
                write_file_name(&mut destination, invalid).is_err(),
                "{invalid:?}"
            );
        }
        assert!(write_file_name(&mut destination, &"x".repeat(260)).is_err());
    }

    #[test]
    fn standard_format_enumerator_supports_clone_and_reset() {
        let (object, _, _) = object();
        let enumerator = unsafe { object.EnumFormatEtc(DATADIR_GET.0.cast_unsigned()) }.unwrap();
        let mut first = FORMATETC::default();
        let mut fetched = 0;
        assert_eq!(
            unsafe { enumerator.Next(std::slice::from_mut(&mut first), Some(&mut fetched)) },
            S_OK
        );
        assert_eq!(fetched, 1);

        let clone = unsafe { enumerator.Clone() }.unwrap();
        let mut from_original = FORMATETC::default();
        let mut from_clone = FORMATETC::default();
        assert_eq!(
            unsafe {
                enumerator.Next(std::slice::from_mut(&mut from_original), Some(&mut fetched))
            },
            S_OK
        );
        assert_eq!(
            unsafe { clone.Next(std::slice::from_mut(&mut from_clone), Some(&mut fetched)) },
            S_OK
        );
        assert_eq!(from_original.cfFormat, from_clone.cfFormat);

        unsafe { enumerator.Reset() }.unwrap();
        let mut all = [FORMATETC::default(); 5];
        assert_eq!(
            unsafe { enumerator.Next(&mut all, Some(&mut fetched)) },
            S_FALSE
        );
        assert_eq!(fetched, 4);
    }
}
