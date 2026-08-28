#![allow(clippy::inline_always, clippy::ref_as_ptr)]

use std::ffi::c_void;
use std::ptr;
use std::sync::{Arc, Mutex};

use windows::Win32::Foundation::{
    E_NOTIMPL, E_OUTOFMEMORY, E_POINTER, E_UNEXPECTED, S_FALSE, S_OK, STG_E_ACCESSDENIED,
    STG_E_INVALIDFUNCTION, STG_E_INVALIDPOINTER,
};
use windows::Win32::System::Com::{
    CoTaskMemAlloc, ISequentialStream_Impl, IStream, IStream_Impl, LOCKTYPE, STATFLAG,
    STATFLAG_DEFAULT, STATFLAG_NONAME, STATFLAG_NOOPEN, STATSTG, STGC, STGM_READ, STGTY_STREAM,
    STREAM_SEEK, STREAM_SEEK_CUR, STREAM_SEEK_END, STREAM_SEEK_SET,
};
use windows::core::{Error, HRESULT, PWSTR, Ref, Result, implement};

use super::probe::ProbeState;
use super::source::ReadAtSource;
use super::{catch_com_hresult, catch_com_result};

#[implement(IStream)]
pub struct VirtualStream {
    source: Arc<dyn ReadAtSource>,
    name: Arc<str>,
    position: Mutex<u64>,
    probe: Arc<ProbeState>,
}

impl VirtualStream {
    pub fn create(
        source: Arc<dyn ReadAtSource>,
        name: Arc<str>,
        position: u64,
        probe: Arc<ProbeState>,
    ) -> IStream {
        Self {
            source,
            name,
            position: Mutex::new(position),
            probe,
        }
        .into()
    }

    fn read_impl(&self, destination: *mut c_void, requested: u32) -> Result<usize> {
        if requested != 0 && destination.is_null() {
            return Err(Error::from_hresult(STG_E_INVALIDPOINTER));
        }

        let mut position = self
            .position
            .lock()
            .map_err(|_| Error::from_hresult(E_UNEXPECTED))?;
        let requested =
            usize::try_from(requested).map_err(|_| Error::from_hresult(STG_E_INVALIDFUNCTION))?;
        self.probe.note_read(*position, requested);

        let destination = if requested == 0 {
            &mut []
        } else {
            unsafe { std::slice::from_raw_parts_mut(destination.cast::<u8>(), requested) }
        };
        let mut read = 0_usize;
        while read < requested {
            let offset = position
                .checked_add(u64::try_from(read).map_err(|_| Error::from_hresult(E_UNEXPECTED))?)
                .ok_or_else(|| Error::from_hresult(STG_E_INVALIDFUNCTION))?;
            let chunk = self.source.read_at(offset, &mut destination[read..])?;
            if chunk > requested - read {
                return Err(Error::from_hresult(E_UNEXPECTED));
            }
            if chunk == 0 {
                break;
            }
            read += chunk;
        }
        *position = position
            .checked_add(u64::try_from(read).map_err(|_| Error::from_hresult(E_UNEXPECTED))?)
            .ok_or_else(|| Error::from_hresult(STG_E_INVALIDFUNCTION))?;
        Ok(read)
    }

    fn seek_impl(&self, displacement: i64, origin: STREAM_SEEK) -> Result<u64> {
        let mut position = self
            .position
            .lock()
            .map_err(|_| Error::from_hresult(E_UNEXPECTED))?;
        let base = match origin {
            STREAM_SEEK_SET => 0_i128,
            STREAM_SEEK_CUR => i128::from(*position),
            STREAM_SEEK_END => i128::from(self.source.len()),
            _ => return Err(Error::from_hresult(STG_E_INVALIDFUNCTION)),
        };
        let next = base + i128::from(displacement);
        let next = u64::try_from(next).map_err(|_| Error::from_hresult(STG_E_INVALIDFUNCTION))?;
        *position = next;
        Ok(next)
    }

    fn allocate_name(&self) -> Result<PWSTR> {
        let wide: Vec<u16> = self.name.encode_utf16().chain(std::iter::once(0)).collect();
        let byte_len = wide
            .len()
            .checked_mul(size_of::<u16>())
            .ok_or_else(|| Error::from_hresult(E_OUTOFMEMORY))?;
        let allocated = unsafe { CoTaskMemAlloc(byte_len) }.cast::<u16>();
        if allocated.is_null() {
            return Err(Error::from_hresult(E_OUTOFMEMORY));
        }
        unsafe { ptr::copy_nonoverlapping(wide.as_ptr(), allocated, wide.len()) };
        Ok(PWSTR(allocated))
    }
}

impl ISequentialStream_Impl for VirtualStream_Impl {
    fn Read(&self, destination: *mut c_void, requested: u32, read_out: *mut u32) -> HRESULT {
        catch_com_hresult(|| {
            if !read_out.is_null() {
                unsafe { read_out.write(0) };
            }
            match self.read_impl(destination, requested) {
                Ok(read) => {
                    let read = u32::try_from(read).unwrap_or(requested);
                    if !read_out.is_null() {
                        unsafe { read_out.write(read) };
                    }
                    if read == requested { S_OK } else { S_FALSE }
                }
                Err(error) => error.code(),
            }
        })
    }

    fn Write(&self, _source: *const c_void, _requested: u32, written_out: *mut u32) -> HRESULT {
        catch_com_hresult(|| {
            self.probe.record("IStream::Write", "rejected=read-only");
            if !written_out.is_null() {
                unsafe { written_out.write(0) };
            }
            STG_E_ACCESSDENIED
        })
    }
}

impl IStream_Impl for VirtualStream_Impl {
    fn Seek(
        &self,
        displacement: i64,
        origin: STREAM_SEEK,
        new_position_out: *mut u64,
    ) -> Result<()> {
        catch_com_result(|| {
            let position = self.seek_impl(displacement, origin)?;
            self.probe.record(
                "IStream::Seek",
                format_args!(
                    "displacement={displacement} origin={} position={position}",
                    origin.0
                ),
            );
            if !new_position_out.is_null() {
                unsafe { new_position_out.write(position) };
            }
            Ok(())
        })
    }

    fn SetSize(&self, _new_size: u64) -> Result<()> {
        catch_com_result(|| {
            self.probe.record("IStream::SetSize", "rejected=read-only");
            Err(Error::from_hresult(STG_E_ACCESSDENIED))
        })
    }

    fn CopyTo(
        &self,
        _target: Ref<IStream>,
        _requested: u64,
        read_out: *mut u64,
        written_out: *mut u64,
    ) -> Result<()> {
        catch_com_result(|| {
            if !read_out.is_null() {
                unsafe { read_out.write(0) };
            }
            if !written_out.is_null() {
                unsafe { written_out.write(0) };
            }
            self.probe.record(
                "IStream::CopyTo",
                "unsupported; caller must use IStream::Read",
            );
            Err(Error::from_hresult(E_NOTIMPL))
        })
    }

    fn Commit(&self, _flags: &STGC) -> Result<()> {
        catch_com_result(|| {
            self.probe.record("IStream::Commit", "read-only no-op");
            Ok(())
        })
    }

    fn Revert(&self) -> Result<()> {
        catch_com_result(|| Err(Error::from_hresult(E_NOTIMPL)))
    }

    fn LockRegion(&self, _offset: u64, _length: u64, _lock_type: &LOCKTYPE) -> Result<()> {
        catch_com_result(|| Err(Error::from_hresult(STG_E_INVALIDFUNCTION)))
    }

    fn UnlockRegion(&self, _offset: u64, _length: u64, _lock_type: u32) -> Result<()> {
        catch_com_result(|| Err(Error::from_hresult(STG_E_INVALIDFUNCTION)))
    }

    fn Stat(&self, stat_out: *mut STATSTG, flag: &STATFLAG) -> Result<()> {
        catch_com_result(|| {
            if stat_out.is_null() {
                return Err(Error::from_hresult(E_POINTER));
            }
            if *flag != STATFLAG_DEFAULT && *flag != STATFLAG_NONAME && *flag != STATFLAG_NOOPEN {
                return Err(Error::from_hresult(STG_E_INVALIDFUNCTION));
            }

            let mut stat = STATSTG {
                r#type: STGTY_STREAM.0.cast_unsigned(),
                cbSize: self.source.len(),
                grfMode: STGM_READ,
                ..Default::default()
            };
            if *flag != STATFLAG_NONAME {
                stat.pwcsName = self.allocate_name()?;
            }
            unsafe { stat_out.write(stat) };
            self.probe.record(
                "IStream::Stat",
                format_args!("size={} flag={}", self.source.len(), flag.0),
            );
            Ok(())
        })
    }

    fn Clone(&self) -> Result<IStream> {
        catch_com_result(|| {
            let position = *self
                .position
                .lock()
                .map_err(|_| Error::from_hresult(E_UNEXPECTED))?;
            self.probe
                .record("IStream::Clone", format_args!("position={position}"));
            Ok(VirtualStream::create(
                Arc::clone(&self.source),
                Arc::clone(&self.name),
                position,
                Arc::clone(&self.probe),
            ))
        })
    }
}

#[cfg(test)]
#[allow(clippy::borrow_as_ptr)]
mod tests {
    use std::ffi::c_void;
    use std::sync::{Arc, Barrier, Mutex};

    use windows::Win32::Foundation::{
        E_NOTIMPL, E_UNEXPECTED, S_FALSE, S_OK, STG_E_ACCESSDENIED, STG_E_INVALIDFUNCTION,
    };
    use windows::Win32::System::Com::{
        CoTaskMemFree, STATFLAG_NONAME, STATSTG, STREAM_SEEK_CUR, STREAM_SEEK_END, STREAM_SEEK_SET,
    };

    use super::VirtualStream;
    use crate::clipboard::probe::ProbeState;
    use crate::clipboard::source::{MemorySource, ReadAtSource};

    struct ShortReadSource;

    impl ReadAtSource for ShortReadSource {
        fn len(&self) -> u64 {
            6
        }

        fn read_at(&self, offset: u64, destination: &mut [u8]) -> windows::core::Result<usize> {
            let bytes = b"abcdef";
            let Ok(offset) = usize::try_from(offset) else {
                return Ok(0);
            };
            if offset >= bytes.len() {
                return Ok(0);
            }
            let copied = (bytes.len() - offset).min(destination.len()).min(2);
            destination[..copied].copy_from_slice(&bytes[offset..offset + copied]);
            Ok(copied)
        }
    }

    struct PanicSource;

    impl ReadAtSource for PanicSource {
        fn len(&self) -> u64 {
            1
        }

        fn read_at(&self, _offset: u64, _destination: &mut [u8]) -> windows::core::Result<usize> {
            panic!("fault injection: source read panic")
        }
    }

    struct BarrierSource {
        barrier: Barrier,
    }

    impl ReadAtSource for BarrierSource {
        fn len(&self) -> u64 {
            6
        }

        fn read_at(&self, offset: u64, destination: &mut [u8]) -> windows::core::Result<usize> {
            self.barrier.wait();
            let bytes = b"abcdef";
            let offset = usize::try_from(offset).unwrap();
            let copied = (bytes.len() - offset).min(destination.len());
            destination[..copied].copy_from_slice(&bytes[offset..offset + copied]);
            Ok(copied)
        }
    }

    fn stream() -> (windows::Win32::System::Com::IStream, Arc<ProbeState>) {
        let probe = Arc::new(ProbeState::default());
        let stream = VirtualStream::create(
            Arc::new(MemorySource::new(&b"abcdef"[..])),
            Arc::<str>::from("test.txt"),
            0,
            Arc::clone(&probe),
        );
        (stream, probe)
    }

    #[test]
    fn read_seek_stat_and_eof_follow_istream_contract() {
        let (stream, probe) = stream();
        let mut buffer = [0_u8; 4];
        let mut read = 0;
        let first =
            unsafe { stream.Read(buffer.as_mut_ptr().cast::<c_void>(), 4, Some(&mut read)) };
        assert_eq!(first, S_OK);
        assert_eq!(read, 4);
        assert_eq!(&buffer, b"abcd");

        let mut position = 0;
        unsafe { stream.Seek(-2, STREAM_SEEK_CUR, Some(&mut position)) }.unwrap();
        assert_eq!(position, 2);
        unsafe { stream.Seek(-1, STREAM_SEEK_END, Some(&mut position)) }.unwrap();
        assert_eq!(position, 5);

        let short =
            unsafe { stream.Read(buffer.as_mut_ptr().cast::<c_void>(), 4, Some(&mut read)) };
        assert_eq!(short, S_FALSE);
        assert_eq!(read, 1);
        assert_eq!(buffer[0], b'f');

        let mut stat = STATSTG::default();
        unsafe { stream.Stat(&mut stat, STATFLAG_NONAME) }.unwrap();
        assert_eq!(stat.cbSize, 6);
        assert!(stat.pwcsName.is_null());
        assert_eq!(probe.read_calls(), 2);
    }

    #[test]
    fn clones_have_independent_positions() {
        let (stream, _) = stream();
        unsafe { stream.Seek(3, STREAM_SEEK_SET, None) }.unwrap();
        let clone = unsafe { stream.Clone() }.unwrap();
        unsafe { stream.Seek(1, STREAM_SEEK_SET, None) }.unwrap();

        let mut original_byte = 0_u8;
        let mut clone_byte = 0_u8;
        assert_eq!(
            unsafe { stream.Read((&raw mut original_byte).cast(), 1, None) },
            S_OK
        );
        assert_eq!(
            unsafe { clone.Read((&raw mut clone_byte).cast(), 1, None) },
            S_OK
        );
        assert_eq!(original_byte, b'b');
        assert_eq!(clone_byte, b'd');
    }

    #[test]
    fn invalid_pointers_and_writes_are_rejected() {
        let (stream, _) = stream();
        let read = unsafe { stream.Read(std::ptr::null_mut(), 1, None) };
        assert!(read.is_err());

        let mut zero_read = 99;
        assert_eq!(
            unsafe { stream.Read(std::ptr::null_mut(), 0, Some(&mut zero_read)) },
            S_OK
        );
        assert_eq!(zero_read, 0);

        let mut written = 99;
        let write = unsafe { stream.Write(std::ptr::null(), 1, Some(&mut written)) };
        assert_eq!(write, STG_E_ACCESSDENIED);
        assert_eq!(written, 0);
    }

    #[test]
    fn stat_allocates_a_cotaskmem_name_when_requested() {
        let (stream, _) = stream();
        let mut stat = STATSTG::default();
        unsafe { stream.Stat(&mut stat, windows::Win32::System::Com::STATFLAG::default()) }
            .unwrap();
        assert!(!stat.pwcsName.is_null());
        unsafe { CoTaskMemFree(Some(stat.pwcsName.0.cast())) };
    }

    #[test]
    fn a_single_com_read_aggregates_network_style_short_reads() {
        let probe = Arc::new(ProbeState::default());
        let stream = VirtualStream::create(
            Arc::new(ShortReadSource),
            Arc::<str>::from("short-read.txt"),
            0,
            Arc::clone(&probe),
        );
        let mut bytes = [0_u8; 6];
        let mut read = 0;

        assert_eq!(
            unsafe { stream.Read(bytes.as_mut_ptr().cast(), 6, Some(&mut read)) },
            S_OK
        );
        assert_eq!(read, 6);
        assert_eq!(&bytes, b"abcdef");
        assert_eq!(probe.read_calls(), 1);
    }

    #[test]
    fn source_panics_are_contained_at_the_com_boundary() {
        let stream = VirtualStream::create(
            Arc::new(PanicSource),
            Arc::<str>::from("panic.txt"),
            0,
            Arc::new(ProbeState::default()),
        );
        let mut byte = 0_u8;

        assert_eq!(
            unsafe { stream.Read((&raw mut byte).cast(), 1, None) },
            E_UNEXPECTED
        );
    }

    #[test]
    fn seek_rejects_negative_positions_but_allows_positions_past_eof() {
        let (stream, _) = stream();
        let error = unsafe { stream.Seek(-1, STREAM_SEEK_SET, None) }.unwrap_err();
        assert_eq!(error.code(), STG_E_INVALIDFUNCTION);

        let mut position = 0;
        unsafe { stream.Seek(64, STREAM_SEEK_SET, Some(&mut position)) }.unwrap();
        assert_eq!(position, 64);

        let mut byte = 0_u8;
        let mut read = 99;
        assert_eq!(
            unsafe { stream.Read((&raw mut byte).cast(), 1, Some(&mut read)) },
            S_FALSE
        );
        assert_eq!(read, 0);
    }

    #[test]
    fn unsupported_copy_to_initializes_output_counts() {
        let (stream, _) = stream();
        let mut read = 99;
        let mut written = 99;
        let error =
            unsafe { stream.CopyTo(&stream, 3, Some(&mut read), Some(&mut written)) }.unwrap_err();

        assert_eq!(error.code(), E_NOTIMPL);
        assert_eq!(read, 0);
        assert_eq!(written, 0);
    }

    #[test]
    fn independent_stream_implementations_read_a_shared_source_concurrently() {
        let source: Arc<dyn ReadAtSource> = Arc::new(BarrierSource {
            barrier: Barrier::new(2),
        });
        let create = || {
            Arc::new(VirtualStream {
                source: Arc::clone(&source),
                name: Arc::<str>::from("concurrent.txt"),
                position: Mutex::new(0),
                probe: Arc::new(ProbeState::default()),
            })
        };
        let first = create();
        let second = create();
        let read = |stream: Arc<VirtualStream>| {
            let mut bytes = [0_u8; 6];
            assert_eq!(
                stream
                    .read_impl(bytes.as_mut_ptr().cast::<c_void>(), 6)
                    .unwrap(),
                6
            );
            bytes
        };

        let first_thread = std::thread::spawn(move || read(first));
        let second_thread = std::thread::spawn(move || read(second));
        assert_eq!(first_thread.join().unwrap(), *b"abcdef");
        assert_eq!(second_thread.join().unwrap(), *b"abcdef");
    }
}
