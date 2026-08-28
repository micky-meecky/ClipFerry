#![allow(clippy::inline_always, clippy::ref_as_ptr)]

use std::sync::{Arc, Mutex};

use windows::Win32::Foundation::{E_POINTER, E_UNEXPECTED, S_FALSE, S_OK};
use windows::Win32::System::Com::{FORMATETC, IEnumFORMATETC, IEnumFORMATETC_Impl};
use windows::core::{Error, HRESULT, Result, implement};

use super::probe::ProbeState;
use super::{catch_com_hresult, catch_com_result};

#[implement(IEnumFORMATETC)]
pub struct FormatEnumerator {
    formats: Arc<[FORMATETC]>,
    position: Mutex<usize>,
    probe: Arc<ProbeState>,
}

impl FormatEnumerator {
    pub fn create(formats: impl Into<Arc<[FORMATETC]>>, probe: Arc<ProbeState>) -> IEnumFORMATETC {
        Self::create_at(formats.into(), 0, probe)
    }

    fn create_at(
        formats: Arc<[FORMATETC]>,
        position: usize,
        probe: Arc<ProbeState>,
    ) -> IEnumFORMATETC {
        Self {
            formats,
            position: Mutex::new(position),
            probe,
        }
        .into()
    }
}

impl IEnumFORMATETC_Impl for FormatEnumerator_Impl {
    fn Next(&self, requested: u32, output: *mut FORMATETC, fetched_out: *mut u32) -> HRESULT {
        catch_com_hresult(|| {
            if requested != 1 && fetched_out.is_null() {
                return E_POINTER;
            }
            if requested != 0 && output.is_null() {
                return E_POINTER;
            }
            if !fetched_out.is_null() {
                unsafe { fetched_out.write(0) };
            }

            let Ok(requested) = usize::try_from(requested) else {
                return E_UNEXPECTED;
            };
            let Ok(mut position) = self.position.lock() else {
                return E_UNEXPECTED;
            };
            let available = self.formats.len().saturating_sub(*position);
            let fetched = requested.min(available);
            for index in 0..fetched {
                unsafe { output.add(index).write(self.formats[*position + index]) };
            }
            *position += fetched;
            if !fetched_out.is_null() {
                unsafe { fetched_out.write(u32::try_from(fetched).unwrap_or(u32::MAX)) };
            }
            self.probe.record(
                "IEnumFORMATETC::Next",
                format_args!("requested={requested} fetched={fetched} position={position}"),
            );
            if fetched == requested { S_OK } else { S_FALSE }
        })
    }

    fn Skip(&self, requested: u32) -> Result<()> {
        catch_com_result(|| {
            let requested =
                usize::try_from(requested).map_err(|_| Error::from_hresult(E_UNEXPECTED))?;
            let mut position = self
                .position
                .lock()
                .map_err(|_| Error::from_hresult(E_UNEXPECTED))?;
            let available = self.formats.len().saturating_sub(*position);
            let skipped = requested.min(available);
            *position += skipped;
            self.probe.record(
                "IEnumFORMATETC::Skip",
                format_args!("requested={requested} skipped={skipped} position={position}"),
            );
            if skipped == requested {
                Ok(())
            } else {
                Err(Error::from_hresult(S_FALSE))
            }
        })
    }

    fn Reset(&self) -> Result<()> {
        catch_com_result(|| {
            *self
                .position
                .lock()
                .map_err(|_| Error::from_hresult(E_UNEXPECTED))? = 0;
            self.probe.record("IEnumFORMATETC::Reset", "position=0");
            Ok(())
        })
    }

    fn Clone(&self) -> Result<IEnumFORMATETC> {
        catch_com_result(|| {
            let position = *self
                .position
                .lock()
                .map_err(|_| Error::from_hresult(E_UNEXPECTED))?;
            self.probe
                .record("IEnumFORMATETC::Clone", format_args!("position={position}"));
            Ok(FormatEnumerator::create_at(
                Arc::clone(&self.formats),
                position,
                Arc::clone(&self.probe),
            ))
        })
    }
}

#[cfg(test)]
#[allow(clippy::borrow_as_ptr)]
mod tests {
    use std::sync::Arc;

    use windows::Win32::Foundation::{E_POINTER, S_FALSE, S_OK};
    use windows::Win32::System::Com::FORMATETC;
    use windows::core::Interface;

    use super::FormatEnumerator;
    use crate::clipboard::probe::ProbeState;

    fn formats() -> [FORMATETC; 3] {
        [10_u16, 11, 12].map(|cf_format| FORMATETC {
            cfFormat: cf_format,
            ..Default::default()
        })
    }

    #[test]
    fn next_enforces_com_pointer_rules_and_partial_fetch() {
        let enumerator = FormatEnumerator::create(formats(), Arc::new(ProbeState::default()));
        let mut two = [FORMATETC::default(); 2];
        assert_eq!(unsafe { enumerator.Next(&mut two, None) }, E_POINTER);

        let mut fetched = 0;
        assert_eq!(
            unsafe { enumerator.Next(&mut two, Some(&mut fetched)) },
            S_OK
        );
        assert_eq!(fetched, 2);
        assert_eq!([two[0].cfFormat, two[1].cfFormat], [10, 11]);

        assert_eq!(
            unsafe { enumerator.Next(&mut two, Some(&mut fetched)) },
            S_FALSE
        );
        assert_eq!(fetched, 1);
        assert_eq!(two[0].cfFormat, 12);
    }

    #[test]
    fn clone_preserves_cursor_but_advances_independently() {
        let enumerator = FormatEnumerator::create(formats(), Arc::new(ProbeState::default()));
        let mut item = FORMATETC::default();
        assert_eq!(
            unsafe { enumerator.Next(std::slice::from_mut(&mut item), None) },
            S_OK
        );
        let clone = unsafe { enumerator.Clone() }.unwrap();

        assert_eq!(
            unsafe { enumerator.Next(std::slice::from_mut(&mut item), None) },
            S_OK
        );
        assert_eq!(item.cfFormat, 11);
        assert_eq!(
            unsafe { clone.Next(std::slice::from_mut(&mut item), None) },
            S_OK
        );
        assert_eq!(item.cfFormat, 11);

        unsafe { enumerator.Skip(1) }.unwrap();
        assert_eq!(
            unsafe { clone.Next(std::slice::from_mut(&mut item), None) },
            S_OK
        );
        assert_eq!(item.cfFormat, 12);
    }

    #[test]
    fn skip_past_the_end_returns_s_false_and_leaves_the_cursor_at_end() {
        let enumerator = FormatEnumerator::create(formats(), Arc::new(ProbeState::default()));
        let skip_result =
            unsafe { (Interface::vtable(&enumerator).Skip)(Interface::as_raw(&enumerator), 4) };
        assert_eq!(skip_result, S_FALSE);

        let mut item = FORMATETC::default();
        let mut fetched = 99;
        assert_eq!(
            unsafe { enumerator.Next(std::slice::from_mut(&mut item), Some(&mut fetched)) },
            S_FALSE
        );
        assert_eq!(fetched, 0);

        unsafe { enumerator.Reset() }.unwrap();
        assert_eq!(
            unsafe { enumerator.Next(std::slice::from_mut(&mut item), None) },
            S_OK
        );
        assert_eq!(item.cfFormat, 10);
    }
}
