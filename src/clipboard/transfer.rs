use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use windows::Win32::Foundation::{E_INVALIDARG, E_UNEXPECTED, ERROR_CANCELLED};
use windows::core::{Error, HRESULT, Result};

use super::source::ReadAtSource;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferControlState {
    Running,
    Paused,
    Cancelled,
}

impl std::fmt::Display for TransferControlState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => formatter.write_str("running"),
            Self::Paused => formatter.write_str("paused"),
            Self::Cancelled => formatter.write_str("cancelled"),
        }
    }
}

#[derive(Debug)]
pub struct TransferControl {
    state: Mutex<TransferControlState>,
    changed: Condvar,
    bytes_served: AtomicU64,
    chunk_calls: AtomicU64,
}

impl Default for TransferControl {
    fn default() -> Self {
        Self {
            state: Mutex::new(TransferControlState::Running),
            changed: Condvar::new(),
            bytes_served: AtomicU64::new(0),
            chunk_calls: AtomicU64::new(0),
        }
    }
}

impl TransferControl {
    pub fn pause(&self) -> Result<TransferControlState> {
        self.transition(|state| match state {
            TransferControlState::Running | TransferControlState::Paused => {
                TransferControlState::Paused
            }
            TransferControlState::Cancelled => TransferControlState::Cancelled,
        })
    }

    pub fn resume(&self) -> Result<TransferControlState> {
        self.transition(|state| match state {
            TransferControlState::Running | TransferControlState::Paused => {
                TransferControlState::Running
            }
            TransferControlState::Cancelled => TransferControlState::Cancelled,
        })
    }

    pub fn cancel(&self) -> Result<TransferControlState> {
        self.transition(|_| TransferControlState::Cancelled)
    }

    pub fn state(&self) -> Result<TransferControlState> {
        self.state
            .lock()
            .map(|state| *state)
            .map_err(|_| Error::from_hresult(E_UNEXPECTED))
    }

    #[must_use]
    pub fn bytes_served(&self) -> u64 {
        self.bytes_served.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn chunk_calls(&self) -> u64 {
        self.chunk_calls.load(Ordering::Relaxed)
    }

    fn transition(
        &self,
        update: impl FnOnce(TransferControlState) -> TransferControlState,
    ) -> Result<TransferControlState> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::from_hresult(E_UNEXPECTED))?;
        *state = update(*state);
        let current = *state;
        drop(state);
        self.changed.notify_all();
        Ok(current)
    }

    fn wait_for_chunk(&self, delay: Duration) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::from_hresult(E_UNEXPECTED))?;
        loop {
            match *state {
                TransferControlState::Cancelled => return Err(cancellation_error()),
                TransferControlState::Paused => {
                    state = self
                        .changed
                        .wait(state)
                        .map_err(|_| Error::from_hresult(E_UNEXPECTED))?;
                }
                TransferControlState::Running if delay.is_zero() => return Ok(()),
                TransferControlState::Running => {
                    let (next_state, timeout) = self
                        .changed
                        .wait_timeout(state, delay)
                        .map_err(|_| Error::from_hresult(E_UNEXPECTED))?;
                    state = next_state;
                    if timeout.timed_out() {
                        return Ok(());
                    }
                }
            }
        }
    }

    fn note_chunk(&self, bytes: usize) -> Result<()> {
        let bytes = u64::try_from(bytes).map_err(|_| Error::from_hresult(E_UNEXPECTED))?;
        self.bytes_served.fetch_add(bytes, Ordering::Relaxed);
        self.chunk_calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[derive(Debug)]
pub struct GeneratedSource {
    length: u64,
    max_chunk: usize,
    delay: Duration,
    control: Arc<TransferControl>,
}

impl GeneratedSource {
    pub fn new(
        length: u64,
        max_chunk: usize,
        delay: Duration,
        control: Arc<TransferControl>,
    ) -> Result<Self> {
        if length == 0 || max_chunk == 0 {
            return Err(Error::from_hresult(E_INVALIDARG));
        }
        Ok(Self {
            length,
            max_chunk,
            delay,
            control,
        })
    }
}

impl ReadAtSource for GeneratedSource {
    fn len(&self) -> u64 {
        self.length
    }

    fn read_at(&self, offset: u64, destination: &mut [u8]) -> Result<usize> {
        if offset >= self.length || destination.is_empty() {
            return Ok(0);
        }
        self.control.wait_for_chunk(self.delay)?;

        let remaining = self.length - offset;
        let destination_length =
            u64::try_from(destination.len()).map_err(|_| Error::from_hresult(E_UNEXPECTED))?;
        let max_chunk =
            u64::try_from(self.max_chunk).map_err(|_| Error::from_hresult(E_UNEXPECTED))?;
        let copied = remaining.min(destination_length).min(max_chunk);
        let copied = usize::try_from(copied).map_err(|_| Error::from_hresult(E_UNEXPECTED))?;
        for (index, byte) in destination[..copied].iter_mut().enumerate() {
            let index = u64::try_from(index).map_err(|_| Error::from_hresult(E_UNEXPECTED))?;
            *byte = generated_byte(offset + index);
        }
        self.control.note_chunk(copied)?;
        Ok(copied)
    }
}

#[must_use]
pub fn generated_byte(offset: u64) -> u8 {
    offset.to_le_bytes()[0].wrapping_mul(31).wrapping_add(0xA5)
}

fn cancellation_error() -> Error {
    Error::from_hresult(HRESULT::from_win32(ERROR_CANCELLED.0))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, mpsc};
    use std::time::{Duration, Instant};

    use super::{GeneratedSource, TransferControl, TransferControlState, generated_byte};
    use crate::clipboard::source::ReadAtSource;

    #[test]
    fn generated_source_is_deterministic_across_offsets_and_chunk_bounds() {
        let control = Arc::new(TransferControl::default());
        let source = GeneratedSource::new(10, 3, Duration::ZERO, Arc::clone(&control)).unwrap();
        let mut bytes = [0_u8; 5];

        assert_eq!(source.read_at(2, &mut bytes).unwrap(), 3);
        assert_eq!(
            bytes[..3],
            [generated_byte(2), generated_byte(3), generated_byte(4)]
        );
        assert_eq!(source.read_at(9, &mut bytes).unwrap(), 1);
        assert_eq!(bytes[0], generated_byte(9));
        assert_eq!(source.read_at(10, &mut bytes).unwrap(), 0);
        assert_eq!(control.bytes_served(), 4);
        assert_eq!(control.chunk_calls(), 2);
    }

    #[test]
    fn paused_reads_resume_without_losing_content() {
        let control = Arc::new(TransferControl::default());
        let source =
            Arc::new(GeneratedSource::new(8, 8, Duration::ZERO, Arc::clone(&control)).unwrap());
        control.pause().unwrap();
        let (sender, receiver) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut bytes = [0_u8; 8];
            let result = source.read_at(0, &mut bytes);
            sender.send((result, bytes)).unwrap();
        });

        std::thread::sleep(Duration::from_millis(30));
        assert!(receiver.try_recv().is_err());
        assert_eq!(control.resume().unwrap(), TransferControlState::Running);
        let (result, bytes) = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(result.unwrap(), 8);
        assert_eq!(bytes[0], generated_byte(0));
        assert_eq!(bytes[7], generated_byte(7));
        worker.join().unwrap();
    }

    #[test]
    fn cancellation_is_terminal_idempotent_and_wakes_a_paused_read() {
        let control = Arc::new(TransferControl::default());
        let source =
            Arc::new(GeneratedSource::new(8, 8, Duration::ZERO, Arc::clone(&control)).unwrap());
        control.pause().unwrap();
        let worker = std::thread::spawn(move || {
            let mut bytes = [0_u8; 8];
            source.read_at(0, &mut bytes).unwrap_err().code()
        });
        std::thread::sleep(Duration::from_millis(30));

        assert_eq!(control.cancel().unwrap(), TransferControlState::Cancelled);
        assert!(worker.join().unwrap().is_err());
        assert_eq!(control.cancel().unwrap(), TransferControlState::Cancelled);
        assert_eq!(control.resume().unwrap(), TransferControlState::Cancelled);
        assert_eq!(control.pause().unwrap(), TransferControlState::Cancelled);
    }

    #[test]
    fn cancellation_interrupts_chunk_throttling() {
        let control = Arc::new(TransferControl::default());
        let source = Arc::new(
            GeneratedSource::new(8, 8, Duration::from_secs(5), Arc::clone(&control)).unwrap(),
        );
        let started = Instant::now();
        let worker = std::thread::spawn(move || {
            let mut bytes = [0_u8; 8];
            source.read_at(0, &mut bytes)
        });
        std::thread::sleep(Duration::from_millis(30));
        control.cancel().unwrap();

        assert!(worker.join().unwrap().is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
