use std::collections::VecDeque;
use std::io::Write as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use windows::Win32::System::Com::{APTTYPE, APTTYPEQUALIFIER, CoGetApartmentType};
use windows::Win32::System::Threading::GetCurrentThreadId;

#[derive(Debug, Default)]
pub struct ProbeState {
    read_calls: AtomicU64,
    event_count: AtomicU64,
    dropped_events: AtomicU64,
    events: Mutex<VecDeque<String>>,
}

const MAX_RETAINED_EVENTS: usize = 4_096;

impl ProbeState {
    pub fn record(&self, method: &str, detail: impl std::fmt::Display) {
        let thread_id = unsafe { GetCurrentThreadId() };
        let apartment = apartment_description();
        let event =
            format!("COM method={method} thread={thread_id} apartment={apartment} {detail}");

        let _ = writeln!(std::io::stderr().lock(), "{event}");
        self.retain(event);
    }

    fn retain(&self, event: String) {
        if let Ok(mut events) = self.events.lock() {
            self.event_count.fetch_add(1, Ordering::Relaxed);
            if events.len() == MAX_RETAINED_EVENTS {
                events.pop_front();
                self.dropped_events.fetch_add(1, Ordering::Relaxed);
            }
            events.push_back(event);
        }
    }

    pub fn note_read(&self, offset: u64, requested: usize) {
        self.read_calls.fetch_add(1, Ordering::Relaxed);
        self.record(
            "IStream::Read",
            format_args!("offset={offset} requested={requested}"),
        );
    }

    #[must_use]
    pub fn read_calls(&self) -> u64 {
        self.read_calls.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn events(&self) -> Vec<String> {
        self.events.lock().map_or_else(
            |poisoned| poisoned.into_inner().iter().cloned().collect(),
            |events| events.iter().cloned().collect(),
        )
    }

    #[must_use]
    pub fn event_count(&self) -> u64 {
        self.event_count.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }
}

fn apartment_description() -> String {
    let mut apartment = APTTYPE::default();
    let mut qualifier = APTTYPEQUALIFIER::default();
    let result = unsafe { CoGetApartmentType(&raw mut apartment, &raw mut qualifier) };
    match result {
        Ok(()) => format!("{}:{}", apartment.0, qualifier.0),
        Err(error) => format!("unknown({:#010X})", error.code().0.cast_unsigned()),
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_RETAINED_EVENTS, ProbeState};

    #[test]
    fn event_history_is_bounded_without_losing_total_counts() {
        let probe = ProbeState::default();
        let total = MAX_RETAINED_EVENTS + 3;
        for index in 0..total {
            probe.retain(format!("event {index}"));
        }

        assert_eq!(probe.events().len(), MAX_RETAINED_EVENTS);
        assert_eq!(probe.event_count(), total as u64);
        assert_eq!(probe.dropped_events(), 3);
        assert_eq!(probe.events().first().unwrap(), "event 3");
    }
}
