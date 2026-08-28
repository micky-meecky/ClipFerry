use std::sync::Arc;

pub trait ReadAtSource: Send + Sync {
    fn len(&self) -> u64;

    fn read_at(&self, offset: u64, destination: &mut [u8]) -> windows::core::Result<usize>;
}

#[derive(Debug)]
pub struct MemorySource {
    bytes: Arc<[u8]>,
}

impl MemorySource {
    #[must_use]
    pub fn new(bytes: impl Into<Arc<[u8]>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }
}

impl ReadAtSource for MemorySource {
    fn len(&self) -> u64 {
        u64::try_from(self.bytes.len()).expect("usize always fits in u64 on Windows x64")
    }

    fn read_at(&self, offset: u64, destination: &mut [u8]) -> windows::core::Result<usize> {
        let Ok(offset) = usize::try_from(offset) else {
            return Ok(0);
        };
        if offset >= self.bytes.len() {
            return Ok(0);
        }

        let available = self.bytes.len() - offset;
        let copied = available.min(destination.len());
        destination[..copied].copy_from_slice(&self.bytes[offset..offset + copied]);
        Ok(copied)
    }
}

#[cfg(test)]
mod tests {
    use super::{MemorySource, ReadAtSource};

    #[test]
    fn memory_source_supports_bounded_offset_reads() {
        let source = MemorySource::new(&b"abcdef"[..]);
        let mut destination = [0_u8; 3];

        assert_eq!(source.read_at(2, &mut destination).unwrap(), 3);
        assert_eq!(&destination, b"cde");
        assert_eq!(source.read_at(6, &mut destination).unwrap(), 0);
        assert_eq!(source.read_at(u64::MAX, &mut destination).unwrap(), 0);
    }
}
