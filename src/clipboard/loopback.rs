use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{
    E_INVALIDARG, E_UNEXPECTED, ERROR_CANCELLED, ERROR_CONNECTION_ABORTED, ERROR_FILE_NOT_FOUND,
    ERROR_INVALID_DATA, ERROR_TIMEOUT,
};
use windows::core::{Error, HRESULT, Result};

use super::source::ReadAtSource;
use super::transfer::{TransferControl, TransferControlState, generated_byte};

const REQUEST_MAGIC: [u8; 4] = *b"CFRQ";
const RESPONSE_MAGIC: [u8; 4] = *b"CFRS";
const PROTOCOL_VERSION: u8 = 1;
const REQUEST_HEADER_LEN: usize = 44;
const RESPONSE_HEADER_LEN: usize = 28;
const MAX_TRACKED_RANGES: usize = 4_096;
pub const DEFAULT_MAX_WORKERS: usize = 32;
const MAX_CONFIGURED_WORKERS: usize = 256;
pub const MAX_PROTOCOL_RANGE_BYTES: usize = 1024 * 1024;

pub const LOOPBACK_FILE_ID: [u8; 16] = *b"ClipFerryRange01";
pub const LOOPBACK_TEST_FILE_NAME: &str = "RemoteClipboard-Loopback-Test.bin";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum Opcode {
    ReadRange = 1,
    Pause = 2,
    Resume = 3,
    Cancel = 4,
    Status = 5,
}

impl Opcode {
    fn from_byte(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::ReadRange),
            2 => Some(Self::Pause),
            3 => Some(Self::Resume),
            4 => Some(Self::Cancel),
            5 => Some(Self::Status),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum ResponseStatus {
    Ok = 0,
    InvalidRequest = 1,
    FileNotFound = 2,
    Cancelled = 3,
    InternalError = 4,
}

impl ResponseStatus {
    fn from_byte(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Ok),
            1 => Some(Self::InvalidRequest),
            2 => Some(Self::FileNotFound),
            3 => Some(Self::Cancelled),
            4 => Some(Self::InternalError),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct RequestHeader {
    opcode: Opcode,
    request_id: u64,
    file_id: [u8; 16],
    offset: u64,
    length: u32,
}

impl RequestHeader {
    fn encode(self) -> [u8; REQUEST_HEADER_LEN] {
        let mut bytes = [0_u8; REQUEST_HEADER_LEN];
        bytes[..4].copy_from_slice(&REQUEST_MAGIC);
        bytes[4] = PROTOCOL_VERSION;
        bytes[5] = self.opcode as u8;
        bytes[8..16].copy_from_slice(&self.request_id.to_be_bytes());
        bytes[16..32].copy_from_slice(&self.file_id);
        bytes[32..40].copy_from_slice(&self.offset.to_be_bytes());
        bytes[40..44].copy_from_slice(&self.length.to_be_bytes());
        bytes
    }

    fn decode(bytes: &[u8; REQUEST_HEADER_LEN]) -> Option<Self> {
        if bytes[..4] != REQUEST_MAGIC || bytes[4] != PROTOCOL_VERSION {
            return None;
        }
        let opcode = Opcode::from_byte(bytes[5])?;
        let request_id = u64::from_be_bytes(bytes[8..16].try_into().ok()?);
        let file_id = bytes[16..32].try_into().ok()?;
        let offset = u64::from_be_bytes(bytes[32..40].try_into().ok()?);
        let length = u32::from_be_bytes(bytes[40..44].try_into().ok()?);
        Some(Self {
            opcode,
            request_id,
            file_id,
            offset,
            length,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct ResponseHeader {
    status: ResponseStatus,
    state: TransferControlState,
    request_id: u64,
    total_length: u64,
    payload_length: u32,
}

impl ResponseHeader {
    fn encode(self) -> [u8; RESPONSE_HEADER_LEN] {
        let mut bytes = [0_u8; RESPONSE_HEADER_LEN];
        bytes[..4].copy_from_slice(&RESPONSE_MAGIC);
        bytes[4] = PROTOCOL_VERSION;
        bytes[5] = self.status as u8;
        bytes[6] = state_byte(self.state);
        bytes[8..16].copy_from_slice(&self.request_id.to_be_bytes());
        bytes[16..24].copy_from_slice(&self.total_length.to_be_bytes());
        bytes[24..28].copy_from_slice(&self.payload_length.to_be_bytes());
        bytes
    }

    fn decode(bytes: &[u8; RESPONSE_HEADER_LEN]) -> Option<Self> {
        if bytes[..4] != RESPONSE_MAGIC || bytes[4] != PROTOCOL_VERSION {
            return None;
        }
        Some(Self {
            status: ResponseStatus::from_byte(bytes[5])?,
            state: state_from_byte(bytes[6])?,
            request_id: u64::from_be_bytes(bytes[8..16].try_into().ok()?),
            total_length: u64::from_be_bytes(bytes[16..24].try_into().ok()?),
            payload_length: u32::from_be_bytes(bytes[24..28].try_into().ok()?),
        })
    }
}

fn state_byte(state: TransferControlState) -> u8 {
    match state {
        TransferControlState::Running => 0,
        TransferControlState::Paused => 1,
        TransferControlState::Cancelled => 2,
    }
}

fn state_from_byte(value: u8) -> Option<TransferControlState> {
    match value {
        0 => Some(TransferControlState::Running),
        1 => Some(TransferControlState::Paused),
        2 => Some(TransferControlState::Cancelled),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LoopbackServerConfig {
    pub length: u64,
    pub file_id: [u8; 16],
    pub max_range_bytes: usize,
    pub fragment_bytes: usize,
    pub range_delay: Duration,
    pub socket_timeout: Duration,
    pub max_workers: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LoopbackMetricsSnapshot {
    pub connections: u64,
    pub read_requests: u64,
    pub served_bytes: u64,
    pub unique_bytes: u64,
    pub retained_ranges: usize,
    pub coverage_saturated: bool,
    pub protocol_errors: u64,
    pub max_concurrent_reads: u64,
}

#[derive(Debug, Default)]
struct RangeCoverage {
    ranges: Vec<(u64, u64)>,
    unique_bytes: u64,
    saturated: bool,
}

impl RangeCoverage {
    fn note(&mut self, start: u64, length: u64) {
        if self.saturated || length == 0 {
            return;
        }
        let Some(end) = start.checked_add(length) else {
            self.saturated = true;
            return;
        };
        self.ranges.push((start, end));
        self.ranges.sort_unstable_by_key(|range| range.0);

        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(self.ranges.len());
        for (range_start, range_end) in self.ranges.drain(..) {
            if let Some(last) = merged.last_mut()
                && range_start <= last.1
            {
                last.1 = last.1.max(range_end);
                continue;
            }
            merged.push((range_start, range_end));
        }
        if merged.len() > MAX_TRACKED_RANGES {
            self.saturated = true;
            self.ranges.clear();
            return;
        }
        self.unique_bytes = merged.iter().map(|(start, end)| end - start).sum();
        self.ranges = merged;
    }
}

#[derive(Debug, Default)]
struct LoopbackMetrics {
    connections: AtomicU64,
    read_requests: AtomicU64,
    served_bytes: AtomicU64,
    protocol_errors: AtomicU64,
    active_reads: AtomicU64,
    max_concurrent_reads: AtomicU64,
    coverage: Mutex<RangeCoverage>,
}

impl LoopbackMetrics {
    fn begin_read(self: &Arc<Self>) -> ActiveRead {
        let current = self.active_reads.fetch_add(1, Ordering::AcqRel) + 1;
        let _ = self.max_concurrent_reads.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |maximum| (current > maximum).then_some(current),
        );
        ActiveRead {
            metrics: Arc::clone(self),
        }
    }

    fn note_success(&self, offset: u64, length: usize) {
        let length = u64::try_from(length).unwrap_or(u64::MAX);
        self.served_bytes.fetch_add(length, Ordering::Relaxed);
        if let Ok(mut coverage) = self.coverage.lock() {
            coverage.note(offset, length);
        }
    }

    fn snapshot(&self) -> LoopbackMetricsSnapshot {
        let coverage = self
            .coverage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        LoopbackMetricsSnapshot {
            connections: self.connections.load(Ordering::Relaxed),
            read_requests: self.read_requests.load(Ordering::Relaxed),
            served_bytes: self.served_bytes.load(Ordering::Relaxed),
            unique_bytes: coverage.unique_bytes,
            retained_ranges: coverage.ranges.len(),
            coverage_saturated: coverage.saturated,
            protocol_errors: self.protocol_errors.load(Ordering::Relaxed),
            max_concurrent_reads: self.max_concurrent_reads.load(Ordering::Relaxed),
        }
    }
}

struct ActiveRead {
    metrics: Arc<LoopbackMetrics>,
}

impl Drop for ActiveRead {
    fn drop(&mut self) {
        self.metrics.active_reads.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug, Default)]
struct WorkerTracker {
    active: Mutex<usize>,
    finished: Condvar,
}

impl WorkerTracker {
    fn try_start(self: &Arc<Self>, maximum: usize) -> Option<WorkerGuard> {
        let mut active = self.active.lock().ok()?;
        if *active >= maximum {
            return None;
        }
        *active += 1;
        Some(WorkerGuard {
            tracker: Arc::clone(self),
        })
    }

    fn wait_until_idle(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *active != 0 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let (next, result) = self
                .finished
                .wait_timeout(active, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            active = next;
            if result.timed_out() {
                break;
            }
        }
    }
}

struct WorkerGuard {
    tracker: Arc<WorkerTracker>,
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        if let Ok(mut active) = self.tracker.active.lock() {
            *active = active.saturating_sub(1);
            self.tracker.finished.notify_all();
        }
    }
}

pub struct LoopbackServer {
    address: SocketAddr,
    control: Arc<TransferControl>,
    metrics: Arc<LoopbackMetrics>,
    stop: Arc<AtomicBool>,
    workers: Arc<WorkerTracker>,
    accept_thread: Option<JoinHandle<()>>,
    socket_timeout: Duration,
}

impl LoopbackServer {
    pub fn start(config: LoopbackServerConfig, control: Arc<TransferControl>) -> Result<Self> {
        validate_server_config(config)?;
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .map_err(|error| io_error(&error))?;
        let address = listener.local_addr().map_err(|error| io_error(&error))?;
        if !address.ip().is_loopback() {
            return Err(Error::from_hresult(E_UNEXPECTED));
        }

        let metrics = Arc::new(LoopbackMetrics::default());
        let stop = Arc::new(AtomicBool::new(false));
        let workers = Arc::new(WorkerTracker::default());
        let accept_control = Arc::clone(&control);
        let accept_metrics = Arc::clone(&metrics);
        let accept_stop = Arc::clone(&stop);
        let accept_workers = Arc::clone(&workers);
        let accept_thread = std::thread::Builder::new()
            .name("clipferry-loopback-accept".to_owned())
            .spawn(move || {
                accept_loop(
                    &listener,
                    config,
                    &accept_control,
                    &accept_metrics,
                    &accept_stop,
                    &accept_workers,
                );
            })
            .map_err(|_| Error::from_hresult(E_UNEXPECTED))?;

        Ok(Self {
            address,
            control,
            metrics,
            stop,
            workers,
            accept_thread: Some(accept_thread),
            socket_timeout: config.socket_timeout,
        })
    }

    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    #[must_use]
    pub fn metrics(&self) -> LoopbackMetricsSnapshot {
        self.metrics.snapshot()
    }
}

impl Drop for LoopbackServer {
    fn drop(&mut self) {
        let _ = self.control.cancel();
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(100));
        if let Some(thread) = self.accept_thread.take() {
            let _ = thread.join();
        }
        self.workers
            .wait_until_idle(self.socket_timeout.saturating_add(Duration::from_secs(1)));
    }
}

fn validate_server_config(config: LoopbackServerConfig) -> Result<()> {
    if config.max_range_bytes == 0
        || config.fragment_bytes == 0
        || config.fragment_bytes > config.max_range_bytes
        || config.max_range_bytes > MAX_PROTOCOL_RANGE_BYTES
        || config.socket_timeout.is_zero()
        || config.max_workers == 0
        || config.max_workers > MAX_CONFIGURED_WORKERS
    {
        return Err(Error::from_hresult(E_INVALIDARG));
    }
    Ok(())
}

fn accept_loop(
    listener: &TcpListener,
    config: LoopbackServerConfig,
    control: &Arc<TransferControl>,
    metrics: &Arc<LoopbackMetrics>,
    stop: &Arc<AtomicBool>,
    workers: &Arc<WorkerTracker>,
) {
    while let Ok((stream, _peer)) = listener.accept() {
        if stop.load(Ordering::Acquire) {
            break;
        }
        metrics.connections.fetch_add(1, Ordering::Relaxed);
        let Some(guard) = workers.try_start(config.max_workers) else {
            metrics.protocol_errors.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let worker_control = Arc::clone(control);
        let worker_metrics = Arc::clone(metrics);
        let spawn_result = std::thread::Builder::new()
            .name("clipferry-loopback-worker".to_owned())
            .spawn(move || {
                let _guard = guard;
                if handle_connection(stream, config, &worker_control, &worker_metrics).is_err() {
                    worker_metrics
                        .protocol_errors
                        .fetch_add(1, Ordering::Relaxed);
                }
            });
        if spawn_result.is_err() {
            metrics.protocol_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn handle_connection(
    mut stream: TcpStream,
    config: LoopbackServerConfig,
    control: &TransferControl,
    metrics: &Arc<LoopbackMetrics>,
) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(config.socket_timeout))?;
    stream.set_write_timeout(Some(config.socket_timeout))?;

    let mut bytes = [0_u8; REQUEST_HEADER_LEN];
    stream.read_exact(&mut bytes)?;
    let Some(request) = RequestHeader::decode(&bytes) else {
        return write_response(
            &mut stream,
            ResponseHeader {
                status: ResponseStatus::InvalidRequest,
                state: control.state().unwrap_or(TransferControlState::Cancelled),
                request_id: 0,
                total_length: config.length,
                payload_length: 0,
            },
        );
    };
    if request.file_id != config.file_id {
        return write_response(
            &mut stream,
            response_for(
                &request,
                config.length,
                control,
                ResponseStatus::FileNotFound,
                0,
            ),
        );
    }

    match request.opcode {
        Opcode::Pause => {
            let _ = control.pause();
            write_response(
                &mut stream,
                response_for(&request, config.length, control, ResponseStatus::Ok, 0),
            )
        }
        Opcode::Resume => {
            let _ = control.resume();
            write_response(
                &mut stream,
                response_for(&request, config.length, control, ResponseStatus::Ok, 0),
            )
        }
        Opcode::Cancel => {
            let _ = control.cancel();
            write_response(
                &mut stream,
                response_for(&request, config.length, control, ResponseStatus::Ok, 0),
            )
        }
        Opcode::Status => write_response(
            &mut stream,
            response_for(&request, config.length, control, ResponseStatus::Ok, 0),
        ),
        Opcode::ReadRange => serve_range(&mut stream, config, control, metrics, request),
    }
}

fn serve_range(
    stream: &mut TcpStream,
    config: LoopbackServerConfig,
    control: &TransferControl,
    metrics: &Arc<LoopbackMetrics>,
    request: RequestHeader,
) -> std::io::Result<()> {
    let Ok(requested) = usize::try_from(request.length) else {
        return write_response(
            stream,
            response_for(
                &request,
                config.length,
                control,
                ResponseStatus::InvalidRequest,
                0,
            ),
        );
    };
    if requested > config.max_range_bytes {
        return write_response(
            stream,
            response_for(
                &request,
                config.length,
                control,
                ResponseStatus::InvalidRequest,
                0,
            ),
        );
    }

    metrics.read_requests.fetch_add(1, Ordering::Relaxed);
    let _active = metrics.begin_read();
    if let Err(error) = control.wait_for_chunk(config.range_delay) {
        let status = if error.code() == HRESULT::from_win32(ERROR_CANCELLED.0) {
            ResponseStatus::Cancelled
        } else {
            ResponseStatus::InternalError
        };
        return write_response(
            stream,
            response_for(&request, config.length, control, status, 0),
        );
    }

    let available = config.length.saturating_sub(request.offset);
    let payload_length = available.min(u64::from(request.length));
    let payload_length = u32::try_from(payload_length).unwrap_or(request.length);
    write_response(
        stream,
        response_for(
            &request,
            config.length,
            control,
            ResponseStatus::Ok,
            payload_length,
        ),
    )?;

    let mut written = 0_usize;
    let payload_length = usize::try_from(payload_length).unwrap_or(0);
    let mut fragment = vec![0_u8; config.fragment_bytes.min(payload_length.max(1))];
    while written < payload_length {
        let count = (payload_length - written).min(fragment.len());
        let written_u64 = u64::try_from(written).unwrap_or(u64::MAX);
        for (index, byte) in fragment[..count].iter_mut().enumerate() {
            let index = u64::try_from(index).unwrap_or(u64::MAX);
            *byte = generated_byte(
                request
                    .offset
                    .saturating_add(written_u64)
                    .saturating_add(index),
            );
        }
        stream.write_all(&fragment[..count])?;
        written += count;
    }
    metrics.note_success(request.offset, payload_length);
    control
        .note_chunk(payload_length)
        .map_err(|_| std::io::Error::other("transfer counter unavailable"))?;
    Ok(())
}

fn response_for(
    request: &RequestHeader,
    total_length: u64,
    control: &TransferControl,
    status: ResponseStatus,
    payload_length: u32,
) -> ResponseHeader {
    ResponseHeader {
        status,
        state: control.state().unwrap_or(TransferControlState::Cancelled),
        request_id: request.request_id,
        total_length,
        payload_length,
    }
}

fn write_response(stream: &mut TcpStream, response: ResponseHeader) -> std::io::Result<()> {
    stream.write_all(&response.encode())
}

#[derive(Debug)]
pub struct TcpRangeSource {
    address: SocketAddr,
    file_id: [u8; 16],
    length: u64,
    max_request_bytes: usize,
    connect_timeout: Duration,
    io_timeout: Duration,
    next_request_id: AtomicU64,
}

impl TcpRangeSource {
    pub fn new(
        address: SocketAddr,
        file_id: [u8; 16],
        length: u64,
        max_request_bytes: usize,
        connect_timeout: Duration,
        io_timeout: Duration,
    ) -> Result<Self> {
        if !address.ip().is_loopback()
            || max_request_bytes == 0
            || max_request_bytes > MAX_PROTOCOL_RANGE_BYTES
            || connect_timeout.is_zero()
            || io_timeout.is_zero()
        {
            return Err(Error::from_hresult(E_INVALIDARG));
        }
        Ok(Self {
            address,
            file_id,
            length,
            max_request_bytes,
            connect_timeout,
            io_timeout,
            next_request_id: AtomicU64::new(1),
        })
    }

    fn next_request(&self, opcode: Opcode, offset: u64, length: u32) -> RequestHeader {
        RequestHeader {
            opcode,
            request_id: self.next_request_id.fetch_add(1, Ordering::Relaxed),
            file_id: self.file_id,
            offset,
            length,
        }
    }

    fn connect(&self) -> Result<TcpStream> {
        let stream = TcpStream::connect_timeout(&self.address, self.connect_timeout)
            .map_err(|error| io_error(&error))?;
        stream.set_nodelay(true).map_err(|error| io_error(&error))?;
        stream
            .set_read_timeout(Some(self.io_timeout))
            .map_err(|error| io_error(&error))?;
        stream
            .set_write_timeout(Some(self.io_timeout))
            .map_err(|error| io_error(&error))?;
        Ok(stream)
    }

    fn exchange(&self, request: RequestHeader) -> Result<(TcpStream, ResponseHeader)> {
        let mut stream = self.connect()?;
        stream
            .write_all(&request.encode())
            .map_err(|error| io_error(&error))?;
        let mut bytes = [0_u8; RESPONSE_HEADER_LEN];
        stream
            .read_exact(&mut bytes)
            .map_err(|error| io_error(&error))?;
        let response = ResponseHeader::decode(&bytes)
            .ok_or_else(|| Error::from_hresult(HRESULT::from_win32(ERROR_INVALID_DATA.0)))?;
        if response.request_id != request.request_id || response.total_length != self.length {
            return Err(Error::from_hresult(HRESULT::from_win32(
                ERROR_INVALID_DATA.0,
            )));
        }
        match response.status {
            ResponseStatus::Ok => Ok((stream, response)),
            ResponseStatus::InvalidRequest => Err(Error::from_hresult(E_INVALIDARG)),
            ResponseStatus::FileNotFound => Err(Error::from_hresult(HRESULT::from_win32(
                ERROR_FILE_NOT_FOUND.0,
            ))),
            ResponseStatus::Cancelled => {
                Err(Error::from_hresult(HRESULT::from_win32(ERROR_CANCELLED.0)))
            }
            ResponseStatus::InternalError => Err(Error::from_hresult(E_UNEXPECTED)),
        }
    }
}

impl ReadAtSource for TcpRangeSource {
    fn len(&self) -> u64 {
        self.length
    }

    fn read_at(&self, offset: u64, destination: &mut [u8]) -> Result<usize> {
        if destination.is_empty() || offset >= self.length {
            return Ok(0);
        }
        let available = self.length - offset;
        let requested = destination
            .len()
            .min(self.max_request_bytes)
            .min(usize::try_from(available).unwrap_or(usize::MAX));
        let request_length =
            u32::try_from(requested).map_err(|_| Error::from_hresult(E_INVALIDARG))?;
        let request = self.next_request(Opcode::ReadRange, offset, request_length);
        let (mut stream, response) = self.exchange(request)?;
        let payload_length = usize::try_from(response.payload_length)
            .map_err(|_| Error::from_hresult(E_UNEXPECTED))?;
        if payload_length == 0 || payload_length > requested {
            return Err(Error::from_hresult(HRESULT::from_win32(
                ERROR_INVALID_DATA.0,
            )));
        }
        stream
            .read_exact(&mut destination[..payload_length])
            .map_err(|error| io_error(&error))?;
        Ok(payload_length)
    }
}

#[derive(Debug)]
pub struct LoopbackControlClient {
    source: Arc<TcpRangeSource>,
}

impl LoopbackControlClient {
    #[must_use]
    pub fn new(source: Arc<TcpRangeSource>) -> Self {
        Self { source }
    }

    pub fn pause(&self) -> Result<TransferControlState> {
        self.command(Opcode::Pause)
    }

    pub fn resume(&self) -> Result<TransferControlState> {
        self.command(Opcode::Resume)
    }

    pub fn cancel(&self) -> Result<TransferControlState> {
        self.command(Opcode::Cancel)
    }

    pub fn state(&self) -> Result<TransferControlState> {
        self.command(Opcode::Status)
    }

    fn command(&self, opcode: Opcode) -> Result<TransferControlState> {
        let request = self.source.next_request(opcode, 0, 0);
        let (_stream, response) = self.source.exchange(request)?;
        if response.payload_length != 0 {
            return Err(Error::from_hresult(HRESULT::from_win32(
                ERROR_INVALID_DATA.0,
            )));
        }
        Ok(response.state)
    }
}

fn io_error(error: &std::io::Error) -> Error {
    let code = match error.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => ERROR_TIMEOUT,
        ErrorKind::InvalidData | ErrorKind::InvalidInput => ERROR_INVALID_DATA,
        _ => ERROR_CONNECTION_ABORTED,
    };
    Error::from_hresult(HRESULT::from_win32(code.0))
}

#[cfg(test)]
mod tests {
    use std::ffi::c_void;
    use std::io::{Read as _, Write as _};
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Barrier, mpsc};
    use std::time::{Duration, Instant};

    use windows::Win32::Foundation::{
        E_INVALIDARG, ERROR_CANCELLED, ERROR_INVALID_DATA, ERROR_TIMEOUT, S_OK,
    };
    use windows::Win32::System::Com::STREAM_SEEK_SET;
    use windows::core::HRESULT;

    use super::{
        DEFAULT_MAX_WORKERS, LOOPBACK_FILE_ID, LoopbackControlClient, LoopbackServer,
        LoopbackServerConfig, MAX_TRACKED_RANGES, Opcode, REQUEST_HEADER_LEN, RangeCoverage,
        RequestHeader, ResponseHeader, ResponseStatus, TcpRangeSource,
    };
    use crate::clipboard::probe::ProbeState;
    use crate::clipboard::source::ReadAtSource;
    use crate::clipboard::stream::VirtualStream;
    use crate::clipboard::transfer::{TransferControl, TransferControlState, generated_byte};

    fn config(length: u64) -> LoopbackServerConfig {
        LoopbackServerConfig {
            length,
            file_id: LOOPBACK_FILE_ID,
            max_range_bytes: 64 * 1024,
            fragment_bytes: 7,
            range_delay: Duration::ZERO,
            socket_timeout: Duration::from_secs(2),
            max_workers: DEFAULT_MAX_WORKERS,
        }
    }

    fn server_and_source(
        length: u64,
    ) -> (LoopbackServer, Arc<TransferControl>, Arc<TcpRangeSource>) {
        let control = Arc::new(TransferControl::default());
        let server = LoopbackServer::start(config(length), Arc::clone(&control)).unwrap();
        let source = Arc::new(
            TcpRangeSource::new(
                server.address(),
                LOOPBACK_FILE_ID,
                length,
                64 * 1024,
                Duration::from_secs(1),
                Duration::from_secs(1),
            )
            .unwrap(),
        );
        (server, control, source)
    }

    fn wait_for_metrics(
        server: &LoopbackServer,
        predicate: impl Fn(super::LoopbackMetricsSnapshot) -> bool,
    ) -> super::LoopbackMetricsSnapshot {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let metrics = server.metrics();
            if predicate(metrics) || Instant::now() >= deadline {
                return metrics;
            }
            std::thread::yield_now();
        }
    }

    #[test]
    fn range_round_trip_is_deterministic_deferred_and_short_frame_safe() {
        let (server, _control, source) = server_and_source(1 << 20);
        assert_eq!(server.metrics().read_requests, 0);
        let mut bytes = [0_u8; 4_097];

        assert_eq!(source.read_at(123, &mut bytes).unwrap(), bytes.len());
        for (index, byte) in bytes.iter().enumerate() {
            assert_eq!(*byte, generated_byte(123 + index as u64));
        }
        let metrics = wait_for_metrics(&server, |metrics| {
            metrics.served_bytes == bytes.len() as u64
        });
        assert_eq!(metrics.read_requests, 1);
        assert_eq!(metrics.served_bytes, bytes.len() as u64);
        assert_eq!(metrics.unique_bytes, bytes.len() as u64);
        assert_eq!(metrics.retained_ranges, 1);
    }

    #[test]
    fn boundary_lengths_include_zero_one_chunk_edges_and_more_than_four_gib() {
        let lengths = [
            0,
            1,
            64 * 1024 - 1,
            64 * 1024,
            64 * 1024 + 1,
            u64::from(u32::MAX) + 2,
        ];

        for length in lengths {
            let (server, _control, source) = server_and_source(length);
            let mut bytes = [0_u8; 3];
            if length == 0 {
                assert_eq!(source.read_at(0, &mut bytes).unwrap(), 0);
                assert_eq!(server.metrics().connections, 0);
                continue;
            }

            let offset = length.saturating_sub(2);
            let read = source.read_at(offset, &mut bytes).unwrap();
            assert_eq!(read, usize::try_from(length - offset).unwrap());
            for (index, byte) in bytes[..read].iter().enumerate() {
                assert_eq!(*byte, generated_byte(offset + index as u64));
            }
        }
    }

    #[test]
    fn randomized_seek_and_read_matches_the_local_reference() {
        let length = 2_u64 * 1024 * 1024;
        let (_server, _control, source) = server_and_source(length);
        let source: Arc<dyn ReadAtSource> = source;
        let stream = VirtualStream::create(
            source,
            Arc::<str>::from("random-loopback.bin"),
            0,
            Arc::new(ProbeState::default()),
        );
        let mut seed = 0xC11F_E221_u32;
        let mut bytes = [0_u8; 4_096];

        for _ in 0..128 {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let requested = usize::try_from((seed % 4_096) + 1).unwrap();
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let offset = u64::from(seed) % (length - requested as u64);
            unsafe { stream.Seek(i64::try_from(offset).unwrap(), STREAM_SEEK_SET, None) }.unwrap();
            let mut read = 0;
            let result = unsafe {
                stream.Read(
                    bytes.as_mut_ptr().cast::<c_void>(),
                    u32::try_from(requested).unwrap(),
                    Some(&raw mut read),
                )
            };

            assert_eq!(result, S_OK);
            assert_eq!(read, u32::try_from(requested).unwrap());
            for (index, byte) in bytes[..requested].iter().enumerate() {
                assert_eq!(*byte, generated_byte(offset + index as u64));
            }
        }
    }

    #[test]
    fn randomly_fragmented_headers_and_payload_are_reassembled() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; REQUEST_HEADER_LEN];
            stream.read_exact(&mut request).unwrap();
            let request = RequestHeader::decode(&request).unwrap();
            let response = ResponseHeader {
                status: ResponseStatus::Ok,
                state: TransferControlState::Running,
                request_id: request.request_id,
                total_length: 1 << 20,
                payload_length: request.length,
            };
            let payload: Vec<u8> = (0..u64::from(request.length))
                .map(|index| generated_byte(request.offset + index))
                .collect();
            let mut frame = response.encode().to_vec();
            frame.extend_from_slice(&payload);
            let mut position = 0_usize;
            let mut seed = 0xA51C_0DE5_u32;
            while position < frame.len() {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                let fragment = usize::try_from((seed % 23) + 1).unwrap();
                let end = (position + fragment).min(frame.len());
                stream.write_all(&frame[position..end]).unwrap();
                position = end;
            }
        });
        let source = TcpRangeSource::new(
            address,
            LOOPBACK_FILE_ID,
            1 << 20,
            64 * 1024,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        let mut bytes = [0_u8; 4_097];

        assert_eq!(source.read_at(123, &mut bytes).unwrap(), bytes.len());
        for (index, byte) in bytes.iter().enumerate() {
            assert_eq!(*byte, generated_byte(123 + index as u64));
        }
        server.join().unwrap();
    }

    #[test]
    fn duplicate_and_overlapping_ranges_separate_served_from_unique_progress() {
        let (server, _control, source) = server_and_source(1 << 20);
        let mut bytes = [0_u8; 100];
        source.read_at(50, &mut bytes).unwrap();
        source.read_at(50, &mut bytes).unwrap();
        source.read_at(100, &mut bytes).unwrap();

        let metrics = wait_for_metrics(&server, |metrics| metrics.served_bytes == 300);
        assert_eq!(metrics.served_bytes, 300);
        assert_eq!(metrics.unique_bytes, 150);
        assert_eq!(metrics.retained_ranges, 1);
    }

    #[test]
    fn seek_and_clone_use_tcp_ranges_with_independent_positions() {
        let (server, _control, source) = server_and_source(1 << 20);
        let source: Arc<dyn ReadAtSource> = source;
        let stream = VirtualStream::create(
            source,
            Arc::<str>::from("loopback.bin"),
            0,
            Arc::new(ProbeState::default()),
        );
        unsafe { stream.Seek(500, STREAM_SEEK_SET, None) }.unwrap();
        let clone = unsafe { stream.Clone() }.unwrap();
        unsafe { stream.Seek(900, STREAM_SEEK_SET, None) }.unwrap();
        let mut first = [0_u8; 32];
        let mut second = [0_u8; 32];

        assert_eq!(
            unsafe { stream.Read(first.as_mut_ptr().cast::<c_void>(), 32, None) },
            S_OK
        );
        assert_eq!(
            unsafe { clone.Read(second.as_mut_ptr().cast::<c_void>(), 32, None) },
            S_OK
        );
        assert_eq!(first[0], generated_byte(900));
        assert_eq!(second[0], generated_byte(500));
        let metrics = wait_for_metrics(&server, |metrics| metrics.unique_bytes == 64);
        assert_eq!(metrics.unique_bytes, 64);
    }

    #[test]
    fn control_messages_pause_resume_and_terminally_cancel_reads() {
        let (server, _control, source) = server_and_source(1 << 20);
        let client = LoopbackControlClient::new(Arc::clone(&source));
        assert_eq!(client.pause().unwrap(), TransferControlState::Paused);
        let (sender, receiver) = mpsc::channel();
        let worker_source = Arc::clone(&source);
        let worker = std::thread::spawn(move || {
            let mut bytes = [0_u8; 32];
            sender.send(worker_source.read_at(0, &mut bytes)).unwrap();
        });
        std::thread::sleep(Duration::from_millis(30));
        assert!(receiver.try_recv().is_err());
        assert_eq!(server.metrics().served_bytes, 0);

        assert_eq!(client.resume().unwrap(), TransferControlState::Running);
        assert_eq!(
            receiver
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap(),
            32
        );
        worker.join().unwrap();
        assert_eq!(client.pause().unwrap(), TransferControlState::Paused);

        let (sender, receiver) = mpsc::channel();
        let worker_source = Arc::clone(&source);
        let worker = std::thread::spawn(move || {
            let mut bytes = [0_u8; 32];
            sender.send(worker_source.read_at(64, &mut bytes)).unwrap();
        });
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(client.cancel().unwrap(), TransferControlState::Cancelled);
        let error = receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code(), HRESULT::from_win32(ERROR_CANCELLED.0));
        worker.join().unwrap();
        assert_eq!(client.resume().unwrap(), TransferControlState::Cancelled);
    }

    #[test]
    fn competing_pause_resume_and_cancel_commands_end_in_cancelled_state() {
        let (server, control, source) = server_and_source(1 << 20);
        control.pause().unwrap();
        let client = Arc::new(LoopbackControlClient::new(Arc::clone(&source)));
        let barrier = Arc::new(Barrier::new(13));
        let mut workers = Vec::new();

        for index in 0..12 {
            let barrier = Arc::clone(&barrier);
            let client = Arc::clone(&client);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                match index % 3 {
                    0 => client.pause(),
                    1 => client.resume(),
                    _ => client.cancel(),
                }
            }));
        }
        barrier.wait();
        for worker in workers {
            let state = worker.join().unwrap().unwrap();
            assert!(matches!(
                state,
                TransferControlState::Running
                    | TransferControlState::Paused
                    | TransferControlState::Cancelled
            ));
        }

        assert_eq!(client.state().unwrap(), TransferControlState::Cancelled);
        let mut bytes = [0_u8; 32];
        let error = source.read_at(0, &mut bytes).unwrap_err();
        assert_eq!(error.code(), HRESULT::from_win32(ERROR_CANCELLED.0));
        assert!(server.metrics().max_concurrent_reads <= 1);
    }

    #[test]
    fn paused_read_has_a_bounded_client_timeout() {
        let control = Arc::new(TransferControl::default());
        let server = LoopbackServer::start(config(1 << 20), Arc::clone(&control)).unwrap();
        control.pause().unwrap();
        let source = TcpRangeSource::new(
            server.address(),
            LOOPBACK_FILE_ID,
            1 << 20,
            64 * 1024,
            Duration::from_secs(1),
            Duration::from_millis(60),
        )
        .unwrap();
        let mut bytes = [0_u8; 32];
        let started = Instant::now();
        let error = source.read_at(0, &mut bytes).unwrap_err();

        assert_eq!(error.code(), HRESULT::from_win32(ERROR_TIMEOUT.0));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn oversized_range_is_rejected_before_payload_allocation() {
        let (server, _control, _source) = server_and_source(1 << 20);
        let mut stream = std::net::TcpStream::connect(server.address()).unwrap();
        let request = RequestHeader {
            opcode: Opcode::ReadRange,
            request_id: 77,
            file_id: LOOPBACK_FILE_ID,
            offset: 0,
            length: 64 * 1024 + 1,
        };
        stream.write_all(&request.encode()).unwrap();
        let mut response = [0_u8; super::RESPONSE_HEADER_LEN];
        stream.read_exact(&mut response).unwrap();
        let response = ResponseHeader::decode(&response).unwrap();

        assert_eq!(response.status, ResponseStatus::InvalidRequest);
        assert_eq!(response.payload_length, 0);
        assert_eq!(server.metrics().served_bytes, 0);
    }

    #[test]
    fn malformed_and_disconnected_clients_do_not_break_the_server() {
        let (server, _control, source) = server_and_source(1 << 20);
        let mut malformed = std::net::TcpStream::connect(server.address()).unwrap();
        malformed.write_all(&[0_u8; REQUEST_HEADER_LEN]).unwrap();
        drop(malformed);

        let mut disconnected = std::net::TcpStream::connect(server.address()).unwrap();
        let request = RequestHeader {
            opcode: Opcode::ReadRange,
            request_id: 88,
            file_id: LOOPBACK_FILE_ID,
            offset: 0,
            length: 64 * 1024,
        };
        disconnected.write_all(&request.encode()).unwrap();
        drop(disconnected);

        let mut bytes = [0_u8; 64];
        assert_eq!(source.read_at(128, &mut bytes).unwrap(), 64);
        assert_eq!(bytes[0], generated_byte(128));
    }

    #[test]
    fn mid_payload_disconnect_is_an_error_and_a_new_connection_can_retry() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; REQUEST_HEADER_LEN];
                stream.read_exact(&mut request).unwrap();
                let request = RequestHeader::decode(&request).unwrap();
                let response = ResponseHeader {
                    status: ResponseStatus::Ok,
                    state: TransferControlState::Running,
                    request_id: request.request_id,
                    total_length: 1 << 20,
                    payload_length: request.length,
                };
                stream.write_all(&response.encode()).unwrap();
                let payload: Vec<u8> = (0..u64::from(request.length))
                    .map(|index| generated_byte(request.offset + index))
                    .collect();
                if attempt == 0 {
                    stream.write_all(&payload[..7]).unwrap();
                } else {
                    stream.write_all(&payload).unwrap();
                }
            }
        });
        let source = TcpRangeSource::new(
            address,
            LOOPBACK_FILE_ID,
            1 << 20,
            64 * 1024,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        let mut bytes = [0_u8; 1_024];

        let first = source.read_at(4_096, &mut bytes).unwrap_err();
        assert_eq!(
            first.code(),
            HRESULT::from_win32(super::ERROR_CONNECTION_ABORTED.0)
        );
        assert_eq!(source.read_at(4_096, &mut bytes).unwrap(), bytes.len());
        for (index, byte) in bytes.iter().enumerate() {
            assert_eq!(*byte, generated_byte(4_096 + index as u64));
        }
        server.join().unwrap();
    }

    #[test]
    fn worker_limit_rejects_excess_connections_and_recovers_capacity() {
        let control = Arc::new(TransferControl::default());
        let mut server_config = config(1 << 20);
        server_config.max_workers = 2;
        server_config.socket_timeout = Duration::from_millis(500);
        let server = LoopbackServer::start(server_config, Arc::clone(&control)).unwrap();
        let first = std::net::TcpStream::connect(server.address()).unwrap();
        let second = std::net::TcpStream::connect(server.address()).unwrap();
        let mut excess = std::net::TcpStream::connect(server.address()).unwrap();
        excess
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut byte = [0_u8; 1];

        assert!(excess.read(&mut byte).is_err() || excess.peek(&mut byte).unwrap_or(0) == 0);
        drop(first);
        drop(second);
        std::thread::sleep(Duration::from_millis(30));

        let source = TcpRangeSource::new(
            server.address(),
            LOOPBACK_FILE_ID,
            1 << 20,
            64 * 1024,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        let mut bytes = [0_u8; 32];
        assert_eq!(source.read_at(0, &mut bytes).unwrap(), bytes.len());
        assert!(server.metrics().protocol_errors >= 1);
    }

    #[test]
    fn concurrent_clients_are_served_without_a_global_io_lock() {
        let mut server_config = config(1 << 20);
        server_config.range_delay = Duration::from_millis(80);
        let control = Arc::new(TransferControl::default());
        let server = LoopbackServer::start(server_config, Arc::clone(&control)).unwrap();
        let source = Arc::new(
            TcpRangeSource::new(
                server.address(),
                LOOPBACK_FILE_ID,
                1 << 20,
                64 * 1024,
                Duration::from_secs(1),
                Duration::from_secs(1),
            )
            .unwrap(),
        );
        let barrier = Arc::new(Barrier::new(3));
        let spawn = |offset| {
            let source = Arc::clone(&source);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let mut bytes = [0_u8; 1_024];
                barrier.wait();
                source.read_at(offset, &mut bytes).unwrap();
                bytes
            })
        };
        let first = spawn(0);
        let second = spawn(4_096);
        barrier.wait();
        let first = first.join().unwrap();
        let second = second.join().unwrap();

        assert_eq!(first[0], generated_byte(0));
        assert_eq!(second[0], generated_byte(4_096));
        assert!(server.metrics().max_concurrent_reads >= 2);
    }

    #[test]
    fn zero_byte_and_large_logical_files_need_no_full_file_buffer() {
        let (zero_server, _control, zero_source) = server_and_source(0);
        let mut byte = [0_u8; 1];
        assert_eq!(zero_source.read_at(0, &mut byte).unwrap(), 0);
        assert_eq!(zero_server.metrics().connections, 0);

        let length = 10_u64 * 1024 * 1024 * 1024;
        let (large_server, _control, large_source) = server_and_source(length);
        let mut bytes = [0_u8; 4_096];
        assert_eq!(
            large_source.read_at(length - 4_096, &mut bytes).unwrap(),
            bytes.len()
        );
        assert_eq!(bytes[0], generated_byte(length - 4_096));
        assert_eq!(large_server.metrics().served_bytes, 4_096);
    }

    #[test]
    fn logical_coverage_tracking_is_bounded_and_marks_saturation() {
        let mut coverage = RangeCoverage::default();
        for index in 0..=MAX_TRACKED_RANGES {
            coverage.note(u64::try_from(index).unwrap() * 2, 1);
        }

        assert!(coverage.saturated);
        assert!(coverage.ranges.is_empty());
        assert_eq!(coverage.unique_bytes, MAX_TRACKED_RANGES as u64);
        coverage.note(0, u64::MAX);
        assert_eq!(coverage.unique_bytes, MAX_TRACKED_RANGES as u64);
    }

    #[test]
    fn client_rejects_an_oversized_response_payload() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; REQUEST_HEADER_LEN];
            stream.read_exact(&mut request).unwrap();
            let request = RequestHeader::decode(&request).unwrap();
            let response = ResponseHeader {
                status: ResponseStatus::Ok,
                state: TransferControlState::Running,
                request_id: request.request_id,
                total_length: 1 << 20,
                payload_length: request.length + 1,
            };
            stream.write_all(&response.encode()).unwrap();
        });
        let source = TcpRangeSource::new(
            address,
            LOOPBACK_FILE_ID,
            1 << 20,
            64 * 1024,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        let mut bytes = [0_u8; 32];
        let error = source.read_at(0, &mut bytes).unwrap_err();

        assert_eq!(error.code(), HRESULT::from_win32(ERROR_INVALID_DATA.0));
        server.join().unwrap();
    }

    #[test]
    fn invalid_server_and_client_limits_are_rejected() {
        let control = Arc::new(TransferControl::default());
        let mut invalid = config(1);
        invalid.fragment_bytes = invalid.max_range_bytes + 1;
        assert_eq!(
            LoopbackServer::start(invalid, Arc::clone(&control))
                .err()
                .unwrap()
                .code(),
            E_INVALIDARG
        );

        let mut invalid = config(1);
        invalid.max_workers = 0;
        assert_eq!(
            LoopbackServer::start(invalid, Arc::clone(&control))
                .err()
                .unwrap()
                .code(),
            E_INVALIDARG
        );

        assert_eq!(
            TcpRangeSource::new(
                "192.0.2.1:9".parse().unwrap(),
                LOOPBACK_FILE_ID,
                1,
                1,
                Duration::from_secs(1),
                Duration::from_secs(1),
            )
            .unwrap_err()
            .code(),
            E_INVALIDARG
        );
    }
}
