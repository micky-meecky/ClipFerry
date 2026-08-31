use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses,
    IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

use crate::app_settings::AppSettings;
use crate::device_store::DeviceStore;
use crate::security::CertificateFingerprint;

pub const DISCOVERY_PORT: u16 = 45_231;
pub const PAIRING_PORT: u16 = 45_232;
pub const SERVICE_PORT: u16 = 45_233;

const MAGIC: &[u8; 8] = b"CFDISC01";
const VERSION: u16 = 1;
const ANNOUNCEMENT: u8 = 1;
const RESPONSE: u8 = 2;
const HEADER_LENGTH: usize = 8 + 2 + 1 + 32 + 2 + 2 + 1;
const LABEL_LIMIT: usize = 63;
const PACKET_LIMIT: usize = HEADER_LENGTH + LABEL_LIMIT;
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(2);
const RECEIVE_TIMEOUT: Duration = Duration::from_millis(400);
const PEER_TTL: Duration = Duration::from_secs(12);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredPeer {
    pub fingerprint: CertificateFingerprint,
    pub label: String,
    pub service_endpoint: SocketAddr,
    pub pairing_endpoint: SocketAddr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Packet {
    kind: u8,
    fingerprint: CertificateFingerprint,
    service_port: u16,
    pairing_port: u16,
    label: String,
}

impl Packet {
    fn new(kind: u8, fingerprint: CertificateFingerprint, label: &str) -> Self {
        Self {
            kind,
            fingerprint,
            service_port: SERVICE_PORT,
            pairing_port: PAIRING_PORT,
            label: bounded_label(label),
        }
    }

    fn encode(&self) -> io::Result<Vec<u8>> {
        if !matches!(self.kind, ANNOUNCEMENT | RESPONSE)
            || self.service_port != SERVICE_PORT
            || self.pairing_port != PAIRING_PORT
        {
            return Err(invalid_data("invalid discovery packet fields"));
        }
        let label = self.label.as_bytes();
        if label.is_empty() || label.len() > LABEL_LIMIT {
            return Err(invalid_data("invalid discovery device label"));
        }
        let label_length = u8::try_from(label.len())
            .map_err(|_| invalid_data("discovery device label is too long"))?;
        let mut encoded = Vec::with_capacity(HEADER_LENGTH + label.len());
        encoded.extend_from_slice(MAGIC);
        encoded.extend_from_slice(&VERSION.to_le_bytes());
        encoded.push(self.kind);
        encoded.extend_from_slice(&self.fingerprint.bytes());
        encoded.extend_from_slice(&self.service_port.to_le_bytes());
        encoded.extend_from_slice(&self.pairing_port.to_le_bytes());
        encoded.push(label_length);
        encoded.extend_from_slice(label);
        Ok(encoded)
    }

    fn decode(encoded: &[u8]) -> io::Result<Self> {
        if encoded.len() < HEADER_LENGTH || encoded.len() > PACKET_LIMIT {
            return Err(invalid_data("invalid discovery packet length"));
        }
        if &encoded[..8] != MAGIC {
            return Err(invalid_data("discovery packet magic mismatch"));
        }
        if u16::from_le_bytes([encoded[8], encoded[9]]) != VERSION {
            return Err(invalid_data("unsupported discovery packet version"));
        }
        let kind = encoded[10];
        if !matches!(kind, ANNOUNCEMENT | RESPONSE) {
            return Err(invalid_data("unknown discovery packet kind"));
        }
        let mut fingerprint = [0_u8; 32];
        fingerprint.copy_from_slice(&encoded[11..43]);
        let service_port = u16::from_le_bytes([encoded[43], encoded[44]]);
        let pairing_port = u16::from_le_bytes([encoded[45], encoded[46]]);
        if service_port != SERVICE_PORT || pairing_port != PAIRING_PORT {
            return Err(invalid_data(
                "discovery packet contains unsupported service ports",
            ));
        }
        let label_length = usize::from(encoded[47]);
        if label_length == 0
            || label_length > LABEL_LIMIT
            || encoded.len() != HEADER_LENGTH + label_length
        {
            return Err(invalid_data("invalid discovery device label length"));
        }
        let label = std::str::from_utf8(&encoded[HEADER_LENGTH..])
            .map_err(|_| invalid_data("discovery device label is not UTF-8"))?;
        if label.chars().any(char::is_control) {
            return Err(invalid_data(
                "discovery device label contains control characters",
            ));
        }
        Ok(Self {
            kind,
            fingerprint: CertificateFingerprint::from_bytes(fingerprint),
            service_port,
            pairing_port,
            label: label.to_owned(),
        })
    }
}

#[derive(Clone)]
struct SeenPeer {
    peer: DiscoveredPeer,
    last_seen: Instant,
}

#[derive(Clone)]
pub struct DiscoveryView {
    peers: Arc<Mutex<HashMap<CertificateFingerprint, SeenPeer>>>,
}

impl DiscoveryView {
    #[must_use]
    pub fn peers(&self) -> Vec<DiscoveredPeer> {
        let now = Instant::now();
        let Ok(mut peers) = self.peers.lock() else {
            return Vec::new();
        };
        peers.retain(|_, peer| now.saturating_duration_since(peer.last_seen) <= PEER_TTL);
        let mut result = peers
            .values()
            .map(|peer| peer.peer.clone())
            .collect::<Vec<_>>();
        result.sort_by(|left, right| {
            left.label.cmp(&right.label).then_with(|| {
                left.fingerprint
                    .to_string()
                    .cmp(&right.fingerprint.to_string())
            })
        });
        result
    }

    #[must_use]
    pub fn peer(&self, fingerprint: CertificateFingerprint) -> Option<DiscoveredPeer> {
        self.peers()
            .into_iter()
            .find(|peer| peer.fingerprint == fingerprint)
    }
}

pub struct DiscoveryRuntime {
    view: DiscoveryView,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl DiscoveryRuntime {
    /// Starts the bounded local-LAN discovery worker.
    ///
    /// Discovery packets contain only a public certificate fingerprint, a bounded device label,
    /// and service ports. They are address hints, never trust assertions.
    ///
    /// # Errors
    ///
    /// Returns an error when identity loading, UDP binding, socket configuration, or worker
    /// creation fails.
    pub fn start(store: DeviceStore) -> io::Result<Self> {
        let identity = store.load_or_create_identity()?.identity;
        let fingerprint = identity.fingerprint();
        let label = local_device_label();
        let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, DISCOVERY_PORT)))?;
        socket.set_broadcast(true)?;
        socket.set_read_timeout(Some(RECEIVE_TIMEOUT))?;
        let peers = Arc::new(Mutex::new(HashMap::new()));
        let view = DiscoveryView {
            peers: Arc::clone(&peers),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::Builder::new()
            .name("clipferry-discovery".to_owned())
            .spawn(move || {
                discovery_loop(&socket, &store, fingerprint, &label, &peers, &worker_stop);
            })?;
        Ok(Self {
            view,
            stop,
            worker: Some(worker),
        })
    }

    #[must_use]
    pub fn view(&self) -> DiscoveryView {
        self.view.clone()
    }
}

impl Drop for DiscoveryRuntime {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).and_then(|socket| {
            socket.send_to(
                &[0],
                SocketAddr::from((Ipv4Addr::LOCALHOST, DISCOVERY_PORT)),
            )?;
            Ok(())
        });
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn discovery_loop(
    socket: &UdpSocket,
    store: &DeviceStore,
    fingerprint: CertificateFingerprint,
    label: &str,
    peers: &Arc<Mutex<HashMap<CertificateFingerprint, SeenPeer>>>,
    stop: &AtomicBool,
) {
    let announcement = Packet::new(ANNOUNCEMENT, fingerprint, label)
        .encode()
        .expect("local discovery packet must be valid");
    let response = Packet::new(RESPONSE, fingerprint, label)
        .encode()
        .expect("local discovery packet must be valid");
    let mut last_announcement = Instant::now()
        .checked_sub(ANNOUNCE_INTERVAL)
        .unwrap_or_else(Instant::now);
    let mut buffer = [0_u8; PACKET_LIMIT + 1];
    while !stop.load(Ordering::Acquire) {
        if last_announcement.elapsed() >= ANNOUNCE_INTERVAL {
            for target in discovery_broadcast_targets() {
                let _ = socket.send_to(&announcement, target);
            }
            last_announcement = Instant::now();
        }
        match socket.recv_from(&mut buffer) {
            Ok((length, source)) => {
                if let Ok(packet) = Packet::decode(&buffer[..length]) {
                    if packet.fingerprint == fingerprint || !is_private_or_loopback(source.ip()) {
                        continue;
                    }
                    let discovered = DiscoveredPeer {
                        fingerprint: packet.fingerprint,
                        label: packet.label,
                        service_endpoint: SocketAddr::new(source.ip(), packet.service_port),
                        pairing_endpoint: SocketAddr::new(source.ip(), packet.pairing_port),
                    };
                    if let Ok(mut known) = peers.lock() {
                        known.insert(
                            discovered.fingerprint,
                            SeenPeer {
                                peer: discovered.clone(),
                                last_seen: Instant::now(),
                            },
                        );
                    }
                    reconcile_trusted_endpoint(store, &discovered);
                    if packet.kind == ANNOUNCEMENT {
                        let _ = socket.send_to(&response, source);
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn discovery_broadcast_targets() -> Vec<SocketAddr> {
    let mut targets = local_private_ipv4_interfaces()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(address, prefix_length)| directed_broadcast(address, prefix_length))
        .map(|address| SocketAddr::from((address, DISCOVERY_PORT)))
        .collect::<Vec<_>>();
    targets.push(SocketAddr::from((Ipv4Addr::BROADCAST, DISCOVERY_PORT)));
    targets.sort_unstable();
    targets.dedup();
    targets
}

fn directed_broadcast(address: Ipv4Addr, prefix_length: u8) -> Option<Ipv4Addr> {
    if !address.is_private() || prefix_length > 30 {
        return None;
    }
    let mask = u32::MAX.checked_shl(u32::from(32 - prefix_length))?;
    Some(Ipv4Addr::from(u32::from(address) | !mask))
}

fn local_private_ipv4_interfaces() -> io::Result<Vec<(Ipv4Addr, u8)>> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut byte_length = 15_000_u32;
    loop {
        let word_length = usize::try_from(byte_length)
            .map_err(|_| invalid_data("adapter address buffer is too large"))?
            .div_ceil(size_of::<usize>());
        let mut buffer = vec![0_usize; word_length];
        // SAFETY: the buffer is writable, pointer-aligned, and remains alive while Windows fills
        // and links the adapter records contained within it.
        let result = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_INET.0),
                flags,
                None,
                Some(buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>()),
                &raw mut byte_length,
            )
        };
        if result == ERROR_BUFFER_OVERFLOW.0 {
            continue;
        }
        if result != NO_ERROR.0 {
            return Err(io::Error::from_raw_os_error(
                i32::try_from(result).unwrap_or(i32::MAX),
            ));
        }
        // SAFETY: a successful GetAdaptersAddresses call initialized a linked list entirely
        // inside `buffer`; it stays allocated for the full traversal.
        return Ok(unsafe {
            collect_private_ipv4_interfaces(buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>())
        });
    }
}

unsafe fn collect_private_ipv4_interfaces(
    mut adapter: *const IP_ADAPTER_ADDRESSES_LH,
) -> Vec<(Ipv4Addr, u8)> {
    let mut interfaces = Vec::new();
    while let Some(current) = unsafe { adapter.as_ref() } {
        if current.OperStatus == IfOperStatusUp {
            let mut unicast = current.FirstUnicastAddress.cast_const();
            while let Some(address) = unsafe { unicast.as_ref() } {
                let socket_address = address.Address;
                if socket_address.iSockaddrLength
                    >= i32::try_from(size_of::<SOCKADDR_IN>()).unwrap_or(i32::MAX)
                    && !socket_address.lpSockaddr.is_null()
                {
                    // SAFETY: the length check above establishes a complete SOCKADDR_IN, and
                    // GetAdaptersAddresses guarantees the pointer lives in the returned buffer.
                    let ipv4 = unsafe {
                        std::ptr::read_unaligned(socket_address.lpSockaddr.cast::<SOCKADDR_IN>())
                    };
                    if ipv4.sin_family == AF_INET {
                        // SAFETY: AF_INET makes the IPv4 byte view of IN_ADDR active.
                        let bytes = unsafe { ipv4.sin_addr.S_un.S_un_b };
                        let value = Ipv4Addr::new(bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4);
                        if value.is_private() && address.OnLinkPrefixLength <= 32 {
                            interfaces.push((value, address.OnLinkPrefixLength));
                        }
                    }
                }
                unicast = address.Next.cast_const();
            }
        }
        adapter = current.Next.cast_const();
    }
    interfaces.sort_unstable();
    interfaces.dedup();
    interfaces
}

fn reconcile_trusted_endpoint(store: &DeviceStore, peer: &DiscoveredPeer) {
    if store.load_peer(peer.fingerprint).is_err() {
        return;
    }
    let existing = AppSettings::load(store).ok();
    if existing
        .as_ref()
        .is_some_and(|settings| settings.active_peer != peer.fingerprint)
    {
        return;
    }
    let Ok(local_ip) = route_local_ip(peer.service_endpoint) else {
        return;
    };
    let settings = AppSettings {
        local_endpoint: SocketAddr::new(local_ip, SERVICE_PORT),
        active_peer: peer.fingerprint,
        peer_endpoint: peer.service_endpoint,
        auto_receive: existing
            .as_ref()
            .is_none_or(|settings| settings.auto_receive),
    };
    if existing.as_ref() == Some(&settings) || settings.save(store).is_err() {
        return;
    }
    let _ = crate::tray::reload_existing();
}

/// Persists one already-trusted discovered peer as the active automatic LAN connection.
///
/// # Errors
///
/// Returns an error when the trust record is missing, no private route exists, or settings cannot
/// be validated and saved.
pub fn activate_discovered_peer(store: &DeviceStore, peer: &DiscoveredPeer) -> io::Result<()> {
    store.load_peer(peer.fingerprint)?;
    let local_ip = route_local_ip(peer.service_endpoint)?;
    AppSettings {
        local_endpoint: SocketAddr::new(local_ip, SERVICE_PORT),
        active_peer: peer.fingerprint,
        peer_endpoint: peer.service_endpoint,
        auto_receive: true,
    }
    .save(store)
}

fn route_local_ip(peer: SocketAddr) -> io::Result<IpAddr> {
    let bind = match peer {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => "[::]:0".parse().expect("valid IPv6 wildcard endpoint"),
    };
    let socket = UdpSocket::bind(bind)?;
    socket.connect(peer)?;
    let address = socket.local_addr()?.ip();
    if is_private_or_loopback(address) {
        Ok(address)
    } else {
        Err(invalid_data(
            "the discovered peer has no private local route",
        ))
    }
}

fn local_device_label() -> String {
    std::env::var("COMPUTERNAME")
        .ok()
        .map_or_else(|| "Windows 设备".to_owned(), |label| bounded_label(&label))
}

fn bounded_label(label: &str) -> String {
    let cleaned = label
        .trim()
        .chars()
        .filter(|character| !character.is_control())
        .collect::<String>();
    let source = if cleaned.is_empty() {
        "Windows 设备"
    } else {
        &cleaned
    };
    let mut result = String::new();
    for character in source.chars() {
        if result.len() + character.len_utf8() > LABEL_LIMIT {
            break;
        }
        result.push(character);
    }
    result
}

fn is_private_or_loopback(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_loopback() || address.is_private(),
        IpAddr::V6(address) => address.is_loopback() || address.is_unique_local(),
    }
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_round_trip_is_strict() {
        let fingerprint = CertificateFingerprint::from_certificate(b"peer");
        let packet = Packet::new(ANNOUNCEMENT, fingerprint, "测试电脑-🚢");
        let encoded = packet.encode().unwrap();
        assert_eq!(Packet::decode(&encoded).unwrap(), packet);

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(Packet::decode(&trailing).is_err());
        assert!(Packet::decode(&encoded[..HEADER_LENGTH - 1]).is_err());

        let mut wrong_port = encoded;
        wrong_port[43..45].copy_from_slice(&45_999_u16.to_le_bytes());
        assert!(Packet::decode(&wrong_port).is_err());
    }

    #[test]
    fn bounded_label_preserves_utf8_boundaries() {
        let label = bounded_label(&format!("{}🚢", "a".repeat(LABEL_LIMIT - 1)));
        assert!(label.len() <= LABEL_LIMIT);
        assert!(label.is_char_boundary(label.len()));
    }

    #[test]
    fn discovery_rejects_public_sources() {
        assert!(is_private_or_loopback("127.0.0.1".parse().unwrap()));
        assert!(is_private_or_loopback("192.168.1.2".parse().unwrap()));
        assert!(!is_private_or_loopback("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn directed_broadcast_uses_each_interface_prefix() {
        assert_eq!(
            directed_broadcast("192.168.137.1".parse().unwrap(), 24),
            Some("192.168.137.255".parse().unwrap())
        );
        assert_eq!(
            directed_broadcast("172.20.144.1".parse().unwrap(), 20),
            Some("172.20.159.255".parse().unwrap())
        );
        assert_eq!(directed_broadcast("8.8.8.8".parse().unwrap(), 24), None);
        assert_eq!(
            directed_broadcast("192.168.137.1".parse().unwrap(), 31),
            None
        );
    }

    #[test]
    fn adapter_enumeration_returns_only_usable_private_ipv4_addresses() {
        for (address, prefix_length) in local_private_ipv4_interfaces().unwrap() {
            assert!(address.is_private());
            assert!(prefix_length <= 32);
        }
    }
}
