use std::fmt::Write as _;
use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use rustls::{ClientConnection, ServerConnection, StreamOwned};
use sha2::{Digest as _, Sha256};

use crate::device_store::{DeviceStore, TrustedPeer};
use crate::security::{CertificateFingerprint, PinnedTlsClient, PinnedTlsServer};

const HELLO_MAGIC: &[u8; 8] = b"CFPAIR01";
const PROOF_MAGIC: &[u8; 8] = b"CFPROOF1";
const CONFIRM_MAGIC: &[u8; 8] = b"CFPCNF01";
const TRANSCRIPT_DOMAIN: &[u8] = b"ClipFerry pairing transcript v1";
const PAIRING_VERSION: u16 = 1;
const NONCE_LENGTH: usize = 32;
const CERTIFICATE_LIMIT: usize = 64 * 1024;
const HELLO_HEADER_LENGTH: usize = 8 + 2 + 1 + NONCE_LENGTH + 4;
const CONFIRM_LENGTH: usize = 8 + 32 + 1;
const PROOF_LENGTH: usize = 8 + 32;
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role {
    Listener = 1,
    Connector = 2,
}

impl TryFrom<u8> for Role {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Listener),
            2 => Ok(Self::Connector),
            _ => Err(invalid_data("pairing hello contains an unknown role")),
        }
    }
}

#[derive(Clone, Debug)]
struct Hello {
    role: Role,
    nonce: [u8; NONCE_LENGTH],
    certificate: Vec<u8>,
}

impl Hello {
    fn create(role: Role, certificate: Vec<u8>) -> io::Result<Self> {
        validate_certificate(&certificate)?;
        let mut nonce = [0_u8; NONCE_LENGTH];
        getrandom::fill(&mut nonce).map_err(|error| {
            io::Error::other(format!("random nonce generation failed: {error}"))
        })?;
        Ok(Self {
            role,
            nonce,
            certificate,
        })
    }

    fn encode(&self) -> io::Result<Vec<u8>> {
        let certificate_length = u32::try_from(self.certificate.len())
            .map_err(|_| invalid_data("pairing certificate length does not fit the protocol"))?;
        let mut encoded = Vec::with_capacity(HELLO_HEADER_LENGTH + self.certificate.len());
        encoded.extend_from_slice(HELLO_MAGIC);
        encoded.extend_from_slice(&PAIRING_VERSION.to_le_bytes());
        encoded.push(self.role as u8);
        encoded.extend_from_slice(&self.nonce);
        encoded.extend_from_slice(&certificate_length.to_le_bytes());
        encoded.extend_from_slice(&self.certificate);
        Ok(encoded)
    }

    fn write_to(&self, stream: &mut impl io::Write) -> io::Result<()> {
        stream.write_all(&self.encode()?)?;
        stream.flush()
    }

    fn read_from(stream: &mut impl io::Read, expected_role: Role) -> io::Result<Self> {
        let mut header = [0_u8; HELLO_HEADER_LENGTH];
        stream.read_exact(&mut header)?;
        if &header[..8] != HELLO_MAGIC {
            return Err(invalid_data("pairing hello magic mismatch"));
        }
        let version = u16::from_le_bytes([header[8], header[9]]);
        if version != PAIRING_VERSION {
            return Err(invalid_data(format!(
                "unsupported pairing version {version}"
            )));
        }
        let role = Role::try_from(header[10])?;
        if role != expected_role {
            return Err(invalid_data("pairing hello role mismatch"));
        }
        let mut nonce = [0_u8; NONCE_LENGTH];
        nonce.copy_from_slice(&header[11..11 + NONCE_LENGTH]);
        let length_offset = 11 + NONCE_LENGTH;
        let certificate_length = usize::try_from(u32::from_le_bytes(
            header[length_offset..length_offset + 4]
                .try_into()
                .map_err(|_| invalid_data("truncated pairing certificate length"))?,
        ))
        .map_err(|_| invalid_data("pairing certificate length does not fit this platform"))?;
        if certificate_length == 0 || certificate_length > CERTIFICATE_LIMIT {
            return Err(invalid_data(format!(
                "pairing certificate length must be between 1 and {CERTIFICATE_LIMIT} bytes"
            )));
        }
        let mut certificate = vec![0_u8; certificate_length];
        stream.read_exact(&mut certificate)?;
        Ok(Self {
            role,
            nonce,
            certificate,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingCode([u8; 8]);

impl std::fmt::Display for PairingCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, chunk) in self.0.chunks_exact(2).enumerate() {
            if index != 0 {
                formatter.write_char('-')?;
            }
            write!(formatter, "{:02X}{:02X}", chunk[0], chunk[1])?;
        }
        Ok(())
    }
}

enum PairingStream {
    Client(StreamOwned<ClientConnection, TcpStream>),
    Server(StreamOwned<ServerConnection, TcpStream>),
}

impl io::Read for PairingStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Client(stream) => stream.read(buffer),
            Self::Server(stream) => stream.read(buffer),
        }
    }
}

impl io::Write for PairingStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Client(stream) => stream.write(buffer),
            Self::Server(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Client(stream) => stream.flush(),
            Self::Server(stream) => stream.flush(),
        }
    }
}

pub struct PendingPairing {
    store: DeviceStore,
    stream: PairingStream,
    peer_address: SocketAddr,
    local_fingerprint: CertificateFingerprint,
    peer_fingerprint: CertificateFingerprint,
    peer_certificate: Vec<u8>,
    transcript_hash: [u8; 32],
    code: PairingCode,
}

impl PendingPairing {
    #[must_use]
    pub fn code(&self) -> PairingCode {
        self.code
    }

    #[must_use]
    pub fn peer_address(&self) -> SocketAddr {
        self.peer_address
    }

    #[must_use]
    pub fn local_fingerprint(&self) -> CertificateFingerprint {
        self.local_fingerprint
    }

    #[must_use]
    pub fn peer_fingerprint(&self) -> CertificateFingerprint {
        self.peer_fingerprint
    }

    /// Exchanges transcript-bound decisions inside the newly pinned mutual-TLS channel.
    ///
    /// The peer is persisted only when both users approved the same pairing session.
    ///
    /// # Errors
    ///
    /// Returns an error for rejection, timeout, transcript mismatch, identity replacement, or
    /// trust-registry persistence failures.
    pub fn confirm(mut self, local_approved: bool, peer_label: &str) -> io::Result<TrustedPeer> {
        let mut message = [0_u8; CONFIRM_LENGTH];
        message[..8].copy_from_slice(CONFIRM_MAGIC);
        message[8..40].copy_from_slice(&self.transcript_hash);
        message[40] = u8::from(local_approved);
        self.stream.write_all(&message)?;
        self.stream.flush()?;

        let mut remote = [0_u8; CONFIRM_LENGTH];
        self.stream.read_exact(&mut remote)?;
        if &remote[..8] != CONFIRM_MAGIC || remote[8..40] != self.transcript_hash {
            return Err(invalid_data("pairing confirmation transcript mismatch"));
        }
        if remote[40] > 1 {
            return Err(invalid_data("pairing confirmation decision is invalid"));
        }
        if !local_approved || remote[40] == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "pairing was not approved on both devices",
            ));
        }
        let current_identity = self.store.load_identity()?;
        if current_identity.fingerprint() != self.local_fingerprint {
            return Err(invalid_data("local device identity changed during pairing"));
        }
        self.store
            .trust_peer(self.peer_certificate, self.peer_fingerprint, peer_label)
    }
}

/// Accepts one bounded first-pairing session on a loopback or private address.
///
/// The raw hello contains only public certificates and nonces. The same socket is then upgraded
/// to TLS 1.3 with exact mutual certificate pins before a [`PendingPairing`] is returned.
///
/// # Errors
///
/// Returns an error for an unsafe address, timeout, protocol violation, or TLS proof failure.
pub fn listen_for_pairing(
    store: DeviceStore,
    address: SocketAddr,
    timeout: Duration,
) -> io::Result<PendingPairing> {
    validate_listener_endpoint(address)?;
    validate_timeout(timeout)?;
    let stored = store.load_or_create_identity()?;
    let local = Hello::create(Role::Listener, stored.identity.certificate_der().to_vec())?;
    let listener = TcpListener::bind(address)?;
    listener.set_nonblocking(true)?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| invalid_data("pairing timeout overflow"))?;
    let (mut socket, peer_address) = loop {
        match listener.accept() {
            Ok(pair) => break pair,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "pairing listener timed out",
                    ));
                }
                std::thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    };
    validate_peer_address(peer_address.ip())?;
    configure_pairing_socket(&socket, timeout)?;
    let remote = Hello::read_from(&mut socket, Role::Connector)?;
    local.write_to(&mut socket)?;
    let transcript_hash = pairing_transcript(&local, &remote)?;
    let peer_fingerprint = CertificateFingerprint::from_certificate(&remote.certificate);
    let tls = PinnedTlsServer::new(
        &stored.identity,
        remote.certificate.clone(),
        peer_fingerprint,
        timeout,
    )?;
    let mut stream = PairingStream::Server(tls.accept(socket)?);
    exchange_tls_proof(&mut stream, transcript_hash)?;
    Ok(PendingPairing {
        store,
        stream,
        peer_address,
        local_fingerprint: stored.identity.fingerprint(),
        peer_fingerprint,
        peer_certificate: remote.certificate,
        transcript_hash,
        code: pairing_code(transcript_hash),
    })
}

/// Connects to one first-pairing listener and proves the generated device identity with TLS 1.3.
///
/// # Errors
///
/// Returns an error for an unsafe address, timeout, protocol violation, or TLS proof failure.
pub fn connect_for_pairing(
    store: DeviceStore,
    address: SocketAddr,
    timeout: Duration,
) -> io::Result<PendingPairing> {
    validate_endpoint(address)?;
    validate_timeout(timeout)?;
    let stored = store.load_or_create_identity()?;
    let local = Hello::create(Role::Connector, stored.identity.certificate_der().to_vec())?;
    let mut socket = TcpStream::connect_timeout(&address, timeout)?;
    configure_pairing_socket(&socket, timeout)?;
    let peer_address = socket.peer_addr()?;
    validate_peer_address(peer_address.ip())?;
    local.write_to(&mut socket)?;
    let remote = Hello::read_from(&mut socket, Role::Listener)?;
    let transcript_hash = pairing_transcript(&remote, &local)?;
    let peer_fingerprint = CertificateFingerprint::from_certificate(&remote.certificate);
    let tls = PinnedTlsClient::new(
        &stored.identity,
        remote.certificate.clone(),
        peer_fingerprint,
        timeout,
    )?;
    let mut stream = PairingStream::Client(tls.connect_socket(socket)?);
    exchange_tls_proof(&mut stream, transcript_hash)?;
    Ok(PendingPairing {
        store,
        stream,
        peer_address,
        local_fingerprint: stored.identity.fingerprint(),
        peer_fingerprint,
        peer_certificate: remote.certificate,
        transcript_hash,
        code: pairing_code(transcript_hash),
    })
}

fn pairing_transcript(listener: &Hello, connector: &Hello) -> io::Result<[u8; 32]> {
    if listener.role != Role::Listener || connector.role != Role::Connector {
        return Err(invalid_data("pairing transcript roles are not canonical"));
    }
    let mut digest = Sha256::new();
    digest.update(TRANSCRIPT_DOMAIN);
    digest.update(listener.encode()?);
    digest.update(connector.encode()?);
    Ok(digest.finalize().into())
}

fn pairing_code(transcript_hash: [u8; 32]) -> PairingCode {
    let mut code = [0_u8; 8];
    code.copy_from_slice(&transcript_hash[..8]);
    PairingCode(code)
}

fn exchange_tls_proof(stream: &mut PairingStream, transcript_hash: [u8; 32]) -> io::Result<()> {
    let mut proof = [0_u8; PROOF_LENGTH];
    proof[..8].copy_from_slice(PROOF_MAGIC);
    proof[8..].copy_from_slice(&transcript_hash);
    stream.write_all(&proof)?;
    stream.flush()?;
    let mut remote = [0_u8; PROOF_LENGTH];
    stream.read_exact(&mut remote)?;
    if remote != proof {
        return Err(invalid_data("pairing TLS proof transcript mismatch"));
    }
    Ok(())
}

fn configure_pairing_socket(socket: &TcpStream, timeout: Duration) -> io::Result<()> {
    socket.set_nonblocking(false)?;
    socket.set_nodelay(true)?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))
}

fn validate_timeout(timeout: Duration) -> io::Result<()> {
    if timeout.is_zero() || timeout > Duration::from_mins(5) {
        return Err(invalid_data(
            "pairing timeout must be between 1 millisecond and 300 seconds",
        ));
    }
    Ok(())
}

fn validate_endpoint(address: SocketAddr) -> io::Result<()> {
    if address.port() == 0 {
        return Err(invalid_data("pairing endpoint port must not be zero"));
    }
    validate_peer_address(address.ip())
}

fn validate_listener_endpoint(address: SocketAddr) -> io::Result<()> {
    if address.port() == 0 {
        return Err(invalid_data("pairing listener port must not be zero"));
    }
    if address.ip().is_unspecified() {
        Ok(())
    } else {
        validate_peer_address(address.ip())
    }
}

fn validate_peer_address(address: IpAddr) -> io::Result<()> {
    let allowed = match address {
        IpAddr::V4(address) => address.is_loopback() || address.is_private(),
        IpAddr::V6(address) => address.is_loopback() || address.is_unique_local(),
    };
    if allowed {
        Ok(())
    } else {
        Err(invalid_data(
            "pairing is restricted to loopback or private unicast addresses",
        ))
    }
}

fn validate_certificate(certificate: &[u8]) -> io::Result<()> {
    if certificate.is_empty() || certificate.len() > CERTIFICATE_LIMIT {
        return Err(invalid_data(format!(
            "pairing certificate length must be between 1 and {CERTIFICATE_LIMIT} bytes"
        )));
    }
    Ok(())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::thread;

    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(name: &str) -> Self {
            let mut random = [0_u8; 8];
            getrandom::fill(&mut random).unwrap();
            let path = std::env::temp_dir().join(format!(
                "clipferry-pairing-{name}-{}-{}",
                std::process::id(),
                u64::from_le_bytes(random)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn listener_address() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        address
    }

    #[test]
    fn wildcard_is_allowed_only_for_the_local_listener() {
        let wildcard = "0.0.0.0:45232".parse().unwrap();
        assert!(validate_listener_endpoint(wildcard).is_ok());
        assert!(validate_endpoint(wildcard).is_err());
        assert!(validate_listener_endpoint("0.0.0.0:0".parse().unwrap()).is_err());
    }

    #[test]
    fn both_approved_pairing_persists_exact_mutual_trust() {
        let first = TestDirectory::new("approved-a");
        let second = TestDirectory::new("approved-b");
        let first_store = DeviceStore::new(&first.0);
        let second_store = DeviceStore::new(&second.0);
        let address = listener_address();
        let server_store = first_store.clone();
        let server = thread::spawn(move || {
            listen_for_pairing(server_store, address, Duration::from_secs(5)).unwrap()
        });
        let client =
            connect_for_pairing(second_store.clone(), address, Duration::from_secs(5)).unwrap();
        let listener = server.join().unwrap();
        assert_eq!(listener.code(), client.code());
        assert_eq!(listener.local_fingerprint(), client.peer_fingerprint());
        assert_eq!(listener.peer_fingerprint(), client.local_fingerprint());

        let server_confirm = thread::spawn(move || listener.confirm(true, "Second PC").unwrap());
        let client_peer = client.confirm(true, "First PC").unwrap();
        let server_peer = server_confirm.join().unwrap();
        assert_eq!(
            first_store
                .load_peer(server_peer.fingerprint)
                .unwrap()
                .label,
            "Second PC"
        );
        assert_eq!(
            second_store
                .load_peer(client_peer.fingerprint)
                .unwrap()
                .label,
            "First PC"
        );
    }

    #[test]
    fn either_side_rejecting_persists_no_trust() {
        let first = TestDirectory::new("rejected-a");
        let second = TestDirectory::new("rejected-b");
        let first_store = DeviceStore::new(&first.0);
        let second_store = DeviceStore::new(&second.0);
        let address = listener_address();
        let server_store = first_store.clone();
        let server = thread::spawn(move || {
            listen_for_pairing(server_store, address, Duration::from_secs(5)).unwrap()
        });
        let client =
            connect_for_pairing(second_store.clone(), address, Duration::from_secs(5)).unwrap();
        let listener = server.join().unwrap();
        let server_confirm = thread::spawn(move || listener.confirm(false, "Second PC"));
        assert!(client.confirm(true, "First PC").is_err());
        assert!(server_confirm.join().unwrap().is_err());
        assert!(first_store.list_peers().unwrap().is_empty());
        assert!(second_store.list_peers().unwrap().is_empty());
    }

    #[test]
    fn fresh_pairing_sessions_have_distinct_transcript_codes() {
        let first = TestDirectory::new("fresh-a");
        let second = TestDirectory::new("fresh-b");
        let first_store = DeviceStore::new(&first.0);
        let second_store = DeviceStore::new(&second.0);
        let run = || {
            let address = listener_address();
            let server_store = first_store.clone();
            let server = thread::spawn(move || {
                listen_for_pairing(server_store, address, Duration::from_secs(5)).unwrap()
            });
            let client =
                connect_for_pairing(second_store.clone(), address, Duration::from_secs(5)).unwrap();
            let listener = server.join().unwrap();
            let code = client.code();
            let server_reject = thread::spawn(move || listener.confirm(false, "Second PC"));
            assert!(client.confirm(false, "First PC").is_err());
            assert!(server_reject.join().unwrap().is_err());
            code
        };
        assert_ne!(run(), run());
    }

    #[test]
    fn advertising_a_certificate_without_its_private_key_fails_before_confirmation() {
        let listener_directory = TestDirectory::new("proof-listener");
        let advertised_directory = TestDirectory::new("proof-advertised");
        let unrelated_directory = TestDirectory::new("proof-unrelated");
        let listener_store = DeviceStore::new(&listener_directory.0);
        let advertised = DeviceStore::new(&advertised_directory.0)
            .load_or_create_identity()
            .unwrap()
            .identity;
        let unrelated = DeviceStore::new(&unrelated_directory.0)
            .load_or_create_identity()
            .unwrap()
            .identity;
        let address = listener_address();
        let server_store = listener_store.clone();
        let server = thread::spawn(move || {
            listen_for_pairing(server_store, address, Duration::from_secs(5))
        });

        let mut socket = TcpStream::connect(address).unwrap();
        configure_pairing_socket(&socket, Duration::from_secs(5)).unwrap();
        let hello = Hello::create(Role::Connector, advertised.certificate_der().to_vec()).unwrap();
        hello.write_to(&mut socket).unwrap();
        let remote = Hello::read_from(&mut socket, Role::Listener).unwrap();
        let peer_fingerprint = CertificateFingerprint::from_certificate(&remote.certificate);
        let tls = PinnedTlsClient::new(
            &unrelated,
            remote.certificate,
            peer_fingerprint,
            Duration::from_secs(5),
        )
        .unwrap();
        let client_result = tls.connect_socket(socket).and_then(|mut stream| {
            stream.write_all(b"PAIR")?;
            stream.flush()?;
            let mut response = [0_u8; 1];
            stream.read_exact(&mut response)
        });
        assert!(client_result.is_err());
        assert!(server.join().unwrap().is_err());
        assert!(listener_store.list_peers().unwrap().is_empty());
    }

    #[test]
    fn active_terminating_mitm_produces_different_codes_and_no_trust_when_rejected() {
        let listener_directory = TestDirectory::new("mitm-listener");
        let connector_directory = TestDirectory::new("mitm-connector");
        let attacker_directory = TestDirectory::new("mitm-attacker");
        let listener_store = DeviceStore::new(&listener_directory.0);
        let connector_store = DeviceStore::new(&connector_directory.0);
        let attacker_store = DeviceStore::new(&attacker_directory.0);

        let target_address = listener_address();
        let listener_thread = {
            let store = listener_store.clone();
            thread::spawn(move || {
                listen_for_pairing(store, target_address, Duration::from_secs(5)).unwrap()
            })
        };
        let attacker_as_connector = connect_for_pairing(
            attacker_store.clone(),
            target_address,
            Duration::from_secs(5),
        )
        .unwrap();
        let real_listener = listener_thread.join().unwrap();

        let attacker_address = listener_address();
        let attacker_thread = {
            let store = attacker_store.clone();
            thread::spawn(move || {
                listen_for_pairing(store, attacker_address, Duration::from_secs(5)).unwrap()
            })
        };
        let real_connector = connect_for_pairing(
            connector_store.clone(),
            attacker_address,
            Duration::from_secs(5),
        )
        .unwrap();
        let attacker_as_listener = attacker_thread.join().unwrap();

        assert_ne!(real_listener.code(), real_connector.code());

        let listener_reject =
            thread::spawn(move || real_listener.confirm(false, "Expected connector"));
        assert!(
            attacker_as_connector
                .confirm(false, "Target listener")
                .is_err()
        );
        assert!(listener_reject.join().unwrap().is_err());

        let attacker_reject =
            thread::spawn(move || attacker_as_listener.confirm(false, "Target connector"));
        assert!(real_connector.confirm(false, "Expected listener").is_err());
        assert!(attacker_reject.join().unwrap().is_err());

        assert!(listener_store.list_peers().unwrap().is_empty());
        assert!(connector_store.list_peers().unwrap().is_empty());
        assert!(attacker_store.list_peers().unwrap().is_empty());
    }

    #[test]
    fn oversized_certificate_is_rejected_before_allocation() {
        let mut header = [0_u8; HELLO_HEADER_LENGTH];
        header[..8].copy_from_slice(HELLO_MAGIC);
        header[8..10].copy_from_slice(&PAIRING_VERSION.to_le_bytes());
        header[10] = Role::Connector as u8;
        let offset = 11 + NONCE_LENGTH;
        header[offset..offset + 4]
            .copy_from_slice(&u32::try_from(CERTIFICATE_LIMIT + 1).unwrap().to_le_bytes());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let sender = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream.write_all(&header).unwrap();
        });
        let (mut stream, _) = listener.accept().unwrap();
        assert!(Hello::read_from(&mut stream, Role::Connector).is_err());
        sender.join().unwrap();
    }

    #[test]
    fn pairing_hello_parser_rejects_bounded_malformed_corpus() {
        let mut corpus = Vec::new();
        for length in 0..HELLO_HEADER_LENGTH {
            corpus.push(vec![0_u8; length]);
        }

        let mut invalid_magic = [0_u8; HELLO_HEADER_LENGTH];
        invalid_magic[..8].copy_from_slice(b"NOTPAIR!");
        invalid_magic[8..10].copy_from_slice(&PAIRING_VERSION.to_le_bytes());
        invalid_magic[10] = Role::Connector as u8;
        invalid_magic[43..47].copy_from_slice(&1_u32.to_le_bytes());
        corpus.push(invalid_magic.to_vec());

        let mut invalid_version = invalid_magic;
        invalid_version[..8].copy_from_slice(HELLO_MAGIC);
        invalid_version[8..10].copy_from_slice(&PAIRING_VERSION.wrapping_add(1).to_le_bytes());
        corpus.push(invalid_version.to_vec());

        let mut invalid_role = invalid_magic;
        invalid_role[..8].copy_from_slice(HELLO_MAGIC);
        invalid_role[10] = 0xFF;
        corpus.push(invalid_role.to_vec());

        let mut wrong_role = invalid_magic;
        wrong_role[..8].copy_from_slice(HELLO_MAGIC);
        wrong_role[10] = Role::Listener as u8;
        corpus.push(wrong_role.to_vec());

        let mut empty_certificate = invalid_magic;
        empty_certificate[..8].copy_from_slice(HELLO_MAGIC);
        empty_certificate[43..47].copy_from_slice(&0_u32.to_le_bytes());
        corpus.push(empty_certificate.to_vec());

        let mut oversized = empty_certificate;
        oversized[43..47]
            .copy_from_slice(&(u32::try_from(CERTIFICATE_LIMIT).unwrap() + 1).to_le_bytes());
        corpus.push(oversized.to_vec());

        let mut missing_certificate = empty_certificate;
        missing_certificate[43..47].copy_from_slice(&16_u32.to_le_bytes());
        corpus.push(missing_certificate.to_vec());

        for bytes in corpus {
            let error = Hello::read_from(&mut bytes.as_slice(), Role::Connector).unwrap_err();
            assert!(matches!(
                error.kind(),
                io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
            ));
        }
    }
}
