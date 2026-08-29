use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    ClientConfig, ClientConnection, ProtocolVersion, RootCertStore, ServerConfig, ServerConnection,
    StreamOwned,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::device_store::DeviceStore;

const CERTIFICATE_LIMIT: usize = 64 * 1024;
const PRIVATE_KEY_LIMIT: usize = 64 * 1024;
const SERVER_NAME: &str = "clipferry.local";
const ALPN_PROTOCOL: &[u8] = b"clipferry/1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CertificateFingerprint([u8; 32]);

impl CertificateFingerprint {
    #[must_use]
    pub fn from_certificate(certificate: &[u8]) -> Self {
        Self(Sha256::digest(certificate).into())
    }

    #[must_use]
    pub fn bytes(self) -> [u8; 32] {
        self.0
    }
}

impl std::fmt::Display for CertificateFingerprint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if index != 0 {
                formatter.write_char(':')?;
            }
            write!(formatter, "{byte:02X}")?;
        }
        Ok(())
    }
}

impl FromStr for CertificateFingerprint {
    type Err = io::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let compact: String = value
            .chars()
            .filter(|character| *character != ':')
            .collect();
        if compact.len() != 64 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid_data(
                "certificate fingerprint must contain exactly 32 hexadecimal bytes",
            ));
        }
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let start = index * 2;
            *byte = u8::from_str_radix(&compact[start..start + 2], 16)
                .map_err(|_| invalid_data("invalid certificate fingerprint"))?;
        }
        Ok(Self(bytes))
    }
}

pub struct TlsIdentity {
    certificate: CertificateDer<'static>,
    private_key: PrivateKeyDer<'static>,
    fingerprint: CertificateFingerprint,
}

impl TlsIdentity {
    /// Loads one DER certificate and its PKCS#8 DER private key from bounded files.
    ///
    /// # Errors
    ///
    /// Returns an error for I/O failures, empty files, or files exceeding the fixed size limits.
    pub fn load(certificate_path: &Path, private_key_path: &Path) -> io::Result<Self> {
        let certificate = read_bounded(certificate_path, CERTIFICATE_LIMIT, "certificate")?;
        let private_key = read_bounded(private_key_path, PRIVATE_KEY_LIMIT, "private key")?;
        Self::from_der(certificate, private_key)
    }

    pub(crate) fn from_der(certificate: Vec<u8>, private_key: Vec<u8>) -> io::Result<Self> {
        if certificate.is_empty() || private_key.is_empty() {
            return Err(invalid_data(
                "certificate and private key must not be empty",
            ));
        }
        let fingerprint = CertificateFingerprint::from_certificate(&certificate);
        Ok(Self {
            certificate: CertificateDer::from(certificate),
            private_key: PrivatePkcs8KeyDer::from(private_key).into(),
            fingerprint,
        })
    }

    #[must_use]
    pub fn fingerprint(&self) -> CertificateFingerprint {
        self.fingerprint
    }

    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        self.certificate.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn from_test_parts(
        certificate: CertificateDer<'static>,
        private_key: PrivateKeyDer<'static>,
        fingerprint: CertificateFingerprint,
    ) -> Self {
        Self {
            certificate,
            private_key,
            fingerprint,
        }
    }
}

/// Creates a self-signed test identity without overwriting either requested output file.
///
/// # Errors
///
/// Returns an error if key generation, exclusive file creation, writing, or syncing fails.
pub fn generate_test_identity(
    certificate_path: &Path,
    private_key_path: &Path,
) -> io::Result<CertificateFingerprint> {
    let (certificate, private_key) = generate_identity_der()?;
    let private_key = Zeroizing::new(private_key);

    write_new_secret(private_key_path, &private_key)?;
    if let Err(error) = write_new_public(certificate_path, &certificate) {
        let _ = fs::remove_file(private_key_path);
        return Err(error);
    }
    Ok(CertificateFingerprint::from_certificate(&certificate))
}

pub(crate) fn generate_identity_der() -> io::Result<(Vec<u8>, Vec<u8>)> {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed([SERVER_NAME.to_owned()]).map_err(invalid_crypto)?;
    Ok((cert.der().as_ref().to_vec(), signing_key.serialize_der()))
}

#[derive(Clone)]
pub struct PinnedTlsClient {
    config: Arc<ClientConfig>,
    expected_peer: CertificateFingerprint,
    timeout: Duration,
}

impl PinnedTlsClient {
    /// Builds a TLS 1.3-only client that pins the exact server certificate and sends its own.
    ///
    /// # Errors
    ///
    /// Returns an error for a pin mismatch or invalid certificate/key configuration.
    pub fn new(
        identity: &TlsIdentity,
        peer_certificate: Vec<u8>,
        expected_peer: CertificateFingerprint,
        timeout: Duration,
    ) -> io::Result<Self> {
        verify_peer_pin(&peer_certificate, expected_peer)?;
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(peer_certificate))
            .map_err(invalid_crypto)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(invalid_crypto)?
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![identity.certificate.clone()],
                identity.private_key.clone_key(),
            )
            .map_err(invalid_crypto)?;
        config.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
        config.enable_early_data = false;
        Ok(Self {
            config: Arc::new(config),
            expected_peer,
            timeout,
        })
    }

    /// Connects, completes mutual TLS, and verifies TLS 1.3, ALPN, and the full peer pin.
    ///
    /// # Errors
    ///
    /// Returns an error for TCP, timeout, TLS, ALPN, or certificate verification failures.
    pub fn connect(
        &self,
        address: SocketAddr,
    ) -> io::Result<StreamOwned<ClientConnection, TcpStream>> {
        let socket = TcpStream::connect_timeout(&address, self.timeout)?;
        self.connect_socket_with_timeout(socket, self.timeout)
    }

    /// Connects with a shorter per-attempt bound while preserving the configured certificate pins.
    /// This lets a higher-level recovery loop remain responsive during a temporary outage.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero timeout, TCP, TLS, ALPN, or certificate verification failure.
    pub fn connect_with_timeout(
        &self,
        address: SocketAddr,
        timeout: Duration,
    ) -> io::Result<StreamOwned<ClientConnection, TcpStream>> {
        if timeout.is_zero() {
            return Err(invalid_data("TLS connection timeout must be non-zero"));
        }
        let timeout = timeout.min(self.timeout);
        let socket = TcpStream::connect_timeout(&address, timeout)?;
        self.connect_socket_with_timeout(socket, timeout)
    }

    /// Completes pinned mutual TLS on an already-connected socket.
    ///
    /// This is used to upgrade the bounded first-pairing exchange and prove possession of the
    /// private keys corresponding to both certificates.
    ///
    /// # Errors
    ///
    /// Returns an error for socket, timeout, TLS, ALPN, or certificate verification failures.
    pub fn connect_socket(
        &self,
        socket: TcpStream,
    ) -> io::Result<StreamOwned<ClientConnection, TcpStream>> {
        self.connect_socket_with_timeout(socket, self.timeout)
    }

    fn connect_socket_with_timeout(
        &self,
        mut socket: TcpStream,
        timeout: Duration,
    ) -> io::Result<StreamOwned<ClientConnection, TcpStream>> {
        configure_socket(&socket, timeout)?;
        let server_name = ServerName::try_from(SERVER_NAME)
            .map_err(invalid_crypto)?
            .to_owned();
        let mut connection =
            ClientConnection::new(Arc::clone(&self.config), server_name).map_err(invalid_crypto)?;
        while connection.is_handshaking() {
            connection
                .complete_io(&mut socket)
                .map_err(invalid_crypto)?;
        }
        verify_negotiated_connection(&connection, self.expected_peer)?;
        Ok(StreamOwned::new(connection, socket))
    }
}

#[derive(Clone)]
pub struct PinnedTlsServer {
    config: Arc<ServerConfig>,
    expected_peer: CertificateFingerprint,
    timeout: Duration,
}

impl PinnedTlsServer {
    /// Builds a TLS 1.3-only server that requires the exact pinned client certificate.
    ///
    /// # Errors
    ///
    /// Returns an error for a pin mismatch or invalid certificate/key configuration.
    pub fn new(
        identity: &TlsIdentity,
        peer_certificate: Vec<u8>,
        expected_peer: CertificateFingerprint,
        timeout: Duration,
    ) -> io::Result<Self> {
        verify_peer_pin(&peer_certificate, expected_peer)?;
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(peer_certificate))
            .map_err(invalid_crypto)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client_verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
                .build()
                .map_err(invalid_crypto)?;
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(invalid_crypto)?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                vec![identity.certificate.clone()],
                identity.private_key.clone_key(),
            )
            .map_err(invalid_crypto)?;
        config.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
        config.max_early_data_size = 0;
        Ok(Self {
            config: Arc::new(config),
            expected_peer,
            timeout,
        })
    }

    /// Completes mutual TLS for an accepted socket and verifies protocol, ALPN, and peer pin.
    ///
    /// # Errors
    ///
    /// Returns an error for socket, timeout, TLS, ALPN, or certificate verification failures.
    pub fn accept(
        &self,
        socket: TcpStream,
    ) -> io::Result<StreamOwned<ServerConnection, TcpStream>> {
        self.accept_authenticated(socket)
            .map(|authenticated| authenticated.stream)
    }

    /// Completes pinned mutual TLS and returns the authenticated client fingerprint.
    ///
    /// # Errors
    ///
    /// Returns an error for socket, timeout, TLS, ALPN, or certificate verification failures.
    pub fn accept_authenticated(
        &self,
        mut socket: TcpStream,
    ) -> io::Result<AuthenticatedServerConnection> {
        socket.set_nonblocking(false)?;
        configure_socket(&socket, self.timeout)?;
        let mut connection =
            ServerConnection::new(Arc::clone(&self.config)).map_err(invalid_crypto)?;
        while connection.is_handshaking() {
            connection
                .complete_io(&mut socket)
                .map_err(invalid_crypto)?;
        }
        verify_negotiated_connection(&connection, self.expected_peer)?;
        Ok(AuthenticatedServerConnection {
            stream: StreamOwned::new(connection, socket),
            peer_fingerprint: self.expected_peer,
        })
    }

    #[must_use]
    pub fn expected_peer(&self) -> CertificateFingerprint {
        self.expected_peer
    }
}

pub struct AuthenticatedServerConnection {
    pub stream: StreamOwned<ServerConnection, TcpStream>,
    pub peer_fingerprint: CertificateFingerprint,
}

#[derive(Clone)]
pub struct TrustedTlsServer {
    identity: Arc<TlsIdentity>,
    trust_store: DeviceStore,
    timeout: Duration,
}

impl TrustedTlsServer {
    /// Builds a TLS 1.3 server whose accepted client set is reloaded from the trust registry for
    /// every new connection.
    ///
    /// # Errors
    ///
    /// Returns an error when the local identity does not match the identity in the supplied store.
    pub fn new(
        identity: TlsIdentity,
        trust_store: DeviceStore,
        timeout: Duration,
    ) -> io::Result<Self> {
        if timeout.is_zero() {
            return Err(invalid_data("TLS timeout must be greater than zero"));
        }
        let stored = trust_store.load_identity()?;
        if stored.fingerprint() != identity.fingerprint() {
            return Err(invalid_data(
                "TLS identity does not match the device trust store",
            ));
        }
        Ok(Self {
            identity: Arc::new(identity),
            trust_store,
            timeout,
        })
    }

    /// Completes mutual TLS against the current trusted-peer set and rechecks the exact peer record
    /// after the handshake, so a concurrent revocation fails closed.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty/corrupt trust registry, socket or TLS failure, an untrusted
    /// certificate, or revocation during the handshake.
    pub fn accept(&self, mut socket: TcpStream) -> io::Result<AuthenticatedServerConnection> {
        socket.set_nonblocking(false)?;
        configure_socket(&socket, self.timeout)?;
        let peers = self.trust_store.list_peers()?;
        if peers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "no trusted peer is authorized for mutual TLS",
            ));
        }
        let mut roots = RootCertStore::empty();
        for peer in peers {
            roots
                .add(CertificateDer::from(peer.into_certificate_der()))
                .map_err(invalid_crypto)?;
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client_verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
                .build()
                .map_err(invalid_crypto)?;
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(invalid_crypto)?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                vec![self.identity.certificate.clone()],
                self.identity.private_key.clone_key(),
            )
            .map_err(invalid_crypto)?;
        config.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
        config.max_early_data_size = 0;
        let mut connection = ServerConnection::new(Arc::new(config)).map_err(invalid_crypto)?;
        while connection.is_handshaking() {
            connection
                .complete_io(&mut socket)
                .map_err(invalid_crypto)?;
        }
        let peer_fingerprint = negotiated_peer_fingerprint(&connection)?;
        let certificate = connection
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .ok_or_else(|| invalid_data("peer did not provide a certificate"))?;
        let current = self.trust_store.load_peer(peer_fingerprint)?;
        if current.certificate_der() != certificate.as_ref() {
            return Err(invalid_data(
                "trusted peer certificate changed during the TLS handshake",
            ));
        }
        Ok(AuthenticatedServerConnection {
            stream: StreamOwned::new(connection, socket),
            peer_fingerprint,
        })
    }

    #[must_use]
    pub fn trust_store(&self) -> DeviceStore {
        self.trust_store.clone()
    }
}

/// Loads a bounded DER peer certificate and verifies its complete SHA-256 fingerprint.
///
/// # Errors
///
/// Returns an error for I/O, size, or exact pin mismatch failures.
pub fn load_and_verify_peer_certificate(
    path: &Path,
    expected: CertificateFingerprint,
) -> io::Result<Vec<u8>> {
    let certificate = read_bounded(path, CERTIFICATE_LIMIT, "peer certificate")?;
    verify_peer_pin(&certificate, expected)?;
    Ok(certificate)
}

fn verify_negotiated_connection(
    connection: &rustls::CommonState,
    expected_peer: CertificateFingerprint,
) -> io::Result<()> {
    let actual = negotiated_peer_fingerprint(connection)?;
    if actual != expected_peer {
        return Err(invalid_data(format!(
            "peer certificate fingerprint mismatch: expected {expected_peer}, got {actual}"
        )));
    }
    Ok(())
}

fn negotiated_peer_fingerprint(
    connection: &rustls::CommonState,
) -> io::Result<CertificateFingerprint> {
    if connection.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
        return Err(invalid_data("TLS 1.3 was not negotiated"));
    }
    if connection.alpn_protocol() != Some(ALPN_PROTOCOL) {
        return Err(invalid_data("ClipFerry ALPN was not negotiated"));
    }
    let certificates = connection
        .peer_certificates()
        .ok_or_else(|| invalid_data("peer did not provide a certificate"))?;
    if certificates.len() != 1 {
        return Err(invalid_data(
            "peer certificate chain must contain exactly the pinned certificate",
        ));
    }
    Ok(CertificateFingerprint::from_certificate(
        certificates[0].as_ref(),
    ))
}

fn verify_peer_pin(certificate: &[u8], expected: CertificateFingerprint) -> io::Result<()> {
    let actual = CertificateFingerprint::from_certificate(certificate);
    if actual != expected {
        return Err(invalid_data(format!(
            "peer certificate fingerprint mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn configure_socket(socket: &TcpStream, timeout: Duration) -> io::Result<()> {
    socket.set_nodelay(true)?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))
}

fn read_bounded(path: &Path, limit: usize, kind: &str) -> io::Result<Vec<u8>> {
    let metadata = fs::metadata(path)?;
    if metadata.len() == 0 || metadata.len() > limit as u64 {
        return Err(invalid_data(format!(
            "{kind} length must be between 1 and {limit} bytes"
        )));
    }
    let mut file = fs::File::open(path)?;
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| invalid_data(format!("{kind} length does not fit this platform")))?;
    let mut bytes = Vec::with_capacity(capacity);
    std::io::Read::by_ref(&mut file)
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(invalid_data(format!("{kind} exceeds {limit} bytes")));
    }
    Ok(bytes)
}

fn write_new_secret(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn write_new_public(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn invalid_crypto(error: impl std::fmt::Display) -> io::Error {
    invalid_data(error.to_string())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    fn generated_identity() -> TlsIdentity {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed([SERVER_NAME.to_owned()]).unwrap();
        TlsIdentity::from_der(cert.der().as_ref().to_vec(), signing_key.serialize_der()).unwrap()
    }

    #[test]
    fn fingerprint_round_trip_is_full_length_and_unambiguous() {
        let fingerprint = CertificateFingerprint::from_certificate(b"certificate");
        let displayed = fingerprint.to_string();
        assert_eq!(displayed.len(), 95);
        assert_eq!(
            displayed.parse::<CertificateFingerprint>().unwrap(),
            fingerprint
        );
        assert_eq!(
            displayed
                .replace(':', "")
                .to_ascii_lowercase()
                .parse::<CertificateFingerprint>()
                .unwrap(),
            fingerprint
        );
        assert!("00:11".parse::<CertificateFingerprint>().is_err());
    }

    #[test]
    fn mutual_tls_is_tls13_only_and_exchanges_application_data() {
        let server_identity = generated_identity();
        let client_identity = generated_identity();
        let server = PinnedTlsServer::new(
            &server_identity,
            client_identity.certificate.as_ref().to_vec(),
            client_identity.fingerprint(),
            Duration::from_secs(5),
        )
        .unwrap();
        let client = PinnedTlsClient::new(
            &client_identity,
            server_identity.certificate.as_ref().to_vec(),
            server_identity.fingerprint(),
            Duration::from_secs(5),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_thread = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut stream = server.accept(socket).unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"PING");
            stream.write_all(b"PONG").unwrap();
        });

        let mut stream = client.connect(address).unwrap();
        stream.write_all(b"PING").unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"PONG");
        server_thread.join().unwrap();
    }

    #[test]
    fn certificate_pin_mismatch_fails_before_network_use() {
        let server_identity = generated_identity();
        let client_identity = generated_identity();
        let unrelated = generated_identity();
        let result = PinnedTlsClient::new(
            &client_identity,
            server_identity.certificate.as_ref().to_vec(),
            unrelated.fingerprint(),
            Duration::from_secs(5),
        );
        assert!(result.is_err());
    }

    #[test]
    fn unpinned_client_identity_is_rejected_by_mutual_tls() {
        let server_identity = generated_identity();
        let expected_client = generated_identity();
        let untrusted_client = generated_identity();
        let server = PinnedTlsServer::new(
            &server_identity,
            expected_client.certificate.as_ref().to_vec(),
            expected_client.fingerprint(),
            Duration::from_secs(5),
        )
        .unwrap();
        let client = PinnedTlsClient::new(
            &untrusted_client,
            server_identity.certificate.as_ref().to_vec(),
            server_identity.fingerprint(),
            Duration::from_secs(5),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_thread = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            server.accept(socket).map(|_| ())
        });

        let client_result = client.connect(address).and_then(|mut stream| {
            stream.write_all(b"PING")?;
            let mut response = [0_u8; 1];
            stream.read_exact(&mut response)
        });
        let server_result = server_thread.join().unwrap();
        assert!(client_result.is_err() || server_result.is_err());
        assert!(server_result.is_err());
    }
}
