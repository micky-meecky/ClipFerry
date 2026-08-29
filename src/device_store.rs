use std::ffi::c_void;
use std::fs::{self, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use zeroize::Zeroizing;

use crate::security::{CertificateFingerprint, TlsIdentity, generate_identity_der};

const IDENTITY_FILE: &str = "identity.dpapi";
const TRUST_DIRECTORY: &str = "trusted-peers";
const IDENTITY_MAGIC: &[u8; 8] = b"CFID\x01\0\0\0";
const TRUST_MAGIC: &[u8; 8] = b"CFPR\x01\0\0\0";
const DPAPI_ENTROPY: &[u8] = b"ClipFerry device identity v1";
const CERTIFICATE_LIMIT: usize = 64 * 1024;
const PRIVATE_KEY_LIMIT: usize = 64 * 1024;
const IDENTITY_PLAINTEXT_LIMIT: usize = 2 * 64 * 1024 + 16;
const IDENTITY_PROTECTED_LIMIT: usize = 256 * 1024;
const TRUST_RECORD_LIMIT: usize = 72 * 1024;
const LABEL_BYTE_LIMIT: usize = 128;
const TRUSTED_PEER_LIMIT: usize = 64;

pub struct StoredIdentity {
    pub identity: TlsIdentity,
    pub created: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedPeer {
    pub fingerprint: CertificateFingerprint,
    pub label: String,
    certificate: Vec<u8>,
}

impl TrustedPeer {
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate
    }

    #[must_use]
    pub fn into_certificate_der(self) -> Vec<u8> {
        self.certificate
    }
}

#[derive(Clone, Debug)]
pub struct DeviceStore {
    root: PathBuf,
}

impl DeviceStore {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Returns the per-user application-data location used by `ClipFerry`.
    ///
    /// # Errors
    ///
    /// Returns an error when Windows did not provide `LOCALAPPDATA`.
    pub fn current_user() -> io::Result<Self> {
        let local_app_data = std::env::var_os("LOCALAPPDATA")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "LOCALAPPDATA is not set"))?;
        Ok(Self::new(PathBuf::from(local_app_data).join("ClipFerry")))
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Loads the existing device identity or atomically creates one protected by user-scope DPAPI.
    ///
    /// # Errors
    ///
    /// Returns an error for key generation, DPAPI, storage, or validation failures.
    pub fn load_or_create_identity(&self) -> io::Result<StoredIdentity> {
        fs::create_dir_all(&self.root)?;
        let path = self.identity_path();
        match self.load_identity() {
            Ok(identity) => {
                return Ok(StoredIdentity {
                    identity,
                    created: false,
                });
            }
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            Err(_) => {}
        }

        let (certificate, private_key) = generate_identity_der()?;
        let private_key = Zeroizing::new(private_key);
        let cleartext = Zeroizing::new(encode_identity_bundle(&certificate, &private_key)?);
        let protected = protect_for_current_user(&cleartext)?;
        let created = match write_new_atomic(&path, &protected) {
            Ok(()) => true,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
            Err(error) => return Err(error),
        };
        let identity = self.load_identity()?;
        Ok(StoredIdentity { identity, created })
    }

    /// Loads and decrypts the current device identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the identity is missing, corrupt, copied from another user context,
    /// or cannot be parsed as a certificate and PKCS#8 key.
    pub fn load_identity(&self) -> io::Result<TlsIdentity> {
        let protected = read_bounded(
            &self.identity_path(),
            IDENTITY_PROTECTED_LIMIT,
            "protected identity",
        )?;
        let cleartext = unprotect_for_current_user(&protected)?;
        let (certificate, private_key) = decode_identity_bundle(&cleartext)?;
        TlsIdentity::from_der(certificate, private_key)
    }

    /// Exports only the public certificate without overwriting an existing file.
    ///
    /// # Errors
    ///
    /// Returns an error for identity loading or exclusive output creation failures.
    pub fn export_certificate(&self, output: &Path) -> io::Result<CertificateFingerprint> {
        let identity = self.load_identity()?;
        write_new_direct(output, identity.certificate_der())?;
        Ok(identity.fingerprint())
    }

    /// Imports one explicitly verified peer certificate into the bounded trust registry.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid label, pin mismatch, self-trust, a full registry, or an
    /// existing record. This is a manual bootstrap primitive, not the final pairing protocol.
    pub fn trust_peer(
        &self,
        certificate: Vec<u8>,
        expected: CertificateFingerprint,
        label: &str,
    ) -> io::Result<TrustedPeer> {
        let identity = self.load_identity()?;
        validate_certificate(&certificate)?;
        let actual = CertificateFingerprint::from_certificate(&certificate);
        if actual != expected {
            return Err(invalid_data(format!(
                "peer certificate fingerprint mismatch: expected {expected}, got {actual}"
            )));
        }
        if actual == identity.fingerprint() {
            return Err(invalid_data(
                "the local device cannot trust itself as a peer",
            ));
        }
        let label = validate_label(label)?;
        let directory = self.trust_directory();
        fs::create_dir_all(&directory)?;
        if self.list_peers()?.len() >= TRUSTED_PEER_LIMIT {
            return Err(invalid_data(format!(
                "trusted peer limit of {TRUSTED_PEER_LIMIT} has been reached"
            )));
        }
        let peer = TrustedPeer {
            fingerprint: actual,
            label,
            certificate,
        };
        let path = self.peer_path(actual);
        write_new_atomic(&path, &encode_trust_record(&peer)?)?;
        if let Err(error) = self.list_peers() {
            let _ = fs::remove_file(&path);
            return Err(error);
        }
        Ok(peer)
    }

    /// Imports a bounded DER certificate file after exact fingerprint verification.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::trust_peer`] plus bounded file I/O failures.
    pub fn trust_peer_file(
        &self,
        certificate_path: &Path,
        expected: CertificateFingerprint,
        label: &str,
    ) -> io::Result<TrustedPeer> {
        let certificate = read_bounded(certificate_path, CERTIFICATE_LIMIT, "peer certificate")?;
        self.trust_peer(certificate, expected, label)
    }

    /// Loads one trusted peer by its complete certificate fingerprint.
    ///
    /// # Errors
    ///
    /// Returns an error when the record is missing, corrupt, or does not match its filename.
    pub fn load_peer(&self, fingerprint: CertificateFingerprint) -> io::Result<TrustedPeer> {
        decode_peer_file(&self.peer_path(fingerprint), fingerprint)
    }

    /// Enumerates all trusted peers after validating every matching record.
    ///
    /// # Errors
    ///
    /// Returns an error for directory I/O, corrupt records, duplicate identities, or excess peers.
    pub fn list_peers(&self) -> io::Result<Vec<TrustedPeer>> {
        let directory = self.trust_directory();
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut peers = Vec::new();
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("peer") {
                continue;
            }
            let stem = path
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or_else(|| invalid_data("trusted peer filename is not valid Unicode"))?;
            let fingerprint = parse_compact_fingerprint(stem)?;
            peers.push(decode_peer_file(&path, fingerprint)?);
            if peers.len() > TRUSTED_PEER_LIMIT {
                return Err(invalid_data(format!(
                    "trusted peer registry exceeds the limit of {TRUSTED_PEER_LIMIT}"
                )));
            }
        }
        peers.sort_by_key(|peer| peer.fingerprint.bytes());
        Ok(peers)
    }

    /// Revokes one trusted peer by deleting its exact fingerprint record.
    ///
    /// # Errors
    ///
    /// Returns an error when the record is absent or cannot be removed.
    pub fn revoke_peer(&self, fingerprint: CertificateFingerprint) -> io::Result<()> {
        fs::remove_file(self.peer_path(fingerprint))
    }

    fn identity_path(&self) -> PathBuf {
        self.root.join(IDENTITY_FILE)
    }

    fn trust_directory(&self) -> PathBuf {
        self.root.join(TRUST_DIRECTORY)
    }

    fn peer_path(&self, fingerprint: CertificateFingerprint) -> PathBuf {
        self.trust_directory()
            .join(format!("{}.peer", compact_fingerprint(fingerprint)))
    }
}

fn protect_for_current_user(cleartext: &[u8]) -> io::Result<Vec<u8>> {
    let input = input_blob(cleartext)?;
    let entropy = input_blob(DPAPI_ENTROPY)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: both input blobs point to live slices for the duration of the call, all optional
    // pointers are absent, and `output` is released with LocalFree after copying.
    unsafe {
        CryptProtectData(
            &raw const input,
            windows_core::w!("ClipFerry device identity"),
            Some(&raw const entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    }
    .map_err(|error| io::Error::other(format!("DPAPI protection failed: {error}")))?;
    copy_local_blob(output, IDENTITY_PROTECTED_LIMIT, "protected identity")
}

fn unprotect_for_current_user(protected: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    let input = input_blob(protected)?;
    let entropy = input_blob(DPAPI_ENTROPY)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: both input blobs point to live slices for the duration of the call, all optional
    // pointers are absent, and `output` is released with LocalFree after copying.
    unsafe {
        CryptUnprotectData(
            &raw const input,
            None,
            Some(&raw const entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    }
    .map_err(|error| invalid_data(format!("DPAPI unprotection failed: {error}")))?;
    Ok(Zeroizing::new(copy_local_blob(
        output,
        IDENTITY_PLAINTEXT_LIMIT,
        "identity plaintext",
    )?))
}

fn input_blob(bytes: &[u8]) -> io::Result<CRYPT_INTEGER_BLOB> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(bytes.len()).map_err(|_| invalid_data("DPAPI input is too large"))?,
        pbData: bytes.as_ptr().cast_mut(),
    })
}

fn copy_local_blob(
    blob: CRYPT_INTEGER_BLOB,
    limit: usize,
    description: &str,
) -> io::Result<Vec<u8>> {
    let allocation = LocalBlob(blob);
    let length = usize::try_from(allocation.0.cbData)
        .map_err(|_| invalid_data(format!("{description} length does not fit this platform")))?;
    if length == 0 || length > limit || allocation.0.pbData.is_null() {
        return Err(invalid_data(format!(
            "{description} length must be between 1 and {limit} bytes"
        )));
    }
    // SAFETY: DPAPI returned a non-null LocalAlloc buffer of exactly `cbData` bytes, retained by
    // `allocation` until the copied Vec is complete.
    let bytes = unsafe { std::slice::from_raw_parts(allocation.0.pbData, length) }.to_vec();
    Ok(bytes)
}

struct LocalBlob(CRYPT_INTEGER_BLOB);

impl Drop for LocalBlob {
    fn drop(&mut self) {
        if !self.0.pbData.is_null() {
            // SAFETY: CryptProtectData and CryptUnprotectData document LocalFree for their output.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0.pbData.cast::<c_void>())));
            }
        }
    }
}

fn encode_identity_bundle(certificate: &[u8], private_key: &[u8]) -> io::Result<Vec<u8>> {
    validate_certificate(certificate)?;
    if private_key.is_empty() || private_key.len() > PRIVATE_KEY_LIMIT {
        return Err(invalid_data(format!(
            "private key length must be between 1 and {PRIVATE_KEY_LIMIT} bytes"
        )));
    }
    let certificate_length = u32::try_from(certificate.len())
        .map_err(|_| invalid_data("certificate length does not fit the identity format"))?;
    let private_key_length = u32::try_from(private_key.len())
        .map_err(|_| invalid_data("private key length does not fit the identity format"))?;
    let capacity = 16_usize
        .checked_add(certificate.len())
        .and_then(|value| value.checked_add(private_key.len()))
        .ok_or_else(|| invalid_data("identity length overflow"))?;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(IDENTITY_MAGIC);
    encoded.extend_from_slice(&certificate_length.to_le_bytes());
    encoded.extend_from_slice(&private_key_length.to_le_bytes());
    encoded.extend_from_slice(certificate);
    encoded.extend_from_slice(private_key);
    Ok(encoded)
}

fn decode_identity_bundle(encoded: &[u8]) -> io::Result<(Vec<u8>, Vec<u8>)> {
    if encoded.len() < 16 || &encoded[..8] != IDENTITY_MAGIC {
        return Err(invalid_data("unsupported or corrupt device identity"));
    }
    let certificate_length = read_u32(&encoded[8..12])?;
    let private_key_length = read_u32(&encoded[12..16])?;
    let expected_length = 16_usize
        .checked_add(certificate_length)
        .and_then(|value| value.checked_add(private_key_length))
        .ok_or_else(|| invalid_data("identity length overflow"))?;
    if encoded.len() != expected_length {
        return Err(invalid_data("device identity length mismatch"));
    }
    let certificate_end = 16 + certificate_length;
    let certificate = encoded[16..certificate_end].to_vec();
    let private_key = encoded[certificate_end..].to_vec();
    validate_certificate(&certificate)?;
    if private_key.is_empty() || private_key.len() > PRIVATE_KEY_LIMIT {
        return Err(invalid_data(
            "private key length is outside the allowed bounds",
        ));
    }
    Ok((certificate, private_key))
}

fn encode_trust_record(peer: &TrustedPeer) -> io::Result<Vec<u8>> {
    validate_certificate(&peer.certificate)?;
    let label = validate_label(&peer.label)?;
    let certificate_length = u32::try_from(peer.certificate.len())
        .map_err(|_| invalid_data("certificate length does not fit the trust format"))?;
    let label_length = u16::try_from(label.len())
        .map_err(|_| invalid_data("peer label length does not fit the trust format"))?;
    let capacity = 14_usize
        .checked_add(peer.certificate.len())
        .and_then(|value| value.checked_add(label.len()))
        .ok_or_else(|| invalid_data("trusted peer length overflow"))?;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(TRUST_MAGIC);
    encoded.extend_from_slice(&certificate_length.to_le_bytes());
    encoded.extend_from_slice(&label_length.to_le_bytes());
    encoded.extend_from_slice(&peer.certificate);
    encoded.extend_from_slice(label.as_bytes());
    Ok(encoded)
}

fn decode_peer_file(path: &Path, expected: CertificateFingerprint) -> io::Result<TrustedPeer> {
    let encoded = read_bounded(path, TRUST_RECORD_LIMIT, "trusted peer record")?;
    if encoded.len() < 14 || &encoded[..8] != TRUST_MAGIC {
        return Err(invalid_data("unsupported or corrupt trusted peer record"));
    }
    let certificate_length = read_u32(&encoded[8..12])?;
    let label_length = usize::from(u16::from_le_bytes([encoded[12], encoded[13]]));
    let expected_length = 14_usize
        .checked_add(certificate_length)
        .and_then(|value| value.checked_add(label_length))
        .ok_or_else(|| invalid_data("trusted peer record length overflow"))?;
    if encoded.len() != expected_length {
        return Err(invalid_data("trusted peer record length mismatch"));
    }
    let certificate_end = 14 + certificate_length;
    let certificate = encoded[14..certificate_end].to_vec();
    validate_certificate(&certificate)?;
    let actual = CertificateFingerprint::from_certificate(&certificate);
    if actual != expected {
        return Err(invalid_data(format!(
            "trusted peer record fingerprint mismatch: filename {expected}, certificate {actual}"
        )));
    }
    let label = std::str::from_utf8(&encoded[certificate_end..])
        .map_err(|_| invalid_data("trusted peer label is not valid UTF-8"))?;
    Ok(TrustedPeer {
        fingerprint: actual,
        label: validate_label(label)?,
        certificate,
    })
}

fn validate_certificate(certificate: &[u8]) -> io::Result<()> {
    if certificate.is_empty() || certificate.len() > CERTIFICATE_LIMIT {
        return Err(invalid_data(format!(
            "certificate length must be between 1 and {CERTIFICATE_LIMIT} bytes"
        )));
    }
    Ok(())
}

fn validate_label(label: &str) -> io::Result<String> {
    let label = label.trim();
    if label.is_empty() || label.len() > LABEL_BYTE_LIMIT || label.chars().any(char::is_control) {
        return Err(invalid_data(format!(
            "peer label must contain 1 to {LABEL_BYTE_LIMIT} UTF-8 bytes without control characters"
        )));
    }
    Ok(label.to_owned())
}

fn read_u32(bytes: &[u8]) -> io::Result<usize> {
    let array: [u8; 4] = bytes
        .try_into()
        .map_err(|_| invalid_data("truncated length field"))?;
    usize::try_from(u32::from_le_bytes(array))
        .map_err(|_| invalid_data("length does not fit this platform"))
}

fn compact_fingerprint(fingerprint: CertificateFingerprint) -> String {
    fingerprint
        .bytes()
        .iter()
        .fold(String::with_capacity(64), |mut text, byte| {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        })
}

fn parse_compact_fingerprint(value: &str) -> io::Result<CertificateFingerprint> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_data("trusted peer filename is not a fingerprint"));
    }
    value.parse()
}

fn read_bounded(path: &Path, limit: usize, description: &str) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > limit as u64 {
        return Err(invalid_data(format!(
            "{description} must be a regular file between 1 and {limit} bytes"
        )));
    }
    let mut file = fs::File::open(path)?;
    let mut bytes =
        Vec::with_capacity(usize::try_from(metadata.len()).map_err(|_| {
            invalid_data(format!("{description} length does not fit this platform"))
        })?);
    std::io::Read::by_ref(&mut file)
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(invalid_data(format!("{description} exceeds {limit} bytes")));
    }
    Ok(bytes)
}

fn write_new_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("output path does not have a parent directory"))?;
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| invalid_data("output filename is not valid Unicode"))?;
    for _ in 0..8 {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).map_err(|error| {
            io::Error::other(format!("temporary filename generation failed: {error}"))
        })?;
        let temporary = parent.join(format!(
            ".{filename}.{}.{:016x}.tmp",
            std::process::id(),
            u64::from_le_bytes(random)
        ));
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        drop(file);
        let linked = fs::hard_link(&temporary, path);
        let _ = fs::remove_file(&temporary);
        return linked;
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique temporary filename",
    ))
}

fn write_new_direct(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;
    use zeroize::Zeroize as _;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(name: &str) -> Self {
            let mut random = [0_u8; 8];
            getrandom::fill(&mut random).unwrap();
            let path = std::env::temp_dir().join(format!(
                "clipferry-{name}-{}-{}",
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

    fn generated_peer() -> (Vec<u8>, CertificateFingerprint) {
        let (certificate, mut private_key) = generate_identity_der().unwrap();
        private_key.zeroize();
        let fingerprint = CertificateFingerprint::from_certificate(&certificate);
        (certificate, fingerprint)
    }

    #[test]
    fn dpapi_round_trip_and_tamper_are_fail_closed() {
        let protected = protect_for_current_user(b"device secret").unwrap();
        assert!(
            !protected
                .windows(b"device secret".len())
                .any(|window| window == b"device secret")
        );
        assert_eq!(
            &*unprotect_for_current_user(&protected).unwrap(),
            b"device secret"
        );

        let mut tampered = protected;
        let midpoint = tampered.len() / 2;
        tampered[midpoint] ^= 0x80;
        assert!(unprotect_for_current_user(&tampered).is_err());
    }

    #[test]
    fn device_identity_is_stable_and_only_dpapi_ciphertext_is_persisted() {
        let directory = TestDirectory::new("identity");
        let store = DeviceStore::new(&directory.0);
        let first = store.load_or_create_identity().unwrap();
        let first_fingerprint = first.identity.fingerprint();
        assert!(first.created);
        let second = store.load_or_create_identity().unwrap();
        assert!(!second.created);
        assert_eq!(second.identity.fingerprint(), first_fingerprint);
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
        let persisted = fs::read(store.identity_path()).unwrap();
        assert_ne!(&persisted[..IDENTITY_MAGIC.len()], IDENTITY_MAGIC);
    }

    #[test]
    fn concurrent_identity_initialization_publishes_one_complete_identity() {
        let directory = TestDirectory::new("identity-concurrent");
        let store = Arc::new(DeviceStore::new(&directory.0));
        let barrier = Arc::new(Barrier::new(8));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    store.load_or_create_identity().unwrap()
                })
            })
            .collect();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.created).count(), 1);
        assert!(
            results.iter().all(|result| {
                result.identity.fingerprint() == results[0].identity.fingerprint()
            })
        );
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
    }

    #[test]
    fn trust_registry_imports_lists_loads_and_revokes_exact_peer() {
        let directory = TestDirectory::new("trust");
        let store = DeviceStore::new(&directory.0);
        store.load_or_create_identity().unwrap();
        let (certificate, fingerprint) = generated_peer();
        let imported = store
            .trust_peer(certificate.clone(), fingerprint, "  Living room PC  ")
            .unwrap();
        assert_eq!(imported.label, "Living room PC");
        assert_eq!(store.list_peers().unwrap(), vec![imported.clone()]);
        assert_eq!(store.load_peer(fingerprint).unwrap(), imported);
        assert!(
            store
                .trust_peer(certificate, fingerprint, "duplicate")
                .is_err()
        );

        store.revoke_peer(fingerprint).unwrap();
        assert!(store.load_peer(fingerprint).is_err());
        assert!(store.list_peers().unwrap().is_empty());
    }

    #[test]
    fn trust_registry_rejects_wrong_pin_self_and_unsafe_labels() {
        let directory = TestDirectory::new("trust-negative");
        let store = DeviceStore::new(&directory.0);
        let local = store.load_or_create_identity().unwrap();
        let (certificate, fingerprint) = generated_peer();
        assert!(
            store
                .trust_peer(certificate.clone(), local.identity.fingerprint(), "peer")
                .is_err()
        );
        assert!(
            store
                .trust_peer(
                    local.identity.certificate_der().to_vec(),
                    local.identity.fingerprint(),
                    "self"
                )
                .is_err()
        );
        assert!(
            store
                .trust_peer(certificate, fingerprint, "unsafe\nlabel")
                .is_err()
        );
    }

    #[test]
    fn tampered_trust_record_is_rejected() {
        let directory = TestDirectory::new("trust-tamper");
        let store = DeviceStore::new(&directory.0);
        store.load_or_create_identity().unwrap();
        let (certificate, fingerprint) = generated_peer();
        store.trust_peer(certificate, fingerprint, "peer").unwrap();
        let path = store.peer_path(fingerprint);
        let mut record = fs::read(&path).unwrap();
        record[14] ^= 0x01;
        fs::write(path, record).unwrap();
        assert!(store.load_peer(fingerprint).is_err());
        assert!(store.list_peers().is_err());
    }
}
