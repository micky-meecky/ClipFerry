use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr as _;

use crate::device_store::DeviceStore;
use crate::security::CertificateFingerprint;

const SETTINGS_FILE: &str = "settings.v1";
const SETTINGS_HEADER: &str = "ClipFerrySettingsV1";
const SETTINGS_LIMIT: u64 = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppSettings {
    pub local_endpoint: SocketAddr,
    pub active_peer: CertificateFingerprint,
    pub peer_endpoint: SocketAddr,
    pub auto_receive: bool,
}

impl AppSettings {
    /// Loads the bounded per-user product settings and revalidates the selected peer.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing/corrupt file, non-private endpoints, or a peer that is no
    /// longer trusted.
    pub fn load(store: &DeviceStore) -> io::Result<Self> {
        let path = settings_path(store);
        let file = OpenOptions::new().read(true).open(&path)?;
        let metadata = file.metadata()?;
        if metadata.len() == 0 || metadata.len() > SETTINGS_LIMIT {
            return Err(invalid_data(
                "settings file length is outside the allowed bounds",
            ));
        }
        let mut text = String::new();
        file.take(SETTINGS_LIMIT + 1).read_to_string(&mut text)?;
        let settings = decode(&text)?;
        settings.validate(store)?;
        Ok(settings)
    }

    /// Saves non-secret product settings for the current user.
    ///
    /// # Errors
    ///
    /// Returns an error when validation or durable file replacement fails.
    pub fn save(&self, store: &DeviceStore) -> io::Result<()> {
        self.validate(store)?;
        fs::create_dir_all(store.root())?;
        let path = settings_path(store);
        let encoded = self.encode();
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.write_all(encoded.as_bytes())?;
        file.sync_all()
    }

    fn validate(&self, store: &DeviceStore) -> io::Result<()> {
        validate_private_endpoint(self.local_endpoint)?;
        validate_private_endpoint(self.peer_endpoint)?;
        if self.local_endpoint.ip().is_loopback() != self.peer_endpoint.ip().is_loopback() {
            return Err(invalid_data(
                "local and peer endpoints must both be loopback or both be private LAN addresses",
            ));
        }
        let peer = store.load_peer(self.active_peer)?;
        if peer.fingerprint != self.active_peer {
            return Err(invalid_data(
                "active peer record does not match its fingerprint",
            ));
        }
        Ok(())
    }

    fn encode(&self) -> String {
        format!(
            "{SETTINGS_HEADER}\nlocal_endpoint={}\nactive_peer={}\npeer_endpoint={}\nauto_receive={}\n",
            self.local_endpoint,
            self.active_peer,
            self.peer_endpoint,
            u8::from(self.auto_receive)
        )
    }
}

fn decode(text: &str) -> io::Result<AppSettings> {
    let mut lines = text.lines();
    if lines.next() != Some(SETTINGS_HEADER) {
        return Err(invalid_data("unsupported settings header"));
    }
    let mut fields = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| invalid_data("settings line is missing '='"))?;
        if !matches!(
            key,
            "local_endpoint" | "active_peer" | "peer_endpoint" | "auto_receive"
        ) {
            return Err(invalid_data("settings contain an unknown field"));
        }
        if fields.insert(key, value).is_some() {
            return Err(invalid_data("settings contain a duplicate field"));
        }
    }
    if fields.len() != 4 {
        return Err(invalid_data("settings are incomplete"));
    }
    let local_endpoint = parse_endpoint(required(&fields, "local_endpoint")?)?;
    let active_peer = CertificateFingerprint::from_str(required(&fields, "active_peer")?)?;
    let peer_endpoint = parse_endpoint(required(&fields, "peer_endpoint")?)?;
    let auto_receive = match required(&fields, "auto_receive")? {
        "0" => false,
        "1" => true,
        _ => return Err(invalid_data("auto_receive must be 0 or 1")),
    };
    Ok(AppSettings {
        local_endpoint,
        active_peer,
        peer_endpoint,
        auto_receive,
    })
}

fn required<'a>(fields: &'a HashMap<&str, &str>, key: &str) -> io::Result<&'a str> {
    fields
        .get(key)
        .copied()
        .ok_or_else(|| invalid_data("settings are incomplete"))
}

fn parse_endpoint(value: &str) -> io::Result<SocketAddr> {
    let endpoint = value
        .parse::<SocketAddr>()
        .map_err(|_| invalid_data("settings contain an invalid socket endpoint"))?;
    validate_private_endpoint(endpoint)?;
    Ok(endpoint)
}

/// Verifies that an endpoint is non-zero and limited to loopback or private unicast space.
///
/// # Errors
///
/// Returns an error for port zero, public addresses, multicast, or unspecified addresses.
pub fn validate_private_endpoint(endpoint: SocketAddr) -> io::Result<()> {
    if endpoint.port() == 0 {
        return Err(invalid_data("endpoint port must not be zero"));
    }
    let allowed = match endpoint.ip() {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local(),
    };
    if !allowed {
        return Err(invalid_data(
            "endpoint must use a loopback or private unicast address",
        ));
    }
    Ok(())
}

fn settings_path(store: &DeviceStore) -> PathBuf {
    store.root().join(SETTINGS_FILE)
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_text_round_trip_is_strict() {
        let fingerprint = CertificateFingerprint::from_certificate(b"peer");
        let settings = AppSettings {
            local_endpoint: "192.168.1.10:45233".parse().unwrap(),
            active_peer: fingerprint,
            peer_endpoint: "192.168.1.11:45233".parse().unwrap(),
            auto_receive: true,
        };
        assert_eq!(decode(&settings.encode()).unwrap(), settings);
    }

    #[test]
    fn settings_reject_unknown_duplicate_and_public_endpoints() {
        let fingerprint = CertificateFingerprint::from_certificate(b"peer");
        let base = format!(
            "{SETTINGS_HEADER}\nlocal_endpoint=192.168.1.10:45233\nactive_peer={fingerprint}\npeer_endpoint=192.168.1.11:45233\nauto_receive=0\n"
        );
        assert!(decode(&format!("{base}unknown=1\n")).is_err());
        assert!(decode(&format!("{base}auto_receive=1\n")).is_err());
        assert!(decode(&base.replace("192.168.1.10", "8.8.8.8")).is_err());
        assert!(decode(&base.replace(":45233", ":0")).is_err());
    }

    #[test]
    fn settings_require_matching_loopback_scope() {
        let fingerprint = CertificateFingerprint::from_certificate(b"peer");
        let settings = AppSettings {
            local_endpoint: "127.0.0.1:45233".parse().unwrap(),
            active_peer: fingerprint,
            peer_endpoint: "192.168.1.11:45233".parse().unwrap(),
            auto_receive: false,
        };
        assert!(settings.validate(&DeviceStore::new("unused")).is_err());
    }
}
