use std::fmt::Write as _;
use std::process::ExitCode;
use std::str::FromStr as _;
use std::time::Duration;

use clipferry::clipboard::secure_transfer::SecureOfferClient;
use clipferry::clipboard::{
    ClipboardProbeOptions, FileCaptureProbeOptions, LoopbackProbeOptions, PauseProbeOptions,
    SecureFetchProbeOptions, SecureReceiverProbeOptions, SecureSourceProbeOptions, SecureSourceTls,
    run_clipboard_probe, run_file_capture_probe, run_loopback_probe, run_pause_probe,
    run_secure_fetch_probe, run_secure_receiver_probe, run_secure_source_probe,
};
use clipferry::device_store::DeviceStore;
use clipferry::pairing::{PendingPairing, connect_for_pairing, listen_for_pairing};
use clipferry::security::{
    CertificateFingerprint, PinnedTlsClient, PinnedTlsServer, TlsIdentity, TrustedTlsServer,
    generate_test_identity, load_and_verify_peer_certificate,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("ClipFerry error: {message}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_lines)]
fn run() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    let Some(command) = arguments.next() else {
        println!("{}", clipferry::validation_banner());
        print_usage();
        return Ok(());
    };

    match command.as_str() {
        "clipboard-test" => {
            let mut lifetime = None;
            while let Some(argument) = arguments.next() {
                if argument != "--lifetime-seconds" {
                    return Err(format!("unknown argument: {argument}"));
                }
                let seconds = arguments
                    .next()
                    .ok_or_else(|| "--lifetime-seconds requires a value".to_owned())?
                    .parse::<u64>()
                    .map_err(|error| format!("invalid lifetime: {error}"))?;
                lifetime = Some(Duration::from_secs(seconds));
            }
            run_clipboard_probe(ClipboardProbeOptions { lifetime })
                .map_err(|error| format!("{error} ({:#010X})", error.code().0.cast_unsigned()))
        }
        "clipboard-pause-test" => {
            let options = parse_pause_probe_options(arguments)?;
            run_pause_probe(options)
                .map_err(|error| format!("{error} ({:#010X})", error.code().0.cast_unsigned()))
        }
        "loopback-clipboard-test" => {
            let options = parse_loopback_probe_options(arguments)?;
            run_loopback_probe(options)
                .map_err(|error| format!("{error} ({:#010X})", error.code().0.cast_unsigned()))
        }
        "file-capture-test" => {
            let options = parse_file_capture_probe_options(arguments)?;
            run_file_capture_probe(options)
                .map_err(|error| format!("{error} ({:#010X})", error.code().0.cast_unsigned()))
        }
        "pair-listen" => {
            let options = parse_pairing_options(arguments, "--listen")?;
            let pending = listen_for_pairing(options.store, options.address, options.timeout)
                .map_err(|error| format!("pairing listener failed: {error}"))?;
            confirm_pairing(pending, &options.label)
        }
        "pair-connect" => {
            let options = parse_pairing_options(arguments, "--connect")?;
            let pending = connect_for_pairing(options.store, options.address, options.timeout)
                .map_err(|error| format!("pairing connection failed: {error}"))?;
            confirm_pairing(pending, &options.label)
        }
        "device-init" => {
            let store = parse_store_only(arguments)?;
            let stored = store
                .load_or_create_identity()
                .map_err(|error| format!("device identity initialization failed: {error}"))?;
            println!(
                "DEVICE created={} fingerprint={} store={}",
                stored.created,
                stored.identity.fingerprint(),
                store.root().display()
            );
            Ok(())
        }
        "device-show" => {
            let store = parse_store_only(arguments)?;
            let identity = store
                .load_identity()
                .map_err(|error| format!("device identity load failed: {error}"))?;
            println!(
                "DEVICE fingerprint={} store={}",
                identity.fingerprint(),
                store.root().display()
            );
            Ok(())
        }
        "device-export-cert" => {
            let (store, output) = parse_store_and_output(arguments)?;
            let fingerprint = store
                .export_certificate(&output)
                .map_err(|error| format!("certificate export failed: {error}"))?;
            println!(
                "CERTIFICATE exported=true fingerprint={fingerprint} path={}",
                output.display()
            );
            Ok(())
        }
        "trust-import" => {
            let (store, certificate, fingerprint, label) = parse_trust_import(arguments)?;
            let peer = store
                .trust_peer_file(&certificate, fingerprint, &label)
                .map_err(|error| format!("trust import failed: {error}"))?;
            println!(
                "TRUST imported=true fingerprint={} label={:?}",
                peer.fingerprint, peer.label
            );
            Ok(())
        }
        "trust-list" => {
            let store = parse_store_only(arguments)?;
            let peers = store
                .list_peers()
                .map_err(|error| format!("trust list failed: {error}"))?;
            println!("TRUST peers={}", peers.len());
            for peer in peers {
                println!(
                    "PEER fingerprint={} label={:?}",
                    peer.fingerprint, peer.label
                );
            }
            Ok(())
        }
        "trust-revoke" => {
            let (store, fingerprint) = parse_store_and_fingerprint(arguments)?;
            store
                .revoke_peer(fingerprint)
                .map_err(|error| format!("trust revocation failed: {error}"))?;
            println!("TRUST revoked=true fingerprint={fingerprint}");
            Ok(())
        }
        "identity-test-generate" => {
            let (certificate, private_key) = parse_identity_generation_options(arguments)?;
            let fingerprint = generate_test_identity(&certificate, &private_key)
                .map_err(|error| format!("identity generation failed: {error}"))?;
            println!(
                "IDENTITY generated=true certificate={} private_key={} fingerprint={fingerprint}",
                certificate.display(),
                private_key.display()
            );
            Ok(())
        }
        "secure-source-test" => {
            let parsed = parse_secure_source_options(arguments)?;
            let (tls, local_fingerprint, peer_fingerprint) =
                parsed.tls.load_source(parsed.io_timeout)?;
            println!(
                "IDENTITY local_fingerprint={local_fingerprint} pinned_peer={peer_fingerprint}"
            );
            run_secure_source_probe(SecureSourceProbeOptions {
                listen_address: parsed.listen_address,
                source_path: parsed.source_path,
                offer_ttl: parsed.offer_ttl,
                transfer_ttl: parsed.transfer_ttl,
                io_timeout: parsed.io_timeout,
                lifetime: parsed.lifetime,
                tls,
            })
            .map_err(|error| format!("secure source failed: {error}"))
        }
        "secure-fetch-test" => {
            let parsed = parse_secure_client_options(arguments, true)?;
            let client = build_secure_client(&parsed)?;
            let output_path = parsed
                .output_path
                .ok_or_else(|| "--output is required".to_owned())?;
            let result = run_secure_fetch_probe(SecureFetchProbeOptions {
                client,
                output_path,
            })
            .map_err(|error| format!("secure fetch failed: {error}"))?;
            println!(
                "FETCH completed=true bytes={} sha256={} state={:?}",
                result.bytes,
                encode_hex(&result.sha256),
                result.status.state
            );
            Ok(())
        }
        "secure-receiver-test" => {
            let parsed = parse_secure_client_options(arguments, false)?;
            let client = build_secure_client(&parsed)?;
            run_secure_receiver_probe(&SecureReceiverProbeOptions {
                client,
                lifetime: parsed.lifetime,
                async_mode: parsed.async_mode,
            })
            .map_err(|error| format!("{error} ({:#010X})", error.code().0.cast_unsigned()))
        }
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        _ => Err(format!("unknown command: {command}")),
    }
}

fn print_usage() {
    println!("Usage:");
    println!("  clipferry clipboard-test [--lifetime-seconds <seconds>]");
    println!(
        "  clipferry clipboard-pause-test [--size-mib <MiB>] [--chunk-kib <KiB>] [--delay-ms <ms>] [--async-mode] [--lifetime-seconds <seconds>]"
    );
    println!(
        "  clipferry loopback-clipboard-test [--size-mib <MiB>] [--range-kib <KiB>] [--fragment-bytes <bytes>] [--delay-ms <ms>] [--io-timeout-seconds <seconds>] [--async-mode] [--lifetime-seconds <seconds>]"
    );
    println!(
        "  clipferry file-capture-test [--offer-ttl-seconds <seconds>] [--async-mode] [--lifetime-seconds <seconds>]"
    );
    println!(
        "  clipferry pair-listen --listen <private-ip:port> --label <peer-name> [--store <directory>] [--timeout-seconds <1..300>]"
    );
    println!(
        "  clipferry pair-connect --connect <private-ip:port> --label <peer-name> [--store <directory>] [--timeout-seconds <1..300>]"
    );
    println!("  clipferry device-init [--store <directory>]");
    println!("  clipferry device-show [--store <directory>]");
    println!("  clipferry device-export-cert --out <certificate.der> [--store <directory>]");
    println!(
        "  clipferry trust-import --cert <certificate.der> --fingerprint <SHA-256> --label <name> [--store <directory>]"
    );
    println!("  clipferry trust-list [--store <directory>]");
    println!("  clipferry trust-revoke --fingerprint <SHA-256> [--store <directory>]");
    println!(
        "  clipferry identity-test-generate --cert-out <certificate.der> --key-out <private-key.der>"
    );
    println!(
        "  clipferry secure-source-test --listen <private-ip:port> --file <path> --identity-cert <certificate.der> --identity-key <private-key.der> --peer-cert <certificate.der> --peer-fingerprint <SHA-256> [--offer-ttl-seconds <seconds>] [--transfer-ttl-seconds <seconds>] [--io-timeout-seconds <seconds>] [--lifetime-seconds <seconds>]"
    );
    println!(
        "  clipferry secure-fetch-test --connect <private-ip:port> --output <new-path> --identity-cert <certificate.der> --identity-key <private-key.der> --peer-cert <certificate.der> --peer-fingerprint <SHA-256> [--io-timeout-seconds <seconds>]"
    );
    println!(
        "  clipferry secure-receiver-test --connect <private-ip:port> --identity-cert <certificate.der> --identity-key <private-key.der> --peer-cert <certificate.der> --peer-fingerprint <SHA-256> [--io-timeout-seconds <seconds>] [--async-mode] [--lifetime-seconds <seconds>]"
    );
    println!(
        "  For secure-*-test, --store <directory> --peer-fingerprint <SHA-256> replaces the three DER path options"
    );
}

#[derive(Default)]
struct TlsCliFiles {
    store: Option<std::path::PathBuf>,
    identity_certificate: Option<std::path::PathBuf>,
    identity_private_key: Option<std::path::PathBuf>,
    peer_certificate: Option<std::path::PathBuf>,
    peer_fingerprint: Option<CertificateFingerprint>,
}

impl TlsCliFiles {
    fn load(self) -> Result<(TlsIdentity, Vec<u8>, CertificateFingerprint), String> {
        if let Some(root) = self.store {
            if self.identity_certificate.is_some()
                || self.identity_private_key.is_some()
                || self.peer_certificate.is_some()
            {
                return Err(
                    "--store cannot be combined with --identity-cert, --identity-key, or --peer-cert"
                        .to_owned(),
                );
            }
            let peer_fingerprint = self
                .peer_fingerprint
                .ok_or_else(|| "--peer-fingerprint is required".to_owned())?;
            let store = DeviceStore::new(root);
            let identity = store
                .load_identity()
                .map_err(|error| format!("device identity load failed: {error}"))?;
            let peer = store
                .load_peer(peer_fingerprint)
                .map_err(|error| format!("trusted peer load failed: {error}"))?;
            return Ok((identity, peer.into_certificate_der(), peer_fingerprint));
        }
        let identity_certificate = self
            .identity_certificate
            .ok_or_else(|| "--identity-cert is required".to_owned())?;
        let identity_private_key = self
            .identity_private_key
            .ok_or_else(|| "--identity-key is required".to_owned())?;
        let peer_certificate_path = self
            .peer_certificate
            .ok_or_else(|| "--peer-cert is required".to_owned())?;
        let peer_fingerprint = self
            .peer_fingerprint
            .ok_or_else(|| "--peer-fingerprint is required".to_owned())?;
        let identity = TlsIdentity::load(&identity_certificate, &identity_private_key)
            .map_err(|error| format!("identity load failed: {error}"))?;
        let peer_certificate =
            load_and_verify_peer_certificate(&peer_certificate_path, peer_fingerprint)
                .map_err(|error| format!("peer pin verification failed: {error}"))?;
        Ok((identity, peer_certificate, peer_fingerprint))
    }

    fn load_source(
        self,
        timeout: Duration,
    ) -> Result<
        (
            SecureSourceTls,
            CertificateFingerprint,
            CertificateFingerprint,
        ),
        String,
    > {
        if let Some(root) = self.store {
            if self.identity_certificate.is_some()
                || self.identity_private_key.is_some()
                || self.peer_certificate.is_some()
            {
                return Err(
                    "--store cannot be combined with --identity-cert, --identity-key, or --peer-cert"
                        .to_owned(),
                );
            }
            let peer_fingerprint = self
                .peer_fingerprint
                .ok_or_else(|| "--peer-fingerprint is required".to_owned())?;
            let store = DeviceStore::new(root);
            let identity = store
                .load_identity()
                .map_err(|error| format!("device identity load failed: {error}"))?;
            store
                .load_peer(peer_fingerprint)
                .map_err(|error| format!("trusted peer load failed: {error}"))?;
            let local_fingerprint = identity.fingerprint();
            let tls = TrustedTlsServer::new(identity, store, timeout)
                .map_err(|error| format!("TLS server configuration failed: {error}"))?;
            return Ok((
                SecureSourceTls::Trusted {
                    tls,
                    authorized_peer: peer_fingerprint,
                },
                local_fingerprint,
                peer_fingerprint,
            ));
        }
        let (identity, peer_certificate, peer_fingerprint) = self.load()?;
        let local_fingerprint = identity.fingerprint();
        let tls = PinnedTlsServer::new(&identity, peer_certificate, peer_fingerprint, timeout)
            .map_err(|error| format!("TLS server configuration failed: {error}"))?;
        Ok((
            SecureSourceTls::Pinned(tls),
            local_fingerprint,
            peer_fingerprint,
        ))
    }
}

fn parse_store_only(mut arguments: impl Iterator<Item = String>) -> Result<DeviceStore, String> {
    let mut root = None;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--store" => root = Some(parse_path(&mut arguments, &argument)?),
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    resolve_store(root)
}

fn parse_store_and_output(
    mut arguments: impl Iterator<Item = String>,
) -> Result<(DeviceStore, std::path::PathBuf), String> {
    let mut root = None;
    let mut output = None;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--store" => root = Some(parse_path(&mut arguments, &argument)?),
            "--out" => output = Some(parse_path(&mut arguments, &argument)?),
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    Ok((
        resolve_store(root)?,
        output.ok_or_else(|| "--out is required".to_owned())?,
    ))
}

fn parse_trust_import(
    mut arguments: impl Iterator<Item = String>,
) -> Result<
    (
        DeviceStore,
        std::path::PathBuf,
        CertificateFingerprint,
        String,
    ),
    String,
> {
    let mut root = None;
    let mut certificate = None;
    let mut fingerprint = None;
    let mut label = None;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--store" => root = Some(parse_path(&mut arguments, &argument)?),
            "--cert" => certificate = Some(parse_path(&mut arguments, &argument)?),
            "--fingerprint" => {
                fingerprint = Some(parse_fingerprint(&mut arguments, &argument)?);
            }
            "--label" => {
                label = Some(
                    arguments
                        .next()
                        .ok_or_else(|| "--label requires a value".to_owned())?,
                );
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    Ok((
        resolve_store(root)?,
        certificate.ok_or_else(|| "--cert is required".to_owned())?,
        fingerprint.ok_or_else(|| "--fingerprint is required".to_owned())?,
        label.ok_or_else(|| "--label is required".to_owned())?,
    ))
}

fn parse_store_and_fingerprint(
    mut arguments: impl Iterator<Item = String>,
) -> Result<(DeviceStore, CertificateFingerprint), String> {
    let mut root = None;
    let mut fingerprint = None;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--store" => root = Some(parse_path(&mut arguments, &argument)?),
            "--fingerprint" => {
                fingerprint = Some(parse_fingerprint(&mut arguments, &argument)?);
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    Ok((
        resolve_store(root)?,
        fingerprint.ok_or_else(|| "--fingerprint is required".to_owned())?,
    ))
}

fn resolve_store(root: Option<std::path::PathBuf>) -> Result<DeviceStore, String> {
    root.map_or_else(
        || {
            DeviceStore::current_user()
                .map_err(|error| format!("device store unavailable: {error}"))
        },
        |root| Ok(DeviceStore::new(root)),
    )
}

struct ParsedSecureSource {
    listen_address: std::net::SocketAddr,
    source_path: std::path::PathBuf,
    offer_ttl: Duration,
    transfer_ttl: Duration,
    io_timeout: Duration,
    lifetime: Option<Duration>,
    tls: TlsCliFiles,
}

struct ParsedSecureClient {
    connect_address: std::net::SocketAddr,
    output_path: Option<std::path::PathBuf>,
    io_timeout: Duration,
    lifetime: Option<Duration>,
    async_mode: bool,
    tls: TlsCliFiles,
}

struct PairingCliOptions {
    address: std::net::SocketAddr,
    store: DeviceStore,
    label: String,
    timeout: Duration,
}

fn parse_pairing_options(
    mut arguments: impl Iterator<Item = String>,
    endpoint_option: &str,
) -> Result<PairingCliOptions, String> {
    let mut address = None;
    let mut root = None;
    let mut label = None;
    let mut timeout_seconds = 120_u64;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            value if value == endpoint_option => {
                address = Some(parse_private_socket(&mut arguments, &argument)?);
            }
            "--store" => root = Some(parse_path(&mut arguments, &argument)?),
            "--label" => {
                label = Some(
                    arguments
                        .next()
                        .ok_or_else(|| "--label requires a value".to_owned())?,
                );
            }
            "--timeout-seconds" => {
                timeout_seconds = parse_value(&mut arguments, &argument)?;
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    if !(1..=300).contains(&timeout_seconds) {
        return Err("--timeout-seconds must be between 1 and 300".to_owned());
    }
    let label = label.ok_or_else(|| "--label is required".to_owned())?;
    let trimmed_label = label.trim();
    if trimmed_label.is_empty()
        || trimmed_label.len() > 128
        || trimmed_label.chars().any(char::is_control)
    {
        return Err(
            "--label must contain 1 to 128 UTF-8 bytes without control characters".to_owned(),
        );
    }
    Ok(PairingCliOptions {
        address: address.ok_or_else(|| format!("{endpoint_option} is required"))?,
        store: resolve_store(root)?,
        label: trimmed_label.to_owned(),
        timeout: Duration::from_secs(timeout_seconds),
    })
}

fn confirm_pairing(pending: PendingPairing, label: &str) -> Result<(), String> {
    println!(
        "PAIR verify_code={} local_fingerprint={} peer_fingerprint={} peer_address={}",
        pending.code(),
        pending.local_fingerprint(),
        pending.peer_fingerprint(),
        pending.peer_address()
    );
    println!("Compare verify_code on both devices. Type YES on both devices to approve:");
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|error| format!("pairing confirmation input failed: {error}"))?;
    let approved = answer.trim() == "YES";
    let peer = pending
        .confirm(approved, label)
        .map_err(|error| format!("pairing confirmation failed: {error}"))?;
    println!(
        "PAIRED completed=true fingerprint={} label={:?}",
        peer.fingerprint, peer.label
    );
    Ok(())
}

fn parse_identity_generation_options(
    mut arguments: impl Iterator<Item = String>,
) -> Result<(std::path::PathBuf, std::path::PathBuf), String> {
    let mut certificate = None;
    let mut private_key = None;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--cert-out" => certificate = Some(parse_path(&mut arguments, &argument)?),
            "--key-out" => private_key = Some(parse_path(&mut arguments, &argument)?),
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    Ok((
        certificate.ok_or_else(|| "--cert-out is required".to_owned())?,
        private_key.ok_or_else(|| "--key-out is required".to_owned())?,
    ))
}

fn parse_secure_source_options(
    mut arguments: impl Iterator<Item = String>,
) -> Result<ParsedSecureSource, String> {
    let mut listen_address = None;
    let mut source_path = None;
    let mut offer_ttl_seconds = 900_u64;
    let mut transfer_ttl_seconds = 3600_u64;
    let mut io_timeout_seconds = 30_u64;
    let mut lifetime = None;
    let mut tls = TlsCliFiles::default();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--listen" => {
                listen_address = Some(parse_private_socket(&mut arguments, &argument)?);
            }
            "--file" => source_path = Some(parse_path(&mut arguments, &argument)?),
            "--offer-ttl-seconds" => {
                offer_ttl_seconds = parse_value(&mut arguments, &argument)?;
            }
            "--transfer-ttl-seconds" => {
                transfer_ttl_seconds = parse_value(&mut arguments, &argument)?;
            }
            "--io-timeout-seconds" => {
                io_timeout_seconds = parse_value(&mut arguments, &argument)?;
            }
            "--lifetime-seconds" => {
                lifetime = Some(Duration::from_secs(parse_value(&mut arguments, &argument)?));
            }
            "--store" => {
                tls.store = Some(parse_path(&mut arguments, &argument)?);
            }
            "--identity-cert" => {
                tls.identity_certificate = Some(parse_path(&mut arguments, &argument)?);
            }
            "--identity-key" => {
                tls.identity_private_key = Some(parse_path(&mut arguments, &argument)?);
            }
            "--peer-cert" => {
                tls.peer_certificate = Some(parse_path(&mut arguments, &argument)?);
            }
            "--peer-fingerprint" => {
                tls.peer_fingerprint = Some(parse_fingerprint(&mut arguments, &argument)?);
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    if offer_ttl_seconds == 0 || transfer_ttl_seconds == 0 || io_timeout_seconds == 0 {
        return Err("secure TTL and timeout values must be greater than zero".to_owned());
    }
    Ok(ParsedSecureSource {
        listen_address: listen_address.ok_or_else(|| "--listen is required".to_owned())?,
        source_path: source_path.ok_or_else(|| "--file is required".to_owned())?,
        offer_ttl: Duration::from_secs(offer_ttl_seconds),
        transfer_ttl: Duration::from_secs(transfer_ttl_seconds),
        io_timeout: Duration::from_secs(io_timeout_seconds),
        lifetime,
        tls,
    })
}

fn parse_secure_client_options(
    mut arguments: impl Iterator<Item = String>,
    allow_output: bool,
) -> Result<ParsedSecureClient, String> {
    let mut connect_address = None;
    let mut output_path = None;
    let mut io_timeout_seconds = 30_u64;
    let mut lifetime = None;
    let mut async_mode = false;
    let mut tls = TlsCliFiles::default();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--connect" => {
                connect_address = Some(parse_private_socket(&mut arguments, &argument)?);
            }
            "--output" if allow_output => {
                output_path = Some(parse_path(&mut arguments, &argument)?);
            }
            "--io-timeout-seconds" => {
                io_timeout_seconds = parse_value(&mut arguments, &argument)?;
            }
            "--lifetime-seconds" if !allow_output => {
                lifetime = Some(Duration::from_secs(parse_value(&mut arguments, &argument)?));
            }
            "--async-mode" if !allow_output => async_mode = true,
            "--store" => {
                tls.store = Some(parse_path(&mut arguments, &argument)?);
            }
            "--identity-cert" => {
                tls.identity_certificate = Some(parse_path(&mut arguments, &argument)?);
            }
            "--identity-key" => {
                tls.identity_private_key = Some(parse_path(&mut arguments, &argument)?);
            }
            "--peer-cert" => {
                tls.peer_certificate = Some(parse_path(&mut arguments, &argument)?);
            }
            "--peer-fingerprint" => {
                tls.peer_fingerprint = Some(parse_fingerprint(&mut arguments, &argument)?);
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    if io_timeout_seconds == 0 {
        return Err("--io-timeout-seconds must be greater than zero".to_owned());
    }
    if allow_output && output_path.is_none() {
        return Err("--output is required".to_owned());
    }
    Ok(ParsedSecureClient {
        connect_address: connect_address.ok_or_else(|| "--connect is required".to_owned())?,
        output_path,
        io_timeout: Duration::from_secs(io_timeout_seconds),
        lifetime,
        async_mode,
        tls,
    })
}

fn build_secure_client(parsed: &ParsedSecureClient) -> Result<SecureOfferClient, String> {
    let tls_files = TlsCliFiles {
        store: parsed.tls.store.clone(),
        identity_certificate: parsed.tls.identity_certificate.clone(),
        identity_private_key: parsed.tls.identity_private_key.clone(),
        peer_certificate: parsed.tls.peer_certificate.clone(),
        peer_fingerprint: parsed.tls.peer_fingerprint,
    };
    let (identity, peer_certificate, peer_fingerprint) = tls_files.load()?;
    println!(
        "IDENTITY local_fingerprint={} pinned_peer={peer_fingerprint}",
        identity.fingerprint()
    );
    let tls = PinnedTlsClient::new(
        &identity,
        peer_certificate,
        peer_fingerprint,
        parsed.io_timeout,
    )
    .map_err(|error| format!("TLS client configuration failed: {error}"))?;
    Ok(SecureOfferClient::new(parsed.connect_address, tls))
}

fn parse_path(
    arguments: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<std::path::PathBuf, String> {
    arguments
        .next()
        .map(std::path::PathBuf::from)
        .ok_or_else(|| format!("{option} requires a path"))
}

fn parse_fingerprint(
    arguments: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<CertificateFingerprint, String> {
    let value = arguments
        .next()
        .ok_or_else(|| format!("{option} requires a SHA-256 fingerprint"))?;
    CertificateFingerprint::from_str(&value)
        .map_err(|error| format!("invalid value for {option}: {error}"))
}

fn parse_private_socket(
    arguments: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<std::net::SocketAddr, String> {
    let value = arguments
        .next()
        .ok_or_else(|| format!("{option} requires an address"))?;
    let address = std::net::SocketAddr::from_str(&value)
        .map_err(|error| format!("invalid value for {option}: {error}"))?;
    let allowed = match address.ip() {
        std::net::IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
        std::net::IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local(),
    };
    if !allowed {
        return Err(format!(
            "{option} must use a loopback or private unicast address"
        ));
    }
    Ok(address)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(
        String::with_capacity(bytes.len().saturating_mul(2)),
        |mut text, byte| {
            let _ = write!(text, "{byte:02X}");
            text
        },
    )
}

fn parse_file_capture_probe_options(
    mut arguments: impl Iterator<Item = String>,
) -> Result<FileCaptureProbeOptions, String> {
    let mut offer_ttl_seconds = 300_u64;
    let mut lifetime = None;
    let mut async_mode = false;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--async-mode" => async_mode = true,
            "--offer-ttl-seconds" => {
                offer_ttl_seconds = parse_value(&mut arguments, &argument)?;
            }
            "--lifetime-seconds" => {
                lifetime = Some(Duration::from_secs(parse_value(&mut arguments, &argument)?));
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    if offer_ttl_seconds == 0 {
        return Err("--offer-ttl-seconds must be greater than zero".to_owned());
    }
    Ok(FileCaptureProbeOptions {
        offer_ttl: Duration::from_secs(offer_ttl_seconds),
        lifetime,
        async_mode,
    })
}

fn parse_loopback_probe_options(
    mut arguments: impl Iterator<Item = String>,
) -> Result<LoopbackProbeOptions, String> {
    let mut size_mib = 64_u64;
    let mut range_kib = 64_u64;
    let mut fragment_bytes = 8 * 1024_u64;
    let mut delay_ms = 1_u64;
    let mut io_timeout_seconds = 30_u64;
    let mut lifetime = None;
    let mut async_mode = false;

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--async-mode" => async_mode = true,
            "--size-mib" => size_mib = parse_value(&mut arguments, &argument)?,
            "--range-kib" => range_kib = parse_value(&mut arguments, &argument)?,
            "--fragment-bytes" => {
                fragment_bytes = parse_value(&mut arguments, &argument)?;
            }
            "--delay-ms" => delay_ms = parse_value(&mut arguments, &argument)?,
            "--io-timeout-seconds" => {
                io_timeout_seconds = parse_value(&mut arguments, &argument)?;
            }
            "--lifetime-seconds" => {
                lifetime = Some(Duration::from_secs(parse_value(&mut arguments, &argument)?));
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    if range_kib == 0 || fragment_bytes == 0 || io_timeout_seconds == 0 {
        return Err(
            "--range-kib, --fragment-bytes and --io-timeout-seconds must be greater than zero"
                .to_owned(),
        );
    }

    let size_bytes = size_mib
        .checked_mul(1024 * 1024)
        .ok_or_else(|| "--size-mib is too large".to_owned())?;
    let range_bytes = range_kib
        .checked_mul(1024)
        .and_then(|bytes| usize::try_from(bytes).ok())
        .ok_or_else(|| "--range-kib is too large".to_owned())?;
    let fragment_bytes =
        usize::try_from(fragment_bytes).map_err(|_| "--fragment-bytes is too large".to_owned())?;
    Ok(LoopbackProbeOptions {
        size_bytes,
        range_bytes,
        fragment_bytes,
        range_delay: Duration::from_millis(delay_ms),
        connect_timeout: Duration::from_secs(2),
        io_timeout: Duration::from_secs(io_timeout_seconds),
        lifetime,
        async_mode,
    })
}

fn parse_pause_probe_options(
    mut arguments: impl Iterator<Item = String>,
) -> Result<PauseProbeOptions, String> {
    let mut size_mib = 64_u64;
    let mut chunk_kib = 64_u64;
    let mut delay_ms = 8_u64;
    let mut lifetime = None;
    let mut async_mode = false;

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--async-mode" => async_mode = true,
            "--size-mib" => size_mib = parse_value(&mut arguments, &argument)?,
            "--chunk-kib" => chunk_kib = parse_value(&mut arguments, &argument)?,
            "--delay-ms" => delay_ms = parse_value(&mut arguments, &argument)?,
            "--lifetime-seconds" => {
                lifetime = Some(Duration::from_secs(parse_value(&mut arguments, &argument)?));
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    if size_mib == 0 || chunk_kib == 0 {
        return Err("--size-mib and --chunk-kib must be greater than zero".to_owned());
    }

    let size_bytes = size_mib
        .checked_mul(1024 * 1024)
        .ok_or_else(|| "--size-mib is too large".to_owned())?;
    let chunk_bytes = chunk_kib
        .checked_mul(1024)
        .and_then(|bytes| usize::try_from(bytes).ok())
        .ok_or_else(|| "--chunk-kib is too large".to_owned())?;
    Ok(PauseProbeOptions {
        size_bytes,
        chunk_bytes,
        chunk_delay: Duration::from_millis(delay_ms),
        lifetime,
        async_mode,
    })
}

fn parse_value(arguments: &mut impl Iterator<Item = String>, option: &str) -> Result<u64, String> {
    arguments
        .next()
        .ok_or_else(|| format!("{option} requires a value"))?
        .parse::<u64>()
        .map_err(|error| format!("invalid value for {option}: {error}"))
}
