//! Shared TLS client configuration for the wss:// connections dialled by the
//! desktop client, the vtermc CLI, and the server's relay uplink.
//!
//! Everything is built on rustls so the binaries never link the system
//! OpenSSL (libssl.so.3), which keeps them compatible with older distros
//! that still ship OpenSSL 1.1 (e.g. Ubuntu 18.04).

use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use tracing::{debug, info, trace, warn};

pub const TLS_CA_FILE_ENV: &str = "TLS_CA_FILE";
pub const TLS_INSECURE_ENV: &str = "TERMINAL_GUI_TLS_INSECURE";
pub const TLS_STRICT_ENV: &str = "TERMINAL_GUI_TLS_STRICT";
const DEFAULT_CERT_FILE: &str = "server.crt";
const DEFAULT_CA_FILE: &str = "server.cer";

/// Default behavior (no env vars set): ACCEPT invalid certs — the products
/// talk to self-signed development servers by default.
/// TERMINAL_GUI_TLS_STRICT=1 or TERMINAL_GUI_TLS_INSECURE=0: REJECT them.
pub fn should_accept_invalid_tls() -> bool {
    if std::env::var(TLS_STRICT_ENV).ok().as_deref() == Some("1") {
        return false;
    }

    std::env::var(TLS_INSECURE_ENV).ok().as_deref() != Some("0")
}

/// Whether a websocket URL points at localhost, where the companion server's
/// locally generated `server.crt` / `server.cer` can be trusted directly.
pub fn uses_localhost(websocket_url: &str) -> bool {
    let Some(authority) = websocket_url
        .strip_prefix("wss://")
        .or_else(|| websocket_url.strip_prefix("ws://"))
    else {
        return false;
    };

    let host = if authority.starts_with('[') {
        authority
            .find(']')
            .map(|end| &authority[..=end])
            .unwrap_or(authority)
    } else {
        authority.split([':', '/']).next().unwrap_or(authority)
    };

    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

/// Verifier that accepts every server certificate but still checks the
/// handshake's signature algorithms via the crypto provider, following the
/// pattern recommended by the rustls documentation.
#[derive(Debug)]
struct AcceptAnyServerCert(CryptoProvider);

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn client_config_with_verifier(
    provider: &Arc<CryptoProvider>,
    verifier: Arc<dyn ServerCertVerifier>,
) -> anyhow::Result<ClientConfig> {
    Ok(ClientConfig::builder_with_provider(Arc::clone(provider))
        .with_safe_default_protocol_versions()
        .map_err(|error| anyhow::anyhow!("Failed to select TLS protocol versions: {}", error))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

/// A client config that accepts any server certificate. Used when
/// strict/insecure env vars ask for it, and by tests driving TLS servers.
pub fn insecure_client_tls_config() -> anyhow::Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(Arc::new(client_config_with_verifier(
        &provider,
        Arc::new(AcceptAnyServerCert((*provider).clone())),
    )?))
}

fn add_ca_file(roots: &mut RootCertStore, certificate_path: &str) -> anyhow::Result<()> {
    let certificate_bytes = std::fs::read(certificate_path).map_err(|error| {
        anyhow::anyhow!("Failed to read TLS CA file {}: {}", certificate_path, error)
    })?;

    if certificate_path.ends_with(".cer") || certificate_path.ends_with(".der") {
        let certificate = CertificateDer::from(certificate_bytes);
        roots.add(certificate).map_err(|error| {
            anyhow::anyhow!(
                "Failed to parse TLS CA file {}: {}",
                certificate_path,
                error
            )
        })?;
    } else {
        let mut count = 0;
        for certificate in rustls_pemfile::certs(&mut BufReader::new(certificate_bytes.as_slice()))
        {
            let certificate = certificate.map_err(|error| {
                anyhow::anyhow!(
                    "Failed to parse TLS CA file {}: {}",
                    certificate_path,
                    error
                )
            })?;
            roots.add(certificate).map_err(|error| {
                anyhow::anyhow!(
                    "Failed to parse TLS CA file {}: {}",
                    certificate_path,
                    error
                )
            })?;
            count += 1;
        }
        if count == 0 {
            anyhow::bail!("No certificates found in TLS CA file {}", certificate_path);
        }
    }

    info!("Loaded TLS CA certificate from {}", certificate_path);
    Ok(())
}

/// Build the rustls client config for dialling `websocket_url`: OS root
/// certificates plus the custom CA files the deployments rely on, or an
/// anything-goes verifier when certificate validation is disabled.
pub fn build_rustls_client_config(websocket_url: &str) -> anyhow::Result<Arc<ClientConfig>> {
    if should_accept_invalid_tls() {
        // Expected deployment configuration, logged once per connection setup
        // — pure noise at the default level.
        trace!(
            "TLS client for {} accepting invalid certificates/hostnames (strict={}, insecure=0 disabled)",
            websocket_url,
            std::env::var(TLS_STRICT_ENV).ok().as_deref() == Some("1")
        );
        return insecure_client_tls_config();
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();

    // `load_native_certs` returns a result struct that tolerates partial
    // failures: usable certs are in `certs`, store problems in `errors`.
    let loaded = rustls_native_certs::load_native_certs();
    let (added, ignored) = roots.add_parsable_certificates(loaded.certs);
    info!(
        "TLS client for {} loaded {} OS root certificate(s) ({} unusable)",
        websocket_url, added, ignored
    );
    for error in &loaded.errors {
        warn!("OS certificate store warning: {}", error);
    }

    if let Ok(ca_file) = std::env::var(TLS_CA_FILE_ENV) {
        info!(
            "TLS client for {} using CA file from {}={}",
            websocket_url, TLS_CA_FILE_ENV, ca_file
        );
        add_ca_file(&mut roots, &ca_file)?;
    } else if uses_localhost(websocket_url) {
        let mut loaded_local_ca = false;
        for candidate in [DEFAULT_CERT_FILE, DEFAULT_CA_FILE] {
            if std::path::Path::new(candidate).exists() {
                info!(
                    "TLS client for {} using local default certificate {}",
                    websocket_url, candidate
                );
                add_ca_file(&mut roots, candidate)?;
                loaded_local_ca = true;
                break;
            }
        }
        if !loaded_local_ca {
            debug!(
                "TLS client for {} found no local default certificate file",
                websocket_url
            );
        }
    }

    if roots.is_empty() {
        warn!(
            "TLS client for {} has an empty root store; every certificate will be rejected",
            websocket_url
        );
    }

    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| anyhow::anyhow!("Failed to select TLS protocol versions: {}", error))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

pub fn build_strict_rustls_client_config(
    websocket_url: &str,
    ca_pem: &str,
) -> anyhow::Result<Arc<ClientConfig>> {
    if ca_pem.trim().is_empty() {
        anyhow::bail!(
            "Strict TLS verification requires a Root CA PEM for {}",
            websocket_url
        );
    }
    let roots = crate::private_ca::root_certificates_from_pem(ca_pem)
        .map_err(|error| anyhow::anyhow!("Invalid Root CA for {}: {}", websocket_url, error))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| anyhow::anyhow!("Failed to select TLS protocol versions: {}", error))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

// ----------------------------------------------------------------------------
// Managed development identities
// ----------------------------------------------------------------------------

/// Write a self-signed localhost PEM identity (certificate + PKCS#8 key).
///
/// Mirrors the attributes the old per-platform generators (openssl on Unix,
/// PowerShell/.NET PFX on Windows) produced: CN=localhost, SAN
/// DNS:localhost + IP:127.0.0.1 + IP:::1, serverAuth EKU, backdated one day
/// and valid for 365 days. Apple clients (ATS) abort the TLS handshake
/// fatally without the SAN and EKU. Everything is generated in-process with
/// rcgen (ring), so no openssl/PowerShell/platform cert store is involved.
pub fn generate_managed_pem_identity(cert_path: &Path, key_path: &Path) -> anyhow::Result<()> {
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("localhost".try_into()?),
        rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        rcgen::SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
    ];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(365);
    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    std::fs::write(cert_path, cert.pem())?;
    std::fs::write(key_path, key_pair.serialize_pem())?;
    Ok(())
}

/// A managed PEM identity stays usable while the certificate parses, carries
/// a SubjectAlternativeName, and does not expire within
/// `renewal_window_secs`.
pub fn managed_pem_is_valid(cert_path: &Path, renewal_window_secs: u64) -> bool {
    let Ok(pem_bytes) = std::fs::read(cert_path) else {
        return false;
    };
    let Ok((_, pem)) = x509_parser::pem::parse_x509_pem(&pem_bytes) else {
        return false;
    };
    let Ok(cert) = pem.parse_x509() else {
        return false;
    };
    if cert.subject_alternative_name().ok().flatten().is_none() {
        return false;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(i64::MAX);
    cert.validity().not_after.timestamp() > now + renewal_window_secs as i64
}

#[cfg(test)]
mod managed_identity_tests {
    use super::*;

    #[test]
    fn generated_identity_is_valid_and_round_trips_through_rustls() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("server.crt");
        let key = dir.path().join("server.key");

        generate_managed_pem_identity(&cert, &key).unwrap();

        assert!(managed_pem_is_valid(
            &cert,
            TLS_RENEWAL_WINDOW_SECS_FOR_TEST
        ));
        // The PEM pair must load into a rustls server config unchanged.
        let certs: Vec<_> =
            rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(&cert).unwrap()))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let key_der =
            rustls_pemfile::private_key(&mut BufReader::new(std::fs::File::open(&key).unwrap()))
                .unwrap()
                .unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key_der);
        assert!(config.is_ok(), "rustls must accept the generated identity");
    }

    #[test]
    fn invalid_when_certificate_is_missing_or_garbage() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!managed_pem_is_valid(&dir.path().join("absent.crt"), 0));
        let garbage = dir.path().join("garbage.crt");
        std::fs::write(&garbage, b"not a certificate").unwrap();
        assert!(!managed_pem_is_valid(&garbage, 0));
    }

    /// A generous window for tests — only checks the "not near expiry" logic
    /// negatively (a fresh cert is never near expiry).
    const TLS_RENEWAL_WINDOW_SECS_FOR_TEST: u64 = 45 * 24 * 60 * 60;
}

#[cfg(test)]
mod strict_tls_tests {
    use super::*;
    use crate::private_ca::{generate_root_ca, issue_leaf_certificate};
    use rustls::pki_types::ServerName;
    use rustls::{ClientConnection, ServerConnection};
    use std::io::Cursor;

    struct TestIdentity {
        _directory: tempfile::TempDir,
        root: std::path::PathBuf,
        root_key: std::path::PathBuf,
        leaf: std::path::PathBuf,
        leaf_key: std::path::PathBuf,
    }

    impl TestIdentity {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let identity = Self {
                root: directory.path().join("root.pem"),
                root_key: directory.path().join("root.key"),
                leaf: directory.path().join("leaf.pem"),
                leaf_key: directory.path().join("leaf.key"),
                _directory: directory,
            };
            generate_root_ca(&identity.root, &identity.root_key, "Test Root CA").unwrap();
            identity.issue(&["localhost"]);
            identity
        }

        fn issue(&self, sans: &[&str]) {
            issue_leaf_certificate(
                &self.root,
                &self.root_key,
                &self.leaf,
                &self.leaf_key,
                "Test Server",
                &sans
                    .iter()
                    .map(|value| value.to_string())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        }

        fn root_pem(&self) -> String {
            std::fs::read_to_string(&self.root).unwrap()
        }

        fn handshake(&self, client: Arc<ClientConfig>, server_name: &str) -> anyhow::Result<()> {
            let certs =
                rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(&self.leaf)?))
                    .collect::<Result<Vec<_>, _>>()?;
            let key = rustls_pemfile::private_key(&mut BufReader::new(std::fs::File::open(
                &self.leaf_key,
            )?))?
            .unwrap();
            let server_config = Arc::new(
                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)?,
            );
            let mut client =
                ClientConnection::new(client, ServerName::try_from(server_name.to_string())?)?;
            let mut server = ServerConnection::new(server_config)?;

            for _ in 0..32 {
                let mut progressed = false;
                let mut client_bytes = Vec::new();
                client.write_tls(&mut client_bytes)?;
                if !client_bytes.is_empty() {
                    server.read_tls(&mut Cursor::new(client_bytes))?;
                    server.process_new_packets()?;
                    progressed = true;
                }
                let mut server_bytes = Vec::new();
                server.write_tls(&mut server_bytes)?;
                if !server_bytes.is_empty() {
                    client.read_tls(&mut Cursor::new(server_bytes))?;
                    client.process_new_packets()?;
                    progressed = true;
                }
                if !client.is_handshaking() && !server.is_handshaking() {
                    return Ok(());
                }
                if !progressed {
                    break;
                }
            }
            anyhow::bail!("TLS handshake did not complete")
        }
    }

    #[test]
    fn correct_ca_connects_and_leaf_reissue_keeps_the_same_trust_anchor() {
        let identity = TestIdentity::new();
        let client =
            build_strict_rustls_client_config("wss://localhost:7878", &identity.root_pem())
                .unwrap();
        identity
            .handshake(Arc::clone(&client), "localhost")
            .unwrap();

        identity.issue(&["localhost", "server.home.arpa"]);
        identity.handshake(client, "localhost").unwrap();
    }

    #[test]
    fn wrong_ca_and_san_mismatch_are_rejected() {
        let identity = TestIdentity::new();
        let wrong_identity = TestIdentity::new();
        let wrong_ca =
            build_strict_rustls_client_config("wss://localhost:7878", &wrong_identity.root_pem())
                .unwrap();
        assert!(identity.handshake(wrong_ca, "localhost").is_err());

        let client =
            build_strict_rustls_client_config("wss://localhost:7878", &identity.root_pem())
                .unwrap();
        assert!(identity.handshake(client, "wrong.example.com").is_err());
    }

    #[test]
    fn strict_mode_requires_a_parseable_ca() {
        assert!(build_strict_rustls_client_config("wss://localhost:7878", "").is_err());
        assert!(build_strict_rustls_client_config("wss://localhost:7878", "not a PEM").is_err());
    }
}
