use std::collections::BTreeSet;
use std::io::{BufReader, Write};
use std::net::IpAddr;
use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use x509_parser::extensions::GeneralName;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInfo {
    pub subject: String,
    pub fingerprint_sha256: String,
    pub not_before: String,
    pub not_after: String,
    pub sans: Vec<String>,
    pub is_ca: bool,
}

pub fn normalize_san(value: &str) -> anyhow::Result<String> {
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("SAN must not be empty");
    }
    if value.contains('*') {
        anyhow::bail!("Wildcard SAN entries are not supported");
    }
    if let Ok(address) = value.trim_matches(['[', ']']).parse::<IpAddr>() {
        if address.is_unspecified() {
            anyhow::bail!("Unspecified IP addresses cannot be used as SAN entries");
        }
        return Ok(address.to_string());
    }

    let domain = value.trim_end_matches('.').to_ascii_lowercase();
    if domain.len() > 253
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        anyhow::bail!("Invalid DNS SAN entry: {}", value);
    }
    Ok(domain)
}

pub fn normalize_sans<I, S>(values: I) -> anyhow::Result<Vec<String>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut normalized = BTreeSet::new();
    for value in values {
        normalized.insert(normalize_san(value.as_ref())?);
    }
    Ok(normalized.into_iter().collect())
}

pub fn generate_root_ca(
    cert_path: &Path,
    key_path: &Path,
    common_name: &str,
) -> anyhow::Result<()> {
    if cert_path.exists() && key_path.exists() {
        certificate_info(cert_path)?;
        return Ok(());
    }

    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(3650);

    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    atomic_write(cert_path, cert.pem().as_bytes(), false)?;
    atomic_write(key_path, key.serialize_pem().as_bytes(), true)?;
    Ok(())
}

pub fn issue_leaf_certificate(
    root_cert_path: &Path,
    root_key_path: &Path,
    leaf_cert_path: &Path,
    leaf_key_path: &Path,
    common_name: &str,
    sans: &[String],
) -> anyhow::Result<()> {
    let sans = normalize_sans(sans)?;
    if sans.is_empty() {
        anyhow::bail!("At least one SAN is required");
    }

    let root_pem = std::fs::read_to_string(root_cert_path)?;
    let root_key = KeyPair::from_pem(&std::fs::read_to_string(root_key_path)?)?;
    let issuer = Issuer::from_ca_cert_pem(&root_pem, root_key)?;

    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.subject_alt_names = sans
        .iter()
        .map(|value| {
            if let Ok(address) = value.parse::<IpAddr>() {
                Ok(SanType::IpAddress(address))
            } else {
                Ok(SanType::DnsName(value.clone().try_into()?))
            }
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(90);

    let leaf_key = KeyPair::generate()?;
    let leaf = params.signed_by(&leaf_key, &issuer)?;
    let chain = format!("{}{}", leaf.pem(), root_pem);
    atomic_write(leaf_cert_path, chain.as_bytes(), false)?;
    atomic_write(leaf_key_path, leaf_key.serialize_pem().as_bytes(), true)?;
    Ok(())
}

pub fn certificate_info(path: &Path) -> anyhow::Result<CertificateInfo> {
    let bytes = std::fs::read(path)?;
    certificate_info_from_pem(&bytes)
}

pub fn certificate_info_from_pem(bytes: &[u8]) -> anyhow::Result<CertificateInfo> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(bytes)?;
    let cert = pem.parse_x509()?;
    let fingerprint = Sha256::digest(pem.contents.as_slice());
    let fingerprint_sha256 = fingerprint
        .iter()
        .map(|byte| format!("{:02X}", byte))
        .collect::<Vec<_>>()
        .join(":");
    let sans = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|extension| {
            extension
                .value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(value) => Some(value.to_string()),
                    GeneralName::IPAddress(bytes) => match bytes.len() {
                        4 => Some(IpAddr::from(<[u8; 4]>::try_from(*bytes).ok()?).to_string()),
                        16 => Some(IpAddr::from(<[u8; 16]>::try_from(*bytes).ok()?).to_string()),
                        _ => None,
                    },
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(CertificateInfo {
        subject: cert.subject().to_string(),
        fingerprint_sha256,
        not_before: format_timestamp(cert.validity().not_before.timestamp()),
        not_after: format_timestamp(cert.validity().not_after.timestamp()),
        sans,
        is_ca: cert
            .basic_constraints()
            .ok()
            .flatten()
            .is_some_and(|value| value.value.ca),
    })
}

pub fn leaf_certificate_needs_reissue(
    cert_path: &Path,
    expected_sans: &[String],
    renewal_window_secs: u64,
) -> bool {
    let Ok(info) = certificate_info(cert_path) else {
        return true;
    };
    let actual = info.sans.into_iter().collect::<BTreeSet<_>>();
    let expected = expected_sans.iter().cloned().collect::<BTreeSet<_>>();
    if actual != expected {
        return true;
    }
    !crate::tls::managed_pem_is_valid(cert_path, renewal_window_secs)
}

pub fn root_certificates_from_pem(pem: &str) -> anyhow::Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    let mut count = 0;
    for certificate in rustls_pemfile::certs(&mut BufReader::new(pem.as_bytes())) {
        roots.add(certificate?)?;
        count += 1;
    }
    if count == 0 {
        anyhow::bail!("The CA PEM does not contain a certificate");
    }
    Ok(roots)
}

fn format_timestamp(timestamp: i64) -> String {
    chrono::DateTime::from_timestamp(timestamp, 0)
        .map(|value| value.to_rfc3339())
        .unwrap_or_default()
}

fn atomic_write(path: &Path, contents: &[u8], private: bool) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options.open(&temporary)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);

    #[cfg(not(windows))]
    std::fs::rename(&temporary, path)?;
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        };
        let from = temporary
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let to = path
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        if unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_ca_and_leaf_with_normalized_sans() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("root.pem");
        let root_key = directory.path().join("root.key");
        let leaf = directory.path().join("leaf.pem");
        let leaf_key = directory.path().join("leaf.key");
        generate_root_ca(&root, &root_key, "Test Root CA").unwrap();
        issue_leaf_certificate(
            &root,
            &root_key,
            &leaf,
            &leaf_key,
            "Test Server",
            &["LOCALHOST".to_string(), "127.0.0.1".to_string()],
        )
        .unwrap();

        let root_info = certificate_info(&root).unwrap();
        let leaf_info = certificate_info(&leaf).unwrap();
        assert!(root_info.is_ca);
        assert!(!leaf_info.is_ca);
        assert_eq!(leaf_info.sans, vec!["127.0.0.1", "localhost"]);
        assert!(!leaf_certificate_needs_reissue(
            &leaf,
            &["127.0.0.1".to_string(), "localhost".to_string()],
            0,
        ));
        assert!(leaf_certificate_needs_reissue(
            &leaf,
            &["server.home.arpa".to_string()],
            0,
        ));
    }

    #[test]
    fn rejects_wildcards_unspecified_addresses_and_invalid_domains() {
        assert!(normalize_san("*.example.com").is_err());
        assert!(normalize_san("0.0.0.0").is_err());
        assert!(normalize_san("bad_domain").is_err());
        assert_eq!(
            normalize_san("Server.Home.Arpa.").unwrap(),
            "server.home.arpa"
        );
    }

    #[test]
    fn private_key_is_not_embedded_in_public_certificate() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("root.pem");
        let root_key = directory.path().join("root.key");
        generate_root_ca(&root, &root_key, "Test Root CA").unwrap();
        let public = std::fs::read_to_string(root).unwrap();
        assert!(!public.contains("PRIVATE KEY"));
    }
}
