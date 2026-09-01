//! The TLS material a listener serves, loaded once at startup.
//!
//! Loaded at startup and not per connection, for the reason every other local
//! configuration failure is: a certificate that cannot be read is an operator
//! problem, and discovering it on the first `STARTTLS` means discovering it
//! when somebody's mail is already in flight.
//!
//! # No path to OpenSSL
//!
//! `rustls` with the `ring` provider, matching the rest of the workspace. The
//! default provider is `aws-lc-rs`, which is banned in `deny.toml` and enforced
//! in CI: see the workspace manifest for why.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

/// Why a listener could not be given TLS.
///
/// Every variant names the file, because an operator reading this has two
/// paths configured and needs to know which one is wrong.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("the TLS certificate {path} could not be read: {reason}")]
    Certificate { path: PathBuf, reason: String },

    #[error("the TLS private key {path} could not be read: {reason}")]
    PrivateKey { path: PathBuf, reason: String },

    #[error("the TLS certificate {path} contains no certificates")]
    EmptyChain { path: PathBuf },

    /// The pair does not go together, which TLS itself refuses to serve.
    #[error("the TLS certificate and private key do not match: {0}")]
    Mismatch(String),
}

/// Load a certificate chain and its private key into a served configuration.
///
/// No client certificates are requested. A public MX authenticates itself to
/// the sender and not the other way round: requiring a client certificate would
/// refuse mail from every correctly configured server on the internet.
pub fn load(certificate: &Path, private_key: &Path) -> Result<Arc<ServerConfig>, TlsError> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(certificate)
        .map_err(|e| TlsError::Certificate {
            path: certificate.to_path_buf(),
            reason: e.to_string(),
        })?
        .collect::<Result<_, _>>()
        .map_err(|e| TlsError::Certificate {
            path: certificate.to_path_buf(),
            reason: e.to_string(),
        })?;

    if chain.is_empty() {
        return Err(TlsError::EmptyChain {
            path: certificate.to_path_buf(),
        });
    }

    let key = PrivateKeyDer::from_pem_file(private_key).map_err(|e| TlsError::PrivateKey {
        path: private_key.to_path_buf(),
        reason: e.to_string(),
    })?;

    // The provider is named rather than taken from the process default. A
    // default installed elsewhere in the process — or not installed at all —
    // would decide this server's cipher suites from a distance.
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| TlsError::Mismatch(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(|e| TlsError::Mismatch(e.to_string()))?;

    Ok(Arc::new(config))
}

/// The certificate a listener is currently serving, swappable in place.
///
/// Certificates are renewed on a schedule nobody coordinates with the mail
/// server — a `certbot` timer, a `lego` cron — and the file changes underneath
/// a running process. Loading once at startup means serving an expired
/// certificate until somebody notices and restarts the daemon, which is exactly
/// the kind of outage that happens on a Sunday.
///
/// Read per connection rather than per handshake so a replacement takes effect
/// on the next connection and never mid-handshake.
#[derive(Clone)]
pub struct Serving(Arc<std::sync::RwLock<Arc<ServerConfig>>>);

impl Serving {
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self(Arc::new(std::sync::RwLock::new(config)))
    }

    pub fn current(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.0.read().expect("TLS configuration lock poisoned"))
    }

    /// Serve a different certificate from now on.
    pub fn replace(&self, config: Arc<ServerConfig>) {
        *self.0.write().expect("TLS configuration lock poisoned") = config;
    }
}

impl std::fmt::Debug for Serving {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Serving")
    }
}

/// When the certificate stops being valid, as a Unix timestamp.
///
/// The leaf, which is the one that expires first in practice and the one a
/// receiver checks. Read from the file rather than from the parsed
/// `ServerConfig`, because rustls does not expose validity: it refuses expired
/// certificates at handshake time and has no reason to tell anyone in advance,
/// which is precisely what an operator needs.
pub fn expires_at(certificate: &Path) -> Result<i64, TlsError> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(certificate)
        .map_err(|e| TlsError::Certificate {
            path: certificate.to_path_buf(),
            reason: e.to_string(),
        })?
        .collect::<Result<_, _>>()
        .map_err(|e| TlsError::Certificate {
            path: certificate.to_path_buf(),
            reason: e.to_string(),
        })?;

    let leaf = chain.first().ok_or_else(|| TlsError::EmptyChain {
        path: certificate.to_path_buf(),
    })?;

    let (_, parsed) =
        x509_parser::parse_x509_certificate(leaf).map_err(|e| TlsError::Certificate {
            path: certificate.to_path_buf(),
            reason: format!("cannot be parsed: {e}"),
        })?;

    Ok(parsed.validity().not_after.timestamp())
}

// ------------------------------------------------------------------ outbound

/// The client configuration used for `STARTTLS` on delivery.
///
/// # Encryption without authentication, deliberately
///
/// Certificates are **not** verified. This is the opportunistic posture every
/// MX-to-MX delivery uses (Postfix calls it `may`), and the reason is that the
/// alternative is worse rather than stricter: a large share of the internet's
/// mail servers present certificates that are self-signed, expired, or issued
/// for a name that is not the MX host. Verifying would fail against them, and
/// the only options at that point are to send in the clear anyway — which is
/// the downgrade this was meant to prevent — or to refuse mail that every other
/// MTA delivers.
///
/// What it buys is protection against a *passive* observer, which is the threat
/// this can address without an authenticated naming scheme. Authenticating the
/// peer needs DANE or MTA-STS, which name the expected certificate out of band;
/// neither exists here yet, and pretending otherwise by verifying against the
/// public roots would be a check that fails open.
///
/// Once offered, though, TLS is not optional: a handshake that fails after the
/// server advertised `STARTTLS` defers the delivery rather than retrying in
/// plaintext. See [`crate::client`].
pub fn outbound() -> Arc<rustls::ClientConfig> {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring supports the default protocol versions")
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(Opportunistic))
    .with_no_client_auth();

    // Nothing here speaks HTTP; leaving ALPN unset avoids offering protocols
    // this client cannot follow.
    config.alpn_protocols.clear();
    Arc::new(config)
}

/// Accepts any certificate, and says so in its name.
///
/// The signature checks are still real: what is skipped is deciding *whose*
/// key it is, which cannot be decided without DANE or MTA-STS.
#[derive(Debug)]
struct Opportunistic;

impl rustls::client::danger::ServerCertVerifier for Opportunistic {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed certificate and its key, written to two files.
    fn material(dir: &Path) -> (PathBuf, PathBuf) {
        let cert = rcgen::generate_simple_self_signed(vec!["mx.test".into()]).expect("generate");
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
        (cert_path, key_path)
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("pigeon-tls-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn a_matching_pair_loads() {
        let dir = tmpdir("ok");
        let (cert, key) = material(&dir);
        assert!(load(&cert, &key).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_file_names_which_one() {
        // Two paths are configured and the operator needs to know which is
        // wrong. A single "TLS failed" would send them to check both.
        let dir = tmpdir("missing");
        let (cert, key) = material(&dir);

        let err = load(&dir.join("absent.pem"), &key).expect_err("a missing certificate");
        assert!(
            matches!(err, TlsError::Certificate { .. }),
            "wrong file blamed: {err}"
        );

        let err = load(&cert, &dir.join("absent.pem")).expect_err("a missing key");
        assert!(
            matches!(err, TlsError::PrivateKey { .. }),
            "wrong file blamed: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_certificates_expiry_is_readable_before_it_matters() {
        // rustls refuses an expired certificate at handshake time and has no
        // reason to say so in advance, which is exactly what an operator needs:
        // a renewal timer that has quietly stopped is only visible from the
        // expiry date.
        let dir = tmpdir("expiry");
        let (cert, _) = material(&dir);

        let at = expires_at(&cert).expect("a generated certificate has an expiry");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(at > now, "the fixture certificate is already expired");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_renewed_certificate_replaces_the_served_one() {
        // A renewal is a file that changed underneath a running process.
        // Loading once at startup means serving an expired certificate until
        // somebody restarts the daemon.
        let dir = tmpdir("swap");
        let (cert, key) = material(&dir);

        let serving = Serving::new(load(&cert, &key).unwrap());
        let first = serving.current();

        let other = tmpdir("swap-new");
        let (cert2, key2) = material(&other);
        serving.replace(load(&cert2, &key2).unwrap());

        assert!(
            !Arc::ptr_eq(&first, &serving.current()),
            "the replacement did not take effect"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&other);
    }

    #[test]
    fn a_key_that_does_not_match_the_certificate_is_refused() {
        // Refused here rather than at the first handshake: a mismatched pair
        // fails every connection, and finding out per connection means finding
        // out while somebody's mail is in flight.
        let dir = tmpdir("mismatch");
        let (cert, _) = material(&dir);
        let other = tmpdir("mismatch-other");
        let (_, key) = material(&other);

        let err = load(&cert, &key).expect_err("a mismatched pair");
        assert!(matches!(err, TlsError::Mismatch(_)), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&other);
    }
}
