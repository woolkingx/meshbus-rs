//! TLS 1.3 for QUIC via the proven `rustls::quic` API.
//!
//! This module owns: the ring crypto provider, the QUIC Initial [`Suite`],
//! `ClientConfig`/`ServerConfig` construction, and a thin handshake session
//! wrapper. RFC 9001 Initial packet protection itself is native in
//! [`crate::crypto`]; everything from Handshake keys onward rides this module.

use std::sync::Arc;

#[cfg(feature = "dangerous-insecure-tls")]
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
#[cfg(feature = "dangerous-insecure-tls")]
use rustls::pki_types::UnixTime;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::quic::{ClientConnection, Connection, KeyChange, ServerConnection, Suite};
use rustls::{ClientConfig, ServerConfig};
#[cfg(feature = "dangerous-insecure-tls")]
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::{Error, Result, Version};

/// ALPN this engine advertises for raw QUIC transport carrying Mesh frames.
pub const ALPN: &[u8] = b"mb-quic/1";

/// The ring crypto provider used for every TLS 1.3 QUIC connection.
pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// QUIC Initial [`Suite`] (TLS13_AES_128_GCM_SHA256), per RFC 9001 §5.2.
pub fn initial_suite() -> Result<Suite> {
    provider()
        .cipher_suites
        .iter()
        .find_map(|cs| match (cs.suite(), cs.tls13()) {
            (rustls::CipherSuite::TLS13_AES_128_GCM_SHA256, Some(s)) => s.quic_suite(),
            _ => None,
        })
        .ok_or(Error::Crypto("no QUIC initial cipher suite"))
}

/// Insecure verifier: the QUIC peer authenticates out of band (Mesh identity),
/// so the TLS certificate is only used to complete the 1.3 handshake.
#[cfg(feature = "dangerous-insecure-tls")]
#[derive(Debug)]
struct AcceptAnyServerCert;

#[cfg(feature = "dangerous-insecure-tls")]
impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

/// Build a QUIC client TLS config (TLS 1.3 only, ALPN = [`ALPN`]).
///
/// The default build has no built-in server-cert verifier: callers MUST use
/// [`TlsSession::client_with`] with an injected, pinned `ClientConfig`.
/// The insecure accept-any path exists only behind the test-only
/// `dangerous-insecure-tls` feature.
pub fn client_config() -> Result<Arc<ClientConfig>> {
    #[cfg(feature = "dangerous-insecure-tls")]
    {
        let mut cfg = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| Error::Tls(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
            .with_no_client_auth();
        cfg.alpn_protocols = vec![ALPN.to_vec()];
        Ok(Arc::new(cfg))
    }
    #[cfg(not(feature = "dangerous-insecure-tls"))]
    {
        Err(Error::Tls(
            "default client TLS has no server-cert verifier; use TlsSession::client_with with a pinned ClientConfig".into(),
        ))
    }
}

/// Build a QUIC server TLS config with a fresh self-signed certificate.
pub fn server_config() -> Result<Arc<ServerConfig>> {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| Error::Tls(e.to_string()))?;
    let cert = CertificateDer::from(ck.cert.der().to_vec());
    let key = PrivateKeyDer::try_from(ck.signing_key.serialize_der())
        .map_err(|e| Error::Tls(e.to_string()))?;
    let mut cfg = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Tls(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| Error::Tls(e.to_string()))?;
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(cfg))
}

/// Thin handshake session over `rustls::quic::Connection`.
pub struct TlsSession {
    inner: Connection,
}

impl TlsSession {
    /// Construct the client side with encoded transport parameters.
    pub fn client(version: Version, params: Vec<u8>) -> Result<TlsSession> {
        Self::client_with(version, params, client_config()?)
    }

    /// Construct the client side with a caller-supplied `ClientConfig`
    /// (e.g. an SPKI-pinned verifier owned by an L7 peer binding).
    pub fn client_with(
        version: Version,
        params: Vec<u8>,
        cfg: Arc<ClientConfig>,
    ) -> Result<TlsSession> {
        let name =
            ServerName::try_from("localhost").map_err(|_| Error::Tls("bad server name".into()))?;
        let c = ClientConnection::new(cfg, version.rustls(), name, params)
            .map_err(|e| Error::Tls(e.to_string()))?;
        Ok(TlsSession {
            inner: Connection::from(c),
        })
    }

    /// Construct the server side with encoded transport parameters.
    pub fn server(version: Version, params: Vec<u8>) -> Result<TlsSession> {
        Self::server_with(version, params, server_config()?)
    }

    /// Construct the server side with a caller-supplied `ServerConfig`
    /// (e.g. an operator certificate/key owned by an L7 peer binding).
    pub fn server_with(
        version: Version,
        params: Vec<u8>,
        cfg: Arc<ServerConfig>,
    ) -> Result<TlsSession> {
        let s = ServerConnection::new(cfg, version.rustls(), params)
            .map_err(|e| Error::Tls(e.to_string()))?;
        Ok(TlsSession {
            inner: Connection::from(s),
        })
    }

    /// Feed peer handshake (CRYPTO) bytes into the TLS state machine.
    pub fn read_handshake(&mut self, plaintext: &[u8]) -> Result<()> {
        self.inner
            .read_hs(plaintext)
            .map_err(|e| Error::Tls(e.to_string()))
    }

    /// Drain locally generated handshake bytes; returns a key transition if the
    /// TLS state machine produced one (Handshake or 1-RTT keys).
    pub fn write_handshake(&mut self, out: &mut Vec<u8>) -> Option<KeyChange> {
        self.inner.write_hs(out)
    }

    /// Peer transport parameters, available once the peer's extensions arrive.
    pub fn peer_transport_parameters(&self) -> Option<Vec<u8>> {
        self.inner.quic_transport_parameters().map(|p| p.to_vec())
    }

    /// Whether the TLS handshake is still in progress.
    pub fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    /// Negotiated ALPN protocol, if any.
    pub fn alpn(&self) -> Option<Vec<u8>> {
        self.inner.alpn_protocol().map(|p| p.to_vec())
    }
}
