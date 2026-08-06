//! The acceptance rule, and the two rustls verifiers that apply it.
//!
//! One rule, both directions. `SSLAuth::ValidateCertificateAndGetContextAttributes`
//! (`SSLImpl.cpp:271`) runs the same code whether it is a client judging a
//! server or a server judging a client — only the expected EKU differs — and so
//! does this:
//!
//! ```text
//! accept(cert) =
//!       sha1(cert)         == thumbprintA  ||  == thumbprintB
//!   ||  (name(cert) == subjectA && sha1(issuer) ∈ parentsA)
//!   ||  (name(cert) == subjectB && sha1(issuer) ∈ parentsB)
//! ```
//!
//! The `A`/`B` duplication is not redundancy: it **is** the rotation
//! mechanism. An operator stages the incoming certificate as `B`, waits for
//! every replica to have both, rolls the fleet's live certificate, then demotes
//! the outgoing one. Nothing here is aware of that — it just has to accept both
//! at once, which it does.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};
use webpki::{CertRevocationList, EndEntityCert, KeyUsage, RevocationOptionsBuilder};

use super::name::{self, Purpose};
use super::thumbprint::Thumbprint;
use super::{ChainValidation, Revocation};

/// One `subject` + acceptable-parents pair — `subjectA`/`thumbPrintsParentA`
/// (`SSLAuth::SetSSLSubjectNames`, `SSLImpl.cpp:949`).
#[derive(Clone, Debug)]
pub struct SubjectRule {
    /// Compared byte-exactly against [`name::simple_display_name`].
    pub subject: String,
    /// SHA-1 pins for the issuer. Any one of them is enough.
    pub parents: Vec<Thumbprint>,
}

/// The compiled acceptance rule: everything the verifiers need, parsed once.
#[derive(Debug)]
pub(crate) struct Rules {
    pub(crate) thumbprint_a: Option<Thumbprint>,
    pub(crate) thumbprint_b: Option<Thumbprint>,
    pub(crate) subject_a: Option<SubjectRule>,
    pub(crate) subject_b: Option<SubjectRule>,
    /// `s_considerIdentitiesWhitelist`. See [`super::TlsConfig::identity_pins`].
    pub(crate) identity_pins: bool,
    pub(crate) chain: ChainValidation,
    pub(crate) revocation: Revocation,
    pub(crate) anchors: Vec<rustls::pki_types::TrustAnchor<'static>>,
    pub(crate) crls: Vec<CertRevocationList<'static>>,
    pub(crate) provider: Arc<CryptoProvider>,
}

impl Rules {
    /// Whether any rule could ever match. A config that pins nothing accepts
    /// nothing, which is worth catching when it is written rather than on the
    /// first handshake.
    pub(crate) fn accepts_anything(&self) -> bool {
        self.identity_pins
            && (self.thumbprint_a.is_some()
                || self.thumbprint_b.is_some()
                || self.subject_a.is_some()
                || self.subject_b.is_some())
    }

    /// The whole judgement on one presented certificate chain.
    fn verify(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
        purpose: Purpose,
    ) -> Result<(), Error> {
        // 1. Extended key usage. Unconditional — see `name::eku_permits` for
        //    why this does not follow the chain toggle the way the C++'s does.
        match name::eku_permits(leaf, purpose) {
            Ok(true) => {}
            Ok(false) => return Err(reject(&name::eku_error(purpose))),
            Err(_) => {
                return Err(Error::InvalidCertificate(
                    rustls::CertificateError::BadEncoding,
                ))
            }
        }

        // 2. Chain, validity dates and revocation — `IsCertificateTrusted`
        //    (`SSLImpl.cpp:339`).
        if let Err(e) = self.verify_chain(leaf, intermediates, now, purpose) {
            match self.chain {
                ChainValidation::Enforce => return Err(e),
                // `SSLError("Cert chain validation failed, skipping due to
                // config")` (`SSLImpl.cpp:296`). The C++ sets
                // `m_bCertCAValidationPassed = false` and carries on; the only
                // consumer of that flag is a log line in `NetSslCxn`
                // (`NetSSLCxn.cpp:231`), so the connection proceeds either way.
                ChainValidation::LogOnly => eprintln!(
                    "rsl-net/tls: chain validation FAILED and is being ignored \
                     (ChainValidation::LogOnly): {e}"
                ),
                ChainValidation::Off => {}
            }
        }

        // 3. Identity. `IsCertificateThumbprintAcceptable` first, then
        //    `IsCertificateSubjectAcceptable` (`SSLImpl.cpp:310-315`).
        if self.thumbprint_accepted(leaf) {
            return Ok(());
        }
        if self.subject_accepted(leaf, intermediates)? {
            return Ok(());
        }
        Err(reject(&format!(
            "cert auth failed: no rule accepts {} (leaf {})",
            match name::simple_display_name(leaf) {
                Ok(Some(name)) => format!("subject {name:?}"),
                _ => "a certificate with no display name".to_string(),
            },
            Thumbprint::of_der(leaf),
        )))
    }

    fn verify_chain(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
        purpose: Purpose,
    ) -> Result<(), Error> {
        if self.chain == ChainValidation::Off {
            return Ok(());
        }
        let cert = EndEntityCert::try_from(leaf)
            .map_err(|_| Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        let usage = match purpose {
            Purpose::Server => KeyUsage::server_auth(),
            Purpose::Client => KeyUsage::client_auth(),
        };
        let crls: Vec<&CertRevocationList<'_>> = self.crls.iter().collect();
        let revocation = match self.revocation {
            Revocation::Skip => None,
            Revocation::Check => Some(
                RevocationOptionsBuilder::new(&crls)
                    .expect("TlsConfig::build rejects Revocation::Check with no CRLs")
                    // The C++ tolerates `CRYPT_E_NO_REVOCATION_CHECK` and
                    // `CRYPT_E_REVOCATION_OFFLINE` and nothing else
                    // (`SSLImpl.cpp:409-431`): a certificate whose status
                    // cannot be determined is not thereby revoked.
                    .with_status_policy(webpki::UnknownStatusPolicy::Allow)
                    .build(),
            ),
        };
        cert.verify_for_usage(
            self.provider.signature_verification_algorithms.all,
            &self.anchors,
            intermediates,
            now,
            usage,
            revocation,
            None,
        )
        .map(|_| ())
        .map_err(|e| reject(&format!("chain validation failed: {e}")))
    }

    /// `IsCertificateThumbprintAcceptable(cert, {A, B})` (`SSLImpl.cpp:440`).
    fn thumbprint_accepted(&self, leaf: &CertificateDer<'_>) -> bool {
        if !self.identity_pins {
            return false;
        }
        let sha1 = Thumbprint::of_der(leaf);
        self.thumbprint_a == Some(sha1) || self.thumbprint_b == Some(sha1)
    }

    /// `IsCertificateSubjectAcceptable` (`SSLImpl.cpp:483`).
    ///
    /// The parent is the certificate that *issued* the leaf, taken from the
    /// chain the peer presented. The C++ takes `rgpElement[1]` of the first
    /// simple chain with at least two elements — which, for a peer that sends
    /// its issuer (every correctly configured TLS server does), is the same
    /// certificate as `intermediates[0]`. A peer that sends a bare leaf has no
    /// parent and fails the rule, exactly as `cElement >= 2` failing does.
    fn subject_accepted(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> Result<bool, Error> {
        if self.subject_a.is_none() && self.subject_b.is_none() {
            return Ok(false);
        }
        let name = match name::simple_display_name(leaf) {
            Ok(Some(name)) => name,
            // "Cert subject not retrievable."
            Ok(None) => return Ok(false),
            Err(_) => {
                return Err(Error::InvalidCertificate(
                    rustls::CertificateError::BadEncoding,
                ))
            }
        };
        let Some(parent) = intermediates.first() else {
            return Ok(false);
        };
        let parent = Thumbprint::of_der(parent);

        for rule in [self.subject_a.as_ref(), self.subject_b.as_ref()]
            .into_iter()
            .flatten()
        {
            // `s_pSubjectA.compare(subject) == 0` — byte-exact, case-sensitive.
            if rule.subject == name && self.identity_pins && rule.parents.contains(&parent) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn reject(why: &str) -> Error {
    eprintln!("rsl-net/tls: {why}");
    Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)
}

// ---------------------------------------------------------------------------
// The rustls verifiers
// ---------------------------------------------------------------------------

/// Used by a TLS **client** to judge the server — `SSLAuthServer`
/// (`SSLImpl.h:113`), whose name means "authenticates the server".
#[derive(Debug)]
pub(crate) struct RemoteServer(pub(crate) Arc<Rules>);

impl ServerCertVerifier for RemoteServer {
    /// Note what is *not* here: any use of `server_name`. The C++ passes
    /// `pwszServerName = NULL` and `ISC_REQ_MANUAL_CRED_VALIDATION`
    /// (`SSLImpl.cpp:387`, `SSLImpl.cpp:1108`) — a replica is identified by its
    /// certificate, never by the name it was dialed with. RSL dials replicas by
    /// IP, so there is no name to check even in principle.
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.0
            .verify(end_entity, intermediates, now, Purpose::Server)
            .map(|()| ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0
            .provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Used by a TLS **server** to judge the client — `SSLAuthClient`
/// (`SSLImpl.h:124`).
#[derive(Debug)]
pub(crate) struct RemoteClient {
    pub(crate) rules: Arc<Rules>,
    pub(crate) hints: Vec<DistinguishedName>,
}

impl ClientCertVerifier for RemoteClient {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.hints
    }

    /// `ASC_REQ_MUTUAL_AUTH` (`SSLImpl.cpp:1113`): a client that presents no
    /// certificate is not a client. There is no anonymous path into an RSL
    /// ring.
    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        self.rules
            .verify(end_entity, intermediates, now, Purpose::Client)
            .map(|()| ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.rules.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.rules.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.rules
            .provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
