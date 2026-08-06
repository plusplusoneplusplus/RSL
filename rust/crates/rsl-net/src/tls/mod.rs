//! Mutual TLS for both RSL ports, with the C++'s trust model.
//!
//! This is the rustls replacement for `SSLImpl.cpp` + `NetSSLCxn.cpp`. What it
//! reproduces is the *operator-facing* model — which certificates a replica
//! presents, which it accepts, and how an operator rotates them — not the
//! SChannel plumbing, which rustls does better.
//!
//! ## The trust model
//!
//! ```text
//! accept(cert) =
//!       sha1(cert)         == thumbprintA  ||  == thumbprintB
//!   ||  (name(cert) == subjectA && sha1(issuer) ∈ parentsA)
//!   ||  (name(cert) == subjectB && sha1(issuer) ∈ parentsB)
//! ```
//!
//! applied in both directions (`SSLAuth::ValidateCertificateAndGetContextAttributes`),
//! with client authentication mandatory, on top of a chain/validity/revocation
//! check whose strictness is a separate toggle. See [`SubjectRule`] for the
//! subject half of the rule and [`name::simple_display_name`] for what `name()`
//! means.
//!
//! `A` and `B` are the rotation mechanism, for the remote acceptance rule and
//! for the local credential ([`Identity`]) alike: stage the new certificate as
//! `B`, wait for the fleet, roll, demote.
//!
//! ## One config, both ports
//!
//! A single [`Tls`] gates the packet port and the learn port, in both
//! directions:
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use std::net::Ipv4Addr;
//! # use rsl_net::tls::{Identity, Tls, TlsConfig};
//! # use rsl_net::{PacketSvc, SvcConfig, LearnClient, LearnConfig};
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # fn handler() -> Arc<dyn rsl_net::PacketHandler> { unimplemented!() }
//! let tls = Tls::new(TlsConfig {
//!     identity: Identity::from_pem_files("replica.pem", "replica.key")?,
//!     thumbprint_a: Some("1b32891adb56d3f7115e7e031cc41e1793252015".parse()?),
//!     ..TlsConfig::default()
//! })?;
//!
//! // Packet port, client side.
//! let client = PacketSvc::start_as_client_with(
//!     tls.dialer(Ipv4Addr::UNSPECIFIED),
//!     handler(),
//!     SvcConfig::default(),
//! );
//! // Packet port, server side.
//! let server = PacketSvc::start_as_server_with(7000, tls.acceptor(), handler(), SvcConfig::default())?;
//! // Learn port, client side. (`LearnServer::bind_with` for the other half.)
//! let learn = LearnClient::with_config(LearnConfig::default()).over(tls.connector());
//! # Ok(())
//! # }
//! ```
//!
//! **This is a divergence, and the point of the phase.** In the C++ the two
//! ports are gated by *different* predicates: the packet port asks
//! `SSLAuth::IsSSLEnabled()` (`NetSSLCxn.cpp:10`), which is true if thumbprints
//! **or** subject names are configured, while the learn port asks
//! `SSLAuth::HasAnyThumbprint()` (`StreamIO.cpp:39`), which is true only for
//! thumbprints. A fleet configured with subject names alone therefore encrypts
//! its consensus traffic and ships its checkpoints — the entire replicated
//! state — in the clear. There is one switch here.
//!
//! ## Deliberate divergences
//!
//! * **File-based credentials, not the Windows certificate store.** The C++
//!   looks its own certificate up in `LocalMachine\MY` by thumbprint
//!   (`GetCertificate`, `SSLImpl.cpp:807`). Here an [`Identity`] is PEM files.
//!   This is a **breaking operational change** and needs a deployment story
//!   before a migration — see `TLS.md`.
//! * **`validateCAChain = false` is [`ChainValidation::LogOnly`]**, which is
//!   named for what it does and logs loudly every time it swallows a failure.
//! * **Revocation is CRL-only.** `checkCertificateRevocation` makes SChannel
//!   *fetch* CRLs and OCSP over the network; rustls checks the CRLs you supply
//!   and nothing else. [`Revocation::Check`] without CRLs is a config error
//!   rather than a check that silently does nothing.
//! * **EKU is checked unconditionally**, and with the roles the right way
//!   round — see [`name::eku_permits`], which documents the C++ bug it declines
//!   to reproduce.
//! * **Certificate refresh does not rekey live connections.** Neither does the
//!   C++: `SetSSLThumbprints` replaces the credential handles and every
//!   established `NetSslCxn` keeps its existing security context. [`Tls::swap`]
//!   keeps that contract, deliberately — a rotation that dropped every
//!   connection would be a fleet-wide election storm.
//!
//! ## What is *not* here
//!
//! No TLS type appears in [`crate::framing`] or in [`crate::svc`]'s internals.
//! A TLS connection reaches the transport as a [`crate::svc::Link`] like any
//! other, which is the same seam the C++ uses when it swaps `NetCxn` for
//! `NetSslCxn` (`NetSSLCxn.cpp:8`).

pub mod name;
mod stream;
pub mod thumbprint;
mod verify;

use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, RwLock};

use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::{ClientConfig, ServerConfig, SupportedCipherSuite};

/// The certificate types [`TlsConfig`] is built from, re-exported so a caller
/// need not depend on rustls directly to name them.
pub use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
pub use stream::{TlsAcceptor, TlsConnector, TlsDialer};
pub use thumbprint::Thumbprint;
pub use verify::SubjectRule;

use verify::Rules;

/// How hard a presented chain is validated — `validateCAChain`
/// (`SSLAuth::SetSSLThumbprints`, `SSLImpl.cpp:979`).
///
/// This covers the signature chain to a trust anchor, the validity dates and
/// (when [`Revocation::Check`] is set) the CRLs. It does **not** cover the
/// identity rule, which always applies: a certificate that chains perfectly to
/// a trusted root but matches no pin is still rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ChainValidation {
    /// `validateCAChain = true`: a chain that does not validate is rejected.
    #[default]
    Enforce,
    /// `validateCAChain = false`: the chain is built, and if it fails the
    /// failure is **logged and ignored**. An expired certificate, a certificate
    /// from an unknown CA, and a revoked one are all accepted as long as the
    /// identity rule matches.
    ///
    /// The C++ spells this as a `bool` and the log line is one of many; the
    /// name here is deliberately ugly because the setting is.
    LogOnly,
    /// No chain is built at all. Not reachable from the C++'s configuration —
    /// it is the honest spelling of a deployment that pins leaf thumbprints and
    /// has no CA, where [`LogOnly`](ChainValidation::LogOnly) would log a
    /// failure on every single handshake and teach operators to ignore it.
    ///
    /// Note what this switches off along with the chain: **validity dates**. An
    /// expired pinned certificate is accepted. That is also true of
    /// `LogOnly`, and it is true of the C++.
    Off,
}

/// Whether revocation is checked — `checkCertificateRevocation`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Revocation {
    /// Do not check. The default, because the C++'s "check" means something
    /// this implementation cannot offer (see below).
    #[default]
    Skip,
    /// Check the leaf and the intermediates against the configured
    /// [`TlsConfig::crls`], tolerating a certificate whose status no CRL
    /// covers — the C++ tolerates `CRYPT_E_NO_REVOCATION_CHECK` and
    /// `CRYPT_E_REVOCATION_OFFLINE` and nothing else (`SSLImpl.cpp:409`).
    ///
    /// Requires at least one CRL: unlike SChannel, nothing here fetches a CRL
    /// or speaks OCSP over the network.
    Check,
}

/// A replica's own credential — the certificate it presents, in both
/// directions, on both ports.
///
/// The C++ finds this in the Windows certificate store by thumbprint, trying
/// `A` and falling back to `B` (`SSLAuth::GetCredential`, `SSLImpl.cpp:904`).
/// The fallback is what makes rotation work: during the roll a replica may be
/// holding either certificate. [`Identity::from_pem_files_with_fallback`] keeps
/// that shape over files.
pub struct Identity {
    /// Leaf first, then the issuers to send with it. The issuer *matters*: a
    /// peer using the subject rule pins the issuer's thumbprint and can only
    /// find it if it is presented.
    pub chain: Vec<CertificateDer<'static>>,
    /// The leaf's private key.
    pub key: PrivateKeyDer<'static>,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("chain", &self.chain.len())
            .field(
                "leaf",
                &self
                    .chain
                    .first()
                    .map(|c| Thumbprint::of_der(c).to_string()),
            )
            .finish_non_exhaustive()
    }
}

impl Clone for Identity {
    fn clone(&self) -> Identity {
        Identity {
            chain: self.chain.clone(),
            key: self.key.clone_key(),
        }
    }
}

impl Identity {
    /// Load a PEM certificate chain and a PEM private key (PKCS#8, PKCS#1 or
    /// SEC1).
    pub fn from_pem_files(
        cert: impl AsRef<Path>,
        key: impl AsRef<Path>,
    ) -> Result<Identity, Error> {
        let cert_path = cert.as_ref();
        let key_path = key.as_ref();
        let chain = std::fs::read(cert_path).map_err(|e| Error::Read {
            path: cert_path.display().to_string(),
            source: e,
        })?;
        let key = std::fs::read(key_path).map_err(|e| Error::Read {
            path: key_path.display().to_string(),
            source: e,
        })?;
        Identity::from_pem(&chain, &key)
    }

    /// [`from_pem_files`](Identity::from_pem_files) with the C++'s A-then-B
    /// credential lookup: if the primary pair cannot be read, the fallback pair
    /// is used and a warning is logged.
    ///
    /// A pair that is present but *malformed* is an error either way — the C++
    /// falls back only when `GetCertificate` finds nothing in the store, not
    /// when it finds something broken.
    pub fn from_pem_files_with_fallback(
        primary: (impl AsRef<Path>, impl AsRef<Path>),
        fallback: (impl AsRef<Path>, impl AsRef<Path>),
    ) -> Result<Identity, Error> {
        let (cert, key) = (primary.0.as_ref(), primary.1.as_ref());
        if cert.is_file() && key.is_file() {
            return Identity::from_pem_files(cert, key);
        }
        eprintln!(
            "rsl-net/tls: primary credential {} is not present; falling back to the B credential",
            cert.display()
        );
        Identity::from_pem_files(fallback.0, fallback.1)
    }

    /// Parse an in-memory PEM chain and key.
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Identity, Error> {
        let chain = rustls_pemfile::certs(&mut &cert_pem[..])
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Error::Pem(format!("certificate chain: {e}")))?;
        if chain.is_empty() {
            return Err(Error::Pem(
                "certificate chain contains no certificate".into(),
            ));
        }
        let key = rustls_pemfile::private_key(&mut &key_pem[..])
            .map_err(|e| Error::Pem(format!("private key: {e}")))?
            .ok_or_else(|| Error::Pem("no private key in the key file".into()))?;
        Ok(Identity { chain, key })
    }

    /// Build from DER that is already in memory — how the test fixtures and an
    /// embedding host that manages its own key material get one.
    pub fn from_der(chain: Vec<CertificateDer<'static>>, key_pkcs8: Vec<u8>) -> Identity {
        Identity {
            chain,
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pkcs8)),
        }
    }
}

/// Everything an operator configures. One of these gates both ports.
#[derive(Clone, Debug)]
pub struct TlsConfig {
    /// What this replica presents.
    pub identity: Identity,
    /// Leaf SHA-1 pin `A` — `thumbPrintA`.
    pub thumbprint_a: Option<Thumbprint>,
    /// Leaf SHA-1 pin `B` — `thumbPrintB`. The rotation slot.
    pub thumbprint_b: Option<Thumbprint>,
    /// Subject + issuer-pin rule `A` — `subjectA` / `thumbPrintsParentA`.
    pub subject_a: Option<SubjectRule>,
    /// Subject + issuer-pin rule `B`.
    pub subject_b: Option<SubjectRule>,
    /// Trust anchors for [`ChainValidation`]. Empty means every chain fails to
    /// build, which only [`ChainValidation::Off`] tolerates.
    pub roots: Vec<CertificateDer<'static>>,
    /// CRLs for [`Revocation::Check`].
    pub crls: Vec<CertificateRevocationListDer<'static>>,
    /// `validateCAChain`.
    pub chain: ChainValidation,
    /// `checkCertificateRevocation`.
    pub revocation: Revocation,
    /// `considerIdentitiesWhitelist` (`SSLImpl.cpp:450`).
    ///
    /// **Setting this to `false` accepts nothing at all, and
    /// [`Tls::new`] rejects it.** In the C++ it gates
    /// `IsCertificateThumbprintAcceptable`, which is the *only* way either rule
    /// can succeed — the subject rule reaches it too, for the issuer pin — so
    /// `false` makes every handshake fail. The field exists so a config
    /// carried over from a C++ deployment produces that sentence instead of a
    /// fleet that mysteriously cannot talk to itself.
    pub identity_pins: bool,
    /// Offer TLS 1.2 only, matching `SP_PROT_TLS1_2_CLIENT|SERVER`
    /// (`CreateCertificateCredential`, `SSLImpl.cpp:850`).
    ///
    /// Defaults to `true`, which is what a mixed fleet needs. Turn it off once
    /// every replica is Rust and TLS 1.3 becomes available for
    /// replica-to-replica links; a C++ replica cannot negotiate it, so a fleet
    /// with one of each simply keeps landing on 1.2.
    pub compat_tls12_only: bool,
}

impl Default for TlsConfig {
    /// A config with no credential and no pins: it will not build. Use it as
    /// the `..Default::default()` tail of a real one.
    fn default() -> TlsConfig {
        TlsConfig {
            identity: Identity {
                chain: Vec::new(),
                key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(Vec::new())),
            },
            thumbprint_a: None,
            thumbprint_b: None,
            subject_a: None,
            subject_b: None,
            roots: Vec::new(),
            crls: Vec::new(),
            chain: ChainValidation::default(),
            revocation: Revocation::default(),
            identity_pins: true,
            compat_tls12_only: true,
        }
    }
}

/// A live TLS configuration: the two rustls configs, swappable underneath the
/// connections already using them.
pub struct Tls {
    current: RwLock<Arc<Live>>,
}

struct Live {
    client: Arc<ClientConfig>,
    server: Arc<ServerConfig>,
}

impl fmt::Debug for Tls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tls").finish_non_exhaustive()
    }
}

impl Tls {
    /// Compile a configuration. Every parse and every consistency check happens
    /// here, so a handshake can only fail for reasons on the wire.
    pub fn new(config: TlsConfig) -> Result<Arc<Tls>, Error> {
        Ok(Arc::new(Tls {
            current: RwLock::new(Arc::new(build(config)?)),
        }))
    }

    /// Replace the configuration — the rotation step, and the answer to a
    /// certificate that is about to expire.
    ///
    /// **Connections that already exist are unaffected**, exactly as in the
    /// C++: `SetSSLThumbprints` frees and re-acquires the credential handles
    /// while every live `NetSslCxn` keeps the security context it negotiated.
    /// New connections — including the reconnect after any peer bounces — use
    /// the new configuration.
    ///
    /// On error nothing is swapped; the previous configuration stays live.
    pub fn swap(&self, config: TlsConfig) -> Result<(), Error> {
        let live = Arc::new(build(config)?);
        *self.current.write().expect("tls config poisoned") = live;
        Ok(())
    }

    fn live(&self) -> Arc<Live> {
        self.current.read().expect("tls config poisoned").clone()
    }

    /// A [`crate::svc::Dialer`] for the packet port's client service: TCP from
    /// `bind_ip`, then a handshake, and only then a connection.
    pub fn dialer(self: &Arc<Self>, bind_ip: Ipv4Addr) -> Arc<dyn crate::svc::Dialer> {
        self.dialer_over(Arc::new(crate::svc::TcpDialer { bind_ip }))
    }

    /// [`dialer`](Tls::dialer) over a caller-supplied transport — the seam the
    /// tests use to run a handshake over a `tokio::io::duplex` pair.
    pub fn dialer_over(
        self: &Arc<Self>,
        inner: Arc<dyn crate::svc::Dialer>,
    ) -> Arc<dyn crate::svc::Dialer> {
        Arc::new(TlsDialer {
            inner,
            tls: self.clone(),
        })
    }

    /// An acceptor for the packet port's server service.
    pub fn acceptor(self: &Arc<Self>) -> Arc<dyn crate::svc::Acceptor> {
        Arc::new(TlsAcceptor { tls: self.clone() })
    }

    /// A connector/acceptor for the learn port, used by both of its sides.
    pub fn connector(self: &Arc<Self>) -> Arc<TlsConnector> {
        Arc::new(TlsConnector { tls: self.clone() })
    }
}

/// The TLS 1.2 cipher suites offered, pinned to the intersection of rustls'
/// TLS 1.2 suites with SChannel's `SCH_USE_STRONG_CRYPTO` defaults
/// (`SSLImpl.cpp:851`).
///
/// The two ChaCha20-Poly1305 suites rustls also supports are excluded:
/// SChannel only offers them on recent Windows 10 and not by default, so
/// leaving them in would mean the suite actually negotiated depends on the
/// Windows build a peer happens to be running. A pinned list is a list we can
/// state in a document and test against.
pub fn tls12_suites() -> &'static [SupportedCipherSuite] {
    use rustls::crypto::ring::cipher_suite::*;
    static SUITES: &[SupportedCipherSuite] = &[
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    ];
    SUITES
}

/// The TLS 1.3 suites, offered only when
/// [`TlsConfig::compat_tls12_only`] is `false`.
pub fn tls13_suites() -> &'static [SupportedCipherSuite] {
    use rustls::crypto::ring::cipher_suite::*;
    static SUITES: &[SupportedCipherSuite] = &[
        TLS13_AES_256_GCM_SHA384,
        TLS13_AES_128_GCM_SHA256,
        TLS13_CHACHA20_POLY1305_SHA256,
    ];
    SUITES
}

fn build(config: TlsConfig) -> Result<Live, Error> {
    if config.identity.chain.is_empty() {
        return Err(Error::Config(
            "no certificate to present: RSL's TLS is mutual in both directions, so a \
             replica always needs its own credential"
                .into(),
        ));
    }
    if !config.identity_pins {
        return Err(Error::Config(
            "identity_pins = false (considerIdentitiesWhitelist) disables the thumbprint \
             comparison that both acceptance rules go through, so nothing would ever be \
             accepted; remove the setting instead"
                .into(),
        ));
    }
    if config.chain != ChainValidation::Off && config.roots.is_empty() {
        return Err(Error::Config(format!(
            "{:?} needs trust anchors in `roots`; use ChainValidation::Off for a \
             deployment that pins certificates and has no CA",
            config.chain
        )));
    }
    if config.revocation == Revocation::Check && config.crls.is_empty() {
        return Err(Error::Config(
            "Revocation::Check needs CRLs in `crls`: nothing here fetches a CRL or speaks \
             OCSP over the network, unlike SChannel"
                .into(),
        ));
    }

    let anchors = config
        .roots
        .iter()
        .map(|root| {
            webpki::anchor_from_trusted_cert(root)
                .map(|a| a.to_owned())
                .map_err(|e| Error::Config(format!("root certificate is not usable: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let crls = config
        .crls
        .iter()
        .map(|crl| {
            webpki::BorrowedCertRevocationList::from_der(crl.as_ref())
                .map(|c| c.to_owned().map(webpki::CertRevocationList::from))
                .map_err(|e| Error::Config(format!("CRL is not usable: {e}")))?
                .map_err(|e| Error::Config(format!("CRL is not usable: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut suites = tls12_suites().to_vec();
    let mut versions: Vec<&'static rustls::SupportedProtocolVersion> =
        vec![&rustls::version::TLS12];
    if !config.compat_tls12_only {
        suites.extend_from_slice(tls13_suites());
        versions.push(&rustls::version::TLS13);
    }

    let provider = Arc::new(rustls::crypto::CryptoProvider {
        cipher_suites: suites,
        ..rustls::crypto::ring::default_provider()
    });

    let rules = Arc::new(Rules {
        thumbprint_a: config.thumbprint_a,
        thumbprint_b: config.thumbprint_b,
        subject_a: config.subject_a.clone(),
        subject_b: config.subject_b.clone(),
        identity_pins: config.identity_pins,
        chain: config.chain,
        revocation: config.revocation,
        anchors,
        crls,
        provider: provider.clone(),
    });
    if !rules.accepts_anything() {
        return Err(Error::Config(
            "no thumbprint and no subject rule is configured, so every peer would be \
             rejected"
                .into(),
        ));
    }

    let hints = config
        .roots
        .iter()
        .filter_map(|root| {
            webpki::anchor_from_trusted_cert(root)
                .ok()
                // `in_sequence`, not `from`: a `TrustAnchor`'s `subject` is the
                // *contents* of the Name, without its SEQUENCE header, while
                // the hint on the wire is a full DER-encoded Name. Handing over
                // the contents produces a CertificateRequest that rustls peers
                // ignore and OpenSSL rejects outright ("parse_ca_names: wrong
                // tag") — a bug only an interop test can see.
                .map(|a| rustls::DistinguishedName::in_sequence(a.subject.as_ref()))
        })
        .collect();

    let client = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&versions)
        .map_err(Error::Rustls)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verify::RemoteServer(rules.clone())))
        .with_client_auth_cert(
            config.identity.chain.clone(),
            config.identity.key.clone_key(),
        )
        .map_err(Error::Rustls)?;

    let server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .map_err(Error::Rustls)?
        .with_client_cert_verifier(Arc::new(verify::RemoteClient { rules, hints }))
        .with_single_cert(config.identity.chain, config.identity.key)
        .map_err(Error::Rustls)?;

    Ok(Live {
        client: Arc::new(client),
        server: Arc::new(server),
    })
}

/// What can go wrong before a byte is sent.
#[derive(Debug)]
pub enum Error {
    /// A file could not be read.
    Read { path: String, source: io::Error },
    /// PEM that is not what it claims to be.
    Pem(String),
    /// A combination of settings that cannot mean anything useful.
    Config(String),
    /// rustls refused the configuration.
    Rustls(rustls::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Read { path, source } => write!(f, "cannot read {path}: {source}"),
            Error::Pem(what) => write!(f, "bad PEM: {what}"),
            Error::Config(what) => write!(f, "bad TLS configuration: {what}"),
            Error::Rustls(e) => write!(f, "rustls rejected the configuration: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl std::str::FromStr for Thumbprint {
    type Err = thumbprint::ParseError;
    fn from_str(s: &str) -> Result<Thumbprint, thumbprint::ParseError> {
        Thumbprint::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn some_identity() -> Identity {
        Identity::from_der(vec![CertificateDer::from(vec![0u8; 4])], vec![0u8; 4])
    }

    #[test]
    fn a_config_with_no_credential_is_refused() {
        let e = Tls::new(TlsConfig::default()).unwrap_err();
        assert!(e.to_string().contains("no certificate to present"), "{e}");
    }

    #[test]
    fn a_config_that_pins_nothing_is_refused() {
        let e = Tls::new(TlsConfig {
            identity: some_identity(),
            chain: ChainValidation::Off,
            ..TlsConfig::default()
        })
        .unwrap_err();
        assert!(
            e.to_string().contains("every peer would be rejected"),
            "{e}"
        );
    }

    #[test]
    fn disabling_the_identity_whitelist_is_refused_with_the_reason() {
        let e = Tls::new(TlsConfig {
            identity: some_identity(),
            identity_pins: false,
            ..TlsConfig::default()
        })
        .unwrap_err();
        assert!(
            e.to_string().contains("nothing would ever be accepted"),
            "{e}"
        );
    }

    #[test]
    fn chain_validation_without_roots_is_refused() {
        let e = Tls::new(TlsConfig {
            identity: some_identity(),
            thumbprint_a: Some(Thumbprint::from_bytes([1; 20])),
            ..TlsConfig::default()
        })
        .unwrap_err();
        assert!(e.to_string().contains("needs trust anchors"), "{e}");
    }

    #[test]
    fn revocation_checking_without_crls_is_refused() {
        let e = Tls::new(TlsConfig {
            identity: some_identity(),
            thumbprint_a: Some(Thumbprint::from_bytes([1; 20])),
            chain: ChainValidation::Off,
            revocation: Revocation::Check,
            ..TlsConfig::default()
        })
        .unwrap_err();
        assert!(e.to_string().contains("needs CRLs"), "{e}");
    }

    #[test]
    fn the_pinned_suite_list_is_the_schannel_intersection() {
        let names: Vec<String> = tls12_suites()
            .iter()
            .map(|s| format!("{:?}", s.suite()))
            .collect();
        assert_eq!(
            names,
            [
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            ]
        );
    }
}
