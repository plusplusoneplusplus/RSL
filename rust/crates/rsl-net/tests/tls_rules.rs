//! The acceptance-rule matrix: for every combination of pin, subject rule and
//! toggle, does a handshake succeed — and does it succeed *in both directions*?
//!
//! Everything here runs a real mutual-TLS handshake over loopback through the
//! public seam ([`rsl_net::learnport::Connector`] /
//! [`rsl_net::learnport::Acceptor`]), rather than calling the verifier
//! directly. A rule that is right in isolation and wrong once rustls is holding
//! it is not right.

mod certs;

use std::sync::Arc;

use certs::{Ca, LeafSpec};
use rcgen::ExtendedKeyUsagePurpose;
use rsl_net::learnport::{Acceptor, Connector};
use rsl_net::tls::{ChainValidation, Revocation, SubjectRule, Thumbprint, Tls, TlsConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// What a handshake attempt ended as.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Both sides authenticated and bytes moved.
    Accepted,
    /// One of them refused. The string is kept for the assertion messages.
    Rejected(String),
}

impl Outcome {
    fn accepted(&self) -> bool {
        matches!(self, Outcome::Accepted)
    }
}

/// Run one mutual handshake, `client` dialing `server`, and move a byte each
/// way so that a rejection which only surfaces on first use still surfaces.
async fn handshake(server: &Arc<Tls>, client: &Arc<Tls>) -> Outcome {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let acceptor = server.connector();
    let serve = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let mut stream = Acceptor::accept(&*acceptor, sock)
            .await
            .map_err(|e| format!("server: {e}"))?;
        stream.write_all(b"o").await.map_err(|e| e.to_string())?;
        let mut got = [0u8; 1];
        stream
            .read_exact(&mut got)
            .await
            .map_err(|e| e.to_string())?;
        Ok::<(), String>(())
    });

    let connector = client.connector();
    let dial = async {
        let mut stream = Connector::connect(&*connector, addr)
            .await
            .map_err(|e| format!("client: {e}"))?;
        let mut got = [0u8; 1];
        stream
            .read_exact(&mut got)
            .await
            .map_err(|e| e.to_string())?;
        stream.write_all(b"k").await.map_err(|e| e.to_string())?;
        Ok::<(), String>(())
    };

    let client_side = dial.await;
    let server_side = serve.await.expect("server task");
    match (client_side, server_side) {
        (Ok(()), Ok(())) => Outcome::Accepted,
        (Err(e), _) => Outcome::Rejected(e),
        (_, Err(e)) => Outcome::Rejected(e),
    }
}

/// The common case: one CA, both peers issued by it, pinned by leaf thumbprint.
struct Fleet {
    ca: Ca,
}

impl Fleet {
    fn new() -> Fleet {
        Fleet {
            ca: Ca::new("RSL Test Root"),
        }
    }
}

// ---------------------------------------------------------------------------
// Thumbprint pinning: slot A, slot B, and the misses
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_pinned_thumbprint_in_slot_a_is_accepted() {
    let fleet = Fleet::new();
    let leaf = fleet.ca.issue(LeafSpec::named("replica-1"));
    let tls = Tls::new(TlsConfig {
        identity: leaf.identity(),
        thumbprint_a: Some(leaf.thumbprint()),
        roots: vec![fleet.ca.der()],
        ..TlsConfig::default()
    })
    .expect("config");
    assert!(handshake(&tls, &tls).await.accepted());
}

#[tokio::test]
async fn a_pinned_thumbprint_in_slot_b_is_accepted() {
    let fleet = Fleet::new();
    let leaf = fleet.ca.issue(LeafSpec::named("replica-1"));
    let other = fleet
        .ca
        .issue(LeafSpec::named("someone-else").with_serial(2));
    let tls = Tls::new(TlsConfig {
        identity: leaf.identity(),
        // A points at a certificate nobody presents; B is the live one.
        thumbprint_a: Some(other.thumbprint()),
        thumbprint_b: Some(leaf.thumbprint()),
        roots: vec![fleet.ca.der()],
        ..TlsConfig::default()
    })
    .expect("config");
    assert!(handshake(&tls, &tls).await.accepted());
}

#[tokio::test]
async fn a_certificate_from_the_right_ca_with_no_matching_pin_is_rejected() {
    let fleet = Fleet::new();
    let leaf = fleet.ca.issue(LeafSpec::named("replica-1"));
    let stranger = fleet.ca.issue(LeafSpec::named("stranger").with_serial(2));
    // Both peers chain to the trusted root; only the pin differs. This is the
    // case a CA-only trust model would let through.
    let tls = Tls::new(TlsConfig {
        identity: stranger.identity(),
        thumbprint_a: Some(leaf.thumbprint()),
        roots: vec![fleet.ca.der()],
        ..TlsConfig::default()
    })
    .expect("config");
    let outcome = handshake(&tls, &tls).await;
    assert!(!outcome.accepted(), "{outcome:?}");
}

#[tokio::test]
async fn a_bare_leaf_still_matches_a_thumbprint_pin() {
    // No issuer is presented, so no chain can be built — but with the chain
    // toggle off, a leaf pin is all the rule needs.
    let fleet = Fleet::new();
    let leaf = fleet.ca.issue(LeafSpec::named("replica-1"));
    let tls = Tls::new(TlsConfig {
        identity: leaf.identity_bare(),
        thumbprint_a: Some(leaf.thumbprint()),
        chain: ChainValidation::Off,
        ..TlsConfig::default()
    })
    .expect("config");
    assert!(handshake(&tls, &tls).await.accepted());
}

// ---------------------------------------------------------------------------
// Subject + parent pin
// ---------------------------------------------------------------------------

fn subject_rule(subject: &str, parents: Vec<Thumbprint>) -> SubjectRule {
    SubjectRule {
        subject: subject.to_string(),
        parents,
    }
}

#[tokio::test]
async fn a_subject_and_parent_pin_is_accepted_in_slot_a_and_in_slot_b() {
    for slot in ["a", "b"] {
        let fleet = Fleet::new();
        let leaf = fleet.ca.issue(LeafSpec::named("replica-1"));
        let rule = subject_rule("replica-1", vec![fleet.ca.thumbprint()]);
        let decoy = subject_rule("nobody", vec![Thumbprint::of_der(b"nothing")]);
        let (a, b) = match slot {
            "a" => (Some(rule), None),
            _ => (Some(decoy), Some(rule)),
        };
        let tls = Tls::new(TlsConfig {
            identity: leaf.identity(),
            subject_a: a,
            subject_b: b,
            roots: vec![fleet.ca.der()],
            ..TlsConfig::default()
        })
        .expect("config");
        assert!(handshake(&tls, &tls).await.accepted(), "slot {slot}");
    }
}

#[tokio::test]
async fn the_right_subject_with_the_wrong_parent_is_rejected() {
    // The partial miss that matters: an attacker who can get *any* CA to issue
    // a certificate with the fleet's common name.
    let fleet = Fleet::new();
    let rogue = Ca::new("Some Other Root");
    let leaf = rogue.issue(LeafSpec::named("replica-1"));
    let tls = Tls::new(TlsConfig {
        identity: leaf.identity(),
        subject_a: Some(subject_rule("replica-1", vec![fleet.ca.thumbprint()])),
        // The rogue root is trusted for chain-building purposes, so the *only*
        // thing standing between it and acceptance is the parent pin.
        roots: vec![fleet.ca.der(), rogue.der()],
        ..TlsConfig::default()
    })
    .expect("config");
    let outcome = handshake(&tls, &tls).await;
    assert!(!outcome.accepted(), "{outcome:?}");
}

#[tokio::test]
async fn the_right_parent_with_the_wrong_subject_is_rejected() {
    let fleet = Fleet::new();
    let leaf = fleet.ca.issue(LeafSpec::named("replica-2"));
    let tls = Tls::new(TlsConfig {
        identity: leaf.identity(),
        subject_a: Some(subject_rule("replica-1", vec![fleet.ca.thumbprint()])),
        roots: vec![fleet.ca.der()],
        ..TlsConfig::default()
    })
    .expect("config");
    let outcome = handshake(&tls, &tls).await;
    assert!(!outcome.accepted(), "{outcome:?}");
}

#[tokio::test]
async fn the_subject_comparison_is_case_sensitive() {
    // `s_pSubjectA.compare(subject) == 0` — a byte comparison, and an operator
    // who types the CN with the wrong case gets a fleet that will not talk.
    let fleet = Fleet::new();
    let leaf = fleet.ca.issue(LeafSpec::named("Replica-1"));
    let tls = Tls::new(TlsConfig {
        identity: leaf.identity(),
        subject_a: Some(subject_rule("replica-1", vec![fleet.ca.thumbprint()])),
        roots: vec![fleet.ca.der()],
        ..TlsConfig::default()
    })
    .expect("config");
    assert!(!handshake(&tls, &tls).await.accepted());
}

#[tokio::test]
async fn a_subject_rule_needs_the_issuer_to_be_presented() {
    // `cElement >= 2` in `GetCertificateSubject`: no parent, no rule.
    let fleet = Fleet::new();
    let leaf = fleet.ca.issue(LeafSpec::named("replica-1"));
    let tls = Tls::new(TlsConfig {
        identity: leaf.identity_bare(),
        subject_a: Some(subject_rule("replica-1", vec![fleet.ca.thumbprint()])),
        chain: ChainValidation::Off,
        ..TlsConfig::default()
    })
    .expect("config");
    assert!(!handshake(&tls, &tls).await.accepted());
}

#[tokio::test]
async fn any_one_of_several_parent_pins_is_enough() {
    let fleet = Fleet::new();
    let leaf = fleet.ca.issue(LeafSpec::named("replica-1"));
    let tls = Tls::new(TlsConfig {
        identity: leaf.identity(),
        subject_a: Some(subject_rule(
            "replica-1",
            vec![
                Thumbprint::of_der(b"an old root"),
                fleet.ca.thumbprint(),
                Thumbprint::of_der(b"a future root"),
            ],
        )),
        roots: vec![fleet.ca.der()],
        ..TlsConfig::default()
    })
    .expect("config");
    assert!(handshake(&tls, &tls).await.accepted());
}

// ---------------------------------------------------------------------------
// Chain validation and expiry
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_expired_certificate_is_rejected_when_the_chain_is_enforced() {
    let fleet = Fleet::new();
    let leaf = fleet.ca.issue(LeafSpec::named("replica-1").expired());
    let tls = Tls::new(TlsConfig {
        identity: leaf.identity(),
        thumbprint_a: Some(leaf.thumbprint()),
        roots: vec![fleet.ca.der()],
        chain: ChainValidation::Enforce,
        ..TlsConfig::default()
    })
    .expect("config");
    let outcome = handshake(&tls, &tls).await;
    assert!(!outcome.accepted(), "{outcome:?}");
}

#[tokio::test]
async fn an_expired_certificate_is_accepted_when_the_chain_is_only_logged() {
    // This is `validateCAChain = false`, and it is exactly as alarming as it
    // reads. The test exists so the behaviour is a decision rather than a
    // discovery.
    let fleet = Fleet::new();
    let leaf = fleet.ca.issue(LeafSpec::named("replica-1").expired());
    let tls = Tls::new(TlsConfig {
        identity: leaf.identity(),
        thumbprint_a: Some(leaf.thumbprint()),
        roots: vec![fleet.ca.der()],
        chain: ChainValidation::LogOnly,
        ..TlsConfig::default()
    })
    .expect("config");
    assert!(handshake(&tls, &tls).await.accepted());
}

#[tokio::test]
async fn an_untrusted_ca_is_rejected_when_the_chain_is_enforced_even_with_a_pin() {
    let fleet = Fleet::new();
    let rogue = Ca::new("Unknown Root");
    let leaf = rogue.issue(LeafSpec::named("replica-1"));
    let tls = Tls::new(TlsConfig {
        identity: leaf.identity(),
        thumbprint_a: Some(leaf.thumbprint()),
        roots: vec![fleet.ca.der()],
        chain: ChainValidation::Enforce,
        ..TlsConfig::default()
    })
    .expect("config");
    let outcome = handshake(&tls, &tls).await;
    assert!(!outcome.accepted(), "{outcome:?}");
}

#[tokio::test]
async fn a_revoked_certificate_is_rejected_when_revocation_is_checked() {
    let fleet = Fleet::new();
    let leaf = fleet.ca.issue(LeafSpec::named("replica-1"));
    let crl = fleet.ca.revoke(&leaf);
    let tls = Tls::new(TlsConfig {
        identity: leaf.identity(),
        thumbprint_a: Some(leaf.thumbprint()),
        roots: vec![fleet.ca.der()],
        crls: vec![crl],
        revocation: Revocation::Check,
        ..TlsConfig::default()
    })
    .expect("config");
    let outcome = handshake(&tls, &tls).await;
    assert!(!outcome.accepted(), "{outcome:?}");
}

#[tokio::test]
async fn a_certificate_no_crl_covers_is_not_thereby_revoked() {
    // `CRYPT_E_NO_REVOCATION_CHECK` is tolerated by the C++, and by us.
    let fleet = Fleet::new();
    let leaf = fleet.ca.issue(LeafSpec::named("replica-1"));
    let elsewhere = Ca::new("Some Other Root");
    let unrelated_crl = elsewhere.revoke(&elsewhere.issue(LeafSpec::named("gone")));
    let tls = Tls::new(TlsConfig {
        identity: leaf.identity(),
        thumbprint_a: Some(leaf.thumbprint()),
        roots: vec![fleet.ca.der()],
        crls: vec![unrelated_crl],
        revocation: Revocation::Check,
        ..TlsConfig::default()
    })
    .expect("config");
    assert!(handshake(&tls, &tls).await.accepted());
}

// ---------------------------------------------------------------------------
// EKU
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_client_only_certificate_cannot_serve() {
    let fleet = Fleet::new();
    let leaf = fleet
        .ca
        .issue(LeafSpec::named("replica-1").with_ekus(vec![ExtendedKeyUsagePurpose::ClientAuth]));
    let tls = Tls::new(TlsConfig {
        identity: leaf.identity(),
        thumbprint_a: Some(leaf.thumbprint()),
        roots: vec![fleet.ca.der()],
        ..TlsConfig::default()
    })
    .expect("config");
    let outcome = handshake(&tls, &tls).await;
    assert!(!outcome.accepted(), "{outcome:?}");
}

#[tokio::test]
async fn a_server_only_certificate_cannot_be_a_client() {
    let fleet = Fleet::new();
    let both = fleet.ca.issue(LeafSpec::named("server"));
    let server_only = fleet.ca.issue(
        LeafSpec::named("client")
            .with_ekus(vec![ExtendedKeyUsagePurpose::ServerAuth])
            .with_serial(2),
    );
    let server = Tls::new(TlsConfig {
        identity: both.identity(),
        thumbprint_a: Some(both.thumbprint()),
        thumbprint_b: Some(server_only.thumbprint()),
        roots: vec![fleet.ca.der()],
        ..TlsConfig::default()
    })
    .expect("config");
    let client = Tls::new(TlsConfig {
        identity: server_only.identity(),
        thumbprint_a: Some(both.thumbprint()),
        thumbprint_b: Some(server_only.thumbprint()),
        roots: vec![fleet.ca.der()],
        ..TlsConfig::default()
    })
    .expect("config");
    let outcome = handshake(&server, &client).await;
    assert!(!outcome.accepted(), "{outcome:?}");
}

#[tokio::test]
async fn a_certificate_with_no_eku_extension_is_good_for_both_roles() {
    let fleet = Fleet::new();
    let leaf = fleet
        .ca
        .issue(LeafSpec::named("replica-1").with_ekus(vec![]));
    let tls = Tls::new(TlsConfig {
        identity: leaf.identity(),
        thumbprint_a: Some(leaf.thumbprint()),
        roots: vec![fleet.ca.der()],
        ..TlsConfig::default()
    })
    .expect("config");
    assert!(handshake(&tls, &tls).await.accepted());
}

// ---------------------------------------------------------------------------
// Mutual authentication
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_server_rejects_a_client_it_does_not_accept() {
    // Asymmetric configuration: the client accepts the server's certificate,
    // the server does not accept the client's. Mutual means both.
    let fleet = Fleet::new();
    let server_leaf = fleet.ca.issue(LeafSpec::named("server"));
    let client_leaf = fleet.ca.issue(LeafSpec::named("client").with_serial(2));

    let server = Tls::new(TlsConfig {
        identity: server_leaf.identity(),
        // Pins only itself: the client is a stranger.
        thumbprint_a: Some(server_leaf.thumbprint()),
        roots: vec![fleet.ca.der()],
        ..TlsConfig::default()
    })
    .expect("config");
    let client = Tls::new(TlsConfig {
        identity: client_leaf.identity(),
        thumbprint_a: Some(server_leaf.thumbprint()),
        roots: vec![fleet.ca.der()],
        ..TlsConfig::default()
    })
    .expect("config");

    let outcome = handshake(&server, &client).await;
    assert!(!outcome.accepted(), "{outcome:?}");
}

#[tokio::test]
async fn the_client_rejects_a_server_it_does_not_accept() {
    let fleet = Fleet::new();
    let server_leaf = fleet.ca.issue(LeafSpec::named("server"));
    let client_leaf = fleet.ca.issue(LeafSpec::named("client").with_serial(2));

    let server = Tls::new(TlsConfig {
        identity: server_leaf.identity(),
        thumbprint_a: Some(client_leaf.thumbprint()),
        roots: vec![fleet.ca.der()],
        ..TlsConfig::default()
    })
    .expect("config");
    let client = Tls::new(TlsConfig {
        identity: client_leaf.identity(),
        // Pins only itself: the server is a stranger.
        thumbprint_a: Some(client_leaf.thumbprint()),
        roots: vec![fleet.ca.der()],
        ..TlsConfig::default()
    })
    .expect("config");

    let outcome = handshake(&server, &client).await;
    assert!(!outcome.accepted(), "{outcome:?}");
}

#[tokio::test]
async fn a_client_with_no_certificate_at_all_is_refused() {
    // `client_auth_mandatory` — there is no anonymous path into a ring. The
    // "client" here is a plain rustls client with no credential, which is the
    // only way to express "presents nothing" through this API.
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};

    let fleet = Fleet::new();
    let leaf = fleet.ca.issue(LeafSpec::named("replica-1"));
    let server = Tls::new(TlsConfig {
        identity: leaf.identity(),
        thumbprint_a: Some(leaf.thumbprint()),
        roots: vec![fleet.ca.der()],
        ..TlsConfig::default()
    })
    .expect("config");

    #[derive(Debug)]
    struct AcceptAnything(rustls::crypto::CryptoProvider);
    impl ServerCertVerifier for AcceptAnything {
        fn verify_server_cert(
            &self,
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &[rustls::pki_types::CertificateDer<'_>],
            _: &rustls::pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            m: &[u8],
            c: &rustls::pki_types::CertificateDer<'_>,
            d: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                m,
                c,
                d,
                &self.0.signature_verification_algorithms,
            )
        }
        fn verify_tls13_signature(
            &self,
            m: &[u8],
            c: &rustls::pki_types::CertificateDer<'_>,
            d: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                m,
                c,
                d,
                &self.0.signature_verification_algorithms,
            )
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let acceptor = server.connector();
    let serve = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.expect("accept");
        Acceptor::accept(&*acceptor, sock).await.map(|_| ())
    });

    let provider = rustls::crypto::ring::default_provider();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider.clone()))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnything(provider)))
        .with_no_client_auth();
    let sock = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let name =
        rustls::pki_types::ServerName::IpAddress(std::net::IpAddr::from([127, 0, 0, 1]).into());
    let attempt = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, sock)
        .await;

    // One side or the other must have failed; with a certificate-less client
    // the server's `CertificateRequired` alert can surface on either.
    let server_side = serve.await.expect("server task");
    assert!(
        attempt.is_err() || server_side.is_err(),
        "a client with no certificate was allowed in"
    );
}
