//! Vectors for the subject string the acceptance rule compares.
//!
//! `SSLAuth::GetCertificateSubject` calls `CertGetNameString(cert,
//! CERT_NAME_SIMPLE_DISPLAY_TYPE, ...)` and compares the result to `subjectA` /
//! `subjectB` with `std::string::compare`. Every assertion below pins one
//! decision of that function against a certificate built for it.
//!
//! **These are Rust-side vectors, not observed SChannel output.** SChannel
//! cannot be executed on Linux, so the closure condition for this file is the
//! Windows checklist in `TLS.md`: run `CertGetNameString` over these same
//! certificates on Windows and confirm every string. Until that is done, the
//! `CN` case — the only shape RSL has ever been deployed with — is the part to
//! rely on.

mod certs;

use certs::{Ca, LeafSpec};
use rcgen::DnType;
use rsl_net::tls::name::{eku_permits, simple_display_name, Purpose};

fn name_of(spec: LeafSpec) -> Option<String> {
    let ca = Ca::new("Root");
    let leaf = ca.issue(spec);
    simple_display_name(&leaf.der).expect("a certificate we just built parses")
}

#[test]
fn the_common_name_wins() {
    let name = name_of(LeafSpec {
        common_name: Some("replica-1".into()),
        organizational_unit: Some("Consensus".into()),
        organization: Some("Contoso".into()),
        ..LeafSpec::default()
    });
    assert_eq!(name.as_deref(), Some("replica-1"));
}

#[test]
fn the_organizational_unit_is_the_first_fallback() {
    let name = name_of(LeafSpec {
        common_name: None,
        organizational_unit: Some("Consensus".into()),
        organization: Some("Contoso".into()),
        ..LeafSpec::default()
    });
    assert_eq!(name.as_deref(), Some("Consensus"));
}

#[test]
fn the_organization_is_the_second_fallback() {
    let name = name_of(LeafSpec {
        common_name: None,
        organizational_unit: None,
        organization: Some("Contoso".into()),
        ..LeafSpec::default()
    });
    assert_eq!(name.as_deref(), Some("Contoso"));
}

#[test]
fn a_subject_with_nothing_we_look_for_has_no_display_name() {
    // No CN, no OU, no O, no email, no SAN: `GetCertificateSubject` fails and
    // the subject rule cannot match. It is not an error — just a certificate
    // that only a thumbprint pin can accept.
    let ca = Ca::new("Root");
    let leaf = ca.issue(LeafSpec {
        common_name: None,
        ..LeafSpec::default()
    });
    assert_eq!(simple_display_name(&leaf.der).expect("parses"), None);
}

#[test]
fn the_name_is_not_a_distinguished_name() {
    // The trap this whole function exists to avoid: an operator (or a port)
    // that configures the DN as OpenSSL or x509-parser renders it will never
    // match. Stated as an assertion so a future refactor that "helpfully"
    // switches to a DN cannot pass.
    let name = name_of(LeafSpec {
        common_name: Some("replica-1".into()),
        organization: Some("Contoso".into()),
        ..LeafSpec::default()
    })
    .expect("a name");
    assert!(!name.contains("CN="), "{name}");
    assert!(!name.contains('/'), "{name}");
    assert!(!name.contains("Contoso"), "{name}");
}

#[test]
fn a_name_longer_than_the_cpp_buffer_is_truncated() {
    // `char pszNameString[256]` — the comparison the C++ makes is against the
    // truncated string, so ours must be too.
    let long = "n".repeat(400);
    let name = name_of(LeafSpec {
        common_name: Some(long),
        ..LeafSpec::default()
    })
    .expect("a name");
    assert_eq!(name.chars().count(), 255);
}

#[test]
fn the_eku_check_reads_both_purposes_off_a_real_certificate() {
    use rcgen::ExtendedKeyUsagePurpose::{ClientAuth, ServerAuth};
    let ca = Ca::new("Root");

    let both = ca.issue(LeafSpec::named("both"));
    assert!(eku_permits(&both.der, Purpose::Server).expect("parses"));
    assert!(eku_permits(&both.der, Purpose::Client).expect("parses"));

    let server_only = ca.issue(LeafSpec::named("server").with_ekus(vec![ServerAuth]));
    assert!(eku_permits(&server_only.der, Purpose::Server).expect("parses"));
    assert!(!eku_permits(&server_only.der, Purpose::Client).expect("parses"));

    let client_only = ca.issue(LeafSpec::named("client").with_ekus(vec![ClientAuth]));
    assert!(!eku_permits(&client_only.der, Purpose::Server).expect("parses"));
    assert!(eku_permits(&client_only.der, Purpose::Client).expect("parses"));

    // No extension at all: valid for everything (RFC 5280, and Windows).
    let unrestricted = ca.issue(LeafSpec::named("any").with_ekus(vec![]));
    assert!(eku_permits(&unrestricted.der, Purpose::Server).expect("parses"));
    assert!(eku_permits(&unrestricted.der, Purpose::Client).expect("parses"));
}

#[test]
fn the_two_server_gated_crypto_oids_count_as_server_auth() {
    // `IsCertificateTrusted` lists `szOID_SERVER_GATED_CRYPTO` and
    // `szOID_SGC_NETSCAPE` alongside `serverAuth` (`SSLImpl.cpp:352-355`).
    // Legacy, but a certificate minted for the old fleet may carry them.
    use rcgen::ExtendedKeyUsagePurpose::Other;
    let ca = Ca::new("Root");
    for oid in [
        vec![1, 3, 6, 1, 4, 1, 311, 10, 3, 3],
        vec![2, 16, 840, 1, 113730, 4, 1],
    ] {
        let leaf = ca.issue(LeafSpec::named("sgc").with_ekus(vec![Other(oid.clone())]));
        assert!(
            eku_permits(&leaf.der, Purpose::Server).expect("parses"),
            "{oid:?} was not accepted as serverAuth"
        );
        assert!(
            !eku_permits(&leaf.der, Purpose::Client).expect("parses"),
            "{oid:?} was accepted as clientAuth"
        );
    }
}

#[test]
fn a_multi_valued_subject_takes_the_most_specific_common_name() {
    // Windows searches the RDNs in reverse encoded order, so the *last* CN in
    // the DER — the most specific one — is what it reports.
    let ca = Ca::new("Root");
    let leaf = ca.issue_with_dn(
        LeafSpec {
            common_name: None,
            organization: Some("Contoso".into()),
            ..LeafSpec::default()
        },
        &[
            (DnType::CommonName, "general"),
            (DnType::CommonName, "specific"),
        ],
    );
    assert_eq!(
        simple_display_name(&leaf.der).expect("parses").as_deref(),
        Some("specific")
    );
}
