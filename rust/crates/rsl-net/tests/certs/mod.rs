//! The certificate fixture — **generator code, not certificate bytes**.
//!
//! Nothing under `tests/` is a checked-in `.pem`. Every certificate the TLS
//! tests use is minted here at run time, which is what lets a test say "the
//! same subject but a different issuer" or "expired last century" in one line
//! and never explains why a fixture expired on a Tuesday in 2031.
//!
//! The shape is always the same: a self-signed CA, and leaves it issues. A
//! chain presented on the wire is `[leaf, ca]`, so a peer applying the subject
//! rule can find the issuer to pin (see `Leaf::identity`).

#![allow(dead_code)]

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateRevocationListParams,
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    RevokedCertParams, SerialNumber,
};
use rsl_net::tls::{CertificateDer, CertificateRevocationListDer, Identity, Thumbprint};

/// The date type rcgen's validity fields use.
pub type Date = time::OffsetDateTime;

/// Long past. Used for the expired-certificate cases.
pub fn expired() -> (Date, Date) {
    (
        rcgen::date_time_ymd(2000, 1, 1),
        rcgen::date_time_ymd(2001, 1, 1),
    )
}

/// What a leaf certificate should look like.
pub struct LeafSpec {
    /// `CN`, when there is one. `None` builds a certificate whose subject has
    /// no common name at all — the case that exercises the fallbacks in
    /// `simple_display_name`.
    pub common_name: Option<String>,
    /// `OU`, if any.
    pub organizational_unit: Option<String>,
    /// `O`, if any.
    pub organization: Option<String>,
    /// Extended key usages. Empty means *no EKU extension*, which RFC 5280
    /// says is valid for every purpose.
    pub ekus: Vec<ExtendedKeyUsagePurpose>,
    /// Validity. Defaults to "valid for a very long time".
    pub not_before: Date,
    pub not_after: Date,
    /// The serial, so the CA can revoke it later.
    pub serial: u64,
}

impl Default for LeafSpec {
    fn default() -> LeafSpec {
        LeafSpec {
            common_name: Some("replica".into()),
            organizational_unit: None,
            organization: None,
            ekus: vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ],
            not_before: rcgen::date_time_ymd(2020, 1, 1),
            not_after: rcgen::date_time_ymd(4096, 1, 1),
            serial: 1,
        }
    }
}

impl LeafSpec {
    /// A leaf with this common name and both EKUs.
    pub fn named(cn: &str) -> LeafSpec {
        LeafSpec {
            common_name: Some(cn.into()),
            ..LeafSpec::default()
        }
    }

    pub fn with_ekus(mut self, ekus: Vec<ExtendedKeyUsagePurpose>) -> LeafSpec {
        self.ekus = ekus;
        self
    }

    pub fn expired(mut self) -> LeafSpec {
        let (before, after) = expired();
        self.not_before = before;
        self.not_after = after;
        self
    }

    pub fn with_serial(mut self, serial: u64) -> LeafSpec {
        self.serial = serial;
        self
    }
}

/// A self-signed certificate authority.
pub struct Ca {
    params: CertificateParams,
    key: KeyPair,
    cert: Certificate,
}

impl Ca {
    /// A CA that can sign certificates and CRLs.
    pub fn new(name: &str) -> Ca {
        let key = KeyPair::generate().expect("keygen");
        let mut params = CertificateParams::default();
        params.distinguished_name = dn(&[(DnType::CommonName, name)]);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let cert = params.self_signed(&key).expect("self-sign");
        Ca { params, key, cert }
    }

    pub fn der(&self) -> CertificateDer<'static> {
        self.cert.der().clone()
    }

    pub fn thumbprint(&self) -> Thumbprint {
        Thumbprint::of_der(self.cert.der())
    }

    /// PEM, for the C++ interop peer, which loads files rather than DER.
    pub fn pem(&self) -> String {
        self.cert.pem()
    }

    fn issuer(&self) -> Issuer<'_, &KeyPair> {
        Issuer::from_params(&self.params, &self.key)
    }

    /// Issue a leaf.
    pub fn issue(&self, spec: LeafSpec) -> Leaf {
        self.issue_with_dn(spec, &[])
    }

    /// Issue a leaf whose subject carries `extra` attributes *after* the ones
    /// [`LeafSpec`] describes — the way to build a DN with a repeated
    /// attribute type, which is what pins the "most specific wins" rule.
    pub fn issue_with_dn(&self, spec: LeafSpec, extra: &[(DnType, &str)]) -> Leaf {
        let key = KeyPair::generate().expect("keygen");
        let mut params = CertificateParams::default();
        let mut attrs: Vec<(DnType, &str)> = Vec::new();
        if let Some(cn) = &spec.common_name {
            attrs.push((DnType::CommonName, cn));
        }
        if let Some(ou) = &spec.organizational_unit {
            attrs.push((DnType::OrganizationalUnitName, ou));
        }
        if let Some(o) = &spec.organization {
            attrs.push((DnType::OrganizationName, o));
        }
        attrs.extend(extra.iter().map(|(t, v)| (t.clone(), *v)));
        params.distinguished_name = dn(&attrs);
        params.extended_key_usages = spec.ekus.clone();
        params.not_before = spec.not_before;
        params.not_after = spec.not_after;
        params.serial_number = Some(SerialNumber::from(spec.serial));
        let cert = params.signed_by(&key, &self.issuer()).expect("sign leaf");
        Leaf {
            der: cert.der().clone(),
            key: key.serialize_der(),
            key_pem: key.serialize_pem(),
            cert_pem: cert.pem(),
            ca_pem: self.pem(),
            ca: self.der(),
            serial: spec.serial,
        }
    }

    /// A CRL revoking `leaf`.
    pub fn revoke(&self, leaf: &Leaf) -> CertificateRevocationListDer<'static> {
        let params = CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2020, 1, 2),
            next_update: rcgen::date_time_ymd(4096, 1, 1),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: vec![RevokedCertParams {
                serial_number: SerialNumber::from(leaf.serial),
                revocation_time: rcgen::date_time_ymd(2020, 1, 2),
                reason_code: Some(rcgen::RevocationReason::KeyCompromise),
                invalidity_date: None,
            }],
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        params
            .signed_by(&self.issuer())
            .expect("sign crl")
            .der()
            .clone()
    }
}

/// An issued certificate and its key.
pub struct Leaf {
    pub der: CertificateDer<'static>,
    key: Vec<u8>,
    key_pem: String,
    cert_pem: String,
    ca_pem: String,
    ca: CertificateDer<'static>,
    serial: u64,
}

impl Leaf {
    /// The credential as a replica presents it: leaf **and issuer**. Sending
    /// the issuer is what makes the subject rule usable at all — the peer pins
    /// its thumbprint and can only see it if it arrives.
    pub fn identity(&self) -> Identity {
        Identity::from_der(vec![self.der.clone(), self.ca.clone()], self.key.clone())
    }

    /// The credential with the issuer withheld: the "presents a bare leaf"
    /// case, which the subject rule must reject and a thumbprint pin must not
    /// care about.
    pub fn identity_bare(&self) -> Identity {
        Identity::from_der(vec![self.der.clone()], self.key.clone())
    }

    pub fn thumbprint(&self) -> Thumbprint {
        Thumbprint::of_der(&self.der)
    }

    /// The leaf and its issuer as one PEM file — what a TLS stack that loads a
    /// "certificate chain file" expects, and the file-based equivalent of the
    /// chain `identity()` builds.
    pub fn cert_pem(&self) -> String {
        format!("{}{}", self.cert_pem, self.ca_pem)
    }

    pub fn key_pem(&self) -> String {
        self.key_pem.clone()
    }
}

fn dn(attrs: &[(DnType, &str)]) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    for (t, v) in attrs {
        dn.push(t.clone(), *v);
    }
    dn
}
