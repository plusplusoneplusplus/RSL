//! Reading the two things out of a certificate that the acceptance rule needs:
//! its *subject display name* and its *extended key usages*.
//!
//! Both are places where "the same certificate" can mean different strings on
//! different stacks, so both are pinned here with an explicit, documented
//! algorithm rather than delegated to whatever a parser happens to produce.

use x509_parser::prelude::*;

/// `CertGetNameString`'s output buffer is `char pszNameString[256]`
/// (`SSLImpl.cpp:735`), so a longer name comes back truncated — and it is the
/// *truncated* string the C++ compares against `subjectA`/`subjectB`.
const MAX_NAME_CHARS: usize = 255;

/// szOID_SERVER_GATED_CRYPTO — Microsoft Server Gated Crypto.
const OID_MS_SGC: &str = "1.3.6.1.4.1.311.10.3.3";
/// szOID_SGC_NETSCAPE — Netscape Server Gated Crypto.
const OID_NETSCAPE_SGC: &str = "2.16.840.1.113730.4.1";

/// Which side of the connection a certificate is being judged as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// The remote is the TLS server; its certificate needs `serverAuth`
    /// (`szOID_PKIX_KP_SERVER_AUTH`, plus the two SGC OIDs the C++ also
    /// accepts).
    Server,
    /// The remote is the TLS client; its certificate needs `clientAuth`.
    Client,
}

impl Purpose {
    fn label(self) -> &'static str {
        match self {
            Purpose::Server => "serverAuth",
            Purpose::Client => "clientAuth",
        }
    }
}

/// A certificate we could not read at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadCertificate;

/// The subject string the C++ compares — `CertGetNameString(cert,
/// CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, buf, 256)`
/// (`SSLAuth::GetCertificateSubject`, `SSLImpl.cpp:737`).
///
/// This is **not** a distinguished name. It is Windows' "simple display name",
/// and reproducing it is the sharpest interop edge in the whole port: a DN
/// rendered by OpenSSL (`/CN=replica-1/O=Contoso`) or by `x509-parser`
/// (`CN=replica-1, O=Contoso`) is a different string, and the comparison is
/// `std::string::compare` — byte-exact, case-sensitive.
///
/// The algorithm implemented, matching the documented behaviour of
/// `CERT_NAME_SIMPLE_DISPLAY_TYPE`:
///
/// 1. The subject's `CN`, else `OU`, else `O`, else `emailAddress`. Within each
///    attribute type the RDNs are searched **from last to first**: an X.509 DN
///    is encoded most-general first, and Windows returns the most specific
///    occurrence.
/// 2. Failing all of those, the first `rfc822Name` in the Subject Alternative
///    Name extension.
/// 3. Failing that, there is no name (`None`) — the C++'s `GetCertificateSubject`
///    fails and the subject rule cannot match.
///
/// Finally the result is truncated to 255 characters, because
/// the C++'s fixed buffer is.
///
/// **Residual risk.** Step 1 and step 2 are reproduced from the documented
/// behaviour, not observed from a running SChannel — see the Windows
/// verification checklist in `TLS.md`. Every fleet certificate RSL has ever
/// been deployed with carries a `CN`, which is step 1's first branch and the
/// part this port is confident in.
pub fn simple_display_name(der: &[u8]) -> Result<Option<String>, BadCertificate> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|_| BadCertificate)?;

    let attrs = [
        oid_registry::OID_X509_COMMON_NAME,
        oid_registry::OID_X509_ORGANIZATIONAL_UNIT,
        oid_registry::OID_X509_ORGANIZATION_NAME,
        oid_registry::OID_PKCS9_EMAIL_ADDRESS,
    ];
    for oid in attrs {
        // Reverse RDN order: most specific first, as Windows reports it.
        for rdn in cert
            .subject()
            .iter_rdn()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
            for attr in rdn.iter() {
                if *attr.attr_type() != oid {
                    continue;
                }
                if let Ok(value) = attr.as_str() {
                    if !value.is_empty() {
                        return Ok(Some(truncate(value)));
                    }
                }
            }
        }
    }

    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::RFC822Name(value) = name {
                if !value.is_empty() {
                    return Ok(Some(truncate(value)));
                }
            }
        }
    }

    Ok(None)
}

fn truncate(s: &str) -> String {
    s.chars().take(MAX_NAME_CHARS).collect()
}

/// Whether a leaf certificate's EKU extension permits `purpose`.
///
/// The rule is RFC 5280's and Windows': an **absent** EKU extension means the
/// certificate is good for every purpose, and a present one must list the
/// purpose (or `anyExtendedKeyUsage`). For [`Purpose::Server`] the two Server
/// Gated Crypto OIDs count as well, because `SSLAuth::IsCertificateTrusted`
/// passes them in its `RequestedUsage` list (`SSLImpl.cpp:352-355`).
///
/// **Divergence, deliberate.** In the C++ this check is a side effect of
/// building the chain, so `validateCAChain = false` discards it along with the
/// chain result: a certificate marked `clientAuth`-only is accepted as a server
/// there if its thumbprint is pinned. Here the EKU is checked *unconditionally*,
/// independent of [`super::ChainValidation`]. A certificate presented for the
/// wrong role is a misconfiguration in every deployment, and pinning does not
/// make it less of one.
///
/// **Divergence.** The C++'s `IsCertificateTrusted` has the two roles inverted
/// — it asks for `clientAuth` when validating the *server's* certificate and
/// `serverAuth` when validating the client's (`SSLImpl.cpp:345-356`), the exact
/// opposite of what its own `GetCertificateSubject` does thirty lines later
/// (`SSLImpl.cpp:755-766`). Only one of the two can be right. This port uses
/// the `GetCertificateSubject` mapping, which is the correct one; the effect is
/// that a fleet whose certificates carry only one of the two EKUs — and which
/// therefore *only* worked because the C++ asked for the wrong one — will be
/// rejected here. That is a real migration hazard and it is called out in
/// `TLS.md`.
pub fn eku_permits(der: &[u8], purpose: Purpose) -> Result<bool, BadCertificate> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|_| BadCertificate)?;
    let eku = match cert.extended_key_usage() {
        Ok(Some(eku)) => eku.value,
        // No EKU extension: good for anything.
        Ok(None) => return Ok(true),
        Err(_) => return Err(BadCertificate),
    };
    if eku.any {
        return Ok(true);
    }
    Ok(match purpose {
        Purpose::Client => eku.client_auth,
        Purpose::Server => {
            eku.server_auth
                || eku
                    .other
                    .iter()
                    .any(|oid| matches!(oid.to_id_string().as_str(), OID_MS_SGC | OID_NETSCAPE_SGC))
        }
    })
}

/// The reason string for a rejected EKU, for the log line.
pub fn eku_error(purpose: Purpose) -> String {
    format!("certificate is not valid for {}", purpose.label())
}

#[cfg(test)]
mod tests {
    // The interesting cases all need real certificates and live in
    // `tests/tls_rules.rs`, next to the rcgen fixtures that can build a subject
    // with a missing CN, a multi-valued RDN, or an over-long name.
    use super::*;

    #[test]
    fn a_non_certificate_is_an_error_not_a_panic() {
        assert_eq!(
            simple_display_name(b"not a certificate"),
            Err(BadCertificate)
        );
        assert_eq!(eku_permits(&[], Purpose::Server), Err(BadCertificate));
    }

    #[test]
    fn truncation_is_at_the_cpp_buffer_size() {
        let long = "x".repeat(300);
        assert_eq!(truncate(&long).chars().count(), MAX_NAME_CHARS);
    }
}
