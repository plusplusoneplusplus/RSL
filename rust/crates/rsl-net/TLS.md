# TLS in `rsl-net`

Phase 4d. Mutual TLS on **both** RSL ports — the packet port (4b) and the learn
port (4c) — with the operator-facing trust model of the C++ SChannel
implementation (`src/NetworkLib/src/SSLImpl.cpp`, `src/NetworkLib/src/NetSSLCxn.cpp`),
minus its bugs.

Feature `tls` (on by default). `--no-default-features --features svc,learnport`
builds the crate without rustls at all.

## The trust model

```text
accept(cert) =
      sha1(cert)         == thumbprintA  ||  == thumbprintB
  ||  (name(cert) == subjectA && sha1(issuer) ∈ parentsA)
  ||  (name(cert) == subjectB && sha1(issuer) ∈ parentsB)
```

applied in both directions, on top of a chain / validity / revocation check
whose strictness is a separate toggle, with client authentication mandatory.
`name()` is Windows' **simple display name**, not a distinguished name — see
below.

The `A`/`B` duplication is the rotation mechanism, and it appears twice: in the
acceptance rule (which peers we accept) and in the local credential lookup
(which certificate we present). A roll is:

1. mint the new certificate;
2. add it as `B` on every replica — both are now accepted;
3. switch each replica's own credential to the new one, one at a time;
4. remove the old one from `B`.

Step 2→3 is the window where a fleet is mixed, and the whole point of the pair
is that the window is safe. There is a test for exactly this
(`tests/tls_ports.rs::a_peer_still_on_the_old_certificate_is_accepted_while_both_slots_are_staged`).

`Tls::swap` performs a step. **Connections that already exist are not rekeyed
and not dropped** — the C++ does the same (`SetSSLThumbprints` re-acquires the
credential handles while every live `NetSslCxn` keeps its security context), and
it is the right behaviour: a rotation that dropped every connection would be a
fleet-wide election storm.

## Configuration

```rust
use rsl_net::tls::{Identity, Tls, TlsConfig, SubjectRule};

let tls = Tls::new(TlsConfig {
    identity: Identity::from_pem_files("replica.pem", "replica.key")?,
    thumbprint_a: Some("1b32891adb56d3f7115e7e031cc41e1793252015".parse()?),
    thumbprint_b: None,                  // the rotation slot
    roots: vec![root_ca_der],
    ..TlsConfig::default()
})?;

let client = PacketSvc::start_as_client_with(tls.dialer(bind_ip), handler, cfg);
let server = PacketSvc::start_as_server_with(port, tls.acceptor(), handler, cfg)?;
let learn_server = LearnServer::bind_with(addr, tls.connector(), source, cfg).await?;
let learn_client = LearnClient::new().over(tls.connector());
```

| C++ setting | Here |
| --- | --- |
| `SetThumbprintsForSsl(A, B, validateCAChain, checkCertificateRevocation)` | `thumbprint_a`, `thumbprint_b`, `chain`, `revocation` |
| `SetSubjectNamesForSsl(subjA, parentsA, subjB, parentsB, whitelist)` | `subject_a`, `subject_b`, `identity_pins` |
| store `"MY"` + thumbprint lookup | `identity` — **PEM files** |
| `SP_PROT_TLS1_2_*` | `compat_tls12_only` (default `true`) |

Every consistency check happens in `Tls::new`, so a handshake can only fail for
reasons on the wire. A config that pins nothing, or that sets
`identity_pins = false`, is refused with the reason rather than accepted into a
fleet that silently cannot talk to itself.

## Deliberate divergences

These are decisions, not omissions. Each is a place where reproducing the C++
faithfully would mean reproducing a defect.

**1. One switch gates both ports.** In the C++ the packet port asks
`SSLAuth::IsSSLEnabled()` (`NetSSLCxn.cpp:10`) — true when thumbprints *or*
subject names are set — while the learn port asks `SSLAuth::HasAnyThumbprint()`
(`StreamIO.cpp:39`), true only for thumbprints. A fleet configured with subject
names alone therefore encrypts its consensus traffic and ships its checkpoints —
the entire replicated state, plus every client request in the log — in the
clear. One `Tls` gates both here.

**2. `validateCAChain = false` is `ChainValidation::LogOnly`.** Same behaviour
(build the chain, log the failure, carry on), a name that says so, and a warning
on every occurrence. `ChainValidation::Off` is added for a deployment that pins
leaf thumbprints and has no CA, where `LogOnly` would log a failure on every
handshake and teach operators to ignore the line. Note what both switch off
along with the chain: **validity dates**. An expired pinned certificate is
accepted — in the C++ too.

**3. EKU is checked unconditionally, with the roles the right way round.** In
the C++ the EKU check is a side effect of building the chain, so
`validateCAChain = false` discards it. Worse, `IsCertificateTrusted` has the two
roles *inverted* — it asks for `clientAuth` when validating the server's
certificate and `serverAuth` when validating the client's (`SSLImpl.cpp:345-356`),
the exact opposite of what `GetCertificateSubject` does thirty lines later
(`SSLImpl.cpp:755-766`). Only one can be right; this port uses the
`GetCertificateSubject` mapping.

> **Migration hazard.** A fleet whose certificates carry only one of the two
> EKUs, and which worked *because* the C++ asked for the wrong one, will be
> rejected here. Check the fleet's certificates for both `clientAuth` and
> `serverAuth` (or no EKU extension at all) before migrating.

**4. Revocation is CRL-only.** `checkCertificateRevocation` makes SChannel
*fetch* CRLs and speak OCSP over the network. Nothing here does: `Revocation::Check`
checks the CRLs you supply, and having none is a config error rather than a
check that silently passes everything. Unknown revocation status is tolerated,
which is the C++'s `CRYPT_E_NO_REVOCATION_CHECK` / `CRYPT_E_REVOCATION_OFFLINE`
allowance (`SSLImpl.cpp:409-431`).

**5. A mistyped thumbprint is an error.** `HexToDec` returns `0` for any
character it does not recognize, so in the C++ a typo silently becomes a
*different, valid-looking* pin. The length rule (`strlen / 2 == 20`, so a
41-character string is accepted) is kept, because configs in the wild have it.

**6. `identity_pins = false` is refused.** The C++'s
`considerIdentitiesWhitelist = false` makes `IsCertificateThumbprintAcceptable`
fail unconditionally — and the subject rule goes through it too, for the issuer
pin — so it accepts nothing at all. Rather than reproduce a knob whose only
value is "reject everything", `Tls::new` says so.

**7. File-based credentials.** See the next section; this one is operational,
not behavioural.

**8. Duplicate-connection detection happens after the handshake** on the packet
port's server side, because until the handshake finishes there is nothing to be
a duplicate of. A second socket from an address that already has a connection
costs one handshake before it is dropped.

Not reproduced because it cannot exist here: the wrong-credential-handle free in
`SetSSLThumbprints` (`SSLImpl.cpp:995` frees and zeroes the *client* handle
while clearing the *server* flag). There is no global mutable credential pair in
this design.

## Operational migration: the certificate store

**This is a breaking operational change and needs a deployment story before any
migration.**

The C++ looks its own certificate up in the Windows certificate store —
`CertOpenStore(CERT_SYSTEM_STORE_LOCAL_MACHINE, "MY")`, then a linear scan for a
matching thumbprint (`SSLImpl.cpp:807`). The private key never leaves the store,
and deployment means "install a certificate on the machine".

Here an `Identity` is a PEM certificate chain and a PEM private key on disk. The
implications an operator must have an answer for:

- **The private key is a file.** It needs the same protection the store gave it:
  ownership by the service account, mode `0600`, and a filesystem that is not
  backed up in the clear. On Linux this is the normal way to run TLS; it is
  still a change from what RSL operators do today.
- **Deployment changes shape.** Instead of installing into a store and
  configuring a thumbprint, the deployment writes two files and configures two
  paths. `Identity::from_pem_files_with_fallback` keeps the A-then-B lookup
  shape so a rotation can stage files the same way it staged store entries.
- **The thumbprint is still the identity.** Pins do not change: the SHA-1 of the
  DER is the same number `certmgr.msc` shows. A fleet's existing `thumbprintA` /
  `thumbprintB` configuration carries over unchanged, which is what makes a
  mixed C++/Rust fleet possible at all.
- **Renewal is now the deployer's job.** Nothing here watches the store for a
  renewed certificate. `Tls::swap` is the hook: re-read the files and swap.

A host that manages key material itself can bypass files entirely with
`Identity::from_der`.

## The subject string

`SSLAuth::GetCertificateSubject` calls
`CertGetNameString(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, buf, 256)` and
compares the result to `subjectA` / `subjectB` with `std::string::compare` —
byte-exact and case-sensitive.

**This is not a distinguished name.** A DN rendered by OpenSSL
(`/CN=replica-1/O=Contoso`) or by `x509-parser` (`CN=replica-1, O=Contoso`) is a
different string and will never match. The algorithm implemented
(`tls::name::simple_display_name`):

1. the subject's `CN`, else `OU`, else `O`, else `emailAddress`, searching the
   RDNs **last to first** so the most specific occurrence wins;
2. failing those, the first `rfc822Name` in the Subject Alternative Name;
3. failing that, no name — the subject rule cannot match, and only a thumbprint
   pin can accept the certificate;
4. truncated to 255 characters, because the C++'s buffer is `char[256]`.

Vectors are in `tests/tls_names.rs`.

> **Residual risk.** Steps 1 and 2 are reproduced from documented behaviour, not
> observed from a running SChannel — it cannot be executed on Linux. The `CN`
> branch, which is the only shape RSL has ever been deployed with, is the part
> to rely on. The Windows checklist below closes the rest.

## Cipher suites

TLS 1.2 only by default (`compat_tls12_only`), matching `SP_PROT_TLS1_2_CLIENT` /
`_SERVER`. The suite list is pinned to the intersection of rustls' TLS 1.2
suites with SChannel's `SCH_USE_STRONG_CRYPTO` defaults:

| | |
| --- | --- |
| `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` | `ECDHE-ECDSA-AES256-GCM-SHA384` |
| `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | `ECDHE-ECDSA-AES128-GCM-SHA256` |
| `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | `ECDHE-RSA-AES256-GCM-SHA384` |
| `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | `ECDHE-RSA-AES128-GCM-SHA256` |

The two ChaCha20-Poly1305 suites rustls also supports are excluded: SChannel
offers them only on recent Windows 10 and not by default, so leaving them in
would make the negotiated suite depend on which Windows build a peer happens to
be running. The right-hand column is the OpenSSL spelling used by the interop
oracle, so the pin is checkable from both sides
(`tools/golden-gen/src/tls_peer.cpp`).

Set `compat_tls12_only = false` once every replica is Rust to allow TLS 1.3 as
well. A C++ replica cannot negotiate it, so a mixed fleet keeps landing on 1.2
regardless — the flag costs nothing to leave on.

## Interoperability

`golden-gen --tls-peer` / `--tls-client` is an RSL packet peer over **OpenSSL**,
built when CMake finds libssl. `tests/tls_interop.rs` drives both directions:

- Rust client → OpenSSL server, and
- OpenSSL client → Rust server,

each with mutual authentication, TLS 1.2, the pinned suites, and the full packet
round trip on top. It has already earned its keep: it caught a malformed
`certificate_authorities` hint in the `CertificateRequest` (a `TrustAnchor`'s
`subject` is the Name's *contents*, without the SEQUENCE header) that two rustls
peers ignore and OpenSSL rejects outright.

Authoritative Windows tests in `tests/schannel_interop.rs` run the production
SChannel/CryptoAPI implementation through `RSLWindowsOracle` in both directions:

- Rust packet client to production C++ server;
- production C++ packet client to Rust server;
- Rust learn client to production C++ server;
- production C++ learn client to Rust server.

The matrix uses ephemeral RSA certificates with both client and server EKUs.
Keys and PFX files live only in a test scratch directory. C++ credentials and
public peer certificates are installed temporarily in the current user's
certificate stores and removed on drop; no private key is committed. Tests
cover thumbprint and simple-display-name authorization, wrong identities,
enforced-chain rejection versus the production log-only policy, mutual
authentication failure, TLS on both ports, and the documented A/B rotation
sequence.

Production SChannel forces TLS 1.2 and `SCH_USE_STRONG_CRYPTO`. The Rust side of
the authoritative matrix offers only the four suites listed above, so every
successful connection proves SChannel selected TLS 1.2 from that intersection.
OpenSSL tests remain supplemental foreign-stack coverage for certificate-chain
encoding and TLS extension handling on portable CI.

The Windows fixture uses CurrentUser stores because CI and developer test
processes need no elevation. Shipping RSL retains LocalMachine `MY` as its
default credential store.

## Cost

`cargo bench -p rsl-net --bench tls`, loopback, local dev machine:

| Benchmark | Time | Throughput |
| --- | --- | --- |
| `tls/handshake/mutual` (full mutual handshake, connection setup included) | ~1.80 ms | — |
| `tls/round_trip` 1 KiB — plaintext | ~87.9 µs | 22.2 MiB/s |
| `tls/round_trip` 1 KiB — TLS | ~100 µs | 19.5 MiB/s |
| `tls/round_trip` 100 KiB — plaintext | ~426 µs | 458 MiB/s |
| `tls/round_trip` 100 KiB — TLS | ~582 µs | 336 MiB/s |
| `tls/round_trip` 10 MiB — plaintext | ~36.5 ms | 549 MiB/s |
| `tls/round_trip` 10 MiB — TLS | ~39.8 ms | 503 MiB/s |

Reading these:

- The **handshake** is ~1.8 ms, and it includes two certificate-chain
  verifications and an ECDHE exchange. Paid once per connection — but "per
  connection" means per *reconnect*, so a flapping replica pays it on every
  retry. The exponential backoff from Phase 4b (`BackoffConfig`) is what keeps
  that bounded.
- At **1 KiB**, the 14 % overhead is per-record framing and one extra copy;
  loopback latency dominates both columns. This is the size consensus traffic
  actually runs at, and 12 µs on an 88 µs round trip is not where a Paxos
  round's time goes.
- At **100 KiB** the record layer is at its worst relative cost (27 %): the
  payload is large enough to be several TLS records and small enough that
  per-record overhead has not amortized.
- At **10 MiB** — checkpoint territory — the gap closes to ~9 %. AES-GCM with
  hardware acceleration is not the bottleneck; the loopback copy is.

A checkpoint transfer is the thing worth worrying about, and it is the case that
costs least.
