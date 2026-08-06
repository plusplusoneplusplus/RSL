# rsl-net

The RSL network layer in pure Rust: the **framing** (Phase 4a), the **transport**
built on it (Phase 4b), the **learn port** a lagging replica catches up through
(Phase 4c), and **TLS** over both ports (Phase 4d).

- **`framing`** — a byte-exact port of the 20-byte NetPacket header that wraps
  every replica-to-replica message, and of the learn-port framing used by the
  fetch/status sockets. It frames and parses identically to the original C++
  (`src/NetworkLib/src/NetPacket.cpp`, `src/NetworkLib/src/NetCxn.cpp`,
  `Message::ReadFromSocket` in `src/RSL/src/message.cpp`), proven against
  C++-generated golden vectors **and** against the real C++ code over a live TCP
  socket. No async runtime, no sockets in the API.
- **`svc`** — `PacketSvc`, the tokio replacement for `NetPacketSvc` + `NetCxn` +
  the IOCP `NetProcessor`. Same statuses, same queue semantics, same
  suspend/resume, same connection identity — proven by a deterministic contract
  matrix and by talking to the C++ peer over real TCP.

- **`learnport`** — the state-transfer protocols: `StatusQuery`, `FetchVotes`
  and `FetchCheckpoint`, server and client. This is where the network layer
  meets the disk, so it is the one part of the crate that depends on
  [`rsl-storage`](../rsl-storage). Proven against the extracted C++
  (`golden-gen --learn-server` / `--learn-client`) in **both** directions.

- **`tls`** — mutual TLS on both ports, with the C++'s operator-facing trust
  model (SHA-1 thumbprint pins, subject + issuer-pin rules, an A/B pair for
  rotation) over rustls instead of SChannel. One config object gates the packet
  port and the learn port, in both directions. See [TLS.md](TLS.md) for the
  model, the eight deliberate divergences, the operational migration from the
  Windows certificate store, and the SChannel residual-risk note.

Zero `unsafe` (`unsafe_code = "forbid"`). The framing kernel's only dependency
is [`rsl-wire`](../rsl-wire); `default-features = false` drops tokio and leaves
just the bytes, `--no-default-features --features svc` keeps the transport
without pulling in the storage crate, and dropping `tls` drops rustls.

## Layout

| Module | Ports |
| --- | --- |
| `framing::packet` | `PacketHdr` + `Packet::Serialize`/`DeSerialize` and the `NetCxn::ReadReadyInternal` receive decision table |
| `framing::learn` | `Message::ReadFromSocket` — the 6-byte version+length prefix that is the message's own header |
| `limits` | the `maxMessageSize` cap and alert threshold (`ConfigParam::Init`, `rslconfig.cpp:118`) |
| `svc` | `NetPacketSvc` / `NetCxn`: connection lifecycle, send queue, timeouts, statuses, callbacks |
| `learnport::server` | `FetchServerLoop` / `HandleFetchRequest` and the three handlers, plus `SendFile` |
| `learnport::client` | `SendStatusRequestMessage`, `LearnVotes` (+ `ReadNextMessage`), `CopyCheckpoint` |
| `tls` | `SSLImpl.cpp`'s trust model + `NetSslCxn`'s "connected means authenticated", over rustls |

## Framing

### Packet frame

```text
offset  0   u32  size          total frame length, header included
        4   u32  protoVersion  always 0 (never assigned by RSL)
        8   u32  xid           always 0 (never assigned by RSL)
       12   u64  checksum      Rabin-64 over the whole frame, this field zeroed
       20   ..   payload       a marshaled rsl-wire message
```

`protoVersion`/`xid` are dead fields, but they are inside the checksum's domain,
so they must still be emitted and preserved.

Receive rules, copied from the C++ and not softened: a size below 20 or above the
cap, or a checksum mismatch, **closes the connection**. RSL never skips a bad
packet and resynchronizes. One read buffer may hold many packets, and
`framing::packet::Packets` drains them all.

### Two checksum domains

The packet checksum covers the *whole frame* with the checksum field zeroed; the
message checksum (in `rsl-wire`) covers the *message* after its own checksum
field. A frame can pass one and fail the other, and the packet layer never looks
inside the payload — the golden corpus pins both directions of that.

### The cap

`Limits::from_config_mb` reproduces `ConfigParam::Init` exactly: the MB value is
range-checked to `[1, INT_MAX]`, multiplied by 1 MiB, then given 1 KB of headroom
"for rsl message headers". The C++ does that arithmetic in a `UInt32` and
**wraps** — 4096 MB configures a 1 KB cap — which this port reproduces rather
than saturating, because a Rust node must agree with a C++ node configured the
same way.

## The transport

```rust
let client = PacketSvc::start_as_client(handler.clone(), SvcConfig::default());
let server = PacketSvc::start_as_server(port, handler, SvcConfig::default())?;

// A client always accepts: if there is no connection it makes one.
assert_eq!(
    client.send(Arc::new(Packet::to_server(peer, marshaled)), timeout),
    TxRxStatus::Success,
);
// ... and exactly one ProcessSend callback follows with the real outcome.
```

The engine runs one of each (`legislator.cpp:6374`), which is why requests
travel over the dialed connection and responses over the accepted one.

### The contract

- **Exactly one outcome per packet.** `send` returning `TxSuccess` promises
  exactly one `process_send` callback; `send` returning anything else promises
  none. A packet that leaks either way is how the engine's outstanding-send
  accounting wedges, so it is a proptest invariant, not a comment.
- **Statuses.** `TxSuccess` — the frame reached the socket. `TxTimedOut` — the
  per-packet deadline passed first (the frame may still be delivered; a write
  already in progress is allowed to finish, as the C++ duplicates the buffer
  and lets its I/O complete). `TxNoConnection` — no connection, and none
  coming. `TxAbort` — the service was stopped or the connection explicitly
  closed.
- **The client queue survives a disconnect.** Packets leave it only on success
  or on their own deadline; the connection reconnects and re-sends.
  `set_fail_packets_on_disconnect(true)` opts out.
- **One packet in flight**, strict FIFO per connection.
- **Duplicate accepts are refused** — a second connection from the same
  `(ip, port)` is dropped and the original kept.
- **Suspend stops consuming the socket.** Buffered bytes and half-decoded
  packets survive; new connections inherit the suspended state; sends are
  unaffected.
- **Callbacks never run on the caller's stack** — a dedicated thread drains one
  queue in order, so a handler may block (the C++ tolerates slow handlers and
  logs past `MAX_CALLBACK_DELAY`, which `PacketHandler::slow_callback`
  reproduces). No lock is ever held across a callback, which is why the C++'s
  try-lock-and-reschedule machinery (`TrySend` → `ScheduleSendRetry` →
  `m_SendRetryQ`) has no counterpart here.

### Shape

One task per connection owns the send queue; a reader task owns the read half
and a writer task the write half. Handing the writer whole frames — rather than
writing from the actor's `select!` — is what makes a deadline firing mid-write
safe: the packet is failed immediately while the frame on the wire still
completes, so the stream stays framed.

`Dialer` and `Link` keep the transport itself abstract: `TcpDialer` in
production, `tokio::io::duplex` in the contract tests, and rustls in Phase 4d —
the same seam the C++ uses to swap `NetCxn` for `NetSslCxn`.

## The learn port

A replica that has fallen behind catches up over a second TCP port — its
`rslLearnPort`, `rslPort + 1` by default. Three protocols share it, and all
three are one-shot: connect, write one request, read until the peer closes.

```rust
let client = LearnClient::new();                       // 5 s timeouts, as in C++
let who = Requester::new(ProtocolVersion::V6, my_member_id, configuration);

// 1. What does that replica have?
let status = client.query_status(peer, &who.status_query()).await?;

// 2. Catch up on decrees, record by record.
let mut votes = client.fetch_votes(peer, &who.fetch_votes(from_decree, ballot)).await?;
while let Some(msg) = votes.next().await? { apply(msg); }

// 3. Or, if we are too far behind, take its checkpoint whole.
let fetched = client.fetch_checkpoint(
    peer,
    &who.fetch_checkpoint(status.checkpointed_decree),
    status.checkpoint_size,      // learnt out of band — there is no length on the wire
    &data_dir,
).await?;                        // verified and durably renamed, or nothing at all
```

Serving is a `LearnServer` over a `LearnSource`; `DirSource` is the
directory-backed one, taking engine state (the status response and
`m_checkpointedDecree`) from a `StatusProvider` that Phase 5 will implement.

### Failure is silence

There is no error message on this wire, in either direction. A decree the server
does not have, a checkpoint decree that is not *its* checkpointed decree, a
primary that is relinquishing — every one of them closes the connection with
nothing written, and the client is expected to try another replica. So:

- The server never writes a diagnostic. `LearnSource` returning `None` **is** the
  refusal.
- The client turns a short or empty stream into `TransferError::Closed` /
  `Truncated`. Nothing else can be inferred.

The `FetchCheckpoint` client therefore has to be told the size in advance, from
a prior `StatusResponse::checkpoint_size`. That is why the parameter exists.

### Snapshot-at-open

`FetchVotes` streams a live log directory while the engine may be appending to
it. Both implementations serve a **snapshot**: the C++ takes the file size once,
in `APSEQREAD::DoInit` (`apdiskio.cpp:146`), and computes `length = FileSize() -
offset` from it (`legislator.cpp:4515`) — it never re-reads the size, so appends
made mid-response are not sent. `rsl_storage::log::LogSet` does the same, fixing
each file's readable length when the set is opened, and `DirSource` re-opens the
set per request.

The one difference: the C++ snapshots the raw file size, this snapshots the end
of the last *valid* record. They differ only for a file ending in a torn or
zeroed tail, which the C++ would stream to the peer as garbage for the peer to
reject; here the transfer simply ends on a record boundary. (`tests/learnport.rs`
executes the snapshot property; the C++ side is a code reading — `APSEQREAD` is
Windows-only and cannot be executed on Linux, so the golden-gen `SendFile` port
reproduces the same open-time `fstat` and the interop tests run against that.)

### Timeouts, and the stall budget

Every socket operation carries `LearnConfig::recv_timeout` / `send_timeout`
(5 s each, from `RSLConfig`'s `m_receiveTimeoutSec`/`m_sendTimeoutSec`,
`rsl.cpp:1365`). There is deliberately **no overall deadline** for a transfer: a
slow but alive peer streaming a multi-gigabyte checkpoint is legal, and only
prolonged silence is a failure.

That is an inherited weakness, not a design: a peer that dribbles one byte every
four seconds holds a transfer open forever. It is documented rather than
silently "fixed", because changing it would make this port abandon transfers the
original completes. A deployment that wants a hard bound should wrap the call in
its own timeout.

The practical figure is therefore a flat **5 s of silence, at any point** — not a
size-dependent budget. The benchmarks below say what a transfer costs when bytes
*are* moving, which is what decides whether a given size can finish on a link
that keeps stalling.

### Deliberate divergences

- **A checkpoint that fails verification is an error, not a crash.** The C++
  `LogAssert(false)`s — "terminating the process to prevent codex corruption"
  (`legislator.cpp:5573`). Here the temp file is deleted and
  `TransferError::Checkpoint` returned, so the caller can try another replica.
  Nothing corrupt is published either way.
- **The copied header is not re-marshaled by default.** The C++ always parses
  the incoming header, raises its `m_maxBallot` and writes the re-marshaled form
  (`legislator.cpp:5535`). `fetch_checkpoint` copies bytes verbatim, which keeps
  a fetched file bit-identical to its source (and makes the interop assertion
  possible); `fetch_checkpoint_with(.., Some(ballot))` is the C++ behaviour.
- **Exactly `expected_size` bytes are read.** The C++ loop can overshoot by up
  to one buffer if the peer sends more than it announced, and writes the excess
  to the file. Here the extra bytes are simply not read.
- **A task per connection** instead of a thread per request
  (`legislator.cpp:5325`). Invisible on the wire.

## Correctness

`cargo test` runs sixteen harnesses. Framing (Phase 4a):

1. **`packet_corpus`** — the 30 `PACKET` vectors in
   `tools/golden-gen/corpus/phase1-golden.txt`. Each is a byte stream the *real
   C++ receive path was executed over*; the recorded outcome (`accept` /
   `need-more` / `reject-header` / `reject-checksum`), consumed byte count,
   payloads and reject wording must all match. Every accepted packet must also
   **re-encode byte-for-byte** to the frame the C++ produced.
2. **`learn_corpus`** — the 15 `LEARN` vectors, likewise executed through
   `Message::ReadFromSocket`'s decision table.
3. **`live_peer`** — spawns `golden-gen --packet-peer` (the extracted C++ over a
   real TCP socket) and talks to it by hand: N packets out, validated and echoed
   back; a corrupt frame really does kill the connection; the learn port
   exchanges a request and a `StatusResponse`.
4. **`proptest`** — round-trips, many packets per buffer, arbitrary truncation,
   arbitrary chunk boundaries, and the cap enforced on the announced size.
5. **`fuzz_smoke`** — random and corpus-mutated bytes never panic, anything
   accepted re-encodes to its own bytes, and a hostile size field allocates
   nothing.

Transport (Phase 4b):

6. **`svc_contract`** — the behaviour matrix over `tokio::io::duplex` under
   `tokio::time::pause()`: queue across a reconnect, a deadline firing
   mid-disconnect and mid-write, duplicate accept, suspend holding a
   half-arrived packet, every status and who does *not* get a callback, `stop()`
   and `close_connection()` flushing `TxAbort`, a corrupt or oversize frame
   closing the connection. Reconnect backoffs and 30-second timeouts cost no
   wall-clock, so the whole file runs in milliseconds.
7. **`svc_exactly_once`** — proptest over random sequences of sends, peer
   deaths, dial failures, closes and clock advances, checking that every
   accepted packet is called back exactly once and no refused packet ever is.
8. **`svc_runtime`** — the guarantees that are about *where* code runs (no
   callback on the caller's thread, a blocking handler does not stall the
   service) plus a full request/response over loopback TCP.
9. **`svc_live_peer`** — a `PacketSvc` client against the C++ peer: a sustained
   24-packet exchange across four sizes, the peer dying mid-packet (a
   disconnect, not a framing error, and no half packet surfaced), and a frame
   the peer will happily send but this service is configured to refuse.

Learn port (Phase 4c):

10. **`learnport`** — the Rust server serving real `rsl-storage` files to the
    Rust client: every protocol, the snapshot property (records appended
    mid-response are not sent, the next request does see them), every silent
    refusal, and the torn-stream matrix — a response cut inside a record header
    and inside a record body, a bad record checksum ending the stream rather
    than resynchronizing, an all-zero page treated as corruption (`restore` is
    false here, unlike recovery), a server killed mid-checkpoint leaving no temp
    file, and the receive timeout firing on a silent peer.
11. **`learnport_interop`** — both directions against executed C++.
    `golden-gen --learn-server` serves a generated data directory and the Rust
    client's results are compared against reading those files directly through
    `rsl-storage`; `golden-gen --learn-client` runs the extracted
    `ReadNextMessage` and checkpoint-copy loops against the Rust server and its
    printed records are compared the same way. Includes the silent-close cases
    on both sides, and a Rust server killed mid-stream where the C++ client's
    behaviour is *recorded from the run* (it reports an incomplete checkpoint
    and deletes its partial file).
12. **`learnport_proptest`** — `fetch_votes` over generated multi-file log sets,
    requesting every decree in turn and checking the response against the files;
    the boundary set spelled out (offset in the first, middle and last file, a
    decree exactly at a file boundary, an empty trailing log, a re-voted decree
    where the index points at the *later* record); and `fetch_checkpoint` across
    page and checksum-block boundaries, plus streaming chunk sizes from 512 B to
    twice the file size.

TLS (Phase 4d):

13. **`tls_rules`** — the acceptance-rule matrix, every case a real mutual
    handshake over loopback rather than a direct call into the verifier:
    thumbprint hit in slot A and in slot B, a certificate from the right CA with
    no matching pin, subject+parent hit in each slot, each partial miss (right
    subject wrong parent, right parent wrong subject, wrong case), a bare leaf
    with no issuer presented, expired × each chain toggle, an untrusted CA, a
    revoked certificate and one no CRL covers, wrong EKU in each direction, no
    EKU extension at all, mutual-auth enforcement in *both* directions, and a
    client that presents no certificate.
14. **`tls_ports`** — the wiring: a packet moving over TLS, a status query over
    the same config, a plaintext client refused by each port, four packets
    queued before the handshake and all four delivered afterwards in order,
    `Connected` never firing for a peer we refuse, and a full A/B rotation
    performed on a live fleet (old connections undisturbed, new ones on the new
    config, and the mixed window in the middle).
15. **`tls_names`** — vectors for the subject display name: CN wins, OU then O
    as fallbacks, no name at all, the 255-character truncation, "this is not a
    DN" stated as an assertion, both EKU roles, the two Server Gated Crypto
    OIDs, and a repeated CN taking the most specific.
16. **`tls_interop`** — `golden-gen --tls-peer` / `--tls-client`: the real C++
    packet framing over **OpenSSL**, mutual auth, TLS 1.2, in both directions.
    A proxy oracle for SChannel, which cannot run here — and it has already
    caught a real bug (a malformed `certificate_authorities` hint that two
    rustls peers ignore and OpenSSL rejects). See [TLS.md](TLS.md) for what it
    does *not* prove and the Windows checklist that closes it.

### Deliberate divergences

Two in the framing, all of them places where the original is unsafe:

- **Bounded reads.** The C++ sizes a buffer from the untrusted header before the
  bytes exist. Here the cap is checked first and the body is read in bounded
  steps, so an announced-but-never-sent 100 MB frame costs one chunk.
- **Learn length below 6.** `ReadFromSocket` `malloc`s `length` bytes and
  `memcpy`s 6 into it — a heap overflow. This port returns
  `LearnError::LengthBelowHeader`; the corpus marks that vector `EXEC no`
  because no faithful C++ outcome exists to copy.

And five in the transport, none of them observable on the wire:

- **Reconnect backoff.** `NetCxn::CONNECT_RETRY_TIME` is a flat 20 ms, so a
  replica that is down is retried 50 times a second by every peer for as long as
  it stays down. Nothing carries or depends on the retry interval, so this port
  backs off exponentially with jitter (`BackoffConfig`), still starting at
  20 ms.
- **Timeouts are exact.** The C++ sweeps a sorted queue every 20 ms and can fail
  a packet that late; each packet here has its own deadline.
- **`ProcessConnect(Connecting)` is not on the caller's stack.** The C++
  documents that it may be; every callback here goes through the callback
  thread.
- **A packet handed to a closing connection is failed by callback**, not by
  `send`'s return value. The C++ resolves that race with a lock and can go
  either way (`NetPacketSvc.h:252-266`); both outcomes are legal there.
- **`send_on_existing` is strict** — "existing" means connected, where the C++
  also accepts a connection that is about to reconnect. The engine never uses
  the flag.

TLS has eight of its own, including two that are security-relevant (the learn
port is encrypted under the same switch as the packet port; the EKU roles are
the right way round). They are listed with their `SSLImpl.cpp` line numbers in
[TLS.md](TLS.md).

## Fuzzing

```sh
cargo install cargo-fuzz
cd rust/crates/rsl-net
cargo +nightly fuzz run packet_decode   # or: learn_decode
```

The `fuzz/` crate is detached from the workspace (nightly + libfuzzer), so a
plain stable build skips it; `fuzz_smoke` is the always-on floor, plus a bounded
`cargo fuzz` smoke step per target in CI. Generated corpora are not checked in.

## Benchmarks

`cargo bench -p rsl-net`. Indicative numbers from a local dev machine
(`--release`).

Framing — throughput is dominated by the Rabin-64 pass over the frame:

| Benchmark | Time | Throughput |
| --- | --- | --- |
| `packet/encode` / 0 B payload | ~30 ns | ~0.6 GiB/s |
| `packet/encode` / 1 KiB | ~0.65 µs | ~1.5 GiB/s |
| `packet/encode` / 1 MiB | ~628 µs | ~1.55 GiB/s |
| `packet/decode` / 0 B payload | ~10.6 ns | ~1.75 GiB/s |
| `packet/decode` / 1 KiB | ~0.60 µs | ~1.63 GiB/s |
| `packet/decode` / 1 MiB | ~600 µs | ~1.6 GiB/s |
| `packet/decode_stream` (64 × 512 B) | ~21 µs | ~1.5 GiB/s |
| `learn/parse_header` | ~0.5 ns | — |

Decoding is faster than encoding because verification chains the fingerprint
across the frame's three regions instead of copying it to zero the checksum
field; encoding still allocates the frame.

Transport — loopback TCP round trips (send + echo back), against a `PacketSvc`
echo server and against `golden-gen --packet-peer echo`. Throughput counts both
directions:

| Benchmark | Payload | Rust peer | C++ peer |
| --- | --- | --- | --- |
| `svc/round_trip` | 1 KiB | ~80 µs | ~95 µs |
| `svc/round_trip` | 100 KiB | ~417 µs (468 MiB/s) | ~576 µs (339 MiB/s) |
| `svc/round_trip` | 10 MiB | ~36.7 ms (544 MiB/s) | ~47.8 ms (419 MiB/s) |
| `svc/throughput` | 100 KiB × 160 | ~29.9 ms (1.04 GiB/s) | ~57.6 ms (552 MiB/s) |
| `svc/throughput` | 10 MiB × 1 | ~30.9 ms (648 MiB/s) | ~47.0 ms (425 MiB/s) |

Learn port — full transfers over loopback TCP, server and client in-process.
`fetch_checkpoint` includes verification (the whole file is re-read and
re-checksummed) and the durable rename, because a real fetch pays for both:

| Benchmark | Size | Time | Throughput |
| --- | --- | --- | --- |
| `fetch_votes` | 4096 votes, no requests (2 MiB) | ~12.2 ms | ~164 MiB/s |
| `fetch_votes` | 2048 votes × 700 B (2 MiB) | ~13.5 ms | ~148 MiB/s |
| `fetch_votes` | 256 votes × 64 KiB (16 MiB) | ~64.4 ms | ~250 MiB/s |
| `fetch_checkpoint` | 1 MiB state | ~22.8 ms | ~44 MiB/s |
| `fetch_checkpoint` | 8 MiB state | ~68.7 ms | ~116 MiB/s |
| `fetch_checkpoint` | 32 MiB state | ~380 ms | ~84 MiB/s |

Against the 5-second inactivity window, none of these is close: a 32 MiB
checkpoint moves in under half a second, so the window is spent entirely on
*silence*, never on work in progress. Small-record vote streams are the slower
case per byte — a 512-byte page read, a header parse and a Rabin-64 per record —
so a catch-up over many small decrees is bounded by record count, not bytes. The
checkpoint numbers include an `fsync` and a directory `fsync` per transfer,
which is why the 1 MiB case looks slow per byte and why the variance is wide.

TLS — the same round trip with and without the record layer, plus a full mutual
handshake:

| Benchmark | Payload | Plaintext | TLS |
| --- | --- | --- | --- |
| `tls/round_trip` | 1 KiB | ~87.9 µs | ~100 µs (+14 %) |
| `tls/round_trip` | 100 KiB | ~426 µs (458 MiB/s) | ~582 µs (336 MiB/s) |
| `tls/round_trip` | 10 MiB | ~36.5 ms (549 MiB/s) | ~39.8 ms (503 MiB/s) |
| `tls/handshake` | — | — | ~1.80 ms |

The handshake is two chain verifications and an ECDHE exchange, paid once per
connection — which means once per *reconnect*, so Phase 4b's backoff is what
bounds it. The record layer costs most in relative terms at 100 KiB, where a
payload is several TLS records but per-record overhead has not amortized, and
least at checkpoint sizes, which is the case worth worrying about.

Round-trip latency at 1 KiB is loopback and scheduling, not framing — the frame
itself costs well under a microsecond. The C++ peer is slower because it is a
single-threaded blocking loop that copies each payload into a fresh frame; it is
here as a correctness oracle that also happens to bound the port's cost, not as
a tuned implementation.

## TLS

`TLS.md` has the whole story. The short version:

```rust
let tls = Tls::new(TlsConfig {
    identity: Identity::from_pem_files("replica.pem", "replica.key")?,
    thumbprint_a: Some("1b32891adb56d3f7115e7e031cc41e1793252015".parse()?),
    roots: vec![root_ca_der],
    ..TlsConfig::default()
})?;

let client = PacketSvc::start_as_client_with(tls.dialer(bind_ip), handler, cfg);
let server = PacketSvc::start_as_server_with(port, tls.acceptor(), handler, cfg)?;
let learn  = LearnServer::bind_with(addr, tls.connector(), source, cfg).await?;
```

`Connected` fires only after the handshake and the certificate check, as it does
in the C++; packets sent before then wait in the send queue and go out
afterwards. `Tls::swap` rotates the configuration without disturbing live
connections.

TLS never appears inside `framing` or `svc` — an encrypted connection reaches
the transport as a `Link` like any other, which is the same seam the C++ uses
when it swaps `NetCxn` for `NetSslCxn`.

Costs, loopback: ~1.8 ms for a full mutual handshake; +14 % round-trip time at
1 KiB, +27 % at 100 KiB, +9 % at 10 MiB. Checkpoint-sized transfers — the thing
worth worrying about — are the case that costs least.

## Example

```rust
use rsl_net::framing::packet::{self, Step};
use rsl_net::Limits;

let limits = Limits::from_config_mb(100, 0).unwrap();
let frame = packet::encode_packet(&marshaled_message);

// A read buffer may hold several packets, or part of one.
let mut packets = packet::Packets::new(&read_buffer, limits);
for item in packets.by_ref() {
    match item {
        Ok((hdr, payload)) => handle(payload),
        Err(e) => return close_connection(e), // never resynchronize
    }
}
let leftover = packets.remainder(); // keep for the next read
```
