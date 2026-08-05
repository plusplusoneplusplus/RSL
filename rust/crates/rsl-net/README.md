# rsl-net

The RSL network layer in pure Rust: the **framing** (Phase 4a) and the
**transport** built on it (Phase 4b).

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

Zero `unsafe` (`unsafe_code = "forbid"`). The framing kernel's only dependency
is [`rsl-wire`](../rsl-wire); `default-features = false` drops tokio and leaves
just the bytes.

## Layout

| Module | Ports |
| --- | --- |
| `framing::packet` | `PacketHdr` + `Packet::Serialize`/`DeSerialize` and the `NetCxn::ReadReadyInternal` receive decision table |
| `framing::learn` | `Message::ReadFromSocket` — the 6-byte version+length prefix that is the message's own header |
| `limits` | the `maxMessageSize` cap and alert threshold (`ConfigParam::Init`, `rslconfig.cpp:118`) |
| `svc` | `NetPacketSvc` / `NetCxn`: connection lifecycle, send queue, timeouts, statuses, callbacks |

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

## Correctness

`cargo test` runs nine harnesses. Framing (Phase 4a):

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

Round-trip latency at 1 KiB is loopback and scheduling, not framing — the frame
itself costs well under a microsecond. The C++ peer is slower because it is a
single-threaded blocking loop that copies each payload into a fresh frame; it is
here as a correctness oracle that also happens to bound the port's cost, not as
a tuned implementation.

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
