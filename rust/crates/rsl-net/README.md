# rsl-net

A **byte-exact, pure-Rust port of the RSL network framing** — the 20-byte
NetPacket header that wraps every replica-to-replica message, and the learn-port
framing used by the fetch/status sockets. It frames and parses identically to the
original C++ (`src/NetworkLib/src/NetPacket.cpp`, `src/NetworkLib/src/NetCxn.cpp`,
`Message::ReadFromSocket` in `src/RSL/src/message.cpp`), proven against
C++-generated golden vectors **and** against the real C++ code over a live TCP
socket.

- **No async runtime, no sockets in the API** — pure byte slices plus thin
  `std::io::Read` adapters, so Phase 4b/4c can pick their own I/O model and the
  tests stay deterministic.
- **Zero `unsafe`** (`unsafe_code = "forbid"`); the only dependency is
  [`rsl-wire`](../rsl-wire).

This is Phase 4a of the RSL Rust port: the byte-level kernel that the tokio
packet service (4b), the learn/fetch port (4c) and TLS (4d) build on.

## Layout

| Module | Ports |
| --- | --- |
| `framing::packet` | `PacketHdr` + `Packet::Serialize`/`DeSerialize` and the `NetCxn::ReadReadyInternal` receive decision table |
| `framing::learn` | `Message::ReadFromSocket` — the 6-byte version+length prefix that is the message's own header |
| `limits` | the `maxMessageSize` cap and alert threshold (`ConfigParam::Init`, `rslconfig.cpp:118`) |

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

## Correctness

`cargo test` runs five harnesses:

1. **`packet_corpus`** — the 30 `PACKET` vectors in
   `tools/golden-gen/corpus/phase1-golden.txt`. Each is a byte stream the *real
   C++ receive path was executed over*; the recorded outcome (`accept` /
   `need-more` / `reject-header` / `reject-checksum`), consumed byte count,
   payloads and reject wording must all match. Every accepted packet must also
   **re-encode byte-for-byte** to the frame the C++ produced.
2. **`learn_corpus`** — the 15 `LEARN` vectors, likewise executed through
   `Message::ReadFromSocket`'s decision table.
3. **`live_peer`** — spawns `golden-gen --packet-peer` (the extracted C++ over a
   real TCP socket) and talks to it: N packets out, validated and echoed back;
   a corrupt frame really does kill the connection; the learn port exchanges a
   request and a `StatusResponse`. Skips with a message if the binary has not
   been built.
4. **`proptest`** — round-trips, many packets per buffer, arbitrary truncation,
   arbitrary chunk boundaries, and the cap enforced on the announced size.
5. **`fuzz_smoke`** — random and corpus-mutated bytes never panic, anything
   accepted re-encodes to its own bytes, and a hostile size field allocates
   nothing.

### Deliberate divergences

Both are places where the original is unsafe; both are documented in the crate
rustdoc and pinned by tests:

- **Bounded reads.** The C++ sizes a buffer from the untrusted header before the
  bytes exist. Here the cap is checked first and the body is read in 64 KiB
  steps, so an announced-but-never-sent 100 MB frame costs one chunk.
- **Learn length below 6.** `ReadFromSocket` `malloc`s `length` bytes and
  `memcpy`s 6 into it — a heap overflow. This port returns
  `LearnError::LengthBelowHeader`; the corpus marks that vector `EXEC no`
  because no faithful C++ outcome exists to copy.

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
(`--release`); throughput is dominated by the Rabin-64 pass over the frame:

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
