# golden-gen — portable extracted interoperability proxy

This Linux-only tool builds an extracted subset of RSL and emits portable
reference vectors for the Rust implementation. It is useful for fast Ubuntu
coverage, but it is not the authoritative C++ oracle for storage, networking,
learning, or TLS. The authoritative process is the Windows production oracle
in [`tools/windows-oracle`](../windows-oracle/README.md).

It is the concrete implementation of
`notes/Plans/rsl-rust-port/01-phase1-minimal-cpp-reference.plan.md`.

## What it compiles

Wire marshaling and fingerprinting compile production translation units.
Storage, packet receive, and learn-port behavior use copied or ported subsets
with blocking POSIX I/O rather than the shipping Windows engine:

| Source | Role |
| --- | --- |
| `src/common/src/msn_fprint.cpp` | Rabin-64 fingerprint (poly `0xa795d0f29b4dcdf8`) |
| `src/common/src/marshal.cpp` | `MarshalData` reader/writer (little-endian) |
| `src/common/src/fingerprint.cpp` | `FingerPrint64` wrapper + singleton |
| `src/common/src/utils.cpp` | `Utils::CalculateChecksum` |
| `src/RSL/src/message.cpp` | production message implementations |
| `tools/golden-gen/src/engine_min.cpp` | `MemberSet` / `RSLNodeCollection` / `RSLNode` — copied **verbatim** from `rsl.cpp` (message.cpp references them) |
| `tools/golden-gen/src/packet_min.cpp` | copied packet types and a ported receive decision table |
| `tools/golden-gen/src/learn_min.cpp` | ported learn-server and learn-client behavior |
| `tools/golden-gen/src/tls_peer.cpp` | the packet peer over TLS 1.2 via OpenSSL — a proxy oracle for SChannel (Phase 4d, optional: needs libssl-dev) |
| `tools/golden-gen/src/main.cpp` | the generator driver |

## How the Windows build stays untouched

Every Linux-only change is guarded by `#ifndef _WIN32` in the shared headers, or
lives entirely under `compat/`. The MSBuild build never sees any of it.

### `compat/` shims (Linux-only, on the include path)

| Shim | Replaces / provides |
| --- | --- |
| `windows.h` | Win32 type surface (LP64-correct: `DWORD == uint32_t`), `Interlocked*`→`__atomic_*`, `VirtualAlloc/Free`→`calloc/free`, critical-section/`SYSTEMTIME` stubs. Pre-includes the libstdc++ headers that use `__in`/`__out` as parameter names before defining the SAL macros. |
| `Winsock2.h`, `mswsock.h` | empty stubs (pulled in by `basic_types.h`) |
| `strsafe.h` | `StringC{b,ch}*` used by the slice; translates MSVC `%I64u`/`%I32d` width specifiers; zero-fills fixed-size copies for canonical member-id padding |
| `pal_logging.h` | logging stub — asserts `abort()`, `RSL{Error,Info,…}` print to stderr, `LogTag_*` enum. (The real `logging.cpp` — SEH/minidump — is deliberately not ported.) |
| `netpacket_min.h` | just the `IMarshalMemoryManager` base class that `marshal.h` derives from |
| `msg_engine_compat.h` | the `MemberSet` declaration + page-rounding helpers that `message.cpp` uses from `legislator.h`, without dragging in the engine |
| `storage_compat.h` | Linux prerequisites for the **shared** `RSL/src/checkpoint.h` (checkpoint types) + `CHECKSUM_SIZE`; declares nothing itself |
| `msvc_builtins.h` | `__int8..__int64` keyword spellings, force-included into every TU |

### Guarded edits to shared headers/sources

- `common/src/marshal.h` — `#include "netpacket.h"` → `<netpacket_min.h>` on Linux
- `common/src/logging.h` — Windows body → `<pal_logging.h>` stub on Linux
- `common/src/basic_types.h` — `FAInt64(DWORD,DWORD)` ctor Windows-only (collides with `(UInt32,UInt32)` on LP64)
- `common/src/constants.h` — `Ui64` literal suffixes → `ULL` on Linux
- `common/src/List.h` — `using DLL<C>::head/link;` in `Queue<C>` (standard two-phase lookup; MSVC was lax)
- `common/src/LogAssert.h` — `<crtdbg.h>` + the `LogAssert` macro are `#ifdef _WIN32` on Linux (the macro already comes from `pal_logging.h`); lets `DynamicBuffer.h` compile in the slice (Phase 3a)
- `RSL/src/legislator.h` — `ConfigurationInfo`/`CheckpointHeader`/`s_ChecksumBlockSize` moved verbatim into the new shared `RSL/src/checkpoint.h`, which `legislator.h` includes at the same point (after `MemberSet`, which they depend on). The symbols `legislator.h` exposes are unchanged, so every existing consumer is unaffected (Phase 3a)
- `RSL/src/message.h` — `list.h`→`List.h`, `streamio.h`→`StreamSocket` fwd decl + `HiResTime.h` on Linux
- `RSL/src/message.cpp` — Linux include block; `Message::ReadFromSocket` (needs a socket) is `#ifdef _WIN32`

None of these change behaviour on Windows.

## Build & run

```sh
cd tools/golden-gen
cmake -S . -B build
cmake --build build -j
./build/golden-gen > corpus/phase1-golden.txt
```

Output is deterministic (member-id fields are zero-padded to their canonical
wire form), so re-running reproduces `corpus/phase1-golden.txt` byte-for-byte.

## Corpus format

Line-oriented, blank-line-separated records:

```
RECORD
TYPE <class>            # Message / Vote / JoinMessage / ...
DESC <human text>
VERSION <1..6>
LEN <bytes>
CHECKSUM <16 hex>       # Rabin-64 over bytes after the 8-byte checksum field
BYTES <hex>             # the full marshaled message, checksum field patched in
FIELDS <json>           # constructor params (see below)

FPRINT                  # raw Rabin-64 vectors for the fingerprint itself
DESC <text>
LEN <bytes>
INPUT <hex>
CHECKSUM <16 hex>

CONTAINER               # raw MarshalData StartContainer/CloseContainer vectors
DESC <scenario name>    # rebuilt by name in the Rust tests/containers.rs
LEN <bytes>
BYTES <hex>             # no checksum: raw MarshalData output, not a message

PACKET                  # 20-byte NetPacket framing (Phase 4a)
DESC <text>
MAXSIZE <u32>           # PacketFactory's m_MaxPacketSize (0 = NetPacket.h default)
MAXALERT <u32>          # m_MaxPacketAlertSize (0 = no alert)
LEN <bytes>
BYTES <hex>             # the byte stream fed to the C++ receive path
OUTCOME <accept|need-more|reject-header|reject-checksum>
CONSUMED <bytes>        # covered by the accepted packets
PAYLOADS <count>
PAYLOAD <hex>           # one line per accepted packet, in order
DETAIL <text>           # the C++'s own reject wording (or an alert note)

LEARN                   # learn-port framing: Message::ReadFromSocket (Phase 4a)
DESC <text>
MAXSIZE <u32>           # RSLConfig::MaxMessageSize()
LEN <bytes>
BYTES <hex>             # the byte stream fed to the reader
EXEC <yes|no>           # no = the original is unsafe here; see below
OUTCOME <accept|reject-short-header|reject-version|reject-too-large|reject-short-body|reject-unmarshal>
VERSION <u16>           # as parsed from the 6-byte header (0 if not reached)
MSGLEN <u32>            # ditto
DETAIL <text>
```

`CONTAINER` blocks (Phase-2 gap closure) pin down the container back-patch
rule — a caller-chosen 1-byte or 4-byte length field, zero-reserved by
`StartContainer` and filled in by `CloseContainer` — which no message-level
record exercises until checkpoint headers arrive in Phase 3. New block kinds
are always appended after the existing output so RECORD/FPRINT bytes never
move.

**Bootstrap appears only at v4–v6.** That is deliberate, not a coverage hole:
`Message_Bootstrap` was introduced with protocol version 4, so no v1–v3
vector can exist.

### `FIELDS` — machine-readable constructor parameters

Each `RECORD` carries a `FIELDS` line: a JSON object describing the exact
parameters the message was built from (member id, decree, ballot, per-subtype
payloads, nested member sets / votes, …). 64-bit integers are `"0x…"` hex
strings, byte blobs (cookies, requests, member-set cookie) are hex strings, and
`memberId`/`hostName` are plain strings.

This exists so a re-implementation can **independently construct** each message
from the fields and check that its marshaling reproduces `BYTES` — a stronger
check than round-tripping `BYTES` alone, which a reader bug mirrored by a writer
bug could pass. The Rust port's `tests/fields.rs` does exactly this. Adding
`FIELDS` does not change `BYTES`/`CHECKSUM`; the marshaled bytes are unaffected.

### Phase 4a: `PACKET` / `LEARN` and the live peer

Both block kinds run the proxy receive implementation over the emitted bytes.
They do not exercise production IOCP, Winsock, or `NetCxn`. `PACKET` payloads are
production-marshaled corpus
messages (one per message type, at the highest version that emits it) plus a few
synthetic edge cases, and the negatives cover an empty/short buffer, every
out-of-range size, both checksum domains — including a frame whose *inner*
message checksum is valid while the outer one is not, and the reverse — and a
good packet followed by a corrupt one (the first is still delivered, then the
connection dies).

`EXEC no` appears on exactly one `LEARN` vector: a length below the 6-byte
framing header. `ReadFromSocket` `malloc`s `length` bytes and then `memcpy`s 6
into it (`message.cpp:672-674`), so the original overflows its allocation and has
no outcome worth copying; `packet_min.cpp` refuses the length instead, and the
Rust port pins that same behaviour.

Note also that `ReadFromSocket` **never verifies the message checksum** — it only
unmarshals. The corpus records a wrong-checksum message as `accept` for that
reason.

```sh
# The live interop peer: single connection, blocking, Linux-only. Not part of
# corpus regeneration; the Rust tests spawn it on demand.
./build/golden-gen --packet-peer 0 --mode echo        # NetPacket framing, echoes
./build/golden-gen --packet-peer 0 --mode log         # NetPacket framing, reports only
./build/golden-gen --packet-peer 0 --mode fetch-stub  # learn port: reads one
                                                      # Message, replies with a
                                                      # StatusResponse
```

Port `0` picks an ephemeral port; the peer prints `PORT <n>` on stdout and
flushes it before accepting, so a harness never has to race on a fixed port.

### Phase 4c: the live learn port (`--learn-server` / `--learn-client`)

`learn_min.cpp` is a ported state-transfer proxy. It is useful for exercising
both directions over a socket, but it does not execute the shipping Windows
learn server/client or their asynchronous I/O.

```sh
# C++ serves a data directory; a Rust client fetches from it.
./build/golden-gen --learn-server 0 --dir /path/to/data --connections 3

# C++ fetches from a Rust server (or from another --learn-server).
./build/golden-gen --learn-client 127.0.0.1 <port> --mode status
./build/golden-gen --learn-client 127.0.0.1 <port> --mode votes --decree 101
./build/golden-gen --learn-client 127.0.0.1 <port> --mode checkpoint \
    --decree 500 --size <bytes> --out copy.codex
```

The server prints `PORT <n>` before accepting, like `--packet-peer`. It handles
`--connections` requests one after another and exits; each protocol is one-shot
(one request, one stream, close), so a test needs one connection per request.

The client prints machine-readable lines — `STATUS ...`, one `VOTE ...` per
record then `VOTES <n>`, or `CHECKPOINT size=.. fp64=.. outcome=..` — and
`ERROR <detail>` on any failure. A server that refuses a request closes without
writing anything, which the client reports as `ERROR closed`: that is the whole
error protocol in both implementations.

Engine state the handlers would read under `m_lock` is derived from the
directory instead: the newest `<decree>.codex` is `m_checkpointedDecree`, and
each log's decree index is rebuilt by re-running `rsl_storage::ScanLog` (itself
the verbatim `ReadNextMessage` recovery loop) over the file, which is what
`LogFile::AddMessage` builds at startup anyway. `SendFile` keeps the original's
snapshot semantics exactly: the file size is taken once, when the file is
opened, so appends made mid-response are never sent.

One deliberate deviation, commented at the site: the C++ `CopyCheckpoint`
re-marshals the incoming header with a raised `m_maxBallot` before writing it.
That is engine state rather than protocol, and it would make a copy differ from
its source, so this oracle copies verbatim — as the Rust client does by default,
with the rewrite available explicitly.

### Phase 4d: the TLS interop oracle (`--tls-peer` / `--tls-client`)

`tls_peer.cpp` is the same packet peer over **TLS 1.2, via OpenSSL**, with
mutual authentication. It is a *proxy* oracle and the proxy is the point: the
real C++ RSL speaks TLS through SChannel, which cannot run on Linux, so what
this establishes is that the Rust port interoperates with a TLS stack that is
not rustls — version, cipher suite, chain encoding, client-certificate exchange.
It has already caught one real bug (a malformed `certificate_authorities` hint
that rustls peers ignore and OpenSSL rejects).

Built only when CMake finds OpenSSL (`apt install libssl-dev`); without it the
two modes exit 3 and say so, and the Rust tests skip themselves.

```sh
# C++/OpenSSL server, Rust client.
./build/golden-gen --tls-peer 0 --cert leaf+chain.pem --key leaf.key     --ca root.pem --mode echo

# C++/OpenSSL client, Rust server.
./build/golden-gen --tls-client 127.0.0.1 <port> --cert leaf+chain.pem     --key leaf.key --ca root.pem --payload "hello" --count 1
```

The server prints `PORT <n>` like `--packet-peer`; the client prints
`ECHOED <n>` and exits 0 only when every packet it sent came back. The cipher
list is pinned to the same four AES-GCM suites the Rust port offers — the
intersection of rustls' TLS 1.2 suites with SChannel's `SCH_USE_STRONG_CRYPTO`
defaults — written out in OpenSSL's spelling so the pin is checkable from both
sides. Certificates are generated by the Rust test fixture
(`rust/crates/rsl-net/tests/certs/mod.rs`) and written to a temp directory; none
are checked in.

What this does **not** prove, and the Windows checklist that closes it, are in
[`rust/crates/rsl-net/TLS.md`](../../rust/crates/rsl-net/TLS.md).

`FPRINT empty` is `a795d0f29b4dcdf8` — equal to the polynomial, the documented
fingerprint of the empty string, a quick correctness check for the Rabin-64
port.

## Portable storage proxy (`--storage` / `--verify-storage`)

The storage corpus covers `.log`, `.codex`, and `defunct.txt` layouts on
Ubuntu. It is generated and verified by `storage_min.cpp`, a port of selected
format-bearing code to in-memory byte buffers. It is not production storage I/O
and its recovery outcomes are proxy results.

The checkpoint **type declarations** are not copied at all — `ConfigurationInfo`
and `CheckpointHeader` live in `RSL/src/checkpoint.h`, which both
`legislator.h` and this tool's `compat/storage_compat.h` include, so the `.codex`
layout has a single definition and cannot drift between the two builds. Only
`CheckpointHeader`'s Windows-only I/O entry points (`Marshal(const char*)`,
`UnMarshal(const char*)`, `UnMarshal(StreamReader*)`, `SetBytesIssued`,
`GetCheckpointFileName`) are `#ifdef _WIN32` — they take engine-only types and
carry no format information. Every data member and marshaling method is shared.

The proxy consists of:

| Source | Extracted into |
| --- | --- |
| `ConfigurationInfo` + `CheckpointHeader` marshal/unmarshal (`legislator.cpp`) | `src/storage_min.cpp` (copied, line-cited) |
| Log record padding + `Legislator::ReadNextMessage` recovery scan | `src/storage_min.cpp` (`rsl_storage::EncodeLogRecord` / `ScanLog`) |
| `RSLCheckpointStreamWriter`/`Reader` 4 MiB block + trailing Rabin-64 (`rsl.cpp`) | `src/storage_min.cpp` (`BuildCheckpointFile` / `VerifyCheckpointFile`) |
| `Read`/`UpdateDefunctFile` (`legislator.cpp`) | `src/storage_min.cpp` (`EncodeDefunct` / `DecodeDefunct`) |

The helpers replace `WriteFileGather`, `APSEQREAD`, and `APSEQWRITE` with
in-memory buffers and zero-fill padding for deterministic Ubuntu output. The
Windows oracle is required for claims about literal production files and
recovery decisions.

```sh
./build/golden-gen --storage        corpus/storage   # generate corpus + MANIFEST
./build/golden-gen --verify-storage  corpus/storage   # reverse: read a dir, report
```

`--verify-storage` exits `0` when every file is accepted or reaches a tolerated
recovery stop, `3` when any file is rejected, and `1` for I/O failure. The
generated corpus contains negative vectors, so verifying the whole corpus
normally exits `3`.

### Corpus layout (`corpus/storage/`)

`MANIFEST.json` records size, whole-file `fp64`, and the proxy recovery outcome
(`accept`, `stop-at-offset`, or `reject`) for every generated sample.
Log entries also carry the recovered record list; checkpoint entries carry
version / header length / recovered user-data size.

Samples: empty / single / multi-record logs, one per protocol version, plus the
recovery edge cases (`torn-tail`, `zero-tail` → stop; `corrupt-checksum`,
`unknown-msgid` → reject; `garbage-pad` → accept); checkpoints per version and at
the 4 MiB block boundaries (`cp-4mib`, `cp-4mib-plus1`, `cp-multiblock`) plus
`cp-corrupt-block` / `cp-truncated` → reject; and `defunct.txt` values.

### What is committed

**Only `MANIFEST.json`.** The sample files are generated test data, not source —
the same call made for the `rsl-wire` fuzz corpus — so they are gitignored and
regenerated by `--storage`. This keeps ~17 MB of binaries (the 4 MiB checkpoints
dominate) out of the repo.

That loses nothing, because the MANIFEST records an `fp64` (Rabin-64 of the whole
file) for every sample, computed from the files as they are written. Diffing the
MANIFEST byte-for-byte therefore proves each regenerated file is byte-identical
to what was recorded — the hash-compare the plan allows in place of checking the
binaries in. Large checkpoints additionally record `statePattern:"ramp"` +
`stateLen`, so their user state is reproducible from the manifest alone.

Portable Rust tests can run `--storage` into a scratch directory and compare the
manifest. These tests complement rather than replace Windows mixed-language
tests.

## Not covered (see the plan)

- **v1/v2 checkpoints** — those predate the `CheckpointHeader` (they are a bare
  page-rounded vote); the checkpoint corpus starts at v3 where the header format
  exists, analogous to `Message_Bootstrap` only existing at v4+.
