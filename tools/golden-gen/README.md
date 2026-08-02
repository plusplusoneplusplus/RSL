# golden-gen — Phase-1 golden-vector generator

This tool builds the **minimum slice** of the original RSL C++ that runs on
Linux and emits byte-exact reference vectors (marshaled bytes + Rabin-64
checksums, for every message type across every protocol version) for the
pure-Rust port to check against.

It is the concrete implementation of
`notes/Plans/rsl-rust-port/01-phase1-minimal-cpp-reference.plan.md`.

## What it compiles

Only what the marshaling / fingerprint / message code actually needs — no
threading, file-I/O, networking, or logging engine:

| Source | Role |
| --- | --- |
| `src/common/src/msn_fprint.cpp` | Rabin-64 fingerprint (poly `0xa795d0f29b4dcdf8`) |
| `src/common/src/marshal.cpp` | `MarshalData` reader/writer (little-endian) |
| `src/common/src/fingerprint.cpp` | `FingerPrint64` wrapper + singleton |
| `src/common/src/utils.cpp` | `Utils::CalculateChecksum` |
| `src/RSL/src/message.cpp` | all message types × versions |
| `tools/golden-gen/src/engine_min.cpp` | `MemberSet` / `RSLNodeCollection` / `RSLNode` — copied **verbatim** from `rsl.cpp` (message.cpp references them) |
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
| `msvc_builtins.h` | `__int8..__int64` keyword spellings, force-included into every TU |

### Guarded edits to shared headers/sources

- `common/src/marshal.h` — `#include "netpacket.h"` → `<netpacket_min.h>` on Linux
- `common/src/logging.h` — Windows body → `<pal_logging.h>` stub on Linux
- `common/src/basic_types.h` — `FAInt64(DWORD,DWORD)` ctor Windows-only (collides with `(UInt32,UInt32)` on LP64)
- `common/src/constants.h` — `Ui64` literal suffixes → `ULL` on Linux
- `common/src/List.h` — `using DLL<C>::head/link;` in `Queue<C>` (standard two-phase lookup; MSVC was lax)
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
```

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

`FPRINT empty` is `a795d0f29b4dcdf8` — equal to the polynomial, the documented
fingerprint of the empty string, a quick correctness check for the Rabin-64
port.

## Not covered (see the plan)

- **Log-file page layout** (512-byte alignment/batching) and **checkpoint
  files** — their `LogFile`/`CheckpointHeader` containers live in
  `legislator.cpp` and would pull in the whole engine. Their *payloads*
  (marshaled Votes/headers) are covered here.
- **Wire-level packet framing** (20-byte NetPacket header) — generate from the
  spec + this checksum tool, or capture from a Windows loopback run.
