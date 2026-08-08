# RSL Windows production oracle

`RSLWindowsOracle` is the authoritative C++ interoperability process for wire
and storage behavior. It links `RSLib.lib`, which contains the shipping common,
RSL, and network libraries, and runs only on Windows.

Fixture construction and JSON/text reporting live in this tool. Message
marshaling, Rabin-64 checksums, log writes, checkpoint writes, log recovery,
checkpoint parsing, and storage verdicts run through production code. The
internal `RSLInteropTestFacade` exposes those paths without copying protocol or
recovery decisions.

## Build

```powershell
.\tools\windows-oracle\build.ps1 -Configuration Debug
.\tools\windows-oracle\build.ps1 -Configuration Release
```

The script prints the executable path after a successful build.

## Commands

```powershell
RSLWindowsOracle.exe --identity
RSLWindowsOracle.exe --self-test
RSLWindowsOracle.exe --wire <wire.txt>
RSLWindowsOracle.exe --storage <directory>
RSLWindowsOracle.exe --verify-storage <directory>
```

`--wire` emits line-oriented message, fingerprint, and `MarshalData` container
vectors. `--storage` writes logs and checkpoints with production Windows I/O,
then creates negative vectors by mutating or truncating those files externally
before passing them to the production readers.

`--verify-storage` emits one JSON object per file. It exits `0` when every file
is accepted or reaches a production-tolerated recovery stop, `3` when any file
is rejected, and `2` for invocation or I/O errors. A reported rejection is
therefore never success-shaped.

Production packet endpoints use `Packet`, `NetCxn`, `NetPacketSvc`, callbacks,
connection tables, and the shipping IOCP threads:

```powershell
RSLWindowsOracle.exe --net-server 0 --mode echo --count 3
RSLWindowsOracle.exe --net-client 127.0.0.1 <port> --payload 001122 --count 3
```

Production learn endpoints share request dispatch, log/checkpoint file transfer,
message parsing, and checkpoint copy/max-ballot rewriting with `Legislator`:

```powershell
RSLWindowsOracle.exe --learn-server 0 --dir <data-dir> --connections 3 --version 6
RSLWindowsOracle.exe --learn-client 127.0.0.1 <port> --mode votes --decree 100
RSLWindowsOracle.exe --learn-client 127.0.0.1 <port> --mode checkpoint `
  --decree 500 --size <bytes> --out copy.codex --max-ballot 99
```

Port `0` selects a loopback port and prints `PORT <n>` before accepting.
Connection scheduling and callback timing are not part of the protocol
contract; tests assert payload bytes and lifecycle states rather than callback
thread order.

Set these environment variables before any packet or learn command to enable
the production SChannel/CryptoAPI transport:

```powershell
$env:RSL_TLS_THUMBPRINT_A = "<40 hex SHA-1>"
$env:RSL_TLS_THUMBPRINT_B = "<optional rotation slot>"
$env:RSL_TLS_STORE_SCOPE = "LocalMachine" # CurrentUser is test-only
$env:RSL_TLS_VALIDATE_CHAIN = "yes"
$env:RSL_TLS_CHECK_REVOCATION = "no"
$env:RSL_TLS_WHITELIST = "yes"
```

Optional subject rules use `RSL_TLS_SUBJECT_A/B` and
`RSL_TLS_PARENT_A/B`. Each parent value is the semicolon-separated issuer
thumbprint format consumed by production `SSLAuth`. TLS configuration is
process-global, so each endpoint and each A/B transition runs in a fresh oracle
process.

## Artifact policy

Every manifest has a schema version, generator identity, source revision when
Git is available, dirty-worktree flag, architecture, and configuration.

Wire and storage files are literal Windows outputs. Fixed-width wire fields and
page-rounded storage regions can contain allocator padding that is not stable
across builds. Their manifests mark `byteStable` as `false`; the canonical
contract is message type/version/length plus production parser verdicts for
wire, and production reader verdicts plus recovered metadata for storage.
Portable Rust CI consumes the committed artifacts, while the Windows
mixed-language job regenerates artifacts and runs the live oracle.

## Rust authoritative mode

Set both variables when running live mixed-language tests:

```powershell
$env:RSL_AUTHORITATIVE_INTEROP = "1"
$env:RSL_WINDOWS_ORACLE = "<path>\RSLWindowsOracle.exe"
cargo test -p rsl-storage --test windows_oracle
```

Authoritative mode fails if `RSL_WINDOWS_ORACLE` is missing or invalid.
