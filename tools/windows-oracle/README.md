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
RSLWindowsOracle.exe --storage-full <directory>
RSLWindowsOracle.exe --verify-storage <directory>
```

`--wire` emits line-oriented message, fingerprint, and `MarshalData` container
vectors. `--storage` writes the small reviewable logs/checkpoints committed under
`corpus/`. `--storage-full` additionally writes 4 MiB checksum-block boundary
and multi-block checkpoints for workflow artifacts. Negative vectors are
created by mutating or truncating production-written files externally before
passing them to the production readers.

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

## Artifact policy and workflow flow

Every manifest has a schema version, generator identity, source revision when
Git is available, dirty-worktree flag, architecture, and configuration.

Wire and storage files are literal Windows outputs. Fixed-width wire fields and
page-rounded storage regions can contain allocator padding that is not stable
across builds. Their manifests mark `byteStable` as `false`; the canonical
contract is message type/version/length plus production parser verdicts for
wire, and production reader verdicts plus recovered metadata for storage.

The small committed corpus is a reviewable local fallback. CI generates the
full Release corpus from a clean checkout:

```powershell
.\tools\windows-oracle\New-InteropArtifact.ps1 `
  -OraclePath <RSLWindowsOracle.exe> `
  -OutputDirectory <artifact-directory>
python .\tools\windows-oracle\validate_artifact.py <artifact-directory> `
  --expected-revision <git-sha>
```

`artifact-manifest.json` records schema version, source revision/dirty state,
architecture/configuration, Windows runner image, MSBuild/compiler/Rust
versions, generator executable hash, command identity, and each file's size and
SHA-256. Validation rejects missing/extra files, hash changes, wrong schema,
dirty provenance, wrong revision/configuration, and missing large checkpoint
boundary cases.

The Release Windows job uploads this package. Linux downloads and validates the
same-run package, sets `RSL_WINDOWS_WIRE` and `RSL_WINDOWS_STORAGE`, and runs
the portable Rust readers over it. Linux never regenerates authoritative
compatibility evidence from the extracted C++ proxy.

## Rust authoritative mode

Set both variables when running live mixed-language tests:

```powershell
$env:RSL_AUTHORITATIVE_INTEROP = "1"
$env:RSL_WINDOWS_ORACLE = "<path>\RSLWindowsOracle.exe"
cargo test -p rsl-storage --test windows_oracle
```

Authoritative mode fails if `RSL_WINDOWS_ORACLE` is missing or invalid.
Portable corpus-only tests can instead set `RSL_WINDOWS_WIRE` to `wire.txt` and
`RSL_WINDOWS_STORAGE` to its storage directory.
