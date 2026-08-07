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
