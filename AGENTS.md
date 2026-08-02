# AGENTS.md

## What this is

RSL (Replicated State Library) is a C++ implementation of the Paxos consensus
protocol for building replicated state machines. It ships a native C++ library
plus a managed (C++/CLI) wrapper so .NET applications can host a state machine.

## Layout

- `src/inc/` — public headers (`rsl.h`, `rslutil.h`, `rsl.contract`) and the API changelog.
- `src/RSL/src/` — core native engine: Paxos (`legislator.*`), messages, config, RSL entry points.
- `src/RSL/ManagedSrc/` — managed layer. `Lib/` is the C++/CLI wrapper; `SampleApp/` and the `*StressTest`/`*Test` projects are usage examples and drivers.
- `src/NetworkLib/` — networking (sockets, SSL, packet handling).
- `src/common/` — shared utilities (buffers, logging, time, ref counting, command-line parsing).
- `src/LF/` — lock-free (`LF`) primitives in C: non-blocking stack, queue, and lock pool.
- `src/lib/` — packages the native library into `RSLib.vcxproj`.
- `src/UnitTest/` and `src/RSL/UnitTest/` — test framework and RSL test suites (state machine, migration, SSL).
- `ossbuild/` — build bootstrap scripts and MSBuild props/targets.

## Build

Windows-only, Visual Studio 2017 with C++ and C# desktop workloads.

1. Open a **Developer Command Prompt for VS 2017**.
2. From `ossbuild/`, run `ossbuild.ps1` in PowerShell to restore packages and set environment variables.
3. From the repo root, `src`, or any project directory, build with MSBuild:

   ```
   msbuild /m:8 /v:m /fl
   ```

   Set `/m` to your core count (`NUMBER_OF_PROCESSORS`). Binaries land in `out/` at the repo root.

You can also open `src/RSL.sln` in the VS IDE from the bootstrapped PowerShell window.

## Tests

Unit tests build alongside the solution. Test sources live under `src/UnitTest/`
(the framework) and `src/RSL/UnitTest/` (RSL scenarios). Build and run the test
projects the same way as the rest of the solution.

## Conventions

- Native code is C++ targeting the Windows SDK (`rsl.h` includes `windows.h`);
  the managed layer is C++/CLI.
- Public API changes go in `src/inc/` and should be documented in `src/inc/RSL_changelog.md`.
- New features are typically opt-in via RSL configuration flags — see the changelog for the pattern.

## Contributing

Contributions require a Microsoft CLA (https://cla.microsoft.com). Report security
issues privately to MSRC, not via public issues — see `SECURITY.md`.
