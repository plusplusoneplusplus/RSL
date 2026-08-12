# C++ Test Suites

Status of the five test projects in `src/RSL.sln`. Verified 2026-08-09 against
VS 17.13.19.12613 / Windows SDK 10.0.22621.0, Debug x64.

## Summary

All five build clean with zero errors and zero warnings. Only one of them is an
automated, self-checking test. Nothing in CI builds or runs any of them —
`build.ps1` targets `src\RSL\src\dll\RSL.vcxproj` only.

| Project | Artifact | What it is | Automated |
|---|---|---|---|
| `src/UnitTest/src/RSLib_UnitTest.vcxproj` | `.lib` | Test framework | — |
| `src/RSL/UnitTest/RslStateMachine/RslTest.vcxproj` | `rsltest.exe` | Engine conformance suite | Yes |
| `src/RSL/UnitTest/RslMigration/NetTest/RSLNetTest.vcxproj` | `RSLNetTest.exe` | A replica node, not a test | No |
| `src/RSL/UnitTest/RslMigration/TestHarness/TestHarness.vcxproj` | `TestHarness.exe` | 5-node cluster chaos test | No |
| `src/RSL/UnitTest/SslPlumbing/Test/RSLSslTest.vcxproj` | `RSLSslTest.exe` | Manual TLS probe | No |

`src/RSL/UnitTest/SeqIoBench/` sits alongside these but is not one of them: it
is a benchmark for the sequential I/O classes in `apdiskio.cpp` — `APSEQREAD`
today, `APSEQWRITE` when someone adds it — asserts nothing, and exists to give
the Rust port a baseline to be compared against. See its
[README](../src/RSL/UnitTest/SeqIoBench/README.md), and
[`rust/crates/rsl-storage/READPATH.md`](../rust/crates/rsl-storage/READPATH.md)
for the verdict it produced.

## Building and running

```powershell
. .\ossbuild\ossbuild.ps1 -Platform x64
msbuild src\RSL\UnitTest\RslStateMachine\RslTest.vcxproj /m /nologo /v:minimal `
  /p:Configuration=Debug /p:Platform=x64
```

Binaries land in `out\debug-amd64\<Project>\`. Dependency projects
(`RSLibImpl`, `RSLib_Network`, `RSLib_Common`, `RSLib_LF`, `RSLib_UnitTest`)
are pulled in automatically.

Run `rsltest.exe` from a scratch directory. It uses relative paths
(`.\rsltest`, `.\debuglogs\rsl`) and writes ~1.15 GB across ~590 files per run.

```powershell
$scratch = "$env:TEMP\rsltest-run"
New-Item -ItemType Directory -Force $scratch | Out-Null
Push-Location $scratch
& out\debug-amd64\RslTest\rsltest.exe
Pop-Location
```

Takes about 9.5 minutes. Results go to `rsltest.exe.xml` next to the exe, in
NUnit format.

## The three methodologies

The five projects are not variants of one approach. They test three different
levels of the stack and do not overlap.

### 1. Scripted-peer conformance — `RslTest`

7,917 LOC. One real `Legislator` surrounded by scripted fake peers, all in a
single process.

```
                 rsltest.exe  (ONE process)
  TEST DRIVER                          SYSTEM UNDER TEST
  +--------------------+               +---------------------+
  | FakeLegislator 1,3 |               | TestStateMachine    |
  |  (scripted peers,  |   real TCP    |      |              |
  |   share port+10)   |<------------->|      v              |
  +--------------------+   127.0.0.1   | Legislator          |
  | m_netlibServer     |               |  (REAL, 7,384 LOC)  |
  | m_netlibClient     |               |  port 20000         |
  | m_pFetchSocket     |               |  learn port 20001   |
  +--------------------+               +----------+----------+
                                                  v
                              .\rsltest\20000\2\*.log  (REAL disk)
```

Everything is real except the peers: real TCP over loopback, real disk, real
timers, real threads. The driver reaches the engine only over sockets, never by
calling its methods.

`FakeLegislator` is a protocol-correct message generator, not a Paxos
implementation. It tracks just enough state to build valid — or deliberately
invalid — messages, and does whatever the test script says.

The rhythm is send, assert reply, assert silence:

```cpp
g_test->SendRequest(Message_Vote, decree, b);
g_test->ReceiveResponse(Message_VoteAccepted, decree, b);
g_test->AssertEmptyQueues();   // fails on ANY unexpected traffic
```

44 registered cases in `main.cpp`:

| Group | Cases | Coverage |
|---|---|---|
| State machine | 3 | Full ordered-pair transition matrix over 6 states |
| Message handling | 7 | 6 message families x 6 states, sweeping decree and ballot boundaries |
| Durability | 8 | Checkpointing, restore, log corruption, replay |
| Reconfiguration | 12 | Add/remove/simultaneous, churn, reconfig during restore |
| Bootstrap + checkpoint | 14 | 3 bootstrap paths, full version-compat grid |

This proves per-node protocol conformance. It cannot prove cluster safety —
the peers are puppets, so no split-brain or quorum-intersection bug involving
two real replicas is visible to it.

### 2. Multi-process chaos — `TestHarness` + `RSLNetTest`

`RSLNetTest.exe <memberId>` is one full replica in a process. It reads its
member set from `members.txt`, replicates an integer counter, and writes its
achieved configuration number to `CurrentConfig.txt`. It asserts almost
nothing. Port is `20000 + memberId * 1000`. Runs `RSLProtocolVersion_4` with
realistic timings (heartbeat 2s, election delay 10s, retries 1-3s).

`TestHarness.exe` is the actual test. It spawns 5 `RSLNetTest.exe` processes,
restarts any that die, drives reconfiguration by rewriting `members.txt`, and
verifies convergence by reading `CurrentConfig.txt` within a deadline.

This is the only real consensus test in the repo: 5 real replicas, continuous
crash-restart chaos, live reconfiguration.

It is not automated. It reads its chaos script from stdin as
`<timeout> <memberIds...>` lines, spawns children with `CREATE_NEW_CONSOLE`,
hardcodes `NUM_REPLICAS 5`, has no wall-clock bound, and returns 0 on its
failure path.

### 3. Manual transport probe — `RSLSslTest`

615 LOC, two-sided CLI tool for the SChannel/TLS layer:

```
rslssltest c <ServerAddress> <ServerPort> <CertThumbprint>
rslssltest s <ServerPort> <CertThumbprint>
rslssltest clienttimeouttest <ServerPort> <CertThumbprint>
rslssltest servertimeouttest <ServerPort> <CertThumbprint>
```

Requires a real certificate in the Windows `MY` store, by thumbprint. Nothing
in the repo provisions one. Run the server in one window, the client in
another.

It does concurrent send/recv over one TLS socket with 4 MB and 4 MB+1 payloads
to probe buffer boundaries, and `memcmp`s the result. Reporting is `printf`.
Do not run it unattended: on mismatch it enters `while(1) Sleep(10)`.

### The framework — `RSLib_UnitTest`

Hand-rolled xUnit, ~1,500 LOC. Assertions are `UT_AssertIsTrue`,
`UT_AssertAreEqual`, `UT_AssertIsNull`, `UT_AssertFail` and friends, each in
bare and printf-formatted variants.

Each case runs inside `try { m_func(); } catch (CUnitTestCaseError*)`, so one
failure does not stop the rest. Only that exception type is caught — an access
violation escapes to a process-level handler that writes a minidump and calls
`ExitProcess(1)`.

Output is colored console plus NUnit XML written next to the exe. Set
`UT_DEBUGBREAK` to break into a debugger on failure.

## Known issues

### rsltest.exe always exits 0

`main` calls `suite1.RunAllSuites()` and discards the return value, then falls
off the end into an implicit `return 0`. `RunAllSuites` returns the failure
count. Any CI gate on the exit code passes unconditionally.

Gate on the `failures` attribute in `rsltest.exe.xml` instead, or change the
call to `return suite1.RunAllSuites();`.

### Failures are not reproducible

`main` calls `srand(time(NULL))` and never prints or accepts a seed. `rand()`
feeds real assertion inputs — member IDs, decrees, ballots, and the
`m_stateSaved` flag in checkpoint header round-trips, plus decree offsets and a
fast-read timeout. A failing run cannot be replayed.

### Hardcoded ports

`g_port` starts at 20000 and advances by 20 per generated configuration, with
no bind-retry. Collides on shared runners. Two instances of the suite cannot
run concurrently.

### Disabled assertions

Three assertions are commented out in the engine suite:

- `TestStateMachine.cpp:109` — the contiguity check
  `UT_AssertAreEqual(m_lastSequenceNumber+1, decree)` is disabled and replaced
  by a monotonicity check. A skipped decree would not fail the suite.
- `TestEngine.cpp:1491` — `UT_AssertAreEqual(m_version, msg->m_version)`,
  marked `// TODO`. Received message versions are never verified.
- `FakeLegislator.cpp:379` — the unknown-message-id failure. Unhandled message
  types are silently ignored.

### Timing is not exercised by rsltest

All intervals are pinned to 60s and send/receive timeouts to 300s. Tests drive
state transitions explicitly rather than letting timers fire, so election,
heartbeat, and retry behavior is barely covered. This is also why the suite
takes 9.5 minutes — roughly 65% of wall-clock is spent waiting out timers
(`TestAddNewReplicas` 116s, `TestNoChanges` 104s, `TestRemoveReplica` 63s).

`RSLNetTest` uses realistic intervals and does cover this, but is not automated.

## Coverage gaps

| Area | Covered by |
|---|---|
| Ballot/decree ordering | `RslTest`, exhaustively |
| State transitions | `RslTest`, full matrix |
| Log/checkpoint durability | `RslTest`, including corruption |
| Reconfiguration | `RslTest` (scripted) and `TestHarness` (live) |
| Version compatibility 1-4 | `RslTest` checkpoint grid; `RSLNetTest` at V4 |
| Crash and restart recovery | `TestHarness` only |
| Real multi-replica consensus | `TestHarness` only |
| Realistic timing and elections | `RSLNetTest` only |
| TLS transport | `RSLSslTest`, manually |
| Packet loss, reorder, partition | **Nothing** |
| Linearizability checking | **Nothing** |

All transport everywhere is reliable, ordered TCP. No test injects loss,
reordering, duplication, or partition.

Untested engine API surface, by grep across all test sources: `Unload`,
`RelinquishPrimary`, `AllowSaveState`, `SetVotePayload`,
`ReplicateRequestExclusiveVote`, `ChangeElectionDelay`, `EnableListenOnAllIPs`,
`SetSaveCheckpointAt`, `AttemptPromotion`, `GetReplicasInformation`, and all
statistics and perf-counter paths.

## Relevance to the Rust port

`RslTest` talks to the engine only over wire protocol and the filesystem, never
through C++ function calls. That makes it implementation-agnostic in principle:
a Rust `Legislator` listening on port 20000 with the same log format would be
driven by the same script unchanged. The `FakeLegislator` message-construction
layer ports directly into a Rust differential harness.

"Rust passes `RslTest`" is necessary and not sufficient. It establishes
per-node conformance. Cluster safety needs `TestHarness`, which needs
automating first.
