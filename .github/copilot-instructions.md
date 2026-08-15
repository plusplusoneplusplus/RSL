# Copilot instructions

## Git: never switch branches to commit

Commit to the branch that is already checked out — including `master`.

Do **not**, as part of making a commit:

- create a new branch (`git checkout -b`, `git switch -c`, `git branch`)
- switch to a different branch (`git checkout <branch>`, `git switch <branch>`)
- stash, rebase, reset, or cherry-pick changes onto another branch

This holds even when the current branch is the default branch. Committing
directly to `master` is expected in this repository; treat a "don't commit to
the default branch" habit as not applying here.

If you believe the work belongs on a separate branch, say so and let the user
decide. Do not switch on your own initiative.

Branch operations are fine when the user explicitly asks for them.

## Committing

- Stage only the files relevant to the change; leave unrelated edits alone.
- Do not push unless the user asks.
- Do not skip hooks (`--no-verify`) or bypass signing.
- Prefer a new commit over amending an existing one.

## Porting C++ to Rust

When porting C++ code to Rust, follow these rules strictly:

### 1. Behavior parity is mandatory

The Rust implementation must produce the same observable behavior as the C++
original. Match semantics, error handling, edge cases, and output exactly.
When in doubt, add an assertion or test that demonstrates equivalence rather
than assuming the Rust version is correct.

### 2. Close test gaps in C++ first

Before writing the Rust port of a component, review the existing C++ test
coverage. If there is a test gap — missing edge-case coverage, untested error
paths, or under-specified behavior — write the missing tests in C++ first so
the expected behavior is documented and verified on the reference
implementation. Only then port the code and mirror those tests in Rust.

### 3. Performance must match

Benchmark the C++ code path before porting. The Rust port must meet or exceed
the same throughput, latency, and memory characteristics. Include comparative
benchmarks in the PR and call out any regressions.

### 4. Preserve OS-specific features

Where the C++ code uses platform-specific APIs (Windows SDK, IOCP, named pipes,
etc.), the Rust port may use cross-platform abstractions, but the resulting
performance and correctness must remain equivalent. If a platform-specific
feature cannot be replicated with the same guarantees through portable APIs,
fall back to platform-specific Rust APIs or raw FFI to preserve the behavior.

## Comments

- Keep comments concise — explain *why*, not *what*.
- When changing code, update or remove any comments that are no longer accurate.
  Stale comments are worse than no comments.
