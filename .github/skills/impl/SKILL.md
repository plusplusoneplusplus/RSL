---
name: impl
description: >-
  Implement a change the user describes, validate it works, then commit.
  Use when the user asks to implement, build, or make a change and wants it
  carried through to a committed state in one step.
metadata:
  author: "Yiheng Tao"
  version: "0.0.1"
---

# Impl

Implement a requested change, validate it, and commit. Keep it simple.

## Workflow

1. **Implement** — make the change the user asked for. If the request is
   ambiguous enough that you'd likely build the wrong thing, ask one
   clarifying question first; otherwise just do it.

2. **Validate** — confirm the change actually works. Prefer building/running
   the relevant tests or exercising the affected code path over eyeballing the
   diff. If it doesn't pass, fix it and re-validate before moving on.

3. **Commit** — stage the change and commit on the current branch with a clear
   message. Never switch branches.

Report what changed, how it was validated, and the commit hash.
