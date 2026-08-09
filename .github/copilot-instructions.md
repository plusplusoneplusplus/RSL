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
