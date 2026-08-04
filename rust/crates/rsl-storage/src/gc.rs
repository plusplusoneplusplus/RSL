//! Retention: which logs and checkpoints may be deleted.
//!
//! Port of `Legislator::CleanupLogsAndCheckpoint` (`legislator.cpp:5675`),
//! split into a pure [`plan`] step and an [`apply`] step so the decision can be
//! tested without touching a filesystem.
//!
//! The C++ rule, verbatim in intent:
//!
//! * Keep the newest `max_checkpoints` checkpoints; delete the rest.
//! * Walk logs oldest-first and delete a log while **both** hold: more than
//!   `max_logs` logs still remain, and the *next* log starts at or before
//!   `oldest_checkpoint + 1` — i.e. everything in this log has been superseded
//!   by a checkpoint.
//!
//! Note the second condition uses the **oldest** checkpoint in the directory
//! (`checkpoints[0]`, including ones this same pass is about to delete), not the
//! newest. That is deliberately conservative: it can only retain more logs than
//! the newest checkpoint strictly needs, never fewer.
//!
//! ## Divergences from C++
//!
//! * **Empty-vector guards.** The C++ log loop reads `checkpoints[0]`
//!   (`legislator.cpp:5713`) without checking that any checkpoint exists — with
//!   no `*.codex` in the directory that is an out-of-bounds read on an empty
//!   `std::vector`. [`plan`] deletes no logs in that case: with no checkpoint,
//!   every log is still needed.
//! * The C++ also trims the in-memory `m_logFiles` list under the engine lock
//!   before touching the disk. That is engine state, not storage, and belongs to
//!   Phase 5.
//! * A failed delete is reported rather than logged-and-forgotten; the caller
//!   decides. `apply` still attempts every remaining deletion, as the C++ does.

use std::io;
use std::path::{Path, PathBuf};

use crate::dir::{checkpoint_file_name, log_file_name, DataDir};
use crate::durability::{Durability, SyncAll};

/// How many files of each kind to keep (`m_cfg.MaxCheckpoints()` /
/// `MaxLogs()`). Both must be non-zero — the C++ `LogAssert`s on that
/// (`legislator.cpp:5700`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retention {
    /// Newest checkpoints to keep.
    pub max_checkpoints: u32,
    /// Logs to keep.
    pub max_logs: u32,
}

impl Default for Retention {
    /// The RSL configuration defaults (`RSLConfig`): 2 checkpoints, 10 logs.
    fn default() -> Retention {
        Retention {
            max_checkpoints: 2,
            max_logs: 10,
        }
    }
}

/// The files a cleanup pass would delete, by decree.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CleanupPlan {
    /// Checkpoint decrees to delete, ascending.
    pub checkpoints: Vec<u64>,
    /// Log decrees to delete, ascending.
    pub logs: Vec<u64>,
}

impl CleanupPlan {
    /// Is there nothing to do?
    pub fn is_empty(&self) -> bool {
        self.checkpoints.is_empty() && self.logs.is_empty()
    }

    /// The paths this plan deletes, in the order `apply` would remove them:
    /// checkpoints first, then logs, both oldest-first.
    pub fn paths(&self, dir: &Path) -> Vec<PathBuf> {
        self.checkpoints
            .iter()
            .map(|d| dir.join(checkpoint_file_name(*d)))
            .chain(self.logs.iter().map(|d| dir.join(log_file_name(*d))))
            .collect()
    }
}

/// Decide what to delete. Pure: reads only the enumerated decrees.
///
/// `max_checkpoints == 0` or `max_logs == 0` deletes nothing of that kind
/// (where the C++ `LogAssert`-aborts): retaining files is always the safe
/// reading of a nonsensical policy.
pub fn plan(dir: &DataDir, retention: Retention) -> CleanupPlan {
    let mut checkpoints = Vec::new();
    if retention.max_checkpoints > 0 {
        let keep = retention.max_checkpoints as usize;
        let excess = dir.checkpoints.len().saturating_sub(keep);
        checkpoints.extend_from_slice(&dir.checkpoints[..excess]);
    }

    let mut logs = Vec::new();
    // The guard the C++ lacks: with no checkpoint at all, every log is still
    // needed to reconstruct state from decree 0.
    if retention.max_logs > 0 && !dir.checkpoints.is_empty() {
        let oldest_checkpoint = dir.checkpoints[0];
        let newest_checkpoint = dir.checkpoints[dir.checkpoints.len() - 1];
        let max_logs = retention.max_logs as usize;

        for i in 0..dir.logs.len() {
            // `logs.size() - i > maxLogs`: more than maxLogs would remain.
            if dir.logs.len() - i <= max_logs {
                break;
            }
            // `logs[i+1] <= checkpoints[0]+1`: the next log already starts at or
            // before the oldest checkpoint, so log i holds nothing newer.
            let Some(&next) = dir.logs.get(i + 1) else {
                break;
            };
            if next > oldest_checkpoint + 1 {
                break;
            }
            // Belt and braces: never drop a log the newest checkpoint would
            // still need. Implied by the line above (oldest <= newest), stated
            // so the invariant is checked and not merely argued.
            debug_assert!(next <= newest_checkpoint + 1);
            logs.push(dir.logs[i]);
        }
    }

    CleanupPlan { checkpoints, logs }
}

/// A deletion that failed, with the error that stopped it.
#[derive(Debug)]
pub struct DeleteFailure {
    /// The file that could not be removed.
    pub path: PathBuf,
    /// Why.
    pub error: io::Error,
}

/// Delete everything in `plan`, attempting every file even after a failure.
///
/// Returns the failures; an empty vector means the whole plan was applied. A
/// file that is already gone is not a failure.
pub fn apply(dir: &Path, plan: &CleanupPlan) -> Vec<DeleteFailure> {
    apply_with(dir, plan, &SyncAll)
}

/// [`apply`] under an explicit durability policy.
///
/// Deletion order is the plan's — the checkpoints being retired first, then the
/// logs, both oldest-first — and the *directory* is fsynced once at the end so
/// the unlinks themselves survive a crash. That ordering is what makes every
/// intermediate state safe: a plan never contains the newest checkpoint or a log
/// still needed to reach it, so whichever prefix of the deletions a crash
/// leaves behind, the surviving directory is still recoverable. Deleting a
/// *stale* file twice is harmless; the danger would be an unlink that outlives
/// the file it made redundant, which cannot arise because nothing is written
/// here.
pub fn apply_with<D: Durability>(
    dir: &Path,
    plan: &CleanupPlan,
    durability: &D,
) -> Vec<DeleteFailure> {
    let mut failures = Vec::new();
    for path in plan.paths(dir) {
        if let Err(error) = durability.remove_file(&path) {
            failures.push(DeleteFailure { path, error });
        }
    }
    if !plan.is_empty() {
        let handle = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        };
        if let Err(error) = durability.sync_dir(handle) {
            failures.push(DeleteFailure {
                path: dir.to_path_buf(),
                error,
            });
        }
    }
    failures
}

/// Enumerate `dir`, plan, and apply in one step — the shape
/// `CleanupLogsAndCheckpoint` has.
pub fn cleanup(
    dir: &Path,
    retention: Retention,
) -> Result<Vec<DeleteFailure>, crate::dir::DirError> {
    cleanup_with(dir, retention, &SyncAll)
}

/// [`cleanup`] under an explicit durability policy.
pub fn cleanup_with<D: Durability>(
    dir: &Path,
    retention: Retention,
    durability: &D,
) -> Result<Vec<DeleteFailure>, crate::dir::DirError> {
    let listing = DataDir::scan_with(dir, durability)?;
    Ok(apply_with(dir, &plan(&listing, retention), durability))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listing(logs: &[u64], checkpoints: &[u64]) -> DataDir {
        DataDir {
            path: PathBuf::from("/data"),
            logs: logs.to_vec(),
            checkpoints: checkpoints.to_vec(),
        }
    }

    #[test]
    fn keeps_the_newest_checkpoints() {
        let dir = listing(&[], &[10, 20, 30, 40]);
        let plan = plan(
            &dir,
            Retention {
                max_checkpoints: 2,
                max_logs: 10,
            },
        );
        assert_eq!(plan.checkpoints, vec![10, 20]);
    }

    #[test]
    fn no_checkpoint_means_no_log_is_deletable() {
        // The C++ reads checkpoints[0] out of bounds here.
        let dir = listing(&[0, 10, 20, 30, 40, 50], &[]);
        let plan = plan(
            &dir,
            Retention {
                max_checkpoints: 2,
                max_logs: 1,
            },
        );
        assert!(plan.logs.is_empty());
    }

    #[test]
    fn deletes_only_logs_covered_by_the_oldest_checkpoint() {
        // Logs start at 0, 10, 20, 30; the oldest checkpoint is at decree 14, so
        // the log starting at 20 is not covered and everything from it stays.
        let dir = listing(&[0, 10, 20, 30], &[14, 25]);
        let plan = plan(
            &dir,
            Retention {
                max_checkpoints: 2,
                max_logs: 1,
            },
        );
        assert_eq!(plan.logs, vec![0]);
    }

    #[test]
    fn keeps_max_logs_even_when_all_are_covered() {
        let dir = listing(&[0, 10, 20, 30], &[99]);
        let plan = plan(
            &dir,
            Retention {
                max_checkpoints: 2,
                max_logs: 2,
            },
        );
        assert_eq!(plan.logs, vec![0, 10]);
    }

    #[test]
    fn the_newest_log_is_never_deleted() {
        // Even with maxLogs = 1 and everything checkpointed, the loop stops
        // before the last log: there is no `logs[i+1]`.
        let dir = listing(&[0], &[99]);
        let plan = plan(
            &dir,
            Retention {
                max_checkpoints: 2,
                max_logs: 1,
            },
        );
        assert!(plan.logs.is_empty());
    }
}
