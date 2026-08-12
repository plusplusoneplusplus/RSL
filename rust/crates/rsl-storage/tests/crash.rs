//! Crash consistency: run a workload against the [`SimCrash`] shadow
//! filesystem, then cut power at **every** point in the recorded operation
//! sequence, under every [`CrashPolicy`], and check what recovery makes of the
//! wreckage.
//!
//! The four properties every case must satisfy (Phase 3d work item 3):
//!
//! * **(a) Nothing acknowledged is ever lost.** Once `append_durable` or
//!   `CheckpointWriter::finish` has returned, no crash may take it back.
//! * **(b) Recovery is total.** It either accepts, stops cleanly at an offset,
//!   or rejects per the C++ decision table — it never panics, hangs, or
//!   allocates its way out of memory on a corrupt length field.
//! * **(c) At most the unsynced tail is lost.** What recovery keeps is always a
//!   *prefix* of what was written, never a hole in the middle.
//! * **(d) A checkpoint is old or new, never hybrid.** Any published `.codex`
//!   verifies completely, with exactly the state that was written under that
//!   name.
//!
//! Two tests sit outside that loop: `the_harness_catches_a_missing_dir_fsync`
//! deliberately breaks the policy to prove the harness has teeth, and
//! `a_killed_writer_leaves_a_recoverable_log` is a real-filesystem sanity layer
//! — a child process `SIGKILL`ed mid-append. The exhaustive coverage comes from
//! the simulator, not from that flaky-by-nature check.

mod common;

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use rsl_storage::checkpoint::{self, CheckpointHeader, CheckpointWriter};
use rsl_storage::dir::DataDir;
use rsl_storage::durability::{Durability, OpenMode, SyncAll};
use rsl_storage::gc::{self, Retention};
use rsl_storage::log::{self, LogError, LogWriter, Outcome};
use rsl_storage::sim::{CrashPolicy, SimCrash, SimFile, POLICIES};
use rsl_wire::messages::MSG_VOTE;
use rsl_wire::{
    BallotNumber, ConfigurationInfo, Header, MemberId, MemberSet, ProtocolVersion, RslNode, Vote,
};

// ---------------------------------------------------------------------------
// Sample data
// ---------------------------------------------------------------------------

fn vote_record(decree: u64, request_len: usize) -> Vec<u8> {
    let mut vote = Vote::new(Header::new(
        ProtocolVersion::V6,
        MSG_VOTE,
        MemberId::from_str("101"),
        decree,
        7,
        BallotNumber::new(3, MemberId::from_str("202")),
        0,
    ));
    if request_len > 0 {
        vote.add_request(vec![b'r'; request_len]);
    }
    vote.marshal_with_checksum().unwrap()
}

fn checkpoint_header(decree: u64) -> CheckpointHeader {
    let vote = Vote::new(Header::new(
        ProtocolVersion::V6,
        MSG_VOTE,
        MemberId::from_str("101"),
        decree + 1,
        7,
        BallotNumber::new(5, MemberId::from_str("202")),
        0,
    ));
    let mut header = CheckpointHeader::new(vote);
    header.member_id = MemberId::from_str("101");
    header.last_executed_decree = decree;
    header.max_ballot = BallotNumber::new(9, MemberId::from_str("202"));
    header.state_configuration = Some(ConfigurationInfo::new(
        1,
        decree + 1,
        MemberSet {
            members: vec![RslNode {
                member_id: MemberId::from_str("101"),
                ip: 0x0100_007f,
                rsl_port: 8080,
                rsl_learn_port: 8081,
                app_port: 0,
                host_name: b"host-a".to_vec(),
            }],
            cookie: b"cfg".to_vec(),
        },
    ));
    header
}

// ---------------------------------------------------------------------------
// The enumeration driver
// ---------------------------------------------------------------------------

/// One materialized post-crash state, handed to a workload's checker.
struct CrashCase<'a> {
    /// The materialized directory, on the real filesystem.
    dir: &'a Path,
    /// Which crash point this is, in words.
    at: String,
    /// How the in-flight state fared.
    policy: CrashPolicy,
    /// Everything the workload had acknowledged as durable by this point.
    acks: Vec<String>,
}

impl CrashCase<'_> {
    /// The last acknowledgement, parsed as a count. Workloads here acknowledge
    /// "how many records/checkpoints are now durable".
    fn acked_count(&self) -> u64 {
        self.acks
            .last()
            .map_or(0, |a| a.parse().expect("count ack"))
    }

    fn fail(&self, message: impl std::fmt::Display) -> String {
        format!("[{} | {}] {message}", self.at, self.policy)
    }
}

/// Materialize every (crash point × policy) of `sim` and run `check` on each,
/// collecting the violations it reports.
fn enumerate(
    sim: &SimCrash,
    scratch: &Path,
    check: impl FnMut(&CrashCase) -> Result<(), String>,
) -> Vec<String> {
    enumerate_from(sim, scratch, 0, check)
}

/// [`enumerate`], but only from crash point `from` onwards — for a workload
/// whose earlier operations are scene-setting rather than the thing under test.
fn enumerate_from(
    sim: &SimCrash,
    scratch: &Path,
    from: usize,
    mut check: impl FnMut(&CrashCase) -> Result<(), String>,
) -> Vec<String> {
    let mut violations = Vec::new();
    for k in from..=sim.len() {
        for &policy in POLICIES {
            sim.materialize(k, policy, scratch).expect("materialize");
            let case = CrashCase {
                dir: scratch,
                at: sim.describe(k),
                policy,
                acks: sim.acks_before(k),
            };
            if let Err(violation) = check(&case) {
                violations.push(violation);
            }
        }
    }
    violations
}

fn assert_clean(violations: Vec<String>, workload: &str) {
    assert!(
        violations.is_empty(),
        "{workload}: {} crash states violated the durability contract:\n  {}",
        violations.len(),
        violations.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Shared log assertions
// ---------------------------------------------------------------------------

/// The four properties, checked against one recovered log.
///
/// `written` is every decree that was ever appended, in order; `acked` is how
/// many of them had been acknowledged durable when the crash hit.
fn check_log(case: &CrashCase, name: &str, written: &[u64], acked: u64) -> Result<(), String> {
    let path = case.dir.join(name);

    if !path.exists() {
        // (a) A log holding acknowledged records may not simply disappear: its
        // directory entry is fsynced when the file is created, precisely so this
        // cannot happen.
        return if acked == 0 {
            Ok(())
        } else {
            Err(case.fail(format!("{name} vanished with {acked} acknowledged records")))
        };
    }

    // (b) Recovery is total: a decision, not a panic and not an I/O error.
    let scan = log::scan_file(&path).map_err(|e| case.fail(format!("{name} scan failed: {e}")))?;

    // (c) What survived is a prefix of what was written — never a hole.
    if scan.records.len() > written.len() {
        return Err(case.fail(format!(
            "{name} recovered {} records but only {} were written",
            scan.records.len(),
            written.len()
        )));
    }
    for (i, record) in scan.records.iter().enumerate() {
        if record.decree != written[i] {
            return Err(case.fail(format!(
                "{name} record {i} is decree {} but decree {} was written there",
                record.decree, written[i]
            )));
        }
    }

    // (a) Everything acknowledged is still here.
    if (scan.records.len() as u64) < acked {
        return Err(case.fail(format!(
            "{name} lost acknowledged records: {} recovered, {acked} acknowledged ({})",
            scan.records.len(),
            scan.detail()
        )));
    }

    // A rejection is a legal outcome (the C++ replica refuses to start), but it
    // must never happen *inside* acknowledged data — the corruption can only be
    // in the tail that was still in flight.
    if scan.end.outcome() == Outcome::Reject {
        let acked_end: u64 = scan
            .records
            .iter()
            .take(acked as usize)
            .map(|r| u64::from(r.padded_len))
            .sum();
        if scan.stop_offset < acked_end {
            return Err(case.fail(format!(
                "{name} rejected at {} which is inside the acknowledged prefix ending at {acked_end}",
                scan.stop_offset
            )));
        }
        return Ok(());
    }

    // Reopening must be idempotent: the writer positions itself past whatever
    // recovery kept, and a rescan sees exactly the same records.
    let mut writer = match LogWriter::open(case.dir, name_decree(name)) {
        Ok(writer) => writer,
        Err(LogError::Corrupt(_)) => return Ok(()),
        Err(e) => return Err(case.fail(format!("{name} could not be reopened: {e}"))),
    };
    let kept = scan.records.len();
    let next = written
        .get(kept)
        .copied()
        .unwrap_or(written[written.len() - 1] + 1);
    writer
        .append_durable(&[&vote_record(next, 0)])
        .map_err(|e| case.fail(format!("{name} could not be appended to: {e}")))?;
    drop(writer);

    let rescan =
        log::scan_file(&path).map_err(|e| case.fail(format!("{name} rescan failed: {e}")))?;
    if rescan.end.outcome() != Outcome::Accept {
        return Err(case.fail(format!(
            "{name} did not scan clean after reopen+append: {}",
            rescan.detail()
        )));
    }
    if rescan.records.len() != kept + 1 {
        return Err(case.fail(format!(
            "{name} holds {} records after appending to {kept}",
            rescan.records.len()
        )));
    }
    Ok(())
}

fn name_decree(name: &str) -> u64 {
    name.trim_end_matches(".log").parse().expect("log name")
}

// ---------------------------------------------------------------------------
// Workload 1 — appending votes
// ---------------------------------------------------------------------------

/// Append votes in a mixture of shapes: one at a time, in a batch, and with an
/// unsynced append in between two synced ones.
fn append_workload(sim: &SimCrash, dir: &Path) -> Vec<u64> {
    let mut writer = LogWriter::open_with(dir, 0, sim.clone()).expect("open");
    let mut written = Vec::new();
    let ack = |sim: &SimCrash, n: usize| sim.ack(n.to_string());

    // A single small vote, made durable on its own.
    writer
        .append_durable(&[&vote_record(0, 0)])
        .expect("append");
    written.push(0);
    ack(sim, written.len());

    // A batch of three, one of them spanning several pages — this is the shape
    // that gives a torn or holey tail real record bytes to damage.
    let batch: Vec<Vec<u8>> = vec![vote_record(1, 0), vote_record(2, 3000), vote_record(3, 100)];
    let refs: Vec<&[u8]> = batch.iter().map(Vec::as_slice).collect();
    writer.append_durable(&refs).expect("append batch");
    written.extend([1, 2, 3]);
    ack(sim, written.len());

    // An append with no sync: not acknowledged, so it is allowed to vanish...
    writer.append(&vote_record(4, 600)).expect("append");
    written.push(4);

    // ...until the next durable append sweeps it to disk with it.
    writer
        .append_durable(&[&vote_record(5, 0)])
        .expect("append");
    written.push(5);
    ack(sim, written.len());

    written
}

#[test]
fn appended_votes_survive_every_crash_point() {
    let scratch = common::TempDir::new("crash-append");
    let data = PathBuf::from("/data");
    let sim = SimCrash::new();
    let written = append_workload(&sim, &data);

    // Counted so the test cannot pass vacuously: a harness that only ever
    // produced clean logs would prove nothing about damaged tails.
    let mut seen: BTreeMap<&'static str, u32> = BTreeMap::new();
    let violations = enumerate(&sim, scratch.path(), |case| {
        let path = case.dir.join("0.log");
        let outcome = if path.exists() {
            log::scan_file(&path).map(|s| s.outcome()).unwrap_or("io")
        } else {
            "absent"
        };
        *seen.entry(outcome).or_default() += 1;
        check_log(case, "0.log", &written, case.acked_count())
    });
    assert_clean(violations, "append");

    for outcome in ["accept", "stop-at-offset", "reject"] {
        assert!(
            seen.get(outcome).is_some_and(|&n| n > 0),
            "no crash state produced a '{outcome}' recovery — the harness is not \
             exercising damaged tails (saw {seen:?})"
        );
    }
}

// ---------------------------------------------------------------------------
// Workload 2 — publishing checkpoints
// ---------------------------------------------------------------------------

#[test]
fn a_published_checkpoint_is_never_a_hybrid() {
    let scratch = common::TempDir::new("crash-checkpoint");
    let data = PathBuf::from("/data");
    let sim = SimCrash::new();

    // Two checkpoints in a row: the second is published over a directory that
    // already holds the first, so every crash point has an "old" to fall back
    // on.
    let mut expected: BTreeMap<String, u64> = BTreeMap::new();
    for (decree, state_len) in [(100u64, 5_000usize), (200, 40_000)] {
        let name = rsl_storage::dir::checkpoint_file_name(decree);
        let mut writer = CheckpointWriter::create_with(
            &data.join(&name),
            checkpoint_header(decree),
            sim.clone(),
        )
        .expect("create");
        writer
            .write_all(&common::ramp_state(state_len))
            .expect("write");
        writer.finish().expect("finish");
        expected.insert(name, state_len as u64);
        sim.ack(expected.len().to_string());
    }

    let violations = enumerate(&sim, scratch.path(), |case| {
        let listing = DataDir::scan(case.dir)
            .map_err(|e| case.fail(format!("directory scan failed: {e}")))?;

        // (d) Whatever is published under a final name is the whole file.
        for decree in &listing.checkpoints {
            let name = rsl_storage::dir::checkpoint_file_name(*decree);
            let path = case.dir.join(&name);
            let verified = checkpoint::verify_file(&path)
                .map_err(|e| case.fail(format!("{name} could not be read: {e}")))?;
            if !verified.accepted() {
                return Err(case.fail(format!("{name} is a hybrid: {}", verified.detail())));
            }
            let want = expected
                .get(&name)
                .copied()
                .ok_or_else(|| case.fail(format!("{name} was never written")))?;
            if verified.user_data_size != want {
                return Err(case.fail(format!(
                    "{name} holds {} user bytes, {want} were written",
                    verified.user_data_size
                )));
            }
        }

        // (a) Once `finish` has returned, that checkpoint is on disk for good.
        let acked = case.acked_count() as usize;
        if listing.checkpoints.len() < acked {
            return Err(case.fail(format!(
                "{} checkpoints on disk, {acked} were acknowledged",
                listing.checkpoints.len()
            )));
        }
        Ok(())
    });
    assert_clean(violations, "checkpoint");
}

// ---------------------------------------------------------------------------
// Workload 3 — garbage collection
// ---------------------------------------------------------------------------

#[test]
fn garbage_collection_never_deletes_a_file_recovery_needs() {
    let scratch = common::TempDir::new("crash-gc");
    let data = PathBuf::from("/data");
    let sim = SimCrash::new();

    // A directory that has been running for a while: four logs and three
    // checkpoints, all durable before the cleanup pass starts.
    for (i, decree) in [0u64, 10, 20, 30].into_iter().enumerate() {
        let mut writer = LogWriter::open_with(&data, decree, sim.clone()).expect("open");
        writer
            .append_durable(&[&vote_record(decree + i as u64, 0)])
            .expect("append");
    }
    for decree in [15u64, 25, 35] {
        let name = rsl_storage::dir::checkpoint_file_name(decree);
        let mut writer = CheckpointWriter::create_with(
            &data.join(&name),
            checkpoint_header(decree),
            sim.clone(),
        )
        .expect("create");
        writer.write_all(&common::ramp_state(1024)).expect("write");
        writer.finish().expect("finish");
    }

    let retention = Retention {
        max_checkpoints: 2,
        max_logs: 2,
    };
    let before = DataDir::scan_with(&data, &sim).expect("scan");
    let plan = gc::plan(&before, retention);
    assert!(!plan.is_empty(), "the scenario must actually delete things");
    let doomed: Vec<String> = plan
        .paths(&data)
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();

    // Only the cleanup pass itself is under test; the crash points that build
    // the directory up belong to the append and checkpoint workloads.
    let start = sim.len();
    let failures = gc::apply_with(&data, &plan, &sim);
    assert!(failures.is_empty(), "cleanup failed: {failures:?}");

    let violations = enumerate_from(&sim, scratch.path(), start, |case| {
        let listing = DataDir::scan(case.dir)
            .map_err(|e| case.fail(format!("directory scan failed: {e}")))?;

        // Only files the plan condemned may be missing — a crash cannot make the
        // cleanup delete something it never planned to.
        for decree in &before.logs {
            let name = rsl_storage::dir::log_file_name(*decree);
            if !case.dir.join(&name).exists() && !doomed.contains(&name) {
                return Err(case.fail(format!("{name} disappeared but was not condemned")));
            }
        }
        for decree in &before.checkpoints {
            let name = rsl_storage::dir::checkpoint_file_name(*decree);
            if !case.dir.join(&name).exists() && !doomed.contains(&name) {
                return Err(case.fail(format!("{name} disappeared but was not condemned")));
            }
        }

        // The newest checkpoint, and a log to replay forward from it, are always
        // there: whichever prefix of the deletions landed, the directory is
        // still a state a replica can start from.
        let newest = listing
            .newest_checkpoint()
            .ok_or_else(|| case.fail("no checkpoint left at all"))?;
        if newest != 35 {
            return Err(case.fail(format!("the newest checkpoint became {newest}")));
        }
        if listing.log_holding(newest).is_none() {
            return Err(case.fail(format!("no log covers the checkpoint at {newest}")));
        }
        Ok(())
    });
    assert_clean(violations, "gc");
    assert!(sim.len() > start, "the cleanup recorded no operations");
}

// ---------------------------------------------------------------------------
// Workload 4 — crash, reopen, keep going
// ---------------------------------------------------------------------------

#[test]
fn a_reopened_log_keeps_everything_acknowledged_before_the_first_crash() {
    let scratch = common::TempDir::new("crash-reopen");
    let data = PathBuf::from("/data");
    let sim = SimCrash::new();

    let mut written = Vec::new();
    {
        let mut writer = LogWriter::open_with(&data, 7, sim.clone()).expect("open");
        for decree in 7..10 {
            writer
                .append_durable(&[&vote_record(decree, 200)])
                .expect("append");
            written.push(decree);
            sim.ack(written.len().to_string());
        }
        // An unsynced tail, then the process goes away without closing cleanly.
        writer.append(&vote_record(10, 2000)).expect("append");
        written.push(10);
    }
    // Restart: reopen scans what is there, truncates whatever recovery
    // discarded, and carries on from the end of it.
    {
        let mut writer = LogWriter::open_with(&data, 7, sim.clone()).expect("reopen");
        let next = writer.index().max_decree() + 1;
        writer
            .append_durable(&[&vote_record(next, 0)])
            .expect("append");
        // That sync swept the previously unsynced decree 10 to disk with it, so
        // the whole file is durable now.
        written.push(next);
        sim.ack(written.len().to_string());
    }

    let violations = enumerate(&sim, scratch.path(), |case| {
        check_log(case, "7.log", &written, case.acked_count())
    });
    assert_clean(violations, "reopen");
}

// ---------------------------------------------------------------------------
// The harness has teeth
// ---------------------------------------------------------------------------

/// A policy that does everything `SimCrash` does *except* publish directory
/// entries — the single omission the risk list calls out, because `fdatasync`
/// on ext4/xfs really does leave a new file's name in the page cache.
#[derive(Clone)]
struct NoDirSync(SimCrash);

impl Durability for NoDirSync {
    type File = SimFile;
    type Bulk = rsl_storage::sim::SimDevice;

    fn open(&self, path: &Path, mode: OpenMode) -> std::io::Result<SimFile> {
        self.0.open(path, mode)
    }
    fn bulk(&self) -> rsl_storage::sim::SimDevice {
        self.0.bulk()
    }
    fn exists(&self, path: &Path) -> bool {
        self.0.exists(path)
    }
    fn read_dir(&self, dir: &Path) -> std::io::Result<Vec<String>> {
        self.0.read_dir(dir)
    }
    fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        self.0.remove_file(path)
    }
    fn sync_data(&self, file: &SimFile) -> std::io::Result<()> {
        self.0.sync_data(file)
    }
    fn sync_file(&self, file: &SimFile) -> std::io::Result<()> {
        self.0.sync_file(file)
    }
    fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.0.rename(from, to)
    }
    fn sync_dir(&self, _dir: &Path) -> std::io::Result<()> {
        Ok(()) // The bug under test.
    }
}

#[test]
fn the_harness_catches_a_missing_dir_fsync() {
    let scratch = common::TempDir::new("crash-nodirsync");
    let data = PathBuf::from("/data");
    let sim = SimCrash::new();
    let broken = NoDirSync(sim.clone());

    let mut writer = LogWriter::open_with(&data, 0, broken).expect("open");
    writer
        .append_durable(&[&vote_record(0, 0)])
        .expect("append");
    sim.ack("1");

    let violations = enumerate(&sim, scratch.path(), |case| {
        check_log(case, "0.log", &[0], case.acked_count())
    });
    assert!(
        violations
            .iter()
            .any(|v| v.contains("vanished with 1 acknowledged records")),
        "a log whose directory entry was never synced must be seen to vanish; got: {violations:?}"
    );
}

/// The other half of the publish sequence: a rename that is durable while the
/// *contents* it publishes are not. `rename_durable` fsyncs the file first
/// precisely so the destination name can never point at a half-written file —
/// this shows what the harness sees when it does not.
#[test]
fn the_harness_catches_an_unsynced_publish() {
    let scratch = common::TempDir::new("crash-nofilesync");
    let data = PathBuf::from("/data");
    let sim = SimCrash::new();

    let name = rsl_storage::dir::checkpoint_file_name(100);
    let tmp = data.join(format!("{name}.tmp"));
    let mut file = sim.open(&tmp, OpenMode::Create).expect("open");
    file.write_all(&[0xab; 4096]).expect("write");
    // The bug: rename and publish the name, but never sync the contents.
    sim.rename(&tmp, &data.join(&name)).expect("rename");
    sim.sync_dir(&data).expect("sync dir");
    sim.ack("1");

    let violations = enumerate(&sim, scratch.path(), |case| {
        if case.acked_count() == 0 {
            return Ok(());
        }
        let size = case
            .dir
            .join(&name)
            .metadata()
            .map(|m| m.len())
            .unwrap_or(0);
        if size != 4096 {
            return Err(case.fail(format!("published checkpoint is {size} bytes, not 4096")));
        }
        Ok(())
    });
    assert!(
        !violations.is_empty(),
        "publishing without syncing the contents must be caught"
    );
}

// ---------------------------------------------------------------------------
// A real filesystem, a real SIGKILL
// ---------------------------------------------------------------------------

/// The sanity layer: fork a process that appends durable votes as fast as it
/// can, `SIGKILL` it mid-stream, and recover the log for real. It cannot say
/// *how many* votes were acknowledged (the child dies before it can tell us),
/// but it can insist that recovery reaches a decision and that what survives is
/// a contiguous prefix — the same properties the simulator checks exhaustively.
#[test]
fn a_killed_writer_leaves_a_recoverable_log() {
    // Child mode: append forever, until the parent kills us.
    if let Ok(dir) = std::env::var("RSL_CRASH_CHILD") {
        let dir = PathBuf::from(dir);
        let mut writer = LogWriter::open_with(&dir, 0, SyncAll).expect("child open");
        let mut decree = 0u64;
        loop {
            writer
                .append_durable(&[&vote_record(decree, (decree as usize % 7) * 500)])
                .expect("child append");
            decree += 1;
        }
    }

    let scratch = common::TempDir::new("crash-kill");
    let mut child = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", "a_killed_writer_leaves_a_recoverable_log"])
        .env("RSL_CRASH_CHILD", scratch.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn writer");

    // Long enough for a handful of fsynced appends, short enough to land in the
    // middle of one.
    std::thread::sleep(std::time::Duration::from_millis(150));
    child.kill().expect("kill writer");
    let _ = child.wait();

    let path = scratch.join("0.log");
    if !path.exists() {
        eprintln!("a_killed_writer_leaves_a_recoverable_log: the child never created the log");
        return;
    }
    let scan = log::scan_file(&path).expect("scan a killed writer's log");
    assert_ne!(
        scan.end.outcome(),
        Outcome::Reject,
        "a killed writer left an unrecoverable log: {}",
        scan.detail()
    );
    for (i, record) in scan.records.iter().enumerate() {
        assert_eq!(
            record.decree, i as u64,
            "recovered records are not a prefix"
        );
    }

    // And the log can be picked up again, which is what a restarting replica
    // does.
    let mut writer = LogWriter::open(scratch.path(), 0).expect("reopen after the kill");
    let next = scan.records.len() as u64;
    writer
        .append_durable(&[&vote_record(next, 0)])
        .expect("append after the kill");
    drop(writer);
    let rescan = log::scan_file(&path).expect("rescan");
    assert_eq!(rescan.end.outcome(), Outcome::Accept);
    assert_eq!(rescan.records.len(), scan.records.len() + 1);
}
