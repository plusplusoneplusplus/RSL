//! The data directory: name parsing, enumeration, `defunct.txt` (against the
//! Phase-3a corpus), and the log/checkpoint retention rule over real files.

mod common;

use rsl_storage::dir::{
    self, checkpoint_file_name, log_file_name, parse_numbered_name, DataDir, DirError, ParsedName,
    CHECKPOINT_EXT, LOG_EXT,
};
use rsl_storage::gc::{self, Retention};

fn touch(dir: &common::TempDir, name: &str) {
    std::fs::write(dir.join(name), b"").expect("touch");
}

#[test]
fn names_round_trip_through_the_cpp_format() {
    assert_eq!(log_file_name(0), "0.log");
    assert_eq!(log_file_name(1234), "1234.log");
    assert_eq!(checkpoint_file_name(u64::MAX), "18446744073709551615.codex");

    assert_eq!(
        parse_numbered_name("0.log", LOG_EXT),
        Some(ParsedName::Decree(0))
    );
    assert_eq!(
        parse_numbered_name("42.codex", CHECKPOINT_EXT),
        Some(ParsedName::Decree(42))
    );
    // sscanf("%I64u") reads the leading digits and ignores the rest.
    assert_eq!(
        parse_numbered_name("42abc.log", LOG_EXT),
        Some(ParsedName::Decree(42))
    );
    // Extension mismatch is simply not a match.
    assert_eq!(parse_numbered_name("42.codex", LOG_EXT), None);
    assert_eq!(parse_numbered_name("defunct.txt", LOG_EXT), None);
    // Matching extension, no leading number: the C++ fails the enumeration.
    assert_eq!(
        parse_numbered_name("foo.log", LOG_EXT),
        Some(ParsedName::Unparsable)
    );
    // Names starting with '.' are skipped outright (legislator.cpp:5780).
    assert_eq!(parse_numbered_name(".hidden.log", LOG_EXT), None);
}

#[test]
fn the_directory_scan_orders_by_decree() {
    let dir = common::TempDir::new("dir-scan");
    for name in ["10.log", "2.log", "100.log", "0.log"] {
        touch(&dir, name);
    }
    for name in ["9.codex", "1000.codex"] {
        touch(&dir, name);
    }
    // Files that are none of RSL's business.
    touch(&dir, "defunct.txt");
    touch(&dir, "notes.md");

    let listing = DataDir::scan(dir.path()).expect("scan");
    assert_eq!(listing.logs, vec![0, 2, 10, 100]);
    assert_eq!(listing.checkpoints, vec![9, 1000]);
    assert_eq!(listing.newest_checkpoint(), Some(1000));
    assert_eq!(listing.log_holding(50), Some(10));
    assert_eq!(listing.log_holding(0), Some(0));
    assert_eq!(listing.log_path(10), dir.join("10.log"));
    assert_eq!(listing.checkpoint_path(9), dir.join("9.codex"));

    // A log whose name has no decree fails the whole scan, as in the C++.
    touch(&dir, "stray.log");
    match DataDir::scan(dir.path()) {
        Err(DirError::UnparsableName(name)) => assert_eq!(name, "stray.log"),
        other => panic!("expected an unparsable-name error, got {other:?}"),
    }
}

#[test]
fn defunct_round_trips_and_matches_the_corpus() {
    let dir = common::TempDir::new("dir-defunct");

    assert_eq!(dir::read_defunct(dir.path()).expect("read"), None);
    for value in [0u32, 42, 0xdead_beef, u32::MAX] {
        dir::write_defunct(dir.path(), value).expect("write");
        assert_eq!(dir::read_defunct(dir.path()).expect("read"), Some(value));
        assert_eq!(
            std::fs::metadata(dir.join("defunct.txt")).unwrap().len(),
            4,
            "defunct.txt is exactly one little-endian u32"
        );
    }

    // A short file reads as absent: ReadDefunctFile bails on a short GetData.
    std::fs::write(dir.join("defunct.txt"), [1u8, 2, 3]).expect("write short");
    assert_eq!(dir::read_defunct(dir.path()).expect("read"), None);

    // Trailing bytes (the Windows page-padded shape) are ignored.
    let mut padded = vec![0u8; 512];
    padded[..4].copy_from_slice(&7u32.to_le_bytes());
    std::fs::write(dir.join("defunct.txt"), &padded).expect("write padded");
    assert_eq!(dir::read_defunct(dir.path()).expect("read"), Some(7));

    // The C++ corpus samples, byte for byte.
    let Some(corpus) = common::storage_corpus() else {
        common::warn_no_corpus("defunct_round_trips_and_matches_the_corpus");
        return;
    };
    for (file, value) in [
        ("defunct-zero.txt", 0u32),
        ("defunct-42.txt", 42),
        ("defunct-large.txt", 0xdead_beef),
    ] {
        let bytes = std::fs::read(corpus.join(file)).expect("read sample");
        assert_eq!(bytes, dir::encode_defunct(value), "{file}: bytes");
        assert_eq!(dir::decode_defunct(&bytes), Some(value), "{file}: decode");
    }
}

#[test]
fn cleanup_deletes_exactly_the_planned_files() {
    let dir = common::TempDir::new("dir-gc");
    // Logs at decrees 0, 10, 20, 30; checkpoints at 15 and 25.
    for decree in [0u64, 10, 20, 30] {
        touch(&dir, &log_file_name(decree));
    }
    for decree in [15u64, 25] {
        touch(&dir, &checkpoint_file_name(decree));
    }

    let retention = Retention {
        max_checkpoints: 1,
        max_logs: 2,
    };
    let listing = DataDir::scan(dir.path()).expect("scan");
    let plan = gc::plan(&listing, retention);
    // The oldest checkpoint (15) goes. Only the log at 0 is deletable: the next
    // log starts at 10 <= 15+1, so nothing in it postdates the checkpoint. The
    // log at 10 stays because the one after it starts at 20, past 15+1 — it can
    // still hold decrees the oldest checkpoint does not cover.
    assert_eq!(plan.checkpoints, vec![15]);
    assert_eq!(plan.logs, vec![0]);

    let failures = gc::apply(dir.path(), &plan);
    assert!(failures.is_empty(), "{failures:?}");

    let after = DataDir::scan(dir.path()).expect("rescan");
    assert_eq!(after.logs, vec![10, 20, 30]);
    assert_eq!(after.checkpoints, vec![25]);

    // The surviving logs still cover everything the surviving checkpoint needs.
    assert!(after.logs[0] <= after.checkpoints[0] + 1);

    // A second pass sees the newer oldest-checkpoint (25) and can drop one more
    // log; a third converges. Each pass re-enumerates, exactly as
    // CleanupLogsAndCheckpoint does on every checkpoint attempt.
    let failures = gc::cleanup(dir.path(), retention).expect("second pass");
    assert!(failures.is_empty(), "{failures:?}");
    let after = DataDir::scan(dir.path()).expect("rescan");
    assert_eq!(after.logs, vec![20, 30]);

    let plan = gc::plan(&after, retention);
    assert!(plan.is_empty(), "the pass should have converged: {plan:?}");
}

#[test]
fn cleanup_keeps_every_log_when_there_is_no_checkpoint() {
    let dir = common::TempDir::new("dir-gc-nocp");
    for decree in [0u64, 10, 20] {
        touch(&dir, &log_file_name(decree));
    }

    // The C++ reads checkpoints[0] out of bounds here; this deletes nothing.
    let failures = gc::cleanup(
        dir.path(),
        Retention {
            max_checkpoints: 1,
            max_logs: 1,
        },
    )
    .expect("cleanup");
    assert!(failures.is_empty());

    let after = DataDir::scan(dir.path()).expect("rescan");
    assert_eq!(after.logs, vec![0, 10, 20]);
}

#[test]
fn cleanup_never_drops_a_log_the_newest_checkpoint_needs() {
    let dir = common::TempDir::new("dir-gc-safety");
    // A checkpoint at decree 5 sits inside the log that starts at 0, so that
    // log must survive however aggressive the policy is.
    touch(&dir, &log_file_name(0));
    touch(&dir, &log_file_name(100));
    touch(&dir, &checkpoint_file_name(5));

    let failures = gc::cleanup(
        dir.path(),
        Retention {
            max_checkpoints: 1,
            max_logs: 1,
        },
    )
    .expect("cleanup");
    assert!(failures.is_empty());

    let after = DataDir::scan(dir.path()).expect("rescan");
    assert_eq!(
        after.logs,
        vec![0, 100],
        "the log holding the checkpoint's decree must survive"
    );
}
