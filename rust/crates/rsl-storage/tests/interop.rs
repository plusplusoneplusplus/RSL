//! Reverse interop: checkpoints written by *this* crate are read back by the
//! extracted **C++** reader (`golden-gen --verify-storage`).
//!
//! `corpus.rs` proves the Rust side reads (and reproduces) C++-written files;
//! this closes the loop in the other direction, which is what the Phase-3a
//! reverse mode exists for. It needs the `golden-gen` binary (cmake + g++); when
//! that is not built the test reports a skip rather than failing.

mod common;

use std::io::Write;
use std::process::Command;

use rsl_storage::checkpoint::{CheckpointHeader, CheckpointWriter};
use rsl_storage::{CHECKSUM_BLOCK_SIZE, CHECKSUM_SIZE};
use rsl_wire::messages::MSG_VOTE;
use rsl_wire::{
    BallotNumber, ConfigurationInfo, Header, MemberId, MemberSet, ProtocolVersion, RslNode, Vote,
};

fn header(version: ProtocolVersion, decree: u64) -> CheckpointHeader {
    let vote = Vote::new(Header::new(
        version,
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
        0x0a0b_0c0d,
        decree + 1,
        MemberSet {
            members: vec![
                RslNode {
                    member_id: MemberId::from_str("101"),
                    ip: 0x0100_007f,
                    rsl_port: 8080,
                    rsl_learn_port: 8081,
                    app_port: 0,
                    host_name: b"host-a".to_vec(),
                },
                RslNode {
                    member_id: MemberId::from_str("202"),
                    ip: 0x0100_017f,
                    rsl_port: 9090,
                    rsl_learn_port: 9091,
                    app_port: 0,
                    host_name: b"host-b".to_vec(),
                },
            ],
            cookie: b"cfg".to_vec(),
        },
    ));
    header
}

#[test]
fn cpp_accepts_rust_written_checkpoints() {
    let Some(generator) = common::golden_gen() else {
        eprintln!(
            "cpp_accepts_rust_written_checkpoints: SKIPPED — golden-gen is not built \
             (cmake -S tools/golden-gen -B tools/golden-gen/build && cmake --build \
             tools/golden-gen/build), and RSL_GOLDEN_GEN is unset."
        );
        return;
    };
    let dir = common::TempDir::new("interop");
    let data_only = (CHECKSUM_BLOCK_SIZE - CHECKSUM_SIZE) as usize;

    // One sample per interesting shape, written with the real durability policy
    // (fsync file → rename → fsync directory), exactly as the engine would.
    let cases: Vec<(&str, ProtocolVersion, usize)> = vec![
        ("rust-v3-empty.codex", ProtocolVersion::V3, 0),
        ("rust-v4-empty.codex", ProtocolVersion::V4, 0),
        ("rust-v5-small.codex", ProtocolVersion::V5, 100),
        ("rust-v6-small.codex", ProtocolVersion::V6, 100),
        ("rust-v6-4mib.codex", ProtocolVersion::V6, data_only),
        (
            "rust-v6-4mib-plus1.codex",
            ProtocolVersion::V6,
            data_only + 1,
        ),
        (
            "rust-v6-multiblock.codex",
            ProtocolVersion::V6,
            data_only + 4096,
        ),
    ];

    let mut expected = Vec::new();
    for (i, (name, version, len)) in cases.iter().enumerate() {
        let path = dir.join(name);
        let state = common::ramp_state(*len);
        let mut writer =
            CheckpointWriter::create(&path, header(*version, 0x1000 + i as u64)).expect("create");
        writer.write_all(&state).expect("write");
        writer.finish().expect("finish");
        expected.push((*name, *version, *len as u64));
    }

    let output = Command::new(&generator)
        .arg("--verify-storage")
        .arg(dir.path())
        .output()
        .unwrap_or_else(|e| panic!("failed to run {}: {e}", generator.display()));
    assert!(
        output.status.success(),
        "golden-gen --verify-storage exited {}",
        output.status
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();

    for (name, version, len) in expected {
        // e.g. "rust-v6-small.codex: accept version=6 userData=100 (checkpoint valid)"
        let line = stdout
            .lines()
            .find(|l| l.starts_with(&format!("{name}:")))
            .unwrap_or_else(|| panic!("no verdict for {name} in:\n{stdout}"));
        assert!(
            line.contains(" accept "),
            "C++ rejected a Rust-written checkpoint: {line}"
        );
        assert!(
            line.contains(&format!("version={}", version.raw())),
            "wrong version reported: {line}"
        );
        assert!(
            line.contains(&format!("userData={len}")),
            "wrong recovered user-data size: {line}"
        );
    }
}

#[test]
fn cpp_rejects_a_corrupted_rust_checkpoint() {
    let Some(generator) = common::golden_gen() else {
        eprintln!("cpp_rejects_a_corrupted_rust_checkpoint: SKIPPED — golden-gen is not built.");
        return;
    };
    let dir = common::TempDir::new("interop-bad");
    let path = dir.join("corrupt.codex");

    let header = header(ProtocolVersion::V6, 0x9000);
    let header_len = header.marshal_len().unwrap() as usize;
    let mut writer = CheckpointWriter::create(&path, header).expect("create");
    writer.write_all(&common::ramp_state(4096)).expect("write");
    writer.finish().expect("finish");

    // Flip a user-data byte: the C++ must reject on the block checksum, and so
    // must we — the two readers agree on corrupt files, not just clean ones.
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[header_len + 17] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();

    assert_eq!(
        rsl_storage::checkpoint::verify_file(&path)
            .unwrap()
            .detail(),
        "block checksum mismatch"
    );

    let output = Command::new(&generator)
        .arg("--verify-storage")
        .arg(dir.path())
        .output()
        .expect("run golden-gen");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let line = stdout
        .lines()
        .find(|l| l.starts_with("corrupt.codex:"))
        .unwrap_or_else(|| panic!("no verdict in:\n{stdout}"));
    assert!(
        line.contains(" reject "),
        "C++ accepted a corrupt file: {line}"
    );
    assert!(
        line.contains("block checksum mismatch"),
        "C++ rejected for a different reason: {line}"
    );
}

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------

use rsl_storage::durability::NoSync;
use rsl_storage::log::{self, LogWriter};
use rsl_wire::messages::{MSG_PREPARE, MSG_RECONFIGURATION_DECISION};
use rsl_wire::{marshal_base, PrepareMsg};

fn log_header(msg_id: u16, decree: u64) -> Header {
    Header::new(
        ProtocolVersion::V6,
        msg_id,
        MemberId::from_str("101"),
        decree,
        7,
        BallotNumber::new(3, MemberId::from_str("202")),
        0,
    )
}

fn vote_record(decree: u64, request_len: usize) -> Vec<u8> {
    let mut vote = Vote::new(log_header(MSG_VOTE, decree));
    if request_len > 0 {
        vote.add_request(vec![b'r'; request_len]);
    }
    vote.marshal_with_checksum().unwrap()
}

/// The `--verify-storage` line for `name`, e.g.
/// `"7.log: accept records=3 stopOffset=2048 (all records valid to EOF)"`.
fn verdict_for<'a>(stdout: &'a str, name: &str) -> &'a str {
    stdout
        .lines()
        .find(|l| l.starts_with(&format!("{name}:")))
        .unwrap_or_else(|| panic!("no verdict for {name} in:\n{stdout}"))
}

fn verify_storage(generator: &std::path::Path, dir: &std::path::Path) -> String {
    let output = Command::new(generator)
        .arg("--verify-storage")
        .arg(dir)
        .output()
        .unwrap_or_else(|e| panic!("failed to run {}: {e}", generator.display()));
    assert!(
        output.status.success(),
        "golden-gen --verify-storage exited {}",
        output.status
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The extracted C++ reader accepts logs this crate writes, and reports the
/// same record count and stop offset the Rust scan does.
#[test]
fn cpp_accepts_rust_written_logs() {
    let Some(generator) = common::golden_gen() else {
        eprintln!("cpp_accepts_rust_written_logs: SKIPPED — golden-gen is not built.");
        return;
    };
    let dir = common::TempDir::new("interop-log");

    // One log per shape, each named after the first decree it holds.
    let cases: Vec<(u64, Vec<Vec<u8>>)> = vec![
        // Empty (a freshly opened log).
        (10, vec![]),
        // A single single-page vote.
        (20, vec![vote_record(20, 0)]),
        // Mixed record kinds, including a multi-page vote.
        (
            30,
            vec![
                PrepareMsg {
                    header: log_header(MSG_PREPARE, 30),
                    primary_cookie: Vec::new(),
                }
                .marshal_with_checksum(),
                vote_record(30, 0),
                vote_record(31, 600),
                marshal_base(&log_header(MSG_RECONFIGURATION_DECISION, 31)),
            ],
        ),
        // A long run, appended one record at a time.
        (
            40,
            (0..32)
                .map(|i| vote_record(40 + i, 40 * i as usize))
                .collect(),
        ),
    ];

    for (file_decree, records) in &cases {
        let mut writer = LogWriter::open(dir.path(), *file_decree).expect("open");
        for record in records {
            writer.append(record).expect("append");
        }
        writer.sync().expect("sync");
    }

    let stdout = verify_storage(&generator, dir.path());
    for (file_decree, records) in &cases {
        let name = format!("{file_decree}.log");
        let line = verdict_for(&stdout, &name);
        assert!(
            line.contains(" accept "),
            "C++ rejected a Rust-written log: {line}"
        );
        assert!(
            line.contains(&format!("records={}", records.len())),
            "wrong recovered record count: {line}"
        );

        let scan = log::scan_file(&dir.join(&name)).expect("scan");
        assert_eq!(scan.records.len(), records.len());
        assert!(
            line.contains(&format!("stopOffset={}", scan.stop_offset)),
            "C++ and Rust disagree on the stop offset: {line}"
        );
        assert!(
            line.contains(scan.detail()),
            "C++ and Rust disagree on the detail: {line}"
        );
    }
}

/// Damaged logs: both readers must reach the *same* verdict, not merely refuse
/// the file. Each case mirrors one Phase-3a corpus sample, built from the Rust
/// side this time.
#[test]
fn cpp_and_rust_agree_on_damaged_rust_logs() {
    let Some(generator) = common::golden_gen() else {
        eprintln!("cpp_and_rust_agree_on_damaged_rust_logs: SKIPPED — golden-gen is not built.");
        return;
    };
    let dir = common::TempDir::new("interop-log-bad");

    // Build one good two-record log, then damage copies of it.
    let mut writer = LogWriter::open_with(dir.path(), 1, NoSync).expect("open");
    writer.append(&vote_record(1, 0)).expect("append");
    writer.append(&vote_record(2, 0)).expect("append");
    drop(writer);
    let clean = std::fs::read(dir.join("1.log")).expect("read");
    std::fs::remove_file(dir.join("1.log")).expect("remove");

    // 2.log: a zero page after the records — the clean end of a log.
    let mut zero_tail = clean.clone();
    zero_tail.resize(clean.len() + rsl_storage::PAGE_SIZE as usize, 0);
    std::fs::write(dir.join("2.log"), &zero_tail).expect("write");

    // 3.log: a torn trailing record (header page plus a partial body).
    let torn = vote_record(3, 600);
    let mut torn_tail = clean.clone();
    torn_tail.extend_from_slice(&torn[..rsl_storage::PAGE_SIZE as usize + 188]);
    std::fs::write(dir.join("3.log"), &torn_tail).expect("write");

    // 4.log: a corrupt first record with a valid one behind it.
    let mut corrupt = clean.clone();
    corrupt[40] ^= 0xff;
    std::fs::write(dir.join("4.log"), &corrupt).expect("write");

    let stdout = verify_storage(&generator, dir.path());
    for name in ["2.log", "3.log", "4.log"] {
        let scan = log::scan_file(&dir.join(name)).expect("scan");
        let line = verdict_for(&stdout, name);
        assert!(
            line.contains(&format!(" {} ", scan.outcome())),
            "C++ and Rust disagree on the outcome for {name}: {line} vs {}",
            scan.outcome()
        );
        assert!(
            line.contains(&format!("records={}", scan.records.len())),
            "record count disagreement for {name}: {line}"
        );
        assert!(
            line.contains(&format!("stopOffset={}", scan.stop_offset)),
            "stop offset disagreement for {name}: {line}"
        );
        assert!(
            line.contains(scan.detail()),
            "detail disagreement for {name}: {line} vs {}",
            scan.detail()
        );
    }
}
