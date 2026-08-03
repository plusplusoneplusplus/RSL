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
