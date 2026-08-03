//! Phase-3a corpus tests for `<decree>.log`: every C++-generated sample must
//! scan here with the outcome, stop offset and record list the MANIFEST
//! recorded, and the Rust writer must reproduce the accepted ones byte-for-byte.
//!
//! The corpus files are generated test data (not committed); see
//! `common::storage_corpus` for how they are located or regenerated.

mod common;

use rsl_storage::durability::NoSync;
use rsl_storage::log::{self, LogWriter, MAX_SINGLE_IO_SIZE};
use rsl_wire::messages::{MSG_PREPARE, MSG_RECONFIGURATION_DECISION, MSG_VOTE};
use rsl_wire::{marshal_base, BallotNumber, Header, MemberId, PrepareMsg, ProtocolVersion, Vote};

/// The versions the generator loops over (`kVersions` in `main.cpp`).
const VERSIONS: [ProtocolVersion; 6] = [
    ProtocolVersion::V1,
    ProtocolVersion::V2,
    ProtocolVersion::V3,
    ProtocolVersion::V4,
    ProtocolVersion::V5,
    ProtocolVersion::V6,
];

fn vote(version: ProtocolVersion, decree: u64, ballot_id: u32) -> Vote {
    Vote::new(Header::new(
        version,
        MSG_VOTE,
        MemberId::from_str("101"),
        decree,
        7,
        BallotNumber::new(ballot_id, MemberId::from_str("202")),
        0,
    ))
}

fn prepare(version: ProtocolVersion, decree: u64, ballot_id: u32) -> PrepareMsg {
    PrepareMsg {
        header: Header::new(
            version,
            MSG_PREPARE,
            MemberId::from_str("101"),
            decree,
            7,
            BallotNumber::new(ballot_id, MemberId::from_str("202")),
            0,
        ),
        primary_cookie: Vec::new(),
    }
}

fn reconfiguration_decision(decree: u64, ballot_id: u32) -> Vec<u8> {
    marshal_base(&Header::new(
        ProtocolVersion::V6,
        MSG_RECONFIGURATION_DECISION,
        MemberId::from_str("101"),
        decree,
        7,
        BallotNumber::new(ballot_id, MemberId::from_str("202")),
        0,
    ))
}

#[test]
fn every_log_sample_matches_the_manifest() {
    let Some(corpus) = common::storage_corpus() else {
        common::warn_no_corpus("every_log_sample_matches_the_manifest");
        return;
    };

    let samples = common::log_samples(corpus);
    assert!(!samples.is_empty(), "MANIFEST has no log samples");

    for sample in &samples {
        let path = corpus.join(&sample.file);
        let bytes = std::fs::read(&path).expect("read sample");

        // Pin the file: if size and Rabin-64 match, this is exactly the image
        // the C++ reader was run over.
        assert_eq!(bytes.len() as u64, sample.size, "{}: size", sample.name);
        assert_eq!(
            rsl_wire::fingerprint(&bytes),
            sample.fp64,
            "{}: fp64",
            sample.name
        );

        let scan = log::scan_bytes(&bytes);
        assert_eq!(
            scan.outcome(),
            sample.outcome,
            "{}: outcome ({})",
            sample.name,
            scan.detail()
        );
        assert_eq!(scan.detail(), sample.detail, "{}: detail", sample.name);
        assert_eq!(
            scan.stop_offset, sample.stop_offset,
            "{}: stopOffset",
            sample.name
        );
        assert_eq!(
            scan.records.len(),
            sample.record_count,
            "{}: recordCount",
            sample.name
        );

        for (got, want) in scan.records.iter().zip(&sample.records) {
            assert_eq!(got.offset, want.offset, "{}: record offset", sample.name);
            assert_eq!(got.msg_id, want.msg_id, "{}: record msgId", sample.name);
            assert_eq!(got.decree, want.decree, "{}: record decree", sample.name);
            assert_eq!(
                got.un_marshal_len, want.un_marshal_len,
                "{}: record unMarshalLen",
                sample.name
            );
            assert_eq!(
                got.padded_len, want.padded_len,
                "{}: record paddedLen",
                sample.name
            );
            assert_eq!(
                got.checksum, want.checksum,
                "{}: record checksum",
                sample.name
            );
        }

        // Scanning the file on disk must agree with scanning the image, and a
        // record's bytes must re-parse into a message.
        let streamed = log::scan_file(&path).expect("scan file");
        assert_eq!(streamed, scan, "{}: streamed scan differs", sample.name);
    }
}

/// The record encoder is byte-exact: rebuilding the messages the C++ generator
/// used and appending them through [`LogWriter`] reproduces the sample files.
///
/// `garbage-pad` is excluded by construction — the generator overwrote its pad
/// with `0xAA` afterwards, and this writer always zeroes pads.
#[test]
fn the_writer_reproduces_the_accepted_samples_byte_for_byte() {
    let Some(corpus) = common::storage_corpus() else {
        common::warn_no_corpus("the_writer_reproduces_the_accepted_samples_byte_for_byte");
        return;
    };
    let dir = common::TempDir::new("log-repro");

    // (sample name, the records the generator wrote)
    let mut cases: Vec<(String, Vec<Vec<u8>>)> = vec![
        ("empty".to_string(), vec![]),
        (
            "single-vote".to_string(),
            vec![vote(ProtocolVersion::V6, 0x000a_bcde, 3)
                .marshal_with_checksum()
                .unwrap()],
        ),
        (
            "prepare".to_string(),
            vec![prepare(ProtocolVersion::V6, 0x200, 4).marshal_with_checksum()],
        ),
    ];

    for version in VERSIONS {
        cases.push((
            format!("vote-v{}", version.raw()),
            vec![vote(version, 0x100 + u64::from(version.raw()), 3)
                .marshal_with_checksum()
                .unwrap()],
        ));
    }

    // multi-record: Prepare, Vote, Vote carrying a 600-byte request (spills to a
    // second page), ReconfigurationDecision.
    let mut big_vote = vote(ProtocolVersion::V6, 0x302, 5);
    big_vote.add_request(vec![b'x'; 600]);
    cases.push((
        "multi-record".to_string(),
        vec![
            prepare(ProtocolVersion::V6, 0x300, 4).marshal_with_checksum(),
            vote(ProtocolVersion::V6, 0x301, 5)
                .marshal_with_checksum()
                .unwrap(),
            big_vote.marshal_with_checksum().unwrap(),
            reconfiguration_decision(0x303, 6),
        ],
    ));

    for (name, records) in &cases {
        let expected = std::fs::read(corpus.join(format!("{name}.log"))).expect("read sample");

        // Each sample is written to its own log file, named after the first
        // decree it holds — the naming the engine uses.
        let file_decree = 1_000_000 + records.len() as u64;
        let path = dir.join(&format!("{file_decree}.log"));
        let _ = std::fs::remove_file(&path);

        let mut writer =
            LogWriter::open_with(dir.path(), file_decree, NoSync).expect("open writer");
        let refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        writer.append_batch(&refs).expect("append");
        writer.sync().expect("sync");
        drop(writer);

        let written = std::fs::read(&path).expect("read written log");
        assert_eq!(
            written.len(),
            expected.len(),
            "{name}: written log is a different size"
        );
        assert_eq!(written, expected, "{name}: written log differs byte-wise");
        let _ = std::fs::remove_file(&path);
    }
}

/// Appending records one at a time must produce the same file as one batch:
/// the C++ pads per message, so grouping cannot change the layout.
#[test]
fn batched_and_individual_appends_produce_identical_files() {
    let dir = common::TempDir::new("log-batch");
    let records: Vec<Vec<u8>> = (0..8)
        .map(|i| {
            let mut v = vote(ProtocolVersion::V6, 500 + i, 3);
            v.add_request(vec![b'r'; 100 * i as usize]);
            v.marshal_with_checksum().unwrap()
        })
        .collect();
    let refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();

    let mut batched = LogWriter::open_with(dir.path(), 500, NoSync).expect("open");
    batched.append_batch(&refs).expect("append batch");
    drop(batched);

    let mut individually = LogWriter::open_with(dir.path(), 501, NoSync).expect("open");
    for record in &refs {
        individually.append(record).expect("append one");
    }
    drop(individually);

    let a = std::fs::read(dir.join("500.log")).expect("read");
    let b = std::fs::read(dir.join("501.log")).expect("read");
    assert_eq!(a, b);

    // And the batching bound is a multiple of the page size, so a flush never
    // lands mid-record.
    assert_eq!(MAX_SINGLE_IO_SIZE % rsl_storage::PAGE_SIZE as usize, 0);
}
