//! Phase-3a corpus tests: every C++-generated `.codex` sample must parse here
//! with the same outcome the MANIFEST recorded, and every accepted sample must
//! be reproduced **byte-for-byte** by the Rust writer.
//!
//! The corpus files are generated test data (not committed); see
//! `common::storage_corpus` for how they are located or regenerated.

mod common;

use std::io::Write;

use rsl_storage::checkpoint::{verify_file, CheckpointHeader, CheckpointReader, CheckpointWriter};
use rsl_storage::durability::NoSync;

#[test]
fn every_checkpoint_sample_matches_the_manifest() {
    let Some(corpus) = common::storage_corpus() else {
        common::warn_no_corpus("every_checkpoint_sample_matches_the_manifest");
        return;
    };

    let samples = common::checkpoint_samples(corpus);
    assert!(!samples.is_empty(), "MANIFEST has no checkpoint samples");

    for sample in &samples {
        let path = corpus.join(&sample.file);
        let bytes = std::fs::read(&path).expect("read sample");

        // The MANIFEST pins each file by size + Rabin-64 of the whole file; if
        // those match, this is exactly the file the C++ reader was run over.
        assert_eq!(bytes.len() as u64, sample.size, "{}: size", sample.name);
        assert_eq!(
            rsl_wire::fingerprint(&bytes),
            sample.fp64,
            "{}: fp64",
            sample.name
        );

        let verification = verify_file(&path).expect("verify");
        assert_eq!(
            verification.outcome(),
            sample.outcome,
            "{}: outcome ({})",
            sample.name,
            verification.detail()
        );
        assert_eq!(
            verification.detail(),
            sample.detail,
            "{}: detail",
            sample.name
        );
        assert_eq!(
            verification.version,
            Some(sample.version),
            "{}: version",
            sample.name
        );
        assert_eq!(
            verification.header_len, sample.header_len,
            "{}: headerLen",
            sample.name
        );
        assert_eq!(
            verification.user_data_size, sample.user_data_size,
            "{}: userDataSize",
            sample.name
        );
        assert_eq!(
            verification.checksum_block_size, sample.checksum_block_size,
            "{}: checksumBlockSize",
            sample.name
        );
        assert_eq!(
            verification.state_saved, sample.state_saved,
            "{}: stateSaved",
            sample.name
        );
    }
}

#[test]
fn accepted_samples_stream_back_their_user_state() {
    let Some(corpus) = common::storage_corpus() else {
        common::warn_no_corpus("accepted_samples_stream_back_their_user_state");
        return;
    };

    for sample in common::checkpoint_samples(corpus) {
        if sample.outcome != "accept" {
            continue;
        }
        let path = corpus.join(&sample.file);
        let mut reader = CheckpointReader::open(&path).expect("open");
        assert_eq!(
            reader.user_data_size(),
            sample.user_data_size,
            "{}: user_data_size",
            sample.name
        );

        let state = reader.read_all().expect("read state");
        assert_eq!(
            state.len() as u64,
            sample.state_len,
            "{}: recovered state length",
            sample.name
        );
        // The MANIFEST records the state as a reproducible pattern, so the bytes
        // themselves are checkable without shipping multi-MiB binaries.
        match sample.state_pattern.as_str() {
            "empty" => assert!(state.is_empty(), "{}: expected empty state", sample.name),
            "ramp" => assert_eq!(
                state,
                common::ramp_state(sample.state_len as usize),
                "{}: state bytes",
                sample.name
            ),
            other => panic!("{}: unknown statePattern {other:?}", sample.name),
        }
    }
}

#[test]
fn rust_writer_reproduces_accepted_samples_byte_for_byte() {
    let Some(corpus) = common::storage_corpus() else {
        common::warn_no_corpus("rust_writer_reproduces_accepted_samples_byte_for_byte");
        return;
    };
    let scratch = common::TempDir::new("rewrite");

    for sample in common::checkpoint_samples(corpus) {
        if sample.outcome != "accept" {
            continue;
        }
        let path = corpus.join(&sample.file);
        let original = std::fs::read(&path).expect("read sample");

        // Parse the header and user state out of the C++ file...
        let (header, state) = {
            let mut reader = CheckpointReader::open(&path).expect("open");
            let header = reader.header().clone();
            let state = reader.read_all().expect("read state");
            (header, state)
        };

        // ...then write a fresh checkpoint from them and compare the bytes. The
        // writer recomputes the header length, every block checksum and the file
        // size, so an exact match pins the whole layout, not just the payload.
        let out = scratch.join(&sample.file);
        let mut writer =
            CheckpointWriter::create_with(&out, header, NoSync).expect("create writer");
        writer.write_all(&state).expect("write state");
        let written_header = writer.finish().expect("finish");

        let rewritten = std::fs::read(&out).expect("read rewritten");
        assert_eq!(
            rewritten.len(),
            original.len(),
            "{}: rewritten size",
            sample.name
        );
        assert!(
            rewritten == original,
            "{}: rewritten bytes differ from the C++ file",
            sample.name
        );
        assert_eq!(
            written_header.size, sample.size,
            "{}: header size field",
            sample.name
        );
        std::fs::remove_file(&out).expect("cleanup");
    }
}

#[test]
fn header_blobs_of_the_corpus_re_marshal_exactly() {
    let Some(corpus) = common::storage_corpus() else {
        common::warn_no_corpus("header_blobs_of_the_corpus_re_marshal_exactly");
        return;
    };

    for sample in common::checkpoint_samples(corpus) {
        let bytes = std::fs::read(corpus.join(&sample.file)).expect("read sample");
        let header_len = sample.header_len as usize;
        if bytes.len() < header_len {
            continue; // truncated sample: nothing to compare against
        }
        let Some(header) = CheckpointHeader::unmarshal(&bytes[..header_len]) else {
            continue; // rejected header: covered by the outcome test
        };
        // ConfigurationInfo + the embedded vote round-trip byte-for-byte.
        assert_eq!(
            header.marshal().expect("re-marshal"),
            bytes[..header_len],
            "{}: header blob",
            sample.name
        );
        assert_eq!(header.un_marshal_len, sample.header_len);
    }
}
