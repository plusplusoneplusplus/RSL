//! Write→read properties and corruption (mutation) tests for checkpoints.
//!
//! These do not need the C++ corpus: they pin the Rust reader and writer against
//! each other and against the format's own arithmetic (block layout, file size,
//! per-block checksums). The corpus tests in `corpus.rs` are what tie the bytes
//! to the C++.

mod common;

use std::io::{Read, Write};

use proptest::prelude::*;
use rsl_storage::checkpoint::{
    reject_reason, CheckpointHeader, CheckpointReader, CheckpointWriter, RejectReason, WriteError,
};
use rsl_storage::durability::NoSync;
use rsl_storage::seqread::{SeqReaderConfig, SECTOR};
use rsl_storage::{round_up_to_page, CHECKSUM_BLOCK_SIZE, CHECKSUM_SIZE, PAGE_SIZE};
use rsl_wire::messages::MSG_VOTE;
use rsl_wire::{
    BallotNumber, ConfigurationInfo, Header, MemberId, MemberSet, ProtocolVersion, RslNode, Vote,
};

/// A v6 checkpoint header (optionally with a non-default block size).
fn header(version: ProtocolVersion, block_size: Option<u32>) -> CheckpointHeader {
    let vote = Vote::new(Header::new(
        version,
        MSG_VOTE,
        MemberId::from_str("101"),
        0x2001,
        7,
        BallotNumber::new(5, MemberId::from_str("202")),
        0,
    ));
    let mut header = CheckpointHeader::new(vote);
    header.member_id = MemberId::from_str("101");
    header.last_executed_decree = 0x2000;
    header.max_ballot = BallotNumber::new(9, MemberId::from_str("202"));
    header.state_configuration = Some(ConfigurationInfo::new(
        0x0a0b_0c0d,
        0x2001,
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
    if let Some(size) = block_size {
        header.checksum_block_size = size;
    }
    header
}

/// Write `state` as a checkpoint and return the file's bytes plus its path's dir.
fn write_checkpoint(dir: &common::TempDir, name: &str, header: CheckpointHeader, state: &[u8]) {
    let path = dir.join(name);
    let mut writer = CheckpointWriter::create_with(&path, header, NoSync).expect("create");
    writer.write_all(state).expect("write");
    writer.finish().expect("finish");
}

/// Expected on-disk size: header + state + one 8-byte checksum per block.
fn expected_file_size(header_len: u32, block_size: u32, state_len: u64) -> u64 {
    let data_only = u64::from(block_size - CHECKSUM_SIZE);
    let blocks = state_len.div_ceil(data_only);
    u64::from(header_len) + state_len + blocks * u64::from(CHECKSUM_SIZE)
}

#[test]
fn round_trips_across_the_4_mib_block_boundary() {
    let dir = common::TempDir::new("boundary");
    let data_only = u64::from(CHECKSUM_BLOCK_SIZE - CHECKSUM_SIZE);
    let sizes = [
        0,
        1,
        data_only - 1,
        data_only,
        data_only + 1,
        2 * data_only,
        2 * data_only + 50,
    ];

    for (i, &len) in sizes.iter().enumerate() {
        let state = common::ramp_state(len as usize);
        let header = header(ProtocolVersion::V6, None);
        let header_len = header.marshal_len().unwrap();
        let name = format!("boundary-{i}.codex");
        write_checkpoint(&dir, &name, header, &state);

        let path = dir.join(&name);
        let on_disk = std::fs::metadata(&path).unwrap().len();
        assert_eq!(
            on_disk,
            expected_file_size(header_len, CHECKSUM_BLOCK_SIZE, len),
            "file size for {len} user bytes"
        );

        let mut reader = CheckpointReader::open(&path).expect("open");
        assert_eq!(reader.header().size, on_disk);
        assert_eq!(reader.user_data_size(), len);
        assert_eq!(reader.read_all().expect("read"), state, "state for {len}");
        std::fs::remove_file(&path).unwrap();
    }
}

/// The reader's ring shape is a performance knob, never a correctness one.
///
/// Worth pinning separately from the default because the state does not start
/// on a sector boundary: `SeqReader::open_at` begins its reads below the
/// header's end and discards the prefix, so every combination of ring block and
/// header length exercises a different skip.
#[test]
fn checkpoints_read_back_at_any_ring_shape() {
    let dir = common::TempDir::new("ringshapes");
    let block = 4 * PAGE_SIZE;
    let state = common::ramp_state(3 * (block - CHECKSUM_SIZE) as usize + 991);

    let path = dir.join("shapes.codex");
    let mut writer =
        CheckpointWriter::create_with(&path, header(ProtocolVersion::V6, Some(block)), NoSync)
            .expect("create");
    writer.write_all(&state).expect("write");
    writer.finish().expect("finish");

    for (threads, slots, ring) in [
        (1, 2, SECTOR),
        (2, 4, SECTOR),
        (3, 3, SECTOR * 2),
        (8, 8, 1 << 20),
    ] {
        let mut reader = CheckpointReader::open_with(
            &path,
            SeqReaderConfig {
                threads,
                slots,
                block: ring,
            },
        )
        .expect("open");
        assert_eq!(reader.user_data_size(), state.len() as u64);
        assert_eq!(
            reader.read_all().expect("read"),
            state,
            "state at {threads}x{slots}x{ring}"
        );
    }
}

#[test]
fn many_small_writes_produce_the_same_file_as_one() {
    let dir = common::TempDir::new("chunked");
    // A small block size keeps the test cheap while still crossing boundaries.
    let block = 4 * PAGE_SIZE;
    let state = common::ramp_state(5 * (block - CHECKSUM_SIZE) as usize + 37);

    write_checkpoint(
        &dir,
        "one.codex",
        header(ProtocolVersion::V6, Some(block)),
        &state,
    );

    let path = dir.join("many.codex");
    let mut writer =
        CheckpointWriter::create_with(&path, header(ProtocolVersion::V6, Some(block)), NoSync)
            .expect("create");
    // Chunk sizes that are coprime-ish with the block size, so writes land at
    // every alignment relative to the block boundary.
    for chunk in state.chunks(1043) {
        writer.write_all(chunk).expect("write");
    }
    assert_eq!(writer.user_bytes(), state.len() as u64);
    writer.finish().expect("finish");

    assert_eq!(
        std::fs::read(dir.join("one.codex")).unwrap(),
        std::fs::read(&path).unwrap(),
        "chunked writes must produce identical bytes"
    );
}

#[test]
fn read_adapter_returns_the_same_bytes_in_any_chunk_size() {
    let dir = common::TempDir::new("chunked-read");
    let block = 4 * PAGE_SIZE;
    let state = common::ramp_state(3 * (block - CHECKSUM_SIZE) as usize + 11);
    write_checkpoint(
        &dir,
        "cp.codex",
        header(ProtocolVersion::V6, Some(block)),
        &state,
    );

    for chunk in [1usize, 7, 512, 4096, 1 << 20] {
        let mut reader = CheckpointReader::open(&dir.join("cp.codex")).expect("open");
        let mut out = Vec::new();
        let mut buf = vec![0u8; chunk];
        loop {
            let n = reader.read(&mut buf).expect("read");
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        assert_eq!(out, state, "chunked read of {chunk} bytes");
    }
}

#[test]
fn unblocked_v3_checkpoint_round_trips() {
    let dir = common::TempDir::new("v3");
    let state = common::ramp_state(9000);
    let header = header(ProtocolVersion::V3, None);
    assert!(!header.uses_blocks(), "v3 has no block checksums");
    let header_len = header.marshal_len().unwrap();
    write_checkpoint(&dir, "v3.codex", header, &state);

    let path = dir.join("v3.codex");
    // No per-block checksum tokens at v3: the state follows the header raw.
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        u64::from(header_len) + state.len() as u64
    );
    let mut reader = CheckpointReader::open(&path).expect("open");
    assert_eq!(reader.user_data_size(), state.len() as u64);
    assert_eq!(reader.read_all().expect("read"), state);
}

#[test]
fn every_block_data_flip_is_caught() {
    let dir = common::TempDir::new("flip-data");
    let block = 2 * PAGE_SIZE;
    let data_only = (block - CHECKSUM_SIZE) as usize;
    let state = common::ramp_state(2 * data_only + 100); // 3 blocks
    let header = header(ProtocolVersion::V6, Some(block));
    let header_len = header.marshal_len().unwrap() as usize;
    write_checkpoint(&dir, "cp.codex", header, &state);
    let good = std::fs::read(dir.join("cp.codex")).unwrap();

    // One flip in each block's data region, and one in each checksum token.
    let mut offsets = Vec::new();
    let mut off = header_len;
    while off < good.len() {
        let blk = (good.len() - off).min(block as usize);
        offsets.push(off); // first data byte
        offsets.push(off + blk - CHECKSUM_SIZE as usize - 1); // last data byte
        offsets.push(off + blk - 1); // inside the checksum token
        off += blk;
    }
    assert_eq!(offsets.len(), 9, "expected three blocks");

    let path = dir.join("mutant.codex");
    for offset in offsets {
        let mut bytes = good.clone();
        bytes[offset] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();

        let verification = rsl_storage::checkpoint::verify_file(&path).expect("verify");
        assert_eq!(
            verification.reject,
            Some(RejectReason::BlockChecksum),
            "flip at {offset} was not caught"
        );

        // The streaming API reports it too, as an InvalidData io::Error.
        let mut reader = CheckpointReader::open(&path).expect("open");
        let err = reader.read_all().expect_err("must fail");
        assert!(matches!(
            err,
            rsl_storage::checkpoint::CheckpointError::Reject(RejectReason::BlockChecksum)
        ));
    }
}

#[test]
fn header_and_size_corruption_is_caught() {
    let dir = common::TempDir::new("flip-header");
    let block = 2 * PAGE_SIZE;
    let state = common::ramp_state(300);
    let header = header(ProtocolVersion::V6, Some(block));
    let vote_offset = header.next_vote_offset().unwrap() as usize;
    write_checkpoint(&dir, "cp.codex", header, &state);
    let good = std::fs::read(dir.join("cp.codex")).unwrap();
    let path = dir.join("mutant.codex");

    let verify = |bytes: &[u8]| {
        std::fs::write(&path, bytes).unwrap();
        rsl_storage::checkpoint::verify_file(&path)
            .expect("verify")
            .reject
    };

    // Version field: no longer a valid protocol version.
    let mut bytes = good.clone();
    bytes[0] = 0x7f;
    assert_eq!(verify(&bytes), Some(RejectReason::InvalidVersion));

    // A field inside the header body — the embedded vote's Rabin-64 covers the
    // vote, and the vote is what the header's integrity rests on.
    let mut bytes = good.clone();
    bytes[vote_offset + 32] ^= 0xff;
    assert_eq!(verify(&bytes), Some(RejectReason::HeaderUnmarshal));

    // The declared size no longer matches the file.
    let mut bytes = good.clone();
    bytes.truncate(bytes.len() - 1);
    assert_eq!(verify(&bytes), Some(RejectReason::SizeMismatch));

    // Extending the file also breaks the size cross-check.
    let mut bytes = good.clone();
    bytes.extend_from_slice(&[0u8; 16]);
    assert_eq!(verify(&bytes), Some(RejectReason::SizeMismatch));

    // Shorter than one page.
    assert_eq!(verify(&good[..100]), Some(RejectReason::ShortFile));

    // A header length field larger than the file.
    let mut bytes = good.clone();
    bytes[2..6].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(verify(&bytes), Some(RejectReason::TruncatedHeader));
}

#[test]
fn a_trailing_block_too_small_for_its_checksum_is_rejected() {
    // Fill exactly one block, then append 4 stray bytes and patch the declared
    // size so the file-size check passes: the block walk is then what rejects.
    let dir = common::TempDir::new("short-block");
    let block = 2 * PAGE_SIZE;
    let header = header(ProtocolVersion::V6, Some(block));
    let vote_offset = header.next_vote_offset().unwrap() as usize;
    let state = common::ramp_state((block - CHECKSUM_SIZE) as usize);
    write_checkpoint(&dir, "cp.codex", header, &state);

    let mut bytes = std::fs::read(dir.join("cp.codex")).unwrap();
    bytes.extend_from_slice(&[0u8; 4]);
    // `m_size` sits between the stateSaved byte and the block size, i.e. 12
    // bytes before the embedded vote.
    let size_offset = vote_offset - 12;
    let len = bytes.len() as u64;
    bytes[size_offset..size_offset + 8].copy_from_slice(&len.to_le_bytes());

    let path = dir.join("short.codex");
    std::fs::write(&path, &bytes).unwrap();
    assert_eq!(
        rsl_storage::checkpoint::verify_file(&path).unwrap().reject,
        Some(RejectReason::BlockTooShort)
    );
}

#[test]
fn a_dropped_writer_leaves_nothing_behind() {
    let dir = common::TempDir::new("dropped");
    let path = dir.join("cp.codex");
    {
        let mut writer =
            CheckpointWriter::create_with(&path, header(ProtocolVersion::V6, None), NoSync)
                .expect("create");
        writer.write_all(b"partial state").expect("write");
        // Dropped without `finish`.
    }
    assert!(!path.exists(), "no checkpoint should be published");
    let tmp = dir.join("cp.codex.tmp");
    assert!(!tmp.exists(), "the temporary file should be removed");
}

#[test]
fn the_final_file_only_appears_on_finish() {
    let dir = common::TempDir::new("atomic");
    let path = dir.join("cp.codex");
    let mut writer =
        CheckpointWriter::create_with(&path, header(ProtocolVersion::V6, None), NoSync)
            .expect("create");
    writer.write_all(&common::ramp_state(1000)).expect("write");
    writer.flush().expect("flush");
    assert!(!path.exists(), "nothing is published before finish");
    assert!(dir.join("cp.codex.tmp").exists(), "staged under .tmp");
    writer.finish().expect("finish");
    assert!(path.exists());
    assert!(
        !dir.join("cp.codex.tmp").exists(),
        "the .tmp is renamed away"
    );
}

#[test]
fn bad_block_sizes_are_refused_by_the_writer() {
    let dir = common::TempDir::new("bad-block");
    // Not a multiple of the page size — the C++ LogAsserts here.
    let err = CheckpointWriter::create_with(
        &dir.join("a.codex"),
        header(ProtocolVersion::V6, Some(PAGE_SIZE + 1)),
        NoSync,
    )
    .expect_err("must be refused");
    assert!(matches!(
        err,
        rsl_storage::checkpoint::CheckpointError::Write(WriteError::BlockSizeNotPageMultiple(_))
    ));
    assert!(!dir.join("a.codex.tmp").exists(), "nothing is created");

    // A v>=3 header without a configuration has no on-disk form.
    let mut no_config = header(ProtocolVersion::V6, None);
    no_config.state_configuration = None;
    let err = CheckpointWriter::create_with(&dir.join("b.codex"), no_config, NoSync)
        .expect_err("must be refused");
    assert!(matches!(
        err,
        rsl_storage::checkpoint::CheckpointError::Write(WriteError::MissingConfiguration)
    ));
}

#[test]
fn reject_reason_survives_the_io_error_wrapper() {
    let dir = common::TempDir::new("io-error");
    let block = 2 * PAGE_SIZE;
    let state = common::ramp_state(600);
    let header = header(ProtocolVersion::V6, Some(block));
    let header_len = header.marshal_len().unwrap() as usize;
    write_checkpoint(&dir, "cp.codex", header, &state);

    let path = dir.join("cp.codex");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[header_len + 5] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();

    let mut reader = CheckpointReader::open(&path).expect("open");
    let mut sink = Vec::new();
    let err = std::io::copy(&mut reader, &mut sink).expect_err("must fail");
    assert_eq!(reject_reason(&err), Some(RejectReason::BlockChecksum));
}

proptest! {
    /// Any user-state length round-trips byte-for-byte, at any legal block size,
    /// with the file size and recovered user-data size the format predicts.
    #[test]
    fn arbitrary_state_round_trips(
        len in 0usize..9000,
        blocks in 1u32..5,
        version in prop::sample::select(vec![ProtocolVersion::V4, ProtocolVersion::V5, ProtocolVersion::V6]),
    ) {
        let dir = common::TempDir::new("prop");
        let block_size = blocks * PAGE_SIZE;
        let state = common::ramp_state(len);
        let header = header(version, Some(block_size));
        let header_len = header.marshal_len().unwrap();
        prop_assert!(header_len.is_multiple_of(PAGE_SIZE));
        prop_assert_eq!(header_len, round_up_to_page(header_len));

        let path = dir.join("prop.codex");
        let mut writer = CheckpointWriter::create_with(&path, header, NoSync).unwrap();
        writer.write_all(&state).unwrap();
        let written = writer.finish().unwrap();

        let on_disk = std::fs::metadata(&path).unwrap().len();
        prop_assert_eq!(on_disk, expected_file_size(header_len, block_size, len as u64));
        prop_assert_eq!(written.size, on_disk);

        let mut reader = CheckpointReader::open(&path).unwrap();
        prop_assert_eq!(reader.user_data_size(), len as u64);
        prop_assert_eq!(reader.header().checksum_block_size, block_size);
        prop_assert_eq!(reader.read_all().unwrap(), state);
    }

    /// Flipping any single byte of the user-data region is always caught.
    #[test]
    fn any_single_bit_flip_in_user_data_is_caught(
        len in 1usize..3000,
        flip in 0usize..3000,
    ) {
        prop_assume!(flip < len);
        let dir = common::TempDir::new("prop-flip");
        let block_size = 2 * PAGE_SIZE;
        let state = common::ramp_state(len);
        let header = header(ProtocolVersion::V6, Some(block_size));
        let header_len = header.marshal_len().unwrap() as usize;

        let path = dir.join("prop.codex");
        let mut writer = CheckpointWriter::create_with(&path, header, NoSync).unwrap();
        writer.write_all(&state).unwrap();
        writer.finish().unwrap();

        // Map the user-state index to its file offset (blocks carry a checksum).
        let data_only = (block_size - CHECKSUM_SIZE) as usize;
        let offset = header_len
            + (flip / data_only) * block_size as usize
            + (flip % data_only);

        let mut bytes = std::fs::read(&path).unwrap();
        bytes[offset] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();

        let verification = rsl_storage::checkpoint::verify_file(&path).unwrap();
        prop_assert_eq!(verification.reject, Some(RejectReason::BlockChecksum));
    }
}
