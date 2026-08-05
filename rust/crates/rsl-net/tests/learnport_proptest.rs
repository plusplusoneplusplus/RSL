//! Property and boundary tests for the learn port.
//!
//! Two families:
//!
//! * **`fetch_votes` over generated log sets** — arbitrary numbers of files,
//!   records per file and record sizes, requesting every decree in turn. What
//!   comes off the socket must equal what `rsl-storage` reads off the files, in
//!   order, for *every* starting decree — including the ones at file
//!   boundaries and behind an empty trailing log.
//! * **`fetch_checkpoint` across block boundaries** — user-state sizes chosen
//!   to straddle the 4 MiB checksum-block edge (and the page edge under a
//!   shrunken block size), where the copy's byte count and the reader's block
//!   walk are most likely to disagree.

mod learnfixture;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use learnfixture::{header, vote_record, write_checkpoint, write_log_records, StubStatus, TempDir};
use proptest::prelude::*;
use rsl_net::learnport::{DirSource, LearnClient, LearnConfig, LearnServer, Requester};
use rsl_storage::checkpoint::{CheckpointHeader, CheckpointWriter};
use rsl_storage::durability::NoSync;
use rsl_storage::log::LogSet;
use rsl_wire::messages::MSG_VOTE;
use rsl_wire::{BallotNumber, MemberId, ProtocolVersion, Vote};

fn requester() -> Requester {
    Requester::new(ProtocolVersion::V6, MemberId::from_str("102"), 7)
}

fn ballot() -> BallotNumber {
    BallotNumber::new(3, MemberId::from_str("202"))
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

async fn serve(dir: &TempDir) -> LearnServer {
    LearnServer::bind(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        Arc::new(DirSource::new(dir.path(), StubStatus::new())),
        LearnConfig::default(),
    )
    .await
    .expect("bind")
}

/// What the files say a `FetchVotes(decree)` response must be: `(msg_id,
/// decree, un_marshal_len)` per record, in order.
fn expected(dir: &TempDir, from: u64) -> Vec<(u16, u64, u32)> {
    let logs = LogSet::open(dir.path()).expect("open log set");
    let Some(spans) = logs.votes_from(from) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for span in spans {
        let bytes = std::fs::read(&span.path).expect("read log");
        let region = &bytes[span.offset as usize..(span.offset + span.len) as usize];
        for record in &rsl_storage::log::scan_bytes(region).records {
            out.push((record.msg_id, record.decree, record.un_marshal_len));
        }
    }
    out
}

/// Fetch from `decree` and collect what actually arrived.
async fn fetch(addr: SocketAddr, from: u64) -> Vec<(u16, u64, u32)> {
    let mut stream = LearnClient::new()
        .fetch_votes(addr, &requester().fetch_votes(from, ballot()))
        .await
        .expect("connect");
    let mut out = Vec::new();
    while let Some(msg) = stream.next().await.expect("vote stream") {
        let h = msg.header();
        out.push((h.msg_id, h.decree, h.un_marshal_len));
    }
    out
}

// ---------------------------------------------------------------------------
// fetch_votes over generated log sets
// ---------------------------------------------------------------------------

/// A log set described by how many records go in each file, and how big each
/// record's client request is. Decrees run consecutively across the whole set,
/// which is the only shape the decree index accepts.
fn a_log_set() -> impl Strategy<Value = Vec<Vec<usize>>> {
    // 1..=4 files, 0..=4 records each, request sizes that cross page boundaries.
    proptest::collection::vec(
        proptest::collection::vec(
            prop_oneof![Just(0usize), Just(340), Just(700), Just(1500)],
            0..5,
        ),
        1..5,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Every decree in the set can be fetched, and the response is exactly the
    /// records at and after it — the same bytes `rsl-storage` reads directly.
    #[test]
    fn fetch_votes_matches_the_files_for_every_starting_decree(shape in a_log_set()) {
        let dir = TempDir::new("learn-prop-votes");
        let mut decree = 100u64;
        let mut all_decrees = Vec::new();
        let mut file_decrees = Vec::new();

        for file in &shape {
            let file_decree = decree;
            let records: Vec<Vec<u8>> = file
                .iter()
                .map(|&len| {
                    let record = vote_record(decree, len);
                    all_decrees.push(decree);
                    decree += 1;
                    record
                })
                .collect();
            // An empty file is a legal shape (a log rolled over but never
            // written), and it must contribute nothing to a response.
            write_log_records(dir.path(), file_decree, &records);
            file_decrees.push(file_decree);
        }

        runtime().block_on(async {
            let server = serve(&dir).await;
            let addr = server.local_addr();

            for &from in &all_decrees {
                let want = expected(&dir, from);
                prop_assert!(!want.is_empty(), "decree {from} is in the set");
                prop_assert_eq!(fetch(addr, from).await, want, "from decree {}", from);
            }

            // One past the end, and one before the start, are both refused.
            prop_assert!(fetch(addr, 99).await.is_empty());
            prop_assert!(fetch(addr, decree).await.is_empty());
            Ok(())
        })?;
    }
}

/// The boundary cases spelled out, so a failure names which one broke: the
/// offset landing in the first, middle and last file, a decree exactly at a
/// file boundary, and an empty trailing log.
#[test]
fn fetch_votes_handles_every_file_boundary() {
    let dir = TempDir::new("learn-bounds");
    write_log_records(dir.path(), 10, &[vote_record(10, 0), vote_record(11, 700)]);
    write_log_records(dir.path(), 12, &[vote_record(12, 0), vote_record(13, 0)]);
    write_log_records(dir.path(), 14, &[vote_record(14, 1500)]);
    // An empty trailing log: the file exists, holds no decree, and must not
    // change any response.
    write_log_records(dir.path(), 15, &[]);

    runtime().block_on(async {
        let server = serve(&dir).await;
        let addr = server.local_addr();

        for from in 10..=14u64 {
            let want = expected(&dir, from);
            assert_eq!(want.len(), (15 - from) as usize, "from {from}");
            assert_eq!(fetch(addr, from).await, want, "from {from}");
        }

        // The empty trailing file holds nothing, so 15 is not fetchable.
        assert!(fetch(addr, 15).await.is_empty());
        assert!(LogSet::open(dir.path()).unwrap().holding(15).is_none());
    });
}

/// A re-vote (a higher ballot for the same decree) leaves two records for that
/// decree in the file; the index points at the *last* one, so that is where the
/// response starts. Everything before it is history the learner must not get.
#[test]
fn fetch_votes_starts_at_the_latest_record_for_a_re_voted_decree() {
    let dir = TempDir::new("learn-revote");
    let mut second = Vote::new(header(MSG_VOTE, 21));
    second.header.ballot = BallotNumber::new(9, MemberId::from_str("202"));
    write_log_records(
        dir.path(),
        20,
        &[
            vote_record(20, 0),
            vote_record(21, 0),
            second.marshal_with_checksum().expect("marshal"),
            vote_record(22, 0),
        ],
    );

    runtime().block_on(async {
        let server = serve(&dir).await;
        let got = fetch(server.local_addr(), 21).await;
        // The superseded record for decree 21 is not sent.
        assert_eq!(got.len(), 2, "got {got:?}");
        assert_eq!(got[0].1, 21);
        assert_eq!(got[1].1, 22);
        assert_eq!(got, expected(&dir, 21));
    });
}

// ---------------------------------------------------------------------------
// fetch_checkpoint across block boundaries
// ---------------------------------------------------------------------------

/// Sizes that straddle the boundaries the checkpoint format cares about: the
/// page, the checksum block, and the block minus its 8-byte checksum token.
#[test]
fn fetch_checkpoint_survives_block_and_page_boundaries() {
    // A shrunken (but still page-multiple) block size keeps the interesting
    // arithmetic while keeping the test fast; `rsl-storage`'s own corpus tests
    // cover the real 4 MiB constant.
    const BLOCK: u32 = 4096;
    let interesting = [
        0usize,
        1,
        511,
        512,
        513,
        (BLOCK - 8 - 1) as usize,
        (BLOCK - 8) as usize,
        (BLOCK - 8 + 1) as usize,
        (2 * (BLOCK - 8)) as usize,
        (2 * (BLOCK - 8) + 7) as usize,
    ];

    runtime().block_on(async {
        for (i, &len) in interesting.iter().enumerate() {
            let source = TempDir::new("learn-cp-bounds-src");
            let dest = TempDir::new("learn-cp-bounds-dst");
            let decree = 500 + i as u64;
            let state: Vec<u8> = (0..len).map(|b| (b % 251) as u8).collect();

            let mut vote = Vote::new(header(MSG_VOTE, decree + 1));
            vote.primary_cookie = Vec::new();
            let mut cp = CheckpointHeader::new(vote);
            cp.member_id = MemberId::from_str("101");
            cp.state_configuration = Some(learnfixture::configuration());
            cp.checksum_block_size = BLOCK;

            let path = source.join(&format!("{decree}.codex"));
            let mut writer =
                CheckpointWriter::create_with(&path, cp, NoSync).expect("create codex");
            std::io::Write::write_all(&mut writer, &state).expect("write state");
            let size = writer.finish().expect("finish").size;

            let server = LearnServer::bind(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                Arc::new(DirSource::new(
                    source.path(),
                    StubStatus::new().with_checkpoint(decree, size),
                )),
                LearnConfig::default(),
            )
            .await
            .expect("bind");

            let fetched = LearnClient::new()
                .fetch_checkpoint(
                    server.local_addr(),
                    &requester().fetch_checkpoint(decree),
                    size,
                    dest.path(),
                )
                .await
                .unwrap_or_else(|e| panic!("state of {len} bytes: {e}"));

            assert_eq!(
                std::fs::read(&fetched.path).expect("read copy"),
                std::fs::read(&path).expect("read source"),
                "state of {len} bytes copied wrong"
            );
            let verification = rsl_storage::checkpoint::verify_file(&fetched.path).expect("verify");
            assert!(
                verification.accepted(),
                "state of {len} bytes: {verification:?}"
            );
            assert_eq!(verification.user_data_size, len as u64);
        }
    });
}

/// The streaming chunk size must not change a single byte, whatever it is —
/// including one that divides the file exactly and one that is larger than it.
#[test]
fn the_streaming_chunk_size_does_not_change_the_bytes() {
    let source = TempDir::new("learn-cp-chunks-src");
    let state: Vec<u8> = (0..20_000u32).map(|i| i as u8).collect();
    let size = write_checkpoint(source.path(), 500, &state);
    let original = std::fs::read(source.join("500.codex")).expect("read source");

    runtime().block_on(async {
        for chunk in [512usize, 4096, 10_000, size as usize, size as usize * 2] {
            let dest = TempDir::new("learn-cp-chunks-dst");
            let config = LearnConfig {
                stream_chunk: chunk,
                ..LearnConfig::default()
            };

            let server = LearnServer::bind(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                Arc::new(DirSource::new(
                    source.path(),
                    StubStatus::new().with_checkpoint(500, size),
                )),
                config.clone(),
            )
            .await
            .expect("bind");

            let fetched = LearnClient::with_config(config)
                .fetch_checkpoint(
                    server.local_addr(),
                    &requester().fetch_checkpoint(500),
                    size,
                    dest.path(),
                )
                .await
                .unwrap_or_else(|e| panic!("chunk {chunk}: {e}"));
            assert_eq!(
                std::fs::read(&fetched.path).expect("read copy"),
                original,
                "chunk {chunk}"
            );
        }
    });
}
