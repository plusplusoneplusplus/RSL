//! The learn port talking to itself: the Rust server serving real
//! `rsl-storage` files to the Rust client, and every way that can go wrong.
//!
//! The C++ interop lives in `learnport_interop.rs`; this file pins the contract
//! that interop then confirms — including the parts the wire cannot express, in
//! particular that *every* refusal is an empty stream.

mod learnfixture;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use learnfixture::{
    decision_record, prepare_record, vote_record, write_checkpoint, write_log, write_log_records,
    StubStatus, TempDir,
};
use rsl_net::learnport::client::RecordError;
use rsl_net::learnport::{
    DirSource, LearnClient, LearnConfig, LearnServer, LearnSource, Requester, TransferError,
};
use rsl_storage::log::LogSet;
use rsl_wire::messages::{MSG_PREPARE, MSG_RECONFIGURATION_DECISION, MSG_VOTE};
use rsl_wire::{BallotNumber, MemberId, Msg, ProtocolVersion};

fn requester() -> Requester {
    Requester::new(ProtocolVersion::V6, MemberId::from_str("102"), 7)
}

fn ballot() -> BallotNumber {
    BallotNumber::new(3, MemberId::from_str("202"))
}

/// Start a server over `dir` with `status`, on an ephemeral loopback port.
async fn serve(dir: &TempDir, status: StubStatus) -> LearnServer {
    serve_source(Arc::new(DirSource::new(dir.path(), status))).await
}

async fn serve_source(source: Arc<dyn LearnSource>) -> LearnServer {
    LearnServer::bind(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        source,
        LearnConfig::default(),
    )
    .await
    .expect("bind learn port")
}

/// Drain a vote stream into the messages it carried.
async fn drain(stream: &mut rsl_net::learnport::VoteStream) -> Result<Vec<Msg>, TransferError> {
    let mut out = Vec::new();
    while let Some(msg) = stream.next().await? {
        out.push(msg);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// StatusQuery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn status_query_returns_the_engine_state() {
    let dir = TempDir::new("learn-status");
    let server = serve(
        &dir,
        StubStatus::new()
            .with_checkpoint(500, 4096)
            .with_log_range(100, 620),
    )
    .await;

    let request = requester().status_query();
    let status = LearnClient::new()
        .query_status(server.local_addr(), &request)
        .await
        .expect("status query");

    assert_eq!(status.min_decree_in_log, 100);
    assert_eq!(status.checkpointed_decree, 500);
    assert_eq!(status.checkpoint_size, 4096);
    // `resp.m_queryDecree = msg->m_decree` — the response echoes the query.
    assert_eq!(status.query_decree, request.decree);
    assert_eq!(status.header.decree, 620);
}

#[tokio::test]
async fn a_relinquishing_primary_closes_without_a_word() {
    let dir = TempDir::new("learn-relinquish");
    let server = serve(&dir, StubStatus::new().relinquishing()).await;

    let err = LearnClient::new()
        .query_status(server.local_addr(), &requester().status_query())
        .await
        .expect_err("must not answer");
    assert!(matches!(err, TransferError::Closed), "got {err:?}");
}

/// A message id the port does not serve is dropped, exactly like an unknown
/// one: no reply, no diagnostic (`legislator.cpp:5360`).
#[tokio::test]
async fn an_unserved_message_id_gets_no_reply() {
    let dir = TempDir::new("learn-unknown-id");
    let server = serve(&dir, StubStatus::new()).await;

    let mut request = requester().status_query();
    request.msg_id = rsl_wire::messages::MSG_VOTE_ACCEPTED;
    let err = LearnClient::new()
        .query_status(server.local_addr(), &request)
        .await
        .expect_err("must not answer");
    assert!(matches!(err, TransferError::Closed), "got {err:?}");
}

// ---------------------------------------------------------------------------
// FetchVotes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fetch_votes_streams_every_record_from_the_decree_on() {
    let dir = TempDir::new("learn-votes");
    write_log(dir.path(), 100, &[100, 101, 102, 103], 0);
    let server = serve(&dir, StubStatus::new().with_log_range(100, 103)).await;

    let request = requester().fetch_votes(101, ballot());
    let mut stream = LearnClient::new()
        .fetch_votes(server.local_addr(), &request)
        .await
        .expect("fetch votes");
    let messages = drain(&mut stream).await.expect("stream");

    let decrees: Vec<u64> = messages.iter().map(|m| m.header().decree).collect();
    assert_eq!(decrees, vec![101, 102, 103]);
    // Every record is a Vote, parsed as one (not as a bare header).
    assert!(messages.iter().all(|m| matches!(m, Msg::Vote(_))));
}

/// The response spans several files: the holding one from an offset, then every
/// later one whole (`legislator.cpp:3663-3676`).
#[tokio::test]
async fn fetch_votes_crosses_log_files() {
    let dir = TempDir::new("learn-votes-multifile");
    write_log(dir.path(), 100, &[100, 101, 102], 0);
    write_log(dir.path(), 103, &[103, 104], 700); // multi-page records
    write_log(dir.path(), 105, &[105], 0);
    let server = serve(&dir, StubStatus::new().with_log_range(100, 105)).await;

    for from in [100u64, 101, 102, 103, 104, 105] {
        let request = requester().fetch_votes(from, ballot());
        let mut stream = LearnClient::new()
            .fetch_votes(server.local_addr(), &request)
            .await
            .expect("fetch votes");
        let decrees: Vec<u64> = drain(&mut stream)
            .await
            .expect("stream")
            .iter()
            .map(|m| m.header().decree)
            .collect();
        let expected: Vec<u64> = (from..=105).collect();
        assert_eq!(decrees, expected, "from decree {from}");
    }
}

/// The stream is the log's bytes, so a `Prepare` and a `ReconfigurationDecision`
/// interleaved with votes come through as themselves.
#[tokio::test]
async fn fetch_votes_carries_all_three_logged_kinds() {
    let dir = TempDir::new("learn-votes-kinds");
    write_log_records(
        dir.path(),
        200,
        &[
            // A prepare before the requested decree: it is behind the starting
            // offset, so it is *not* sent.
            prepare_record(200),
            vote_record(200, 0),
            // ... and one after it, which is.
            prepare_record(201),
            vote_record(201, 0),
            decision_record(201),
            vote_record(202, 0),
        ],
    );
    let server = serve(&dir, StubStatus::new().with_log_range(200, 202)).await;

    let request = requester().fetch_votes(200, ballot());
    let mut stream = LearnClient::new()
        .fetch_votes(server.local_addr(), &request)
        .await
        .expect("fetch votes");
    let messages = drain(&mut stream).await.expect("stream");

    let ids: Vec<u16> = messages.iter().map(|m| m.header().msg_id).collect();
    assert_eq!(
        ids,
        vec![
            MSG_VOTE,
            MSG_PREPARE,
            MSG_VOTE,
            MSG_RECONFIGURATION_DECISION,
            MSG_VOTE,
        ],
    );
    // Each kind is parsed by its own parser, not left as a bare header: the
    // reconfiguration decision is the one that genuinely *is* a base message.
    assert!(matches!(messages[1], Msg::Prepare(_)));
    assert!(matches!(messages[3], Msg::Base(_)));
}

/// The whole response is served from a snapshot taken when the request arrived:
/// records appended while the client is reading are not in it.
#[tokio::test]
async fn fetch_votes_serves_a_snapshot_not_a_tail() {
    let dir = TempDir::new("learn-votes-snapshot");
    write_log(dir.path(), 300, &[300, 301], 0);
    let server = serve(&dir, StubStatus::new().with_log_range(300, 301)).await;

    let request = requester().fetch_votes(300, ballot());
    let mut stream = LearnClient::new()
        .fetch_votes(server.local_addr(), &request)
        .await
        .expect("fetch votes");
    // Read one record, then grow the log under the server.
    let first = stream.next().await.expect("first").expect("a record");
    assert_eq!(first.header().decree, 300);
    write_log(dir.path(), 300, &[302, 303], 0);

    let rest: Vec<u64> = drain(&mut stream)
        .await
        .expect("stream")
        .iter()
        .map(|m| m.header().decree)
        .collect();
    assert_eq!(rest, vec![301], "the response must not chase the appends");

    // The next request does see them — the snapshot is per request.
    let mut stream = LearnClient::new()
        .fetch_votes(server.local_addr(), &requester().fetch_votes(300, ballot()))
        .await
        .expect("fetch votes");
    let decrees: Vec<u64> = drain(&mut stream)
        .await
        .expect("stream")
        .iter()
        .map(|m| m.header().decree)
        .collect();
    assert_eq!(decrees, vec![300, 301, 302, 303]);
}

#[tokio::test]
async fn an_unknown_decree_closes_without_a_word() {
    let dir = TempDir::new("learn-votes-missing");
    write_log(dir.path(), 100, &[100, 101], 0);
    let server = serve(&dir, StubStatus::new().with_log_range(100, 101)).await;

    for decree in [99u64, 102, u64::MAX] {
        let request = requester().fetch_votes(decree, ballot());
        let mut stream = LearnClient::new()
            .fetch_votes(server.local_addr(), &request)
            .await
            .expect("connect");
        assert!(
            stream.next().await.expect("clean close").is_none(),
            "decree {decree} must produce an empty stream"
        );
    }
}

/// An empty data directory has nothing to serve and must not panic on the
/// `m_logFiles.front()` the C++ would do here.
#[tokio::test]
async fn an_empty_directory_serves_nothing() {
    let dir = TempDir::new("learn-empty-dir");
    let server = serve(&dir, StubStatus::new()).await;

    let mut stream = LearnClient::new()
        .fetch_votes(server.local_addr(), &requester().fetch_votes(1, ballot()))
        .await
        .expect("connect");
    assert!(stream.next().await.expect("clean close").is_none());

    assert_eq!(
        LogSet::open(dir.path()).expect("open").min_decree_in_log(),
        None
    );
}

// ---------------------------------------------------------------------------
// FetchCheckpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fetch_checkpoint_copies_verifies_and_publishes() {
    let source_dir = TempDir::new("learn-cp-src");
    let dest_dir = TempDir::new("learn-cp-dst");
    let state: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
    let size = write_checkpoint(source_dir.path(), 500, &state);

    let server = serve(&source_dir, StubStatus::new().with_checkpoint(500, size)).await;
    let request = requester().fetch_checkpoint(500);
    let fetched = LearnClient::new()
        .fetch_checkpoint(server.local_addr(), &request, size, dest_dir.path())
        .await
        .expect("fetch checkpoint");

    assert_eq!(fetched.path, dest_dir.join("500.codex"));
    assert_eq!(fetched.size, size);
    // A byte-for-byte copy, and it verifies.
    let original = std::fs::read(source_dir.join("500.codex")).expect("read source");
    let copy = std::fs::read(&fetched.path).expect("read copy");
    assert_eq!(copy, original);
    assert!(rsl_storage::checkpoint::verify_file(&fetched.path)
        .expect("verify")
        .accepted());

    // Nothing is left behind in the destination.
    let leftovers: Vec<_> = std::fs::read_dir(dest_dir.path())
        .expect("read dir")
        .map(|e| e.expect("entry").file_name())
        .filter(|n| n != "500.codex")
        .collect();
    assert!(leftovers.is_empty(), "temp files left: {leftovers:?}");
}

/// Any decree other than the replica's own `m_checkpointedDecree` is refused,
/// even when a checkpoint file for it is sitting right there.
#[tokio::test]
async fn a_mismatched_checkpoint_decree_closes_without_a_word() {
    let source_dir = TempDir::new("learn-cp-mismatch-src");
    let dest_dir = TempDir::new("learn-cp-mismatch-dst");
    let size_500 = write_checkpoint(source_dir.path(), 500, b"five hundred");
    let size_400 = write_checkpoint(source_dir.path(), 400, b"four hundred");

    // The engine's checkpointed decree is 500; 400 exists on disk but is not it.
    let server = serve(
        &source_dir,
        StubStatus::new().with_checkpoint(500, size_500),
    )
    .await;
    let request = requester().fetch_checkpoint(400);
    let err = LearnClient::new()
        .fetch_checkpoint(server.local_addr(), &request, size_400, dest_dir.path())
        .await
        .expect_err("must be refused");
    assert!(matches!(err, TransferError::Closed), "got {err:?}");

    // Refusal leaves no temp file behind.
    assert_eq!(std::fs::read_dir(dest_dir.path()).unwrap().count(), 0);
}

/// The client is told the size out of band. If the peer sends less, the copy is
/// abandoned and the temp file deleted — nothing half-copied is published.
#[tokio::test]
async fn a_short_checkpoint_stream_deletes_the_temp_file() {
    let source_dir = TempDir::new("learn-cp-short-src");
    let dest_dir = TempDir::new("learn-cp-short-dst");
    let size = write_checkpoint(source_dir.path(), 500, b"some state");

    let server = serve(&source_dir, StubStatus::new().with_checkpoint(500, size)).await;
    let request = requester().fetch_checkpoint(500);
    // Claim the checkpoint is a page longer than it is.
    let err = LearnClient::new()
        .fetch_checkpoint(server.local_addr(), &request, size + 512, dest_dir.path())
        .await
        .expect_err("must not publish");
    match err {
        TransferError::Truncated { got, expected } => {
            assert_eq!(got, size);
            assert_eq!(expected, size + 512);
        }
        other => panic!("expected a truncation, got {other:?}"),
    }
    assert_eq!(
        std::fs::read_dir(dest_dir.path()).unwrap().count(),
        0,
        "the temp file must be gone"
    );
}

/// A copy that arrives intact but does not verify is not published either.
#[tokio::test]
async fn a_corrupt_checkpoint_is_never_published() {
    let source_dir = TempDir::new("learn-cp-corrupt-src");
    let dest_dir = TempDir::new("learn-cp-corrupt-dst");
    let size = write_checkpoint(source_dir.path(), 500, &vec![7u8; 4096]);

    // Flip a byte inside the user state, past the header.
    let path = source_dir.join("500.codex");
    let mut bytes = std::fs::read(&path).expect("read");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&path, &bytes).expect("write");

    let server = serve(&source_dir, StubStatus::new().with_checkpoint(500, size)).await;
    let err = LearnClient::new()
        .fetch_checkpoint(
            server.local_addr(),
            &requester().fetch_checkpoint(500),
            size,
            dest_dir.path(),
        )
        .await
        .expect_err("must not publish");
    assert!(
        matches!(err, TransferError::Checkpoint(_)),
        "expected a verification failure, got {err:?}"
    );
    assert_eq!(std::fs::read_dir(dest_dir.path()).unwrap().count(), 0);
}

/// `raise_max_ballot` is the C++'s "reset the maxballot in the header"
/// (`legislator.cpp:5535`): the header is re-marshaled on the way to disk and
/// the file still verifies.
#[tokio::test]
async fn the_header_rewrite_raises_the_max_ballot() {
    let source_dir = TempDir::new("learn-cp-ballot-src");
    let dest_dir = TempDir::new("learn-cp-ballot-dst");
    let size = write_checkpoint(source_dir.path(), 500, b"state");
    let server = serve(&source_dir, StubStatus::new().with_checkpoint(500, size)).await;

    let higher = BallotNumber::new(99, MemberId::from_str("909"));
    let fetched = LearnClient::new()
        .fetch_checkpoint_with(
            server.local_addr(),
            &requester().fetch_checkpoint(500),
            size,
            dest_dir.path(),
            Some(higher.clone()),
        )
        .await
        .expect("fetch checkpoint");

    let reader = rsl_storage::checkpoint::CheckpointReader::open(&fetched.path).expect("open");
    assert_eq!(reader.header().max_ballot, higher);
    assert_eq!(reader.header().last_executed_decree, 500);
    // The rewrite keeps the file the same length, so the size check still holds.
    assert_eq!(std::fs::metadata(&fetched.path).unwrap().len(), size);
    assert!(rsl_storage::checkpoint::verify_file(&fetched.path)
        .expect("verify")
        .accepted());
}

/// Every other checkpoint in this file fits inside one ring block, so the
/// `SeqWriter` behind `copy_checkpoint` never rotates: one partial block,
/// padded and cut back by `finish`. This is the case that does rotate — enough
/// blocks to recycle every slot many times over, so slot reuse, a caller
/// running ahead of the writers, and a tail that is not a block multiple are
/// all on the path.
///
/// The ring block is [`LearnConfig::stream_chunk`] rounded up to a sector, so
/// shrinking the chunk buys the rotation for a couple of hundred kilobytes
/// instead of a couple of hundred megabytes. The server keeps the default, so
/// the bytes still arrive in chunks far larger than the block.
#[tokio::test]
async fn a_checkpoint_spanning_many_ring_blocks_copies_byte_for_byte() {
    let source_dir = TempDir::new("learn-cp-blocks-src");
    let dest_dir = TempDir::new("learn-cp-blocks-dst");
    // Deliberately not a multiple of anything: the file's length is whatever
    // `finish`'s `set_len` says, not what the sector-multiple writes could
    // express.
    let state: Vec<u8> = (0..200_003u32).map(|i| (i * 7) as u8).collect();
    let size = write_checkpoint(source_dir.path(), 500, &state);

    let server = serve(&source_dir, StubStatus::new().with_checkpoint(500, size)).await;
    let client = LearnClient::with_config(LearnConfig {
        stream_chunk: 4096,
        ..LearnConfig::default()
    });
    let fetched = client
        .fetch_checkpoint(
            server.local_addr(),
            &requester().fetch_checkpoint(500),
            size,
            dest_dir.path(),
        )
        .await
        .expect("fetch checkpoint");

    let original = std::fs::read(source_dir.join("500.codex")).expect("read source");
    let copy = std::fs::read(&fetched.path).expect("read copy");
    assert_eq!(copy.len() as u64, size, "the ring padded the file");
    assert_eq!(copy, original);
    assert!(rsl_storage::checkpoint::verify_file(&fetched.path)
        .expect("verify")
        .accepted());
}

/// The rewritten header goes through the ring ahead of the body, which leaves
/// every later socket chunk straddling a block boundary. Same assertion as the
/// single-block rewrite above, over a file long enough for that to matter.
#[tokio::test]
async fn the_header_rewrite_survives_a_multi_block_copy() {
    let source_dir = TempDir::new("learn-cp-rewrite-src");
    let dest_dir = TempDir::new("learn-cp-rewrite-dst");
    let state: Vec<u8> = (0..200_003u32).map(|i| (i * 11) as u8).collect();
    let size = write_checkpoint(source_dir.path(), 500, &state);

    let server = serve(&source_dir, StubStatus::new().with_checkpoint(500, size)).await;
    let higher = BallotNumber::new(99, MemberId::from_str("909"));
    let client = LearnClient::with_config(LearnConfig {
        stream_chunk: 4096,
        ..LearnConfig::default()
    });
    let fetched = client
        .fetch_checkpoint_with(
            server.local_addr(),
            &requester().fetch_checkpoint(500),
            size,
            dest_dir.path(),
            Some(higher.clone()),
        )
        .await
        .expect("fetch checkpoint");

    let reader = rsl_storage::checkpoint::CheckpointReader::open(&fetched.path).expect("open");
    assert_eq!(reader.header().max_ballot, higher);
    assert_eq!(std::fs::metadata(&fetched.path).unwrap().len(), size);
    assert!(rsl_storage::checkpoint::verify_file(&fetched.path)
        .expect("verify")
        .accepted());

    // The body is untouched by the rewrite: only the header page differs.
    let original = std::fs::read(source_dir.join("500.codex")).expect("read source");
    let copy = std::fs::read(&fetched.path).expect("read copy");
    let tail = rsl_storage::PAGE_SIZE as usize;
    assert_eq!(copy[tail..], original[tail..]);
}

// ---------------------------------------------------------------------------
// Torn streams
// ---------------------------------------------------------------------------

/// A peer that dies mid-record must produce a clean error, not a partial
/// message. `restore` is false in `LearnVotes`, so there is no tolerated tail:
/// a cut inside the header page and a cut inside the body are both hard
/// failures, and they are distinguishable.
#[tokio::test]
async fn a_vote_stream_cut_mid_record_errors_cleanly() {
    let dir = TempDir::new("learn-torn");
    write_log(dir.path(), 400, &[400, 401], 700);
    let log = std::fs::read(dir.join("400.log")).expect("read log");

    // Where record two starts, straight from the storage scanner.
    let scan = rsl_storage::log::scan_bytes(&log);
    let second = scan.records[1].offset as usize;
    assert!(scan.records[1].padded_len > 512, "record two spans pages");

    for cut in [second + 188, second + 512 + 100] {
        let mut stream = serve_bytes(&log[..cut]).await;
        // The first record is whole and is delivered.
        assert_eq!(
            stream
                .next()
                .await
                .expect("first")
                .expect("record")
                .header()
                .decree,
            400
        );
        let err = stream.next().await.expect_err("torn record");
        let torn = if cut < second + 512 {
            matches!(
                err,
                TransferError::Record(RecordError::ShortHeaderPage { .. })
            )
        } else {
            matches!(err, TransferError::Record(RecordError::ShortBody { .. }))
        };
        assert!(torn, "cut at {cut}: got {err:?}");
    }
}

/// Serve `bytes` verbatim as a `FetchVotes` response from a one-shot peer, and
/// hand back the client's stream over it. This is how a torn or corrupt
/// response is staged: the *server* here is a raw socket, so the bytes are
/// exactly what the test wrote.
async fn serve_bytes(bytes: &[u8]) -> rsl_net::learnport::VoteStream {
    use tokio::io::AsyncWriteExt;

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let bytes = bytes.to_vec();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        // Read (and ignore) the request, then answer with the staged bytes.
        let mut scratch = [0u8; 4096];
        let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut scratch).await;
        let _ = stream.write_all(&bytes).await;
        let _ = stream.shutdown().await;
    });

    LearnClient::new()
        .fetch_votes(addr, &requester().fetch_votes(400, ballot()))
        .await
        .expect("connect")
}

/// A record whose checksum fails is a close, not a resync: the stream ends
/// there and the records after it are never delivered.
#[tokio::test]
async fn a_bad_record_checksum_ends_the_stream() {
    let dir = TempDir::new("learn-badsum");
    write_log(dir.path(), 400, &[400, 401, 402], 0);
    let mut log = std::fs::read(dir.join("400.log")).expect("read log");
    // Corrupt a byte inside the *second* record's message body.
    log[512 + 40] ^= 0xff;

    let mut stream = serve_bytes(&log).await;
    assert_eq!(
        stream
            .next()
            .await
            .expect("first")
            .expect("record")
            .header()
            .decree,
        400
    );
    let err = stream.next().await.expect_err("bad checksum");
    assert!(
        matches!(err, TransferError::Record(RecordError::ChecksumMismatch)),
        "got {err:?}"
    );
    // And the stream stays ended — record three is not reachable.
    assert!(stream.next().await.expect("ended").is_none());
}

/// An all-zero page mid-stream is corruption here, where recovery would call it
/// a clean end of log: `LearnVotes` passes `restore = false`.
#[tokio::test]
async fn a_zero_page_mid_stream_is_corruption() {
    let dir = TempDir::new("learn-zeropage");
    write_log(dir.path(), 400, &[400], 0);
    let mut log = std::fs::read(dir.join("400.log")).expect("read log");
    log.extend_from_slice(&[0u8; 512]);

    let mut stream = serve_bytes(&log).await;
    assert!(stream.next().await.expect("first").is_some());
    let err = stream.next().await.expect_err("zero page");
    assert!(
        matches!(err, TransferError::Record(RecordError::HeaderUnmarshal)),
        "got {err:?}"
    );
}

/// Killing the server mid-transfer leaves the client with an error, never a
/// half-published file.
#[tokio::test]
async fn a_server_shut_down_mid_checkpoint_leaves_nothing_behind() {
    let source_dir = TempDir::new("learn-cp-kill-src");
    let dest_dir = TempDir::new("learn-cp-kill-dst");
    // Big enough that the transfer cannot finish inside one chunk.
    let state = vec![0xabu8; 8 * 1024 * 1024];
    let size = write_checkpoint(source_dir.path(), 500, &state);

    let config = LearnConfig {
        stream_chunk: 4096,
        recv_timeout: Duration::from_secs(2),
        ..LearnConfig::default()
    };
    let server = LearnServer::bind(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        Arc::new(DirSource::new(
            source_dir.path(),
            StubStatus::new().with_checkpoint(500, size),
        )),
        config.clone(),
    )
    .await
    .expect("bind");
    let addr = server.local_addr();

    let client = LearnClient::with_config(config);
    let dest = dest_dir.path().to_path_buf();
    let fetch = tokio::spawn(async move {
        client
            .fetch_checkpoint(addr, &requester().fetch_checkpoint(500), size, &dest)
            .await
    });

    tokio::time::sleep(Duration::from_millis(20)).await;
    drop(server); // shutdown mid-stream

    let result = fetch.await.expect("join");
    assert!(
        result.is_err(),
        "a killed server must not yield a checkpoint"
    );
    let left: Vec<_> = std::fs::read_dir(dest_dir.path())
        .expect("read dir")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert!(left.is_empty(), "left behind: {left:?}");
}

// ---------------------------------------------------------------------------
// Timeouts
// ---------------------------------------------------------------------------

/// A peer that accepts and then says nothing trips the per-operation receive
/// timeout — the only deadline in the protocol.
#[tokio::test]
async fn a_silent_peer_trips_the_receive_timeout() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let held = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        // Hold the connection open, saying nothing at all.
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop(stream);
    });

    let config = LearnConfig {
        recv_timeout: Duration::from_millis(150),
        ..LearnConfig::default()
    };
    let err = LearnClient::with_config(config)
        .query_status(addr, &requester().status_query())
        .await
        .expect_err("must time out");
    assert!(matches!(err, TransferError::Timeout), "got {err:?}");
    held.abort();
}
