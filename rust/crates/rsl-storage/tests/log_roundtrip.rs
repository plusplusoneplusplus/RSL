//! Log writer/reader round trips: reopen-and-append idempotence, the decree
//! index, replay, mutation tolerance, and property tests over random record
//! sequences.
//!
//! These need no corpus — they check that this crate is self-consistent and
//! that its recovery decisions land on the C++ rule for every mutation of a
//! record's header, body and pad regions.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::Arc;

use rsl_storage::durability::{Durability, NoSync, OpenMode, SyncAll};
use rsl_storage::log::{
    self, LogError, LogReader, LogWriter, Outcome, RejectReason, ScanEnd, StopReason,
};
use rsl_storage::{round_up_to_page, PAGE_SIZE};
use rsl_wire::messages::{MSG_PREPARE, MSG_RECONFIGURATION_DECISION, MSG_VOTE, MSG_VOTE_ACCEPTED};
use rsl_wire::{marshal_base, BallotNumber, Header, MemberId, PrepareMsg, ProtocolVersion, Vote};

fn header(msg_id: u16, decree: u64) -> Header {
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

/// A vote record with `request_len` bytes of payload.
fn vote_record(decree: u64, request_len: usize) -> Vec<u8> {
    let mut vote = Vote::new(header(MSG_VOTE, decree));
    if request_len > 0 {
        vote.add_request(vec![b'r'; request_len]);
    }
    vote.marshal_with_checksum().unwrap()
}

fn prepare_record(decree: u64) -> Vec<u8> {
    PrepareMsg {
        header: header(MSG_PREPARE, decree),
        primary_cookie: Vec::new(),
    }
    .marshal_with_checksum()
}

fn decision_record(decree: u64) -> Vec<u8> {
    marshal_base(&header(MSG_RECONFIGURATION_DECISION, decree))
}

fn append_all(writer: &mut LogWriter<NoSync>, records: &[Vec<u8>]) {
    let refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    writer.append_batch(&refs).expect("append");
}

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

#[test]
fn reopen_append_rescan_is_idempotent() {
    let dir = common::TempDir::new("log-reopen");
    let first: Vec<Vec<u8>> = (0..3).map(|i| vote_record(100 + i, 0)).collect();
    let second: Vec<Vec<u8>> = (3..6).map(|i| vote_record(100 + i, 700)).collect();

    let mut writer = LogWriter::open_with(dir.path(), 100, NoSync).expect("open");
    append_all(&mut writer, &first);
    let after_first = writer.data_len();
    drop(writer);

    // Reopening scans, so the index and the write pointer are rebuilt from the
    // file alone.
    let mut writer = LogWriter::open_with(dir.path(), 100, NoSync).expect("reopen");
    assert_eq!(writer.data_len(), after_first);
    assert_eq!(writer.index().max_decree(), 102);
    append_all(&mut writer, &second);
    let total = writer.data_len();
    drop(writer);

    let scan = log::scan_file(&dir.join("100.log")).expect("scan");
    assert_eq!(scan.end, ScanEnd::Eof);
    assert_eq!(scan.stop_offset, total);
    assert_eq!(scan.records.len(), 6);
    for (i, record) in scan.records.iter().enumerate() {
        assert_eq!(record.decree, 100 + i as u64);
    }

    // Scanning again changes nothing.
    let again = log::scan_file(&dir.join("100.log")).expect("rescan");
    assert_eq!(again, scan);
}

#[test]
fn a_zero_tail_is_overwritten_by_the_next_append() {
    use std::io::Write;

    let dir = common::TempDir::new("log-zero-tail");
    let mut writer = LogWriter::open_with(dir.path(), 200, NoSync).expect("open");
    append_all(&mut writer, &[vote_record(200, 0)]);
    let good_len = writer.data_len();
    drop(writer);

    // Simulate a preallocated / partially-written tail.
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(dir.join("200.log"))
        .expect("open for append");
    file.write_all(&[0u8; PAGE_SIZE as usize * 2]).expect("pad");
    drop(file);

    let scan = log::scan_file(&dir.join("200.log")).expect("scan");
    assert_eq!(scan.end, ScanEnd::Stop(StopReason::ZeroRegion));
    assert_eq!(scan.stop_offset, good_len);

    let mut writer = LogWriter::open_with(dir.path(), 200, NoSync).expect("reopen");
    assert_eq!(writer.data_len(), good_len, "write pointer skips the zeros");
    append_all(&mut writer, &[vote_record(201, 0)]);
    drop(writer);

    let scan = log::scan_file(&dir.join("200.log")).expect("scan");
    assert_eq!(scan.end, ScanEnd::Eof);
    assert_eq!(scan.records.len(), 2);
}

#[test]
fn a_torn_tail_is_discarded_and_overwritten() {
    use std::io::Write;

    let dir = common::TempDir::new("log-torn");
    let mut writer = LogWriter::open_with(dir.path(), 300, NoSync).expect("open");
    append_all(&mut writer, &[vote_record(300, 0)]);
    let good_len = writer.data_len();
    drop(writer);

    // A multi-page record whose body was cut short by a crash.
    let torn = vote_record(301, 600);
    assert!(round_up_to_page(torn.len() as u32) > PAGE_SIZE);
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(dir.join("300.log"))
        .expect("open for append");
    file.write_all(&torn[..PAGE_SIZE as usize + 188])
        .expect("torn write");
    drop(file);

    let scan = log::scan_file(&dir.join("300.log")).expect("scan");
    assert_eq!(scan.end, ScanEnd::Stop(StopReason::TornTail));
    assert_eq!(scan.stop_offset, good_len);
    assert_eq!(scan.records.len(), 1);

    let mut writer = LogWriter::open_with(dir.path(), 300, NoSync).expect("reopen");
    assert_eq!(writer.data_len(), good_len);
    append_all(&mut writer, &[vote_record(301, 0)]);
    drop(writer);

    let scan = log::scan_file(&dir.join("300.log")).expect("scan");
    assert_eq!(scan.end, ScanEnd::Eof);
    assert_eq!(scan.records.len(), 2);
    assert_eq!(scan.records[1].decree, 301);
}

#[test]
fn a_corrupt_log_cannot_be_opened_for_append() {
    let dir = common::TempDir::new("log-corrupt");
    let mut writer = LogWriter::open_with(dir.path(), 400, NoSync).expect("open");
    append_all(&mut writer, &[vote_record(400, 0), vote_record(401, 0)]);
    drop(writer);

    // Corrupt the first record's body; a valid record follows, so this is the
    // hard-reject case.
    let path = dir.join("400.log");
    let mut bytes = std::fs::read(&path).expect("read");
    bytes[20] ^= 0xff;
    std::fs::write(&path, &bytes).expect("write");

    match LogWriter::open_with(dir.path(), 400, NoSync) {
        Err(LogError::Corrupt(scan)) => {
            assert_eq!(scan.end, ScanEnd::Reject(RejectReason::ChecksumMismatch));
            assert_eq!(scan.stop_offset, 0);
        }
        other => panic!("expected a corrupt-log error, got {other:?}"),
    }
}

#[test]
fn the_writer_refuses_records_no_reader_would_accept() {
    let dir = common::TempDir::new("log-strict");
    let mut writer = LogWriter::open_with(dir.path(), 500, NoSync).expect("open");

    // An id the engine never logs.
    let not_loggable = marshal_base(&header(MSG_VOTE_ACCEPTED, 500));
    assert!(matches!(
        writer.append(&not_loggable),
        Err(LogError::NotLoggable(MSG_VOTE_ACCEPTED))
    ));

    // Bytes that are not a message at all.
    assert!(matches!(
        writer.append(&[0u8; 64]),
        Err(LogError::NotAMessage)
    ));

    // A record whose buffer does not match its own declared length.
    let mut padded = vote_record(500, 0);
    padded.push(0);
    assert!(matches!(
        writer.append(&padded),
        Err(LogError::LengthMismatch { .. })
    ));

    // An out-of-sequence vote: decree must be MaxDecree or MaxDecree+1.
    append_all(&mut writer, &[vote_record(500, 0)]);
    assert!(matches!(
        writer.append(&vote_record(600, 0)),
        Err(LogError::Index(_))
    ));

    // None of the rejected appends touched the file.
    assert_eq!(writer.data_len(), 512);
    drop(writer);
    assert_eq!(
        std::fs::metadata(dir.join("500.log")).unwrap().len(),
        512,
        "a rejected append must not write anything"
    );
}

// ---------------------------------------------------------------------------
// Index and replay
// ---------------------------------------------------------------------------

#[test]
fn the_index_mirrors_the_cpp_decree_map() {
    let dir = common::TempDir::new("log-index");
    let mut writer = LogWriter::open_with(dir.path(), 700, NoSync).expect("open");

    // Prepares and reconfiguration decisions occupy space but are not indexed.
    append_all(
        &mut writer,
        &[
            vote_record(700, 0),
            prepare_record(700),
            vote_record(701, 600),
            decision_record(701),
            vote_record(702, 0),
        ],
    );

    let index = writer.index().clone();
    assert_eq!(index.min_decree(), 700);
    assert_eq!(index.max_decree(), 702);
    assert_eq!(index.len(), 3);
    assert_eq!(index.offset(700), Some(0));
    // decree 700's record + the prepare that follows it.
    assert_eq!(index.offset(701), Some(1024));
    assert_eq!(index.length_of_decree(700), Some(1024));
    // decree 701's two-page vote + the decision.
    assert_eq!(index.length_of_decree(701), Some(1536));
    assert_eq!(index.length_of_decree(702), Some(512));
    assert!(index.has_decree(701));
    assert!(!index.has_decree(703));
    assert_eq!(index.offset(703), None);
    assert_eq!(writer.data_len(), 3072);

    // A re-vote on the current maximum decree replaces its entry, so a lookup
    // finds the later record (LogFile::AddMessage pops the back).
    let before = writer.data_len();
    append_all(&mut writer, &[vote_record(702, 0)]);
    assert_eq!(writer.index().max_decree(), 702);
    assert_eq!(writer.index().offset(702), Some(before));
    drop(writer);

    // The scan rebuilds exactly the same index.
    let reader = LogReader::open(dir.path(), 700).expect("open reader");
    assert_eq!(reader.index().offset(702), Some(before));
    assert_eq!(reader.index().max_decree(), 702);
    assert_eq!(reader.index().data_len(), before + 512);
}

// ---------------------------------------------------------------------------
// The durability watermark
// ---------------------------------------------------------------------------

/// `SyncAll`, counting the flushes — so a test can say how many device flushes
/// a sequence of appends cost, not merely that it survived.
#[derive(Clone, Default)]
struct CountingSync {
    flushes: Arc<AtomicUsize>,
}

impl Durability for CountingSync {
    type File = std::fs::File;
    type Bulk = rsl_storage::seqwrite::RealDevice;

    fn open(&self, path: &std::path::Path, mode: OpenMode) -> std::io::Result<std::fs::File> {
        SyncAll.open(path, mode)
    }
    fn bulk(&self) -> rsl_storage::seqwrite::RealDevice {
        SyncAll.bulk()
    }
    fn exists(&self, path: &std::path::Path) -> bool {
        SyncAll.exists(path)
    }
    fn read_dir(&self, dir: &std::path::Path) -> std::io::Result<Vec<String>> {
        SyncAll.read_dir(dir)
    }
    fn remove_file(&self, path: &std::path::Path) -> std::io::Result<()> {
        SyncAll.remove_file(path)
    }
    fn sync_data(&self, file: &std::fs::File) -> std::io::Result<()> {
        self.flushes.fetch_add(1, AtomicOrdering::SeqCst);
        SyncAll.sync_data(file)
    }
    fn sync_file(&self, file: &std::fs::File) -> std::io::Result<()> {
        SyncAll.sync_file(file)
    }
    fn rename(&self, from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
        SyncAll.rename(from, to)
    }
    fn sync_dir(&self, dir: &std::path::Path) -> std::io::Result<()> {
        SyncAll.sync_dir(dir)
    }
}

#[test]
fn the_watermark_tracks_what_has_been_flushed() {
    let dir = common::TempDir::new("log-watermark");
    let counter = CountingSync::default();
    let flushes = Arc::clone(&counter.flushes);
    let mut writer = LogWriter::open_with(dir.path(), 900, counter).expect("open");

    assert_eq!(writer.durable_len(), 0);
    assert_eq!(writer.durable_max_decree(), 0);

    // A plain append is durable when it returns.
    writer.append(&vote_record(900, 0)).expect("append");
    assert_eq!(writer.durable_len(), writer.data_len());
    assert_eq!(writer.durable_max_decree(), 900);
    assert_eq!(flushes.load(AtomicOrdering::SeqCst), 1);

    // An unsynced batch runs the writer's state ahead of the disk.
    let committed = writer.durable_len();
    let batch = [vote_record(901, 0), vote_record(902, 3000)];
    let refs: Vec<&[u8]> = batch.iter().map(|r| r.as_slice()).collect();
    let unsynced = writer.append_unsynced(&refs).expect("append unsynced");
    assert_eq!(unsynced.offset(), committed);
    assert!(writer.durable_len() < writer.data_len());
    assert_eq!(writer.durable_len(), committed);
    assert_eq!(writer.durable_max_decree(), 900);
    assert_eq!(
        flushes.load(AtomicOrdering::SeqCst),
        1,
        "no flush was asked for"
    );

    // ...and `sync` closes the gap.
    writer.sync().expect("sync");
    assert_eq!(writer.durable_len(), writer.data_len());
    assert_eq!(writer.durable_max_decree(), 902);
    assert_eq!(flushes.load(AtomicOrdering::SeqCst), 2);

    // A second `sync` with nothing new to commit costs no device flush, and
    // neither does an empty batch.
    writer.sync().expect("sync again");
    writer.append_batch(&[]).expect("empty batch");
    assert_eq!(flushes.load(AtomicOrdering::SeqCst), 2);

    // Reopening starts from what recovery found on disk.
    let total = writer.data_len();
    drop(writer);
    let reopened = LogWriter::open_with(dir.path(), 900, NoSync).expect("reopen");
    assert_eq!(reopened.durable_len(), total);
    assert_eq!(reopened.durable_max_decree(), 902);
}

#[test]
fn replay_starts_at_the_requested_decree() {
    let dir = common::TempDir::new("log-replay");
    let mut writer = LogWriter::open_with(dir.path(), 800, NoSync).expect("open");
    let records: Vec<Vec<u8>> = (0..5)
        .map(|i| vote_record(800 + i, 100 * i as usize))
        .collect();
    append_all(&mut writer, &records);
    drop(writer);

    let reader = LogReader::open(dir.path(), 800).expect("open reader");
    let mut scanner = reader
        .replay_from(802)
        .expect("replay")
        .expect("decree is in this log");

    let mut seen = Vec::new();
    while let Some(record) = scanner.next_record().expect("scan") {
        assert!(record.parse().is_some(), "record must re-parse");
        seen.push((record.info.offset, record.info.decree));
    }
    assert_eq!(scanner.end(), Some(ScanEnd::Eof));
    assert_eq!(
        seen,
        vec![
            (reader.index().offset(802).unwrap(), 802),
            (reader.index().offset(803).unwrap(), 803),
            (reader.index().offset(804).unwrap(), 804),
        ]
    );

    // A decree this log does not hold.
    assert!(reader.replay_from(900).expect("replay").is_none());
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

/// A three-record log to mutate: two single-page votes and a two-page vote.
fn mutation_fixture(dir: &common::TempDir) -> (std::path::PathBuf, Vec<u8>) {
    let mut writer = LogWriter::open_with(dir.path(), 900, NoSync).expect("open");
    append_all(
        &mut writer,
        &[
            vote_record(900, 0),
            vote_record(901, 600),
            vote_record(902, 0),
        ],
    );
    drop(writer);
    let path = dir.join("900.log");
    let bytes = std::fs::read(&path).expect("read");
    (path, bytes)
}

#[test]
fn pad_mutations_never_invalidate_a_record() {
    let dir = common::TempDir::new("log-mutate-pad");
    let (_, clean) = mutation_fixture(&dir);
    let baseline = log::scan_bytes(&clean);
    assert_eq!(baseline.end, ScanEnd::Eof);

    // Every byte of every record's pad region. The checksum covers only the
    // message body, so all of them must scan identically to the clean file.
    for record in &baseline.records {
        let body_end = record.offset + u64::from(record.un_marshal_len);
        let pad_end = record.offset + u64::from(record.padded_len);
        for offset in body_end..pad_end {
            let mut mutated = clean.clone();
            mutated[offset as usize] ^= 0xff;
            let scan = log::scan_bytes(&mutated);
            assert_eq!(
                scan, baseline,
                "flipping pad byte {offset} changed the scan outcome"
            );
        }
    }
}

#[test]
fn body_mutations_reject_when_data_follows_and_stop_when_it_does_not() {
    let dir = common::TempDir::new("log-mutate-body");
    let (_, clean) = mutation_fixture(&dir);
    let baseline = log::scan_bytes(&clean);
    let last = *baseline.records.last().unwrap();

    // A body byte of a record with valid records after it: hard corruption.
    for record in &baseline.records[..baseline.records.len() - 1] {
        // Past version, length, checksum, magic and message id: everything
        // here is payload to the parser, so only the checksum can catch it.
        let start = record.offset + 22;
        let end = record.offset + u64::from(record.un_marshal_len);
        for offset in (start..end).step_by(7) {
            let mut mutated = clean.clone();
            mutated[offset as usize] ^= 0xff;
            let scan = log::scan_bytes(&mutated);
            assert_eq!(
                scan.end.outcome(),
                Outcome::Reject,
                "flipping body byte {offset} should reject"
            );
            assert_eq!(scan.stop_offset, record.offset);
        }
    }

    // The same flip in the *last* record, whose pad is zero and which nothing
    // follows: the tolerated half-written tail.
    let start = last.offset + 22;
    let end = last.offset + u64::from(last.un_marshal_len);
    for offset in (start..end).step_by(7) {
        let mut mutated = clean.clone();
        mutated[offset as usize] ^= 0xff;
        let scan = log::scan_bytes(&mutated);
        assert_eq!(
            scan.end,
            ScanEnd::Stop(StopReason::TrailingChecksumMismatch),
            "flipping trailing body byte {offset}"
        );
        assert_eq!(scan.stop_offset, last.offset);
        assert_eq!(scan.records.len(), baseline.records.len() - 1);
    }
}

#[test]
fn header_mutations_stop_or_reject_like_the_cpp() {
    let dir = common::TempDir::new("log-mutate-header");
    let (_, clean) = mutation_fixture(&dir);
    let baseline = log::scan_bytes(&clean);
    let second = baseline.records[1];

    // An unparsable version field: the page is not zero, so this is corruption.
    let mut mutated = clean.clone();
    mutated[second.offset as usize] = 0xff;
    mutated[second.offset as usize + 1] = 0xff;
    let scan = log::scan_bytes(&mutated);
    assert_eq!(scan.end, ScanEnd::Reject(RejectReason::HeaderUnmarshal));
    assert_eq!(scan.stop_offset, second.offset);

    // Broken magic: same verdict, from the other check in Message::UnMarshal.
    let mut mutated = clean.clone();
    mutated[second.offset as usize + 14] ^= 0xff;
    let scan = log::scan_bytes(&mutated);
    assert_eq!(scan.end, ScanEnd::Reject(RejectReason::HeaderUnmarshal));

    // A message id that is never logged.
    let mut mutated = clean.clone();
    let id_offset = second.offset as usize + 18;
    assert_eq!(
        u16::from_le_bytes(mutated[id_offset..id_offset + 2].try_into().unwrap()),
        MSG_VOTE,
        "message id is where the header layout says it is"
    );
    mutated[id_offset..id_offset + 2].copy_from_slice(&MSG_VOTE_ACCEPTED.to_le_bytes());
    let scan = log::scan_bytes(&mutated);
    assert_eq!(scan.end, ScanEnd::Reject(RejectReason::UnknownMessageId));
    assert_eq!(scan.stop_offset, second.offset);

    // Truncating mid-page leaves less than a header page at the tail.
    let mut truncated = clean.clone();
    truncated.truncate(clean.len() - 100);
    let scan = log::scan_bytes(&truncated);
    assert_eq!(scan.end, ScanEnd::Reject(RejectReason::PartialHeaderPage));

    // Zeroing a whole trailing record is the clean end-of-log.
    let last = *baseline.records.last().unwrap();
    let mut zeroed = clean.clone();
    zeroed[last.offset as usize..].fill(0);
    let scan = log::scan_bytes(&zeroed);
    assert_eq!(scan.end, ScanEnd::Stop(StopReason::ZeroRegion));
    assert_eq!(scan.stop_offset, last.offset);

    // ...but a zero page with non-zero data after it is not.
    let mut zeroed_then_data = clean.clone();
    zeroed_then_data
        [second.offset as usize..(second.offset + u64::from(second.padded_len)) as usize]
        .fill(0);
    let scan = log::scan_bytes(&zeroed_then_data);
    assert_eq!(scan.end, ScanEnd::Reject(RejectReason::HeaderUnmarshal));
    assert_eq!(scan.stop_offset, second.offset);
}

/// A record header declaring a near-4 GiB length is a torn tail, and reaching
/// that verdict must not allocate the declared size.
#[test]
fn an_absurd_declared_length_is_a_torn_tail() {
    let dir = common::TempDir::new("log-huge-len");
    let (_, clean) = mutation_fixture(&dir);
    let baseline = log::scan_bytes(&clean);
    let last = *baseline.records.last().unwrap();

    let mut mutated = clean.clone();
    let len_at = last.offset as usize + 2;
    mutated[len_at..len_at + 4].copy_from_slice(&0xffff_f000u32.to_le_bytes());

    let scan = log::scan_bytes(&mutated);
    assert_eq!(scan.end, ScanEnd::Stop(StopReason::TornTail));
    assert_eq!(scan.stop_offset, last.offset);
    assert_eq!(scan.records.len(), baseline.records.len() - 1);
}

#[test]
fn an_empty_log_scans_clean() {
    let scan = log::scan_bytes(&[]);
    assert_eq!(scan.end, ScanEnd::Eof);
    assert_eq!(scan.stop_offset, 0);
    assert!(scan.records.is_empty());
    assert_eq!(scan.outcome(), "accept");
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

mod properties {
    use super::*;
    use proptest::prelude::*;

    /// What to append next: a vote (indexed), a prepare, or a decision.
    #[derive(Clone, Copy, Debug)]
    enum Kind {
        Vote,
        Prepare,
        Decision,
    }

    fn kinds() -> impl Strategy<Value = Kind> {
        prop_oneof![
            3 => Just(Kind::Vote),
            1 => Just(Kind::Prepare),
            1 => Just(Kind::Decision),
        ]
    }

    /// A record sequence with legal decrees: votes advance by 0 or 1, other
    /// records track the current decree.
    fn sequence() -> impl Strategy<Value = Vec<Step>> {
        prop::collection::vec((kinds(), any::<bool>(), 0usize..1500), 0..12)
    }

    /// One generated step: what to write, whether a vote advances the decree,
    /// and how big its request payload is.
    type Step = (Kind, bool, usize);

    /// What a written record must scan back as: id, decree, padded length.
    type Expected = (u16, u64, u32);

    /// Build the records and the shapes they must scan back as.
    fn build(seq: &[Step]) -> (Vec<Vec<u8>>, Vec<Expected>) {
        let mut records = Vec::new();
        let mut expected = Vec::new();
        let mut decree = 1_000u64;
        let mut first_vote = true;
        for (kind, advance, request_len) in seq {
            let record = match kind {
                Kind::Vote => {
                    if !first_vote && *advance {
                        decree += 1;
                    }
                    first_vote = false;
                    vote_record(decree, *request_len)
                }
                Kind::Prepare => prepare_record(decree),
                Kind::Decision => decision_record(decree),
            };
            let msg_id = match kind {
                Kind::Vote => MSG_VOTE,
                Kind::Prepare => MSG_PREPARE,
                Kind::Decision => MSG_RECONFIGURATION_DECISION,
            };
            expected.push((msg_id, decree, round_up_to_page(record.len() as u32)));
            records.push(record);
        }
        (records, expected)
    }

    proptest! {
        /// Whatever the sequence, a scan recovers exactly what was written, at
        /// the offsets page-rounding predicts.
        #[test]
        fn written_records_scan_back_identically(seq in sequence()) {
            let (records, expected) = build(&seq);
            let image: Vec<u8> = {
                let mut image = Vec::new();
                for (record, (_, _, padded)) in records.iter().zip(&expected) {
                    image.extend_from_slice(record);
                    image.resize(image.len() + (*padded as usize - record.len()), 0);
                }
                image
            };

            let scan = log::scan_bytes(&image);
            prop_assert_eq!(scan.end, ScanEnd::Eof);
            prop_assert_eq!(scan.stop_offset, image.len() as u64);
            prop_assert_eq!(scan.records.len(), expected.len());

            let mut offset = 0u64;
            for (got, (msg_id, decree, padded)) in scan.records.iter().zip(&expected) {
                prop_assert_eq!(got.offset, offset);
                prop_assert_eq!(got.msg_id, *msg_id);
                prop_assert_eq!(got.decree, *decree);
                prop_assert_eq!(got.padded_len, *padded);
                offset += u64::from(*padded);
            }
        }

        /// Splitting the same sequence into batches at an arbitrary point,
        /// with a reopen in between, produces the same bytes as one batch.
        #[test]
        fn batch_splits_and_reopens_do_not_change_the_file(
            seq in sequence(),
            split in 0usize..12,
        ) {
            let (records, _) = build(&seq);
            let split = split.min(records.len());
            let dir = common::TempDir::new("log-prop-split");

            let mut whole = LogWriter::open_with(dir.path(), 1, NoSync).unwrap();
            append_all(&mut whole, &records);
            drop(whole);

            let mut part = LogWriter::open_with(dir.path(), 2, NoSync).unwrap();
            append_all(&mut part, &records[..split]);
            drop(part);
            let mut part = LogWriter::open_with(dir.path(), 2, NoSync).unwrap();
            append_all(&mut part, &records[split..]);
            let split_len = part.data_len();
            drop(part);

            let a = std::fs::read(dir.join("1.log")).unwrap();
            let b = std::fs::read(dir.join("2.log")).unwrap();
            prop_assert_eq!(&a, &b);
            prop_assert_eq!(split_len, a.len() as u64);
        }

        /// Truncating a log anywhere leaves it either accepted (on a record
        /// boundary) or cleanly stopped/rejected — never a panic, and never a
        /// record the scan did not fully validate.
        #[test]
        fn truncation_is_always_a_clean_decision(seq in sequence(), cut in 0usize..8192) {
            let (records, expected) = build(&seq);
            let mut image = Vec::new();
            for (record, (_, _, padded)) in records.iter().zip(&expected) {
                image.extend_from_slice(record);
                image.resize(image.len() + (*padded as usize - record.len()), 0);
            }
            let cut = cut.min(image.len());
            image.truncate(cut);

            let scan = log::scan_bytes(&image);
            prop_assert!(scan.stop_offset <= image.len() as u64);
            for record in &scan.records {
                prop_assert!(record.offset + u64::from(record.padded_len) <= scan.stop_offset);
            }
            if cut % PAGE_SIZE as usize != 0 {
                prop_assert_ne!(scan.end, ScanEnd::Eof);
            }
        }
    }
}
