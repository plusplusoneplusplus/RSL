//! Golden-vector harness (plan item 6).
//!
//! For every corpus RECORD: (a) `unmarshal` succeeds, (b) the checksum verifies
//! and equals the stated CHECKSUM, (c) re-marshal is byte-identical to BYTES,
//! and (d) TYPE/VERSION agree with the parsed message. For every FPRINT: the
//! Rabin-64 fingerprint matches.

mod common;

use rsl_wire::{fingerprint, messages::verify_checksum, Msg};

#[test]
fn corpus_is_present_and_populated() {
    let (records, fprints) = common::load();
    // The Phase-1 corpus is a fixed 122 records + 7 fingerprints.
    assert_eq!(records.len(), 122, "unexpected record count");
    assert_eq!(fprints.len(), 7, "unexpected fingerprint count");
}

#[test]
fn all_fingerprints_match() {
    let (_, fprints) = common::load();
    for fp in &fprints {
        assert_eq!(fp.input.len(), fp.len, "FPRINT {} length", fp.desc);
        assert_eq!(
            fingerprint(&fp.input),
            fp.checksum,
            "FPRINT {} mismatch",
            fp.desc
        );
    }
}

#[test]
fn every_record_round_trips_byte_exact() {
    let (records, _) = common::load();
    for rec in &records {
        let ctx = format!("{} / {} / v{}", rec.type_name, rec.desc, rec.version);

        // (0) sanity: declared LEN matches the byte blob.
        assert_eq!(rec.bytes.len(), rec.len, "{ctx}: LEN vs BYTES");

        // (a) unmarshal succeeds for the record's declared TYPE.
        let msg = Msg::unmarshal(rec.kind(), &rec.bytes)
            .unwrap_or_else(|| panic!("{ctx}: unmarshal failed"));

        // (d) TYPE/VERSION agree with the parsed header.
        let header = msg.header();
        assert_eq!(
            header.version.raw(),
            rec.version,
            "{ctx}: parsed version mismatch"
        );

        // (b) checksum verifies against a recomputation, and the stored value
        // equals the corpus CHECKSUM.
        assert!(
            verify_checksum(&rec.bytes),
            "{ctx}: checksum does not verify"
        );
        assert_eq!(header.checksum, rec.checksum, "{ctx}: checksum field value");

        // (c) re-marshal is byte-identical.
        let remarshaled = msg.marshal_with_checksum();
        assert_eq!(
            remarshaled, rec.bytes,
            "{ctx}: re-marshal is not byte-identical"
        );
    }
}
