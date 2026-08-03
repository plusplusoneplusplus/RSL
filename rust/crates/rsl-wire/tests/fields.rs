//! Independent-construction harness (plan item 7).
//!
//! Round-trip alone (parse BYTES, re-marshal, compare) can miss a reader bug
//! that a mirrored writer bug hides. This harness never parses BYTES: it builds
//! each message *from the corpus `FIELDS` metadata* and requires the marshaled
//! result to equal BYTES. A reader is not on the path, so the two failure modes
//! can no longer cancel out.

mod common;

use serde_json::Value;

use rsl_wire::messages::{
    Header, MSG_BOOTSTRAP, MSG_JOIN, MSG_PREPARE, MSG_PREPARE_ACCEPTED, MSG_STATUS_RESPONSE,
    MSG_VOTE,
};
use rsl_wire::{
    BallotNumber, BootstrapMsg, JoinMessage, MemberId, MemberSet, Msg, PrepareAccepted, PrepareMsg,
    ProtocolVersion, RslNode, StatusResponse, Vote,
};

/// Parse a `"0x…"` hex-string field.
fn hex_field(v: &Value, key: &str) -> u64 {
    let s = v[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing hex field {key}"));
    u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap()
}

fn u32_field(v: &Value, key: &str) -> u32 {
    v[key]
        .as_u64()
        .unwrap_or_else(|| panic!("missing u32 field {key}")) as u32
}

fn u16_field(v: &Value, key: &str) -> u16 {
    v[key]
        .as_u64()
        .unwrap_or_else(|| panic!("missing u16 field {key}")) as u16
}

fn bool_field(v: &Value, key: &str) -> bool {
    v[key]
        .as_bool()
        .unwrap_or_else(|| panic!("missing bool field {key}"))
}

/// Decode a hex-string bytes field (absent or `""` ⇒ empty).
fn bytes_field(v: &Value, key: &str) -> Vec<u8> {
    match v[key].as_str() {
        Some("") | None => Vec::new(),
        Some(s) => common::from_hex(s),
    }
}

/// An empty string denotes the empty member id.
fn member(s: &str) -> MemberId {
    if s.is_empty() {
        MemberId::empty()
    } else {
        MemberId::from_str(s)
    }
}

fn ballot(v: &Value, id_key: &str, member_key: &str) -> BallotNumber {
    BallotNumber::new(
        u32_field(v, id_key),
        member(v[member_key].as_str().unwrap_or("")),
    )
}

/// Build the common header from an object carrying the standard header keys.
fn header_from(v: &Value, version: ProtocolVersion, msg_id: u16) -> Header {
    Header::new(
        version,
        msg_id,
        member(v["memberId"].as_str().unwrap_or("")),
        hex_field(v, "decree"),
        u32_field(v, "configurationNumber"),
        ballot(v, "ballotId", "ballotMember"),
        hex_field(v, "payload"),
    )
}

fn node_from(v: &Value) -> RslNode {
    RslNode {
        member_id: member(v["memberId"].as_str().unwrap_or("")),
        ip: u32_field(v, "ip"),
        rsl_port: u16_field(v, "rslPort"),
        rsl_learn_port: u16_field(v, "rslLearnPort"),
        app_port: u16_field(v, "appPort"),
        host_name: v["hostName"].as_str().unwrap_or("").as_bytes().to_vec(),
    }
}

fn members_from(v: &Value) -> Vec<RslNode> {
    v["members"]
        .as_array()
        .map(|arr| arr.iter().map(node_from).collect())
        .unwrap_or_default()
}

fn requests_from(v: &Value) -> Vec<Vec<u8>> {
    v["requests"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|r| common::from_hex(r.as_str().unwrap()))
                .collect()
        })
        .unwrap_or_default()
}

fn vote_from(v: &Value, version: ProtocolVersion) -> Vote {
    let is_reconfiguration = bool_field(v, "isReconfiguration");
    Vote {
        header: header_from(v, version, MSG_VOTE),
        primary_cookie: bytes_field(v, "primaryCookie"),
        is_reconfiguration,
        members_in_new_configuration: is_reconfiguration.then(|| MemberSet {
            members: members_from(v),
            cookie: bytes_field(v, "cookie"),
        }),
        relinquish_primary: bool_field(v, "relinquishPrimary"),
        requests: requests_from(v),
    }
}

/// Construct a `Msg` purely from the record's FIELDS metadata.
fn build(type_name: &str, v: &Value, version: ProtocolVersion) -> Msg {
    match type_name {
        "Message" => Msg::Base(header_from(v, version, u16_field(v, "msgId"))),
        "Vote" => Msg::Vote(vote_from(v, version)),
        "JoinMessage" => Msg::Join(JoinMessage {
            header: header_from(v, version, MSG_JOIN),
            learn_port: u16_field(v, "learnPort"),
            min_decree_in_log: hex_field(v, "minDecreeInLog"),
            checkpointed_decree: hex_field(v, "checkpointedDecree"),
            checkpoint_size: hex_field(v, "checkpointSize"),
        }),
        "PrepareMsg" => Msg::Prepare(PrepareMsg {
            header: header_from(v, version, MSG_PREPARE),
            primary_cookie: bytes_field(v, "primaryCookie"),
        }),
        "PrepareAccepted" => Msg::PrepareAccepted(PrepareAccepted {
            header: header_from(v, version, MSG_PREPARE_ACCEPTED),
            vote: vote_from(&v["vote"], version),
        }),
        "StatusResponse" => Msg::StatusResponse(StatusResponse {
            header: header_from(v, version, MSG_STATUS_RESPONSE),
            query_decree: hex_field(v, "queryDecree"),
            query_ballot: ballot(v, "queryBallotId", "queryBallotMember"),
            last_received_ago: hex_field(v, "lastReceivedAgo") as i64,
            min_decree_in_log: hex_field(v, "minDecreeInLog"),
            checkpointed_decree: hex_field(v, "checkpointedDecree"),
            checkpoint_size: hex_field(v, "checkpointSize"),
            max_ballot: ballot(v, "maxBallotId", "maxBallotMember"),
            state: u32_field(v, "state"),
        }),
        "BootstrapMsg" => Msg::Bootstrap(BootstrapMsg {
            header: header_from(v, version, MSG_BOOTSTRAP),
            member_set: MemberSet {
                members: members_from(v),
                cookie: bytes_field(v, "cookie"),
            },
        }),
        other => panic!("unknown TYPE {other:?}"),
    }
}

#[test]
fn every_record_reconstructs_from_fields() {
    let (records, _) = common::load();
    let mut checked = 0;
    for rec in &records {
        let ctx = format!("{} / {} / v{}", rec.type_name, rec.desc, rec.version);
        let fields = rec
            .fields
            .as_ref()
            .unwrap_or_else(|| panic!("{ctx}: record has no FIELDS metadata"));
        let v: Value =
            serde_json::from_str(fields).unwrap_or_else(|e| panic!("{ctx}: bad JSON: {e}"));
        let version = ProtocolVersion::from_wire(rec.version).unwrap();

        let msg = build(&rec.type_name, &v, version);
        let bytes = msg
            .marshal_with_checksum()
            .unwrap_or_else(|e| panic!("{ctx}: marshal failed: {e}"));
        assert_eq!(
            bytes, rec.bytes,
            "{ctx}: independently-constructed bytes differ from BYTES"
        );
        checked += 1;
    }
    assert_eq!(checked, 122, "expected to reconstruct all 122 records");
}
