//! Property tests (plan item 9): arbitrary *valid* messages, built directly as
//! Rust structs across all six protocol versions, marshal and re-parse to a
//! stable byte fixpoint.
//!
//! The invariant checked is `marshal(parse(marshal(m))) == marshal(m)`: the
//! writer's output must parse, and re-marshaling the parse must be identical.
//! This catches reader/writer disagreements without needing `PartialEq` on the
//! message types, and without assuming the writer preserves every non-canonical
//! encoding a hand-built struct might contain.

mod common;

use proptest::prelude::*;

use rsl_wire::messages::{
    Header, MSG_BOOTSTRAP, MSG_JOIN, MSG_PREPARE, MSG_PREPARE_ACCEPTED, MSG_STATUS_RESPONSE,
    MSG_VOTE, MSG_VOTE_ACCEPTED,
};
use rsl_wire::{
    BallotNumber, BootstrapMsg, JoinMessage, MemberId, MemberSet, Msg, MsgKind, PrepareAccepted,
    PrepareMsg, ProtocolVersion, RslNode, StatusResponse, Vote,
};

/// Member ids must round-trip at every version. Pre-v3 marshals the id as a
/// `u64` (decimal parse), so only canonical decimal strings survive; generate
/// those (plus the empty id) and they round-trip at v>=4 too.
fn member_id() -> impl Strategy<Value = MemberId> {
    prop_oneof![
        1 => Just(MemberId::empty()),
        6 => any::<u64>().prop_map(|n| MemberId::from_str(&n.to_string())),
    ]
}

fn version() -> impl Strategy<Value = ProtocolVersion> {
    (1u16..=6).prop_map(|r| ProtocolVersion::from_wire(r).unwrap())
}

fn ballot() -> impl Strategy<Value = BallotNumber> {
    (any::<u32>(), member_id()).prop_map(|(id, m)| BallotNumber::new(id, m))
}

fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..max)
}

fn header(version: ProtocolVersion, msg_id: u16) -> impl Strategy<Value = Header> {
    (
        member_id(),
        any::<u64>(),
        any::<u32>(),
        ballot(),
        any::<u64>(),
    )
        .prop_map(move |(m, decree, config, b, payload)| {
            Header::new(version, msg_id, m, decree, config, b, payload)
        })
}

fn node() -> impl Strategy<Value = RslNode> {
    (
        member_id(),
        any::<u32>(),
        any::<u16>(),
        any::<u16>(),
        any::<u16>(),
        bytes(40),
    )
        .prop_map(
            |(member_id, ip, rsl_port, rsl_learn_port, app_port, host_name)| RslNode {
                member_id,
                ip,
                rsl_port,
                rsl_learn_port,
                app_port,
                host_name,
            },
        )
}

fn member_set() -> impl Strategy<Value = MemberSet> {
    (prop::collection::vec(node(), 0..4), bytes(32))
        .prop_map(|(members, cookie)| MemberSet { members, cookie })
}

/// A non-empty request payload (the writer accepts zero-length requests, but the
/// reader rejects a `0` length, so keep them non-empty for a clean round-trip).
fn request() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..40)
}

fn vote(version: ProtocolVersion) -> impl Strategy<Value = Vote> {
    // Reconfiguration (with a member set) is only valid at v>=3.
    let reconf = if version >= ProtocolVersion::V3 {
        prop_oneof![Just(None), member_set().prop_map(Some)].boxed()
    } else {
        Just(None).boxed()
    };
    (
        header(version, MSG_VOTE),
        bytes(24),
        reconf,
        any::<bool>(),
        prop::collection::vec(request(), 0..4),
    )
        .prop_map(move |(header, primary_cookie, ms, relinquish, requests)| {
            let is_reconfiguration = ms.is_some();
            Vote {
                header,
                primary_cookie,
                is_reconfiguration,
                members_in_new_configuration: ms,
                relinquish_primary: relinquish,
                // A reconfiguration vote carries no client requests.
                requests: if is_reconfiguration {
                    Vec::new()
                } else {
                    requests
                },
            }
        })
}

/// A message plus the [`MsgKind`] that parses it.
fn message() -> impl Strategy<Value = (MsgKind, Msg)> {
    version().prop_flat_map(|v| {
        prop_oneof![
            // Base message: any payload-less id (VoteAccepted stands in).
            header(v, MSG_VOTE_ACCEPTED).prop_map(|h| (MsgKind::Base, Msg::Base(h))),
            vote(v).prop_map(|m| (MsgKind::Vote, Msg::Vote(m))),
            (
                header(v, MSG_JOIN),
                any::<u16>(),
                any::<u64>(),
                any::<u64>(),
                any::<u64>()
            )
                .prop_map(|(header, learn_port, a, b, c)| (
                    MsgKind::Join,
                    Msg::Join(JoinMessage {
                        header,
                        learn_port,
                        min_decree_in_log: a,
                        checkpointed_decree: b,
                        checkpoint_size: c,
                    })
                )),
            (header(v, MSG_PREPARE), bytes(24)).prop_map(|(header, primary_cookie)| (
                MsgKind::Prepare,
                Msg::Prepare(PrepareMsg {
                    header,
                    primary_cookie
                })
            )),
            (header(v, MSG_PREPARE_ACCEPTED), vote(v)).prop_map(|(header, vote)| (
                MsgKind::PrepareAccepted,
                Msg::PrepareAccepted(PrepareAccepted { header, vote })
            )),
            (
                header(v, MSG_STATUS_RESPONSE),
                any::<u64>(),
                ballot(),
                any::<i64>(),
                any::<u64>(),
                any::<u64>(),
                any::<u64>(),
                ballot(),
                any::<u32>(),
            )
                .prop_map(|(header, qd, qb, lra, mdl, cd, cs, mb, state)| (
                    MsgKind::StatusResponse,
                    Msg::StatusResponse(StatusResponse {
                        header,
                        query_decree: qd,
                        query_ballot: qb,
                        last_received_ago: lra,
                        min_decree_in_log: mdl,
                        checkpointed_decree: cd,
                        checkpoint_size: cs,
                        max_ballot: mb,
                        state,
                    })
                )),
            (header(v, MSG_BOOTSTRAP), member_set()).prop_map(|(header, member_set)| (
                MsgKind::Bootstrap,
                Msg::Bootstrap(BootstrapMsg { header, member_set })
            )),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn arbitrary_messages_reach_a_byte_fixpoint((kind, msg) in message()) {
        // The strategies never build the C++-lethal reconfig+requests shape,
        // so marshaling cannot fail.
        let b0 = msg.marshal_with_checksum().expect("valid message failed to marshal");

        // The writer's output must parse as the same kind.
        let parsed = Msg::unmarshal(kind, &b0)
            .expect("marshaled message failed to parse");

        // Its checksum must verify.
        prop_assert!(rsl_wire::messages::verify_checksum(&b0));

        // Re-marshaling the parse is byte-identical.
        let b1 = parsed.marshal_with_checksum().expect("re-marshal failed");
        prop_assert_eq!(b0, b1);
    }
}
