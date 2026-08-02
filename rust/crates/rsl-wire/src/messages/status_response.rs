//! `StatusResponse` — port of the `StatusResponse` class in `message.cpp`.
//!
//! Body: `queryDecree` (`u64`), `queryBallot`, `lastReceivedAgo` (`i64`),
//! `minDecreeInLog`, `checkpointedDecree`, `checkpointSize` (`u64` each),
//! `maxBallot`, and `state` (`u32`).

use super::{Header, MSG_STATUS_RESPONSE};
use crate::marshal::{Reader, Writer};
use crate::types::BallotNumber;

#[derive(Clone, Debug)]
pub struct StatusResponse {
    pub header: Header,
    pub query_decree: u64,
    pub query_ballot: BallotNumber,
    pub last_received_ago: i64,
    pub min_decree_in_log: u64,
    pub checkpointed_decree: u64,
    pub checkpoint_size: u64,
    pub max_ballot: BallotNumber,
    pub state: u32,
}

impl StatusResponse {
    /// `StatusResponse::GetMarshalLen`.
    pub fn marshal_len(&self) -> u32 {
        let v = self.header.version;
        8 + BallotNumber::base_size(v)
            + 8
            + 8
            + 8
            + 8
            + BallotNumber::base_size(v)
            + 4
            + Header::base_size(v)
    }

    pub fn marshal_with_checksum(&self) -> Vec<u8> {
        let v = self.header.version;
        let mut w = Writer::with_capacity(self.marshal_len() as usize);
        self.header.write(&mut w, self.marshal_len());
        w.write_u64(self.query_decree);
        self.query_ballot.marshal(&mut w, v);
        w.write_u64(self.last_received_ago as u64);
        w.write_u64(self.min_decree_in_log);
        w.write_u64(self.checkpointed_decree);
        w.write_u64(self.checkpoint_size);
        self.max_ballot.marshal(&mut w, v);
        w.write_u32(self.state);
        super::finalize(w.into_bytes())
    }

    pub fn unmarshal(buf: &[u8]) -> Option<StatusResponse> {
        let mut r = Reader::new(buf);
        let header = Header::unmarshal(&mut r)?;
        if header.msg_id != MSG_STATUS_RESPONSE {
            return None;
        }
        let v = header.version;
        let query_decree = r.read_u64()?;
        let query_ballot = BallotNumber::unmarshal(&mut r, v)?;
        let last_received_ago = r.read_u64()? as i64;
        let min_decree_in_log = r.read_u64()?;
        let checkpointed_decree = r.read_u64()?;
        let checkpoint_size = r.read_u64()?;
        let max_ballot = BallotNumber::unmarshal(&mut r, v)?;
        let state = r.read_u32()?;
        Some(StatusResponse {
            header,
            query_decree,
            query_ballot,
            last_received_ago,
            min_decree_in_log,
            checkpointed_decree,
            checkpoint_size,
            max_ballot,
            state,
        })
    }
}
