//! `JoinMessage` — port of the `JoinMessage` class in `message.cpp`.
//!
//! Body: `learnPort` (`u16`), then `minDecreeInLog`, `checkpointedDecree`,
//! `checkpointSize` (`u64` each). No version gating — identical on all versions.

use super::{Header, MSG_JOIN};
use crate::marshal::{Reader, Writer};

#[derive(Clone, Debug)]
pub struct JoinMessage {
    pub header: Header,
    pub learn_port: u16,
    pub min_decree_in_log: u64,
    pub checkpointed_decree: u64,
    pub checkpoint_size: u64,
}

impl JoinMessage {
    /// `JoinMessage::GetMarshalLen` = base + 2 + 8 + 8 + 8.
    pub fn marshal_len(&self) -> u32 {
        Header::base_size(self.header.version) + 2 + 8 + 8 + 8
    }

    pub fn marshal_with_checksum(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(self.marshal_len() as usize);
        self.header.write(&mut w, self.marshal_len());
        w.write_u16(self.learn_port);
        w.write_u64(self.min_decree_in_log);
        w.write_u64(self.checkpointed_decree);
        w.write_u64(self.checkpoint_size);
        super::finalize(w.into_bytes())
    }

    pub fn unmarshal(buf: &[u8]) -> Option<JoinMessage> {
        let mut r = Reader::new(buf);
        let header = Header::unmarshal(&mut r)?;
        if header.msg_id != MSG_JOIN {
            return None;
        }
        let learn_port = r.read_u16()?;
        let min_decree_in_log = r.read_u64()?;
        let checkpointed_decree = r.read_u64()?;
        let checkpoint_size = r.read_u64()?;
        Some(JoinMessage {
            header,
            learn_port,
            min_decree_in_log,
            checkpointed_decree,
            checkpoint_size,
        })
    }
}
