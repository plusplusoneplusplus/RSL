//! `BootstrapMsg` — port of the `BootstrapMsg` class in `message.cpp`.
//!
//! Body: a [`MemberSet`]. Introduced with v4 (the driver only emits v4+), but
//! the marshaling itself is version-parameterized like everything else.

use super::{Header, MSG_BOOTSTRAP};
use crate::marshal::{Reader, Writer};
use crate::types::MemberSet;

#[derive(Clone, Debug)]
pub struct BootstrapMsg {
    pub header: Header,
    pub member_set: MemberSet,
}

impl BootstrapMsg {
    /// `BootstrapMsg::GetMarshalLen` = base + member set length.
    pub fn marshal_len(&self) -> u32 {
        Header::base_size(self.header.version) + self.member_set.marshal_len(self.header.version)
    }

    pub fn marshal_with_checksum(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(self.marshal_len() as usize);
        self.header.write(&mut w, self.marshal_len());
        self.member_set.marshal(&mut w, self.header.version);
        super::finalize(w.into_bytes())
    }

    pub fn unmarshal(buf: &[u8]) -> Option<BootstrapMsg> {
        let mut r = Reader::new(buf);
        let header = Header::unmarshal(&mut r)?;
        if header.msg_id != MSG_BOOTSTRAP {
            return None;
        }
        let member_set = MemberSet::unmarshal(&mut r, header.version)?;
        Some(BootstrapMsg { header, member_set })
    }
}
