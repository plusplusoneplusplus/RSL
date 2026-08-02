//! `PrepareMsg` — port of the `PrepareMsg` class in `message.cpp`.
//!
//! Body: a primary cookie (`v>=2` only), same encoding as in [`super::Vote`].

use super::vote::{read_primary_cookie, write_primary_cookie};
use super::{Header, MSG_PREPARE};
use crate::marshal::{Reader, Writer};

#[derive(Clone, Debug)]
pub struct PrepareMsg {
    pub header: Header,
    /// Primary cookie bytes (empty if none / pre-v2).
    pub primary_cookie: Vec<u8>,
}

impl PrepareMsg {
    /// `PrepareMsg::GetMarshalLen`.
    pub fn marshal_len(&self) -> u32 {
        let cookie = if self.header.version.has_primary_cookie() {
            4 + self.primary_cookie.len() as u32
        } else {
            0
        };
        cookie + Header::base_size(self.header.version)
    }

    pub fn marshal_with_checksum(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(self.marshal_len() as usize);
        self.header.write(&mut w, self.marshal_len());
        if self.header.version.has_primary_cookie() {
            write_primary_cookie(&mut w, &self.primary_cookie);
        }
        super::finalize(w.into_bytes())
    }

    pub fn unmarshal(buf: &[u8]) -> Option<PrepareMsg> {
        let mut r = Reader::new(buf);
        let header = Header::unmarshal(&mut r)?;
        if header.msg_id != MSG_PREPARE {
            return None;
        }
        let primary_cookie = if header.version.has_primary_cookie() {
            read_primary_cookie(&mut r)?
        } else {
            Vec::new()
        };
        Some(PrepareMsg {
            header,
            primary_cookie,
        })
    }
}
