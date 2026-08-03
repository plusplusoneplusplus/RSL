//! `PrepareAccepted` — port of the `PrepareAccepted` class in `message.cpp`.
//!
//! Body: a complete nested [`Vote`] message, marshaled in full (its own header
//! included). The nested vote's checksum field is left as-is (zero in practice);
//! only the outer message's checksum is patched, and it covers the nested vote's
//! zeroed checksum field along with everything else.

use super::vote::Vote;
use super::{Header, MarshalError, MSG_PREPARE_ACCEPTED};
use crate::marshal::{Reader, Writer};

#[derive(Clone, Debug)]
pub struct PrepareAccepted {
    pub header: Header,
    pub vote: Vote,
}

impl PrepareAccepted {
    /// `PrepareAccepted::GetMarshalLen` = vote length + base.
    pub fn marshal_len(&self) -> u32 {
        self.vote.marshal_len() + Header::base_size(self.header.version)
    }

    /// Errors on the C++-lethal nested-vote reconfiguration shapes — see
    /// `Vote::write_to`.
    pub fn marshal_with_checksum(&self) -> Result<Vec<u8>, MarshalError> {
        let mut w = Writer::with_capacity(self.marshal_len() as usize);
        self.header.write(&mut w, self.marshal_len());
        // Nested vote is written in full, unchecksummed (write_to, not
        // marshal_with_checksum).
        self.vote.write_to(&mut w)?;
        Ok(super::finalize(w.into_bytes()))
    }

    pub fn unmarshal(buf: &[u8]) -> Option<PrepareAccepted> {
        let mut r = Reader::new(buf);
        let header = Header::unmarshal(&mut r)?;
        if header.msg_id != MSG_PREPARE_ACCEPTED {
            return None;
        }
        // The nested vote begins immediately after this header.
        let vote_start = r.read_pointer() as usize;
        let vote = Vote::unmarshal(&buf[vote_start..])?;
        Some(PrepareAccepted { header, vote })
    }
}
