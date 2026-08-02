//! `Vote` — the workhorse message. Port of the `Vote` class in `message.cpp`.
//!
//! Body layout after the common header, in order:
//! * `v>=2`: primary cookie (`u32` length + bytes).
//! * `v>=3`: a reconfiguration byte; if set, a [`MemberSet`] follows and there
//!   are no requests.
//! * `v>=5`: a `relinquishPrimary` byte.
//! * remaining bytes: zero or more client requests, each a `u32` length + bytes,
//!   filling the message out to its `un_marshal_len`.

use super::{Header, MSG_VOTE};
use crate::marshal::{Reader, Writer};
use crate::types::MemberSet;

#[derive(Clone, Debug)]
pub struct Vote {
    pub header: Header,
    /// Primary cookie bytes (empty if none / pre-v2).
    pub primary_cookie: Vec<u8>,
    pub is_reconfiguration: bool,
    /// Present iff `is_reconfiguration` (and `v>=3`).
    pub members_in_new_configuration: Option<MemberSet>,
    pub relinquish_primary: bool,
    /// Client request payloads, in order.
    pub requests: Vec<Vec<u8>>,
}

impl Vote {
    /// Total marshaled length (`Vote::GetMarshalLen`).
    pub fn marshal_len(&self) -> u32 {
        Header::base_size(self.header.version) + self.body_len()
    }

    fn body_len(&self) -> u32 {
        let v = self.header.version;
        let mut len = 0u32;
        if v.has_primary_cookie() {
            len += 4 + self.primary_cookie.len() as u32;
        }
        if v.has_reconfiguration() {
            len += 1;
            if self.is_reconfiguration {
                if let Some(ms) = &self.members_in_new_configuration {
                    len += ms.marshal_len(v);
                }
            }
        }
        if v.has_relinquish_primary() {
            len += 1;
        }
        for req in &self.requests {
            len += 4 + req.len() as u32;
        }
        len
    }

    /// Write the full message (header + body) without patching the checksum.
    /// Used both standalone and when nested inside a [`super::PrepareAccepted`].
    pub(crate) fn write_to(&self, w: &mut Writer) {
        let v = self.header.version;
        self.header.write(w, self.marshal_len());

        if v.has_primary_cookie() {
            write_primary_cookie(w, &self.primary_cookie);
        }
        if v.has_reconfiguration() {
            w.write_bool(self.is_reconfiguration);
            if self.is_reconfiguration {
                self.members_in_new_configuration
                    .as_ref()
                    .expect("reconfiguration vote without a member set")
                    .marshal(w, v);
            }
        }
        if v.has_relinquish_primary() {
            w.write_bool(self.relinquish_primary);
        }
        for req in &self.requests {
            w.write_u32(req.len() as u32);
            w.write_data(req);
        }
    }

    /// Marshal to bytes with the checksum patched in.
    pub fn marshal_with_checksum(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(self.marshal_len() as usize);
        self.write_to(&mut w);
        super::finalize(w.into_bytes())
    }

    /// Parse a vote from `buf` (which starts at the vote header). Requests are
    /// read only up to the vote's own `un_marshal_len`, mirroring the C++ which
    /// copies exactly that many bytes into a private buffer before parsing.
    pub fn unmarshal(buf: &[u8]) -> Option<Vote> {
        let mut r = Reader::new(buf);
        let header = Header::unmarshal(&mut r)?;
        if header.msg_id != MSG_VOTE {
            return None;
        }
        let v = header.version;
        let ulen = header.un_marshal_len as usize;
        if ulen > buf.len() {
            return None;
        }

        // Re-scope to the vote's own bytes so a request length can't run past
        // the message into unrelated trailing data.
        let mut br = Reader::new(&buf[..ulen]);
        br.set_read_pointer(Header::base_size(v));

        let primary_cookie = if v.has_primary_cookie() {
            read_primary_cookie(&mut br)?
        } else {
            Vec::new()
        };

        let (is_reconfiguration, members_in_new_configuration) = if v.has_reconfiguration() {
            let is_reconf = br.read_bool()?;
            let members = if is_reconf {
                Some(MemberSet::unmarshal(&mut br, v)?)
            } else {
                None
            };
            (is_reconf, members)
        } else {
            (false, None)
        };

        let relinquish_primary = if v.has_relinquish_primary() {
            br.read_bool()?
        } else {
            false
        };

        let mut requests = Vec::new();
        while (br.read_pointer() as usize) < ulen {
            let req_len = br.read_u32()?;
            // reqLen == 0 is rejected by the C++ ("Incorrect length").
            if req_len == 0 {
                return None;
            }
            let req = br.read_data(req_len)?.to_vec();
            requests.push(req);
        }

        Some(Vote {
            header,
            primary_cookie,
            is_reconfiguration,
            members_in_new_configuration,
            relinquish_primary,
            requests,
        })
    }
}

/// `PrimaryCookie::Marshal` — `u32` length then bytes (bytes omitted if empty).
/// Shared with [`super::PrepareMsg`], which uses the same encoding.
pub(crate) fn write_primary_cookie(w: &mut Writer, cookie: &[u8]) {
    w.write_u32(cookie.len() as u32);
    if !cookie.is_empty() {
        w.write_data(cookie);
    }
}

/// `PrimaryCookie::UnMarshal` — consumes `4 + len` bytes either way.
pub(crate) fn read_primary_cookie(r: &mut Reader) -> Option<Vec<u8>> {
    let len = r.read_u32()?;
    if len == 0 {
        return Some(Vec::new());
    }
    Some(r.read_data(len)?.to_vec())
}

impl Vote {
    /// A vote carrying only the header (no cookie, reconfiguration, or
    /// requests), mirroring the simplest `Vote(version, ...)` constructor.
    pub fn new(header: Header) -> Vote {
        Vote {
            header,
            primary_cookie: Vec::new(),
            is_reconfiguration: false,
            members_in_new_configuration: None,
            relinquish_primary: false,
            requests: Vec::new(),
        }
    }

    /// Append a client request (mirrors `Vote::AddRequest`).
    pub fn add_request(&mut self, request: impl Into<Vec<u8>>) {
        self.requests.push(request.into());
    }
}
