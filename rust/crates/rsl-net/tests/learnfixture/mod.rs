//! Scaffolding for the Phase-4c learn-port tests: scratch data directories, a
//! stub [`StatusProvider`], and helpers that build real logs and checkpoints
//! with `rsl-storage`.
//!
//! Each integration-test binary links its own copy and uses a different subset,
//! so unused-item warnings here are expected.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use rsl_net::learnport::StatusProvider;
use rsl_storage::checkpoint::{CheckpointHeader, CheckpointWriter};
use rsl_storage::durability::NoSync;
use rsl_storage::log::LogWriter;
use rsl_wire::messages::{
    Header, StatusResponse, MSG_PREPARE, MSG_RECONFIGURATION_DECISION, MSG_STATUS_RESPONSE,
    MSG_VOTE,
};
use rsl_wire::{
    marshal_base, BallotNumber, ConfigurationInfo, MemberId, MemberSet, PrepareMsg,
    ProtocolVersion, RslNode, Vote,
};

/// A scratch directory under the test binary's temp dir, removed on drop.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(prefix: &str) -> TempDir {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("{prefix}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create scratch dir");
        TempDir { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

pub fn header(msg_id: u16, decree: u64) -> Header {
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

/// A vote record with `request_len` bytes of client payload.
pub fn vote_record(decree: u64, request_len: usize) -> Vec<u8> {
    let mut vote = Vote::new(header(MSG_VOTE, decree));
    if request_len > 0 {
        vote.add_request(vec![b'r'; request_len]);
    }
    vote.marshal_with_checksum().expect("marshal vote")
}

pub fn prepare_record(decree: u64) -> Vec<u8> {
    PrepareMsg {
        header: header(MSG_PREPARE, decree),
        primary_cookie: Vec::new(),
    }
    .marshal_with_checksum()
}

pub fn decision_record(decree: u64) -> Vec<u8> {
    marshal_base(&header(MSG_RECONFIGURATION_DECISION, decree))
}

// ---------------------------------------------------------------------------
// Data directories
// ---------------------------------------------------------------------------

/// Write `<dir>/<file_decree>.log` holding a vote per decree in `decrees`.
/// Returns the file's length.
pub fn write_log(dir: &Path, file_decree: u64, decrees: &[u64], request_len: usize) -> u64 {
    let records: Vec<Vec<u8>> = decrees
        .iter()
        .map(|&d| vote_record(d, request_len))
        .collect();
    write_log_records(dir, file_decree, &records)
}

/// Write `<dir>/<file_decree>.log` from already-marshaled records.
pub fn write_log_records(dir: &Path, file_decree: u64, records: &[Vec<u8>]) -> u64 {
    let mut writer = LogWriter::open_with(dir, file_decree, NoSync).expect("open log");
    let refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    writer.append_batch(&refs).expect("append");
    writer.data_len()
}

/// A configuration good enough for a v6 checkpoint header.
pub fn configuration() -> ConfigurationInfo {
    ConfigurationInfo::new(
        7,
        1,
        MemberSet {
            members: vec![RslNode {
                member_id: MemberId::from_str("101"),
                ip: 0x0100_007f,
                rsl_port: 8080,
                rsl_learn_port: 8081,
                app_port: 0,
                host_name: b"host-a".to_vec(),
            }],
            cookie: Vec::new(),
        },
    )
}

/// Write `<dir>/<decree>.codex` with `state` as the user state. Returns its
/// size, which is what a client must learn out-of-band before fetching it.
pub fn write_checkpoint(dir: &Path, decree: u64, state: &[u8]) -> u64 {
    let mut vote = Vote::new(header(MSG_VOTE, decree + 1));
    vote.primary_cookie = Vec::new();
    let mut header = CheckpointHeader::new(vote);
    header.member_id = MemberId::from_str("101");
    header.state_configuration = Some(configuration());

    let path = dir.join(rsl_storage::dir::checkpoint_file_name(decree));
    let mut writer = CheckpointWriter::create_with(&path, header, NoSync).expect("create codex");
    std::io::Write::write_all(&mut writer, state).expect("write state");
    let final_header = writer.finish().expect("finish codex");
    final_header.size
}

// ---------------------------------------------------------------------------
// A stub engine
// ---------------------------------------------------------------------------

/// A [`StatusProvider`] with fixed answers, plus counters so a test can prove
/// the server actually consulted it.
pub struct StubStatus {
    pub checkpointed_decree: Option<u64>,
    pub checkpoint_size: u64,
    pub min_decree_in_log: u64,
    pub max_decree: u64,
    /// When true, `status` returns `None` — the `m_relinquishPrimary` case.
    pub relinquishing: bool,
    pub status_calls: AtomicU64,
}

impl StubStatus {
    pub fn new() -> StubStatus {
        StubStatus {
            checkpointed_decree: None,
            checkpoint_size: 0,
            min_decree_in_log: 1,
            max_decree: 1,
            relinquishing: false,
            status_calls: AtomicU64::new(0),
        }
    }

    pub fn with_checkpoint(mut self, decree: u64, size: u64) -> StubStatus {
        self.checkpointed_decree = Some(decree);
        self.checkpoint_size = size;
        self
    }

    pub fn with_log_range(mut self, min: u64, max: u64) -> StubStatus {
        self.min_decree_in_log = min;
        self.max_decree = max;
        self
    }

    pub fn relinquishing(mut self) -> StubStatus {
        self.relinquishing = true;
        self
    }
}

impl Default for StubStatus {
    fn default() -> StubStatus {
        StubStatus::new()
    }
}

impl StatusProvider for StubStatus {
    fn status(&self, request: &Header) -> Option<StatusResponse> {
        self.status_calls.fetch_add(1, Ordering::Relaxed);
        if self.relinquishing {
            return None;
        }
        Some(StatusResponse {
            header: Header::new(
                request.version,
                MSG_STATUS_RESPONSE,
                MemberId::from_str("101"),
                self.max_decree,
                7,
                BallotNumber::new(3, MemberId::from_str("202")),
                0,
            ),
            query_decree: request.decree,
            query_ballot: request.ballot.clone(),
            last_received_ago: 0,
            min_decree_in_log: self.min_decree_in_log,
            checkpointed_decree: self.checkpointed_decree.unwrap_or(0),
            checkpoint_size: self.checkpoint_size,
            max_ballot: BallotNumber::new(3, MemberId::from_str("202")),
            state: 0,
        })
    }

    fn checkpointed_decree(&self) -> Option<u64> {
        self.checkpointed_decree
    }
}

/// The `rsl-linux-proxy` binary, if it has been built (or `RSL_LINUX_PROXY` points at
/// one). Building it needs cmake + g++, so its absence is not a test failure.
pub fn linux_proxy() -> Option<PathBuf> {
    if let Some(value) = std::env::var_os("RSL_LINUX_PROXY") {
        if !value.is_empty() {
            let path = PathBuf::from(value);
            assert!(
                path.is_file(),
                "RSL_LINUX_PROXY={} is not a file",
                path.display()
            );
            return Some(path);
        }
    }
    #[cfg(unix)]
    {
        let path = repo_root().join("tools/linux-proxy/build/rsl-linux-proxy");
        path.is_file().then_some(path)
    }
    #[cfg(not(unix))]
    None
}

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repo root")
}

pub fn warn_no_peer(test: &str) {
    eprintln!(
        "{test}: SKIPPED — no rsl-linux-proxy binary. Build it with \
         `cmake -S tools/linux-proxy -B tools/linux-proxy/build && \
         cmake --build tools/linux-proxy/build`, or set RSL_LINUX_PROXY."
    );
}
