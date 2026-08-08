//! Shared scaffolding for portable proxy framing tests and authoritative
//! Windows oracle tests.
//!
//! Each integration-test binary links its own copy and uses a different subset,
//! so unused-item warnings here are expected.
#![allow(dead_code)]

use std::path::PathBuf;

/// One `PACKET` block: a byte stream fed to the extracted proxy receive path.
pub struct PacketVector {
    pub desc: String,
    /// `MAXSIZE`/`MAXALERT` exactly as passed to the C++ (0 = library default).
    pub max_size: u32,
    pub max_alert: u32,
    pub bytes: Vec<u8>,
    /// `accept` / `need-more` / `reject-header` / `reject-checksum`.
    pub outcome: String,
    /// Bytes covered by the accepted packets.
    pub consumed: usize,
    /// Payloads of the accepted packets, in order.
    pub payloads: Vec<Vec<u8>>,
    pub detail: String,
}

/// One `LEARN` block: a byte stream fed to `Message::ReadFromSocket`.
pub struct LearnVector {
    pub desc: String,
    pub max_size: u32,
    pub bytes: Vec<u8>,
    /// `false` when the C++ could not safely be run on this input, so the
    /// recorded outcome is this port's documented behaviour instead.
    pub executed: bool,
    pub outcome: String,
    /// Version as parsed from the 6-byte header (0 if never reached).
    pub version: u16,
    /// Length as parsed from the 6-byte header (0 if never reached).
    pub msg_len: u32,
    pub detail: String,
}

/// One `RECORD` block, reduced to what the framing tests need.
pub struct MessageVector {
    pub type_name: String,
    pub version: u16,
    pub bytes: Vec<u8>,
}

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repo root")
}

pub fn corpus_path() -> PathBuf {
    repo_root().join("tools/golden-gen/corpus/phase1-golden.txt")
}

/// The `golden-gen` binary, if it has been built (or `RSL_GOLDEN_GEN` points at
/// one). Building it needs cmake + g++, so its absence is not a test failure —
/// the live-peer tests skip instead.
pub fn golden_gen() -> Option<PathBuf> {
    if let Some(value) = std::env::var_os("RSL_GOLDEN_GEN") {
        if !value.is_empty() {
            let path = PathBuf::from(value);
            return path.is_file().then_some(path);
        }
    }
    let path = repo_root().join("tools/golden-gen/build/golden-gen");
    path.is_file().then_some(path)
}

pub fn authoritative_interop() -> bool {
    std::env::var("RSL_AUTHORITATIVE_INTEROP")
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

pub fn windows_oracle() -> Option<PathBuf> {
    if let Some(value) = std::env::var_os("RSL_WINDOWS_ORACLE") {
        if !value.is_empty() {
            let path = PathBuf::from(value);
            assert!(
                path.is_file(),
                "RSL_WINDOWS_ORACLE={} is not a file",
                path.display()
            );
            return Some(path);
        }
    }
    assert!(
        !authoritative_interop(),
        "RSL_AUTHORITATIVE_INTEROP requires RSL_WINDOWS_ORACLE"
    );
    None
}

pub fn warn_no_peer(test: &str) {
    eprintln!(
        "{test}: SKIPPED — no golden-gen binary. Build it with \
         `cmake -S tools/golden-gen -B tools/golden-gen/build && \
         cmake --build tools/golden-gen/build`, or set RSL_GOLDEN_GEN."
    );
}

/// Parse every framing block in the corpus.
pub fn load() -> (Vec<PacketVector>, Vec<LearnVector>, Vec<MessageVector>) {
    let path = corpus_path();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read corpus at {}: {e}", path.display()));

    let mut packets = Vec::new();
    let mut learns = Vec::new();
    let mut messages = Vec::new();

    let mut block: Vec<&str> = Vec::new();
    let mut flush = |block: &mut Vec<&str>| {
        if !block.is_empty() {
            match block[0] {
                "PACKET" => packets.push(parse_packet(block)),
                "LEARN" => learns.push(parse_learn(block)),
                "RECORD" => messages.push(parse_message(block)),
                // RECORD/FPRINT/CONTAINER belong to the rsl-wire tests.
                _ => {}
            }
            block.clear();
        }
    };

    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        if line.trim().is_empty() {
            flush(&mut block);
        } else {
            block.push(line);
        }
    }
    flush(&mut block);

    assert!(!packets.is_empty(), "corpus has no PACKET blocks");
    assert!(!learns.is_empty(), "corpus has no LEARN blocks");
    (packets, learns, messages)
}

fn value<'a>(lines: &[&'a str], key: &str) -> Option<&'a str> {
    lines
        .iter()
        .find(|l| l.starts_with(key) && l[key.len()..].starts_with(' '))
        .map(|l| &l[key.len() + 1..])
}

fn require<'a>(lines: &[&'a str], key: &str) -> &'a str {
    value(lines, key).unwrap_or_else(|| panic!("missing {key} in block {:?}", lines[0]))
}

/// All values of a repeated `KEY value` line, in order.
fn values<'a>(lines: &[&'a str], key: &str) -> Vec<&'a str> {
    lines
        .iter()
        .filter(|l| l.starts_with(key) && l[key.len()..].starts_with(' '))
        .map(|l| &l[key.len() + 1..])
        .collect()
}

fn parse_packet(lines: &[&str]) -> PacketVector {
    let vector = PacketVector {
        desc: require(lines, "DESC").to_string(),
        max_size: require(lines, "MAXSIZE").parse().unwrap(),
        max_alert: require(lines, "MAXALERT").parse().unwrap(),
        bytes: from_hex(value(lines, "BYTES").unwrap_or("")),
        outcome: require(lines, "OUTCOME").to_string(),
        consumed: require(lines, "CONSUMED").parse().unwrap(),
        payloads: values(lines, "PAYLOAD").into_iter().map(from_hex).collect(),
        detail: require(lines, "DETAIL").to_string(),
    };
    let declared: usize = require(lines, "PAYLOADS").parse().unwrap();
    assert_eq!(declared, vector.payloads.len(), "{}: PAYLOADS", vector.desc);
    assert_eq!(
        require(lines, "LEN").parse::<usize>().unwrap(),
        vector.bytes.len(),
        "{}: LEN",
        vector.desc
    );
    vector
}

fn parse_learn(lines: &[&str]) -> LearnVector {
    let vector = LearnVector {
        desc: require(lines, "DESC").to_string(),
        max_size: require(lines, "MAXSIZE").parse().unwrap(),
        bytes: from_hex(value(lines, "BYTES").unwrap_or("")),
        executed: require(lines, "EXEC") == "yes",
        outcome: require(lines, "OUTCOME").to_string(),
        version: require(lines, "VERSION").parse().unwrap(),
        msg_len: require(lines, "MSGLEN").parse().unwrap(),
        detail: require(lines, "DETAIL").to_string(),
    };
    assert_eq!(
        require(lines, "LEN").parse::<usize>().unwrap(),
        vector.bytes.len(),
        "{}: LEN",
        vector.desc
    );
    vector
}

fn parse_message(lines: &[&str]) -> MessageVector {
    MessageVector {
        type_name: require(lines, "TYPE").to_string(),
        version: require(lines, "VERSION").parse().unwrap(),
        bytes: from_hex(value(lines, "BYTES").unwrap_or("")),
    }
}

pub fn from_hex(s: &str) -> Vec<u8> {
    let s = s.trim();
    assert!(s.len().is_multiple_of(2), "odd-length hex: {s:?}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex"))
        .collect()
}
