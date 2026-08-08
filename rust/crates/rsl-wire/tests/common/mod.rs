//! Shared corpus loader for supplemental Linux proxy vectors.
//!
//! Parses `tools/linux-proxy/corpus/proxy-vectors.txt` — a line-oriented,
//! blank-line-separated format of `RECORD` and `FPRINT` blocks.
//!
//! Each integration-test binary links its own copy of this module and uses a
//! different subset of it, so unused-item warnings here are expected.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use rsl_wire::MsgKind;

/// One marshaled-message reference vector.
pub struct Record {
    pub type_name: String,
    pub desc: String,
    pub version: u16,
    pub len: usize,
    pub checksum: u64,
    pub bytes: Vec<u8>,
    /// The `FIELDS {json}` line, if present (added in plan item 7).
    #[allow(dead_code)]
    pub fields: Option<String>,
}

/// One raw Rabin-64 fingerprint vector.
pub struct Fprint {
    pub desc: String,
    pub len: usize,
    pub input: Vec<u8>,
    pub checksum: u64,
}

/// One raw `MarshalData` container vector (`StartContainer`/`CloseContainer`
/// back-patch scenarios; no checksum — these are not messages). The Rust test
/// rebuilds the scenario named by `desc` and must reproduce `bytes` exactly.
pub struct Container {
    pub desc: String,
    pub len: usize,
    pub bytes: Vec<u8>,
}

impl Record {
    /// Map the corpus `TYPE` to the parser that should handle it. The base
    /// class handles the twelve payload-less message ids.
    pub fn kind(&self) -> MsgKind {
        match self.type_name.as_str() {
            "Message" => MsgKind::Base,
            "Vote" => MsgKind::Vote,
            "JoinMessage" => MsgKind::Join,
            "PrepareMsg" => MsgKind::Prepare,
            "PrepareAccepted" => MsgKind::PrepareAccepted,
            "StatusResponse" => MsgKind::StatusResponse,
            "BootstrapMsg" => MsgKind::Bootstrap,
            other => panic!("unknown record TYPE {other:?}"),
        }
    }
}

/// Absolute path to the supplemental proxy corpus.
pub fn corpus_path() -> PathBuf {
    // CARGO_MANIFEST_DIR = <repo>/rust/crates/rsl-wire
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tools/linux-proxy/corpus/proxy-vectors.txt")
}

/// Load and parse the corpus into its records and fingerprint vectors.
pub fn load() -> (Vec<Record>, Vec<Fprint>) {
    let (records, fprints, _) = load_all();
    (records, fprints)
}

/// Load only the raw container vectors.
pub fn load_containers() -> Vec<Container> {
    load_all().2
}

/// Load and parse every block kind in the corpus.
pub fn load_all() -> (Vec<Record>, Vec<Fprint>, Vec<Container>) {
    let path = corpus_path();
    load_all_from(&path)
}

/// Load and parse every block kind in a corpus at `path`.
pub fn load_all_from(path: &Path) -> (Vec<Record>, Vec<Fprint>, Vec<Container>) {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read corpus at {}: {e}", path.display()));

    let mut records = Vec::new();
    let mut fprints = Vec::new();
    let mut containers = Vec::new();

    // Split into blocks on blank lines; skip comment lines.
    let mut block: Vec<&str> = Vec::new();
    let mut flush = |block: &mut Vec<&str>| {
        if block.is_empty() {
            return;
        }
        match block[0] {
            "RECORD" => records.push(parse_record(block)),
            "FPRINT" => fprints.push(parse_fprint(block)),
            "CONTAINER" => containers.push(parse_container(block)),
            // Phase-4a framing blocks live in the same corpus file but belong to
            // rsl-net (see its tests/common/mod.rs); nothing here consumes them.
            "PACKET" | "LEARN" => {}
            other => panic!("unexpected block header {other:?}"),
        }
        block.clear();
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

    (records, fprints, containers)
}

/// Value after the first space of a `KEY value` line.
fn value<'a>(lines: &[&'a str], key: &str) -> Option<&'a str> {
    lines
        .iter()
        .find(|l| l.starts_with(key) && l[key.len()..].starts_with(' '))
        .map(|l| &l[key.len() + 1..])
}

fn require<'a>(lines: &[&'a str], key: &str) -> &'a str {
    value(lines, key).unwrap_or_else(|| panic!("missing {key} in block {:?}", lines[0]))
}

fn parse_record(lines: &[&str]) -> Record {
    // BYTES may be empty (zero-length message), so tolerate a bare "BYTES".
    let bytes_line = value(lines, "BYTES").unwrap_or("");
    Record {
        type_name: require(lines, "TYPE").to_string(),
        desc: require(lines, "DESC").to_string(),
        version: require(lines, "VERSION").parse().unwrap(),
        len: require(lines, "LEN").parse().unwrap(),
        checksum: u64::from_str_radix(require(lines, "CHECKSUM"), 16).unwrap(),
        bytes: from_hex(bytes_line),
        fields: value(lines, "FIELDS").map(str::to_string),
    }
}

fn parse_container(lines: &[&str]) -> Container {
    let bytes_line = value(lines, "BYTES").unwrap_or("");
    Container {
        desc: require(lines, "DESC").to_string(),
        len: require(lines, "LEN").parse().unwrap(),
        bytes: from_hex(bytes_line),
    }
}

fn parse_fprint(lines: &[&str]) -> Fprint {
    let input_line = value(lines, "INPUT").unwrap_or("");
    Fprint {
        desc: require(lines, "DESC").to_string(),
        len: require(lines, "LEN").parse().unwrap(),
        input: from_hex(input_line),
        checksum: u64::from_str_radix(require(lines, "CHECKSUM"), 16).unwrap(),
    }
}

/// Decode a whitespace-free lowercase hex string.
pub fn from_hex(s: &str) -> Vec<u8> {
    let s = s.trim();
    assert!(s.len().is_multiple_of(2), "odd-length hex: {s:?}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex"))
        .collect()
}
