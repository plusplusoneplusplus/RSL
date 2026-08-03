//! Shared test scaffolding: locating the Phase-3a storage corpus, reading its
//! MANIFEST, and scratch directories.
//!
//! Each integration-test binary links its own copy and uses a different subset,
//! so unused-item warnings here are expected.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;

/// `<repo>/rust/crates/rsl-storage` → `<repo>`.
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repo root")
}

/// An environment variable as a path, treating "set but empty" as unset.
fn env_path(name: &str) -> Option<PathBuf> {
    let value = std::env::var_os(name)?;
    (!value.is_empty()).then(|| PathBuf::from(value))
}

/// The `golden-gen` binary, if it has been built (or `RSL_GOLDEN_GEN` points at
/// one). Building it needs cmake + g++, so its absence is not a test failure.
pub fn golden_gen() -> Option<PathBuf> {
    if let Some(path) = env_path("RSL_GOLDEN_GEN") {
        return path.is_file().then_some(path);
    }
    let path = repo_root().join("tools/golden-gen/build/golden-gen");
    path.is_file().then_some(path)
}

/// The Phase-3a storage corpus directory, or `None` if it is unavailable here.
///
/// The sample files are generated test data and deliberately not committed (see
/// `tools/golden-gen/.gitignore`), so this looks, in order, at
/// `$RSL_STORAGE_CORPUS`, the in-repo corpus directory, and finally regenerates
/// the corpus with `golden-gen --storage` into this test run's temp directory.
pub fn storage_corpus() -> Option<&'static Path> {
    static CORPUS: OnceLock<Option<PathBuf>> = OnceLock::new();
    CORPUS
        .get_or_init(|| {
            if let Some(dir) = env_path("RSL_STORAGE_CORPUS") {
                assert!(
                    dir.join("MANIFEST.json").is_file(),
                    "RSL_STORAGE_CORPUS={} has no MANIFEST.json",
                    dir.display()
                );
                return Some(dir);
            }

            let in_repo = repo_root().join("tools/golden-gen/corpus/storage");
            if in_repo.join("cp-small.codex").is_file() {
                return Some(in_repo);
            }

            // Regenerate from the C++ generator if it is available.
            let generator = golden_gen()?;
            let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("storage-corpus");
            let _ = std::fs::remove_dir_all(&out);
            let status = std::process::Command::new(&generator)
                .arg("--storage")
                .arg(&out)
                .status()
                .unwrap_or_else(|e| panic!("failed to run {}: {e}", generator.display()));
            assert!(status.success(), "golden-gen --storage failed: {status}");
            Some(out)
        })
        .as_deref()
}

/// Print why a corpus-dependent test did nothing. Kept in one place so the
/// wording (and the hint) stays consistent.
pub fn warn_no_corpus(test: &str) {
    eprintln!(
        "{test}: SKIPPED — no Phase-3a storage corpus. Build the generator \
         (cmake -S tools/golden-gen -B tools/golden-gen/build && cmake --build \
         tools/golden-gen/build) or set RSL_STORAGE_CORPUS."
    );
}

/// Parse the MANIFEST once per test binary.
fn manifest(corpus: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(corpus.join("MANIFEST.json")).expect("read MANIFEST.json");
    serde_json::from_str(&text).expect("parse MANIFEST.json")
}

/// One `records[]` entry of a `kind: "log"` MANIFEST file.
#[derive(Debug)]
pub struct ManifestRecord {
    pub offset: u64,
    pub msg_id: u16,
    pub decree: u64,
    pub un_marshal_len: u32,
    pub padded_len: u32,
    pub checksum: u64,
}

/// One `kind: "log"` entry of `corpus/storage/MANIFEST.json`.
#[derive(Debug)]
pub struct LogSample {
    pub name: String,
    pub file: String,
    pub size: u64,
    pub fp64: u64,
    pub outcome: String,
    pub stop_offset: u64,
    pub record_count: usize,
    pub detail: String,
    pub records: Vec<ManifestRecord>,
}

/// Every `kind: "log"` entry in the corpus MANIFEST.
pub fn log_samples(corpus: &Path) -> Vec<LogSample> {
    let manifest = manifest(corpus);
    let files = manifest["files"].as_array().expect("files[]");
    files
        .iter()
        .filter(|f| f["kind"] == "log")
        .map(|f| LogSample {
            name: f["name"].as_str().unwrap().to_string(),
            file: f["file"].as_str().unwrap().to_string(),
            size: f["size"].as_u64().unwrap(),
            fp64: u64::from_str_radix(f["fp64"].as_str().unwrap(), 16).unwrap(),
            outcome: f["outcome"].as_str().unwrap().to_string(),
            stop_offset: f["stopOffset"].as_u64().unwrap(),
            record_count: f["recordCount"].as_u64().unwrap() as usize,
            detail: f["detail"].as_str().unwrap().to_string(),
            records: f["records"]
                .as_array()
                .expect("records[]")
                .iter()
                .map(|r| ManifestRecord {
                    offset: r["offset"].as_u64().unwrap(),
                    msg_id: r["msgId"].as_u64().unwrap() as u16,
                    decree: u64::from_str_radix(
                        r["decree"].as_str().unwrap().trim_start_matches("0x"),
                        16,
                    )
                    .unwrap(),
                    un_marshal_len: r["unMarshalLen"].as_u64().unwrap() as u32,
                    padded_len: r["paddedLen"].as_u64().unwrap() as u32,
                    checksum: u64::from_str_radix(r["checksum"].as_str().unwrap(), 16).unwrap(),
                })
                .collect(),
        })
        .collect()
}

/// One `kind: "checkpoint"` entry of `corpus/storage/MANIFEST.json`.
#[derive(Debug)]
pub struct CheckpointSample {
    pub name: String,
    pub file: String,
    pub size: u64,
    pub fp64: u64,
    pub outcome: String,
    pub detail: String,
    pub version: u16,
    pub header_len: u32,
    pub user_data_size: u64,
    pub checksum_block_size: u32,
    pub state_saved: bool,
    pub state_pattern: String,
    pub state_len: u64,
}

/// Every `kind: "checkpoint"` entry in the corpus MANIFEST.
pub fn checkpoint_samples(corpus: &Path) -> Vec<CheckpointSample> {
    let manifest = manifest(corpus);
    let files = manifest["files"].as_array().expect("files[]");
    files
        .iter()
        .filter(|f| f["kind"] == "checkpoint")
        .map(|f| CheckpointSample {
            name: f["name"].as_str().unwrap().to_string(),
            file: f["file"].as_str().unwrap().to_string(),
            size: f["size"].as_u64().unwrap(),
            fp64: u64::from_str_radix(f["fp64"].as_str().unwrap(), 16).unwrap(),
            outcome: f["outcome"].as_str().unwrap().to_string(),
            detail: f["detail"].as_str().unwrap().to_string(),
            version: f["version"].as_u64().unwrap() as u16,
            header_len: f["headerLen"].as_u64().unwrap() as u32,
            user_data_size: f["userDataSize"].as_u64().unwrap(),
            checksum_block_size: f["checksumBlockSize"].as_u64().unwrap() as u32,
            state_saved: f["stateSaved"].as_bool().unwrap(),
            state_pattern: f["statePattern"].as_str().unwrap().to_string(),
            state_len: f["stateLen"].as_u64().unwrap(),
        })
        .collect()
}

/// The MANIFEST's `"ramp"` user-state pattern: byte `i` is `i & 0xff`.
pub fn ramp_state(len: usize) -> Vec<u8> {
    (0..len).map(|i| i as u8).collect()
}

/// A scratch directory under the test binary's temp dir, removed on drop.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create a uniquely-named scratch directory.
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

    /// A path inside this directory.
    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
