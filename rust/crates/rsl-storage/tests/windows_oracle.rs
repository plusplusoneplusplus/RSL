//! Production-Windows storage artifacts and optional live mixed-language test.
//!
//! The storage fixtures are literal, non-byte-stable Windows outputs, so they
//! are generated rather than committed (see `tools/windows-oracle/.gitignore`).
//! Tests resolve a corpus from `$RSL_WINDOWS_STORAGE` (a validated CI artifact)
//! or by running `RSLWindowsOracle.exe --storage` into this test run's temp
//! directory.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// The production Windows storage corpus for this test run, or `None` when
/// neither a published artifact nor the oracle executable is available.
fn corpus_dir() -> Option<&'static Path> {
    static CORPUS: OnceLock<Option<PathBuf>> = OnceLock::new();
    CORPUS
        .get_or_init(|| {
            if let Some(path) = std::env::var_os("RSL_WINDOWS_STORAGE") {
                assert!(!path.is_empty(), "RSL_WINDOWS_STORAGE is empty");
                let directory = PathBuf::from(path);
                assert!(
                    directory.join("MANIFEST.json").is_file(),
                    "RSL_WINDOWS_STORAGE={} has no MANIFEST.json",
                    directory.display()
                );
                return Some(directory);
            }
            Some(generate(&common::windows_oracle()?))
        })
        .as_deref()
}

/// Run the production oracle to write a fresh storage corpus.
fn generate(oracle: &Path) -> PathBuf {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("windows-oracle-storage");
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("create Windows storage scratch directory");
    let status = Command::new(oracle)
        .arg("--storage")
        .arg(&directory)
        .status()
        .unwrap_or_else(|e| panic!("run {} --storage: {e}", oracle.display()));
    assert!(status.success(), "Windows oracle corpus generation failed");
    directory
}

/// Print why a corpus-dependent test did nothing, in one consistent wording.
fn warn_no_corpus(test: &str) {
    eprintln!(
        "{test}: SKIPPED — no production Windows storage corpus. Build the oracle \
         (.\\tools\\windows-oracle\\build.ps1) and set RSL_WINDOWS_ORACLE, or set \
         RSL_WINDOWS_STORAGE to a published artifact's storage directory."
    );
}

fn manifest(directory: &Path) -> serde_json::Value {
    let path = directory.join("MANIFEST.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "required Windows storage manifest {} is missing: {e}",
            path.display()
        )
    });
    serde_json::from_str(&text).expect("parse Windows storage manifest")
}

fn assert_rust_matches_manifest(directory: &Path) {
    let manifest = manifest(directory);
    assert_eq!(manifest["schemaVersion"], 1);
    assert_eq!(
        manifest["generator"]["identity"],
        "rsl-windows-production-oracle"
    );
    assert_eq!(manifest["artifactPolicy"]["literalWindowsFiles"], true);
    assert_eq!(manifest["artifactPolicy"]["byteStable"], false);

    let files = manifest["files"].as_array().expect("files[]");
    assert!(!files.is_empty(), "Windows manifest has no files");
    for sample in files {
        let name = sample["file"].as_str().expect("file");
        let expected = sample["outcome"].as_str().expect("outcome");
        let path = directory.join(name);
        let actual = match sample["kind"].as_str().expect("kind") {
            "log" => rsl_storage::log::scan_file(&path)
                .unwrap_or_else(|e| panic!("scan {}: {e}", path.display()))
                .outcome(),
            "checkpoint" => rsl_storage::checkpoint::verify_file(&path)
                .unwrap_or_else(|e| panic!("verify {}: {e}", path.display()))
                .outcome(),
            kind => panic!("unknown Windows storage kind {kind:?}"),
        };
        assert_eq!(actual, expected, "{name}: Rust and production C++ differ");
    }
}

#[test]
fn production_windows_storage_artifacts_match_rust() {
    let Some(corpus) = corpus_dir() else {
        warn_no_corpus("production_windows_storage_artifacts_match_rust");
        return;
    };
    assert_rust_matches_manifest(corpus);
}

#[test]
fn live_production_windows_oracle_matches_rust() {
    let Some(oracle) = common::windows_oracle() else {
        eprintln!(
            "live_production_windows_oracle_matches_rust: not requested; \
             set RSL_AUTHORITATIVE_INTEROP=1 and RSL_WINDOWS_ORACLE"
        );
        return;
    };

    let identity = Command::new(&oracle)
        .arg("--identity")
        .output()
        .unwrap_or_else(|e| panic!("run {}: {e}", oracle.display()));
    assert!(identity.status.success(), "oracle identity failed");
    let identity: serde_json::Value =
        serde_json::from_slice(&identity.stdout).expect("parse oracle identity");
    assert_eq!(identity["identity"], "rsl-windows-production-oracle");
    assert_eq!(identity["schemaVersion"], 1);

    let scratch = common::TempDir::new("windows-oracle");
    let status = Command::new(&oracle)
        .arg("--storage")
        .arg(scratch.path())
        .status()
        .expect("generate production storage corpus");
    assert!(status.success(), "Windows oracle corpus generation failed");
    assert_rust_matches_manifest(scratch.path());

    let output = Command::new(&oracle)
        .arg("--verify-storage")
        .arg(scratch.path())
        .output()
        .expect("verify production storage corpus");
    assert_eq!(
        output.status.code(),
        Some(3),
        "mixed positive/negative corpus must report rejection"
    );
    let reports: Vec<serde_json::Value> = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("parse oracle JSONL report"))
        .collect();
    assert!(reports.iter().any(|report| report["outcome"] == "accept"));
    assert!(reports.iter().any(|report| report["outcome"] == "reject"));
}
