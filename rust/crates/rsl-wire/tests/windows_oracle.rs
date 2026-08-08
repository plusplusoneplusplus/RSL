//! Portable consumption of wire artifacts emitted on Windows by the production
//! RSL implementation.

mod common;

use std::path::PathBuf;
use std::process::Command;

use rsl_wire::{fingerprint, messages::verify_checksum, Msg};

fn corpus_path() -> PathBuf {
    if let Some(path) = std::env::var_os("RSL_WINDOWS_WIRE") {
        assert!(!path.is_empty(), "RSL_WINDOWS_WIRE is empty");
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tools/windows-oracle/corpus/wire.txt")
}

fn assert_corpus(path: &std::path::Path) {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "required Windows wire corpus {} is missing: {e}",
            path.display()
        )
    });
    assert!(text.contains("# schemaVersion=1"));
    assert!(text.contains("# generator=rsl-windows-production-oracle"));

    let manifest_path = path.with_file_name("wire.txt.manifest.json");
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&manifest_path).unwrap_or_else(|e| {
            panic!(
                "required Windows wire manifest {} is missing: {e}",
                manifest_path.display()
            )
        }),
    )
    .expect("parse Windows wire manifest");
    assert_eq!(manifest["schemaVersion"], 1);
    assert_eq!(
        manifest["generator"]["identity"],
        "rsl-windows-production-oracle"
    );
    assert_eq!(manifest["artifactPolicy"]["literalWindowsFile"], true);
    assert_eq!(manifest["artifactPolicy"]["byteStable"], false);

    let (records, fingerprints, containers) = common::load_all_from(path);
    assert_eq!(records.len() as u64, manifest["records"].as_u64().unwrap());
    assert_eq!(
        fingerprints.len() as u64,
        manifest["fingerprints"].as_u64().unwrap()
    );
    assert_eq!(
        containers.len() as u64,
        manifest["containers"].as_u64().unwrap()
    );
    assert_eq!(
        manifest["vectors"].as_array().expect("vectors[]").len(),
        records.len() + fingerprints.len() + containers.len()
    );

    for vector in fingerprints {
        assert_eq!(vector.input.len(), vector.len, "{} length", vector.desc);
        assert_eq!(
            fingerprint(&vector.input),
            vector.checksum,
            "{} fingerprint",
            vector.desc
        );
    }

    for record in records {
        let context = format!(
            "{} / {} / v{}",
            record.type_name, record.desc, record.version
        );
        assert_eq!(record.bytes.len(), record.len, "{context}: length");
        assert!(
            verify_checksum(&record.bytes),
            "{context}: checksum does not verify"
        );
        let message = Msg::unmarshal(record.kind(), &record.bytes)
            .unwrap_or_else(|| panic!("{context}: unmarshal failed"));
        assert_eq!(
            message.header().version.raw(),
            record.version,
            "{context}: parsed version"
        );
        assert_eq!(
            message.header().un_marshal_len as usize,
            record.bytes.len(),
            "{context}: parsed length"
        );
        assert_eq!(
            message.header().checksum,
            record.checksum,
            "{context}: parsed checksum"
        );
    }

    for container in containers {
        assert_eq!(
            container.bytes.len(),
            container.len,
            "{} container length",
            container.desc
        );
    }
}

fn authoritative_interop() -> bool {
    std::env::var("RSL_AUTHORITATIVE_INTEROP")
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn windows_oracle() -> Option<PathBuf> {
    let path = std::env::var_os("RSL_WINDOWS_ORACLE").map(PathBuf::from);
    if let Some(path) = path {
        assert!(
            path.is_file(),
            "RSL_WINDOWS_ORACLE={} is not a file",
            path.display()
        );
        return Some(path);
    }
    assert!(
        !authoritative_interop(),
        "RSL_AUTHORITATIVE_INTEROP requires RSL_WINDOWS_ORACLE"
    );
    None
}

#[test]
fn committed_production_windows_wire_artifacts_parse_and_verify() {
    assert_corpus(&corpus_path());
}

#[test]
fn live_production_windows_wire_oracle_parses_and_verifies() {
    let Some(oracle) = windows_oracle() else {
        eprintln!(
            "live_production_windows_wire_oracle_parses_and_verifies: not requested; \
             set RSL_AUTHORITATIVE_INTEROP=1 and RSL_WINDOWS_ORACLE"
        );
        return;
    };

    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("windows-wire-oracle-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("create Windows wire scratch directory");
    let path = directory.join("wire.txt");

    let status = Command::new(&oracle)
        .arg("--wire")
        .arg(&path)
        .status()
        .unwrap_or_else(|e| panic!("run {}: {e}", oracle.display()));
    assert!(status.success(), "Windows wire generation failed");
    assert_corpus(&path);

    std::fs::remove_file(path).expect("remove generated wire corpus");
    std::fs::remove_file(directory.join("wire.txt.manifest.json"))
        .expect("remove generated wire manifest");
    std::fs::remove_dir(directory).expect("remove Windows wire scratch directory");
}
