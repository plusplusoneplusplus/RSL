//! Helpers shared by the criterion benches.
//!
//! Not a bench target itself: `Cargo.toml` names every bench explicitly, and
//! cargo's auto-discovery only picks up `benches/*.rs` and `benches/*/main.rs`
//! in any case.

use std::path::PathBuf;

/// A fresh scratch directory for one bench case, under the system temp dir.
///
/// Keyed by process id, so two concurrent `cargo bench` runs cannot land in the
/// same place, and cleared on the way in, so a previous run's leftovers never
/// count toward a measurement.
pub fn scratch(bench: &str, name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rsl-{bench}-bench-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}
