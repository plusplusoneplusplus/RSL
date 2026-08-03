//! The data directory: file naming, enumeration, and `defunct.txt`.
//!
//! A replica's data directory holds three kinds of file:
//!
//! * `<decree>.log` — logs, named after the first decree they can hold
//!   (`LogFile::Open`, `legislator.cpp:516`).
//! * `<decree>.codex` — checkpoints, named after the last executed decree they
//!   contain (`CheckpointHeader::GetCheckpointFileName`, `legislator.cpp:1082`).
//! * `defunct.txt` — a single little-endian `u32`: the highest configuration
//!   number known to be defunct (`Legislator::UpdateDefunctInfo`,
//!   `legislator.cpp:7357`, read back at `:7211`).
//!
//! The decree in a name is printed with `%I64u`, so it is plain decimal with no
//! padding, and parsed back with `sscanf("%I64u")` (`Legislator::GetFileNumbers`,
//! `legislator.cpp:5786`) — which reads the *leading* digits and ignores the
//! rest, so `12.log` and `12garbage.log` both yield 12.
//!
//! ## Divergences from C++
//!
//! * `sscanf("%I64u")` also skips leading whitespace and accepts a sign; this
//!   parser takes leading ASCII digits only. No engine-created name can contain
//!   either, and a `-1.log` parsed the C++ way would wrap to a nonsense decree.
//! * The C++ enumeration fails the whole directory scan
//!   (`ERROR_INVALID_PARAMETER`) when a matching name has no leading digits.
//!   [`DataDir::scan`] does the same via [`DirError::UnparsableName`] rather
//!   than silently skipping the file, because a stray `foo.log` in a data
//!   directory means something else is writing there.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::durability::{Durability, SyncAll};

/// The name of the defunct-configuration file (`legislator.cpp:7202`).
pub const DEFUNCT_FILE: &str = "defunct.txt";

/// The log file extension.
pub const LOG_EXT: &str = "log";

/// The checkpoint file extension.
pub const CHECKPOINT_EXT: &str = "codex";

/// `<decree>.log` (`legislator.cpp:516`).
pub fn log_file_name(decree: u64) -> String {
    format!("{decree}.{LOG_EXT}")
}

/// `<decree>.codex` (`legislator.cpp:1082`).
pub fn checkpoint_file_name(decree: u64) -> String {
    format!("{decree}.{CHECKPOINT_EXT}")
}

/// The decree encoded in `name`, if it ends in `.<ext>`.
///
/// Returns `Some(None)` shape via [`ParsedName`]: the extension matched but the
/// leading characters were not digits — the case the C++ turns into a hard
/// enumeration failure.
pub fn parse_numbered_name(name: &str, ext: &str) -> Option<ParsedName> {
    // FindFirstFileA("*.log") matches on the extension only; names starting
    // with '.' are skipped explicitly (legislator.cpp:5780).
    if name.starts_with('.') {
        return None;
    }
    let stem = name.strip_suffix(ext)?.strip_suffix('.')?;
    let digits: String = stem.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return Some(ParsedName::Unparsable);
    }
    match digits.parse::<u64>() {
        Ok(decree) => Some(ParsedName::Decree(decree)),
        // More digits than a u64 holds; `sscanf` saturates, which no engine
        // name can reach. Treat it as unparsable rather than inventing a value.
        Err(_) => Some(ParsedName::Unparsable),
    }
}

/// The outcome of matching one directory entry against an extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParsedName {
    /// The name is `<decree>.<ext>`.
    Decree(u64),
    /// The extension matched but there is no leading decimal number.
    Unparsable,
}

/// Why a directory scan failed.
#[derive(Debug)]
pub enum DirError {
    /// Underlying I/O failure.
    Io(io::Error),
    /// A `*.log` or `*.codex` name with no leading decree, which the C++
    /// enumeration rejects outright.
    UnparsableName(String),
}

impl From<io::Error> for DirError {
    fn from(e: io::Error) -> DirError {
        DirError::Io(e)
    }
}

impl std::fmt::Display for DirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DirError::Io(e) => write!(f, "data directory I/O error: {e}"),
            DirError::UnparsableName(name) => {
                write!(f, "'{name}' does not start with a decree number")
            }
        }
    }
}

impl std::error::Error for DirError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DirError::Io(e) => Some(e),
            DirError::UnparsableName(_) => None,
        }
    }
}

/// The decrees of every log and checkpoint in a data directory, ascending.
///
/// This is `Legislator::GetFileNumbers(dir, "*.log" | "*.codex")`
/// (`legislator.cpp:5766`) for both patterns at once, with the same sort order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DataDir {
    /// The directory this describes.
    pub path: PathBuf,
    /// Decrees of the `<decree>.log` files, ascending.
    pub logs: Vec<u64>,
    /// Decrees of the `<decree>.codex` files, ascending.
    pub checkpoints: Vec<u64>,
}

impl DataDir {
    /// Enumerate `path`.
    pub fn scan(path: &Path) -> Result<DataDir, DirError> {
        let mut logs = Vec::new();
        let mut checkpoints = Vec::new();

        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };

            for (ext, out) in [(LOG_EXT, &mut logs), (CHECKPOINT_EXT, &mut checkpoints)] {
                match parse_numbered_name(name, ext) {
                    Some(ParsedName::Decree(decree)) => out.push(decree),
                    Some(ParsedName::Unparsable) => {
                        return Err(DirError::UnparsableName(name.to_string()))
                    }
                    None => {}
                }
            }
        }

        logs.sort_unstable();
        checkpoints.sort_unstable();
        Ok(DataDir {
            path: path.to_path_buf(),
            logs,
            checkpoints,
        })
    }

    /// Path of the log holding decrees from `decree` on.
    pub fn log_path(&self, decree: u64) -> PathBuf {
        self.path.join(log_file_name(decree))
    }

    /// Path of the checkpoint at `decree`.
    pub fn checkpoint_path(&self, decree: u64) -> PathBuf {
        self.path.join(checkpoint_file_name(decree))
    }

    /// The newest checkpoint's decree, if any.
    pub fn newest_checkpoint(&self) -> Option<u64> {
        self.checkpoints.last().copied()
    }

    /// The log that would hold `decree`: the last one whose name-decree is
    /// `<= decree`. `None` if every log starts after it.
    pub fn log_holding(&self, decree: u64) -> Option<u64> {
        self.logs.iter().rev().find(|&&d| d <= decree).copied()
    }
}

// ---------------------------------------------------------------------------
// defunct.txt
// ---------------------------------------------------------------------------

/// Encode the highest defunct configuration number: a little-endian `u32`.
pub fn encode_defunct(highest_defunct_configuration_number: u32) -> [u8; 4] {
    highest_defunct_configuration_number.to_le_bytes()
}

/// Decode `defunct.txt`'s contents. Only the leading four bytes are read, which
/// is all `ReadDefunctFile` consumes (`legislator.cpp:7211`) — the Windows
/// unbuffered writer may have padded the file out to a page.
pub fn decode_defunct(buf: &[u8]) -> Option<u32> {
    let head: [u8; 4] = buf.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(head))
}

/// Read `<dir>/defunct.txt`.
///
/// A missing or too-short file is `Ok(None)`: `ReadDefunctFile` returns without
/// touching `m_highestDefunctConfigurationNumber` in both cases.
pub fn read_defunct(dir: &Path) -> io::Result<Option<u32>> {
    let path = dir.join(DEFUNCT_FILE);
    let mut buf = [0u8; 4];
    let mut file = match File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok((filled == buf.len()).then(|| u32::from_le_bytes(buf)))
}

/// Write `<dir>/defunct.txt` with the real durability policy.
pub fn write_defunct(dir: &Path, value: u32) -> io::Result<()> {
    write_defunct_with(dir, value, &SyncAll)
}

/// Write `<dir>/defunct.txt`, syncing per `durability`.
///
/// The C++ overwrites the file in place with a 4-byte write-through write
/// (`legislator.cpp:7355`). The file is a single word, so an in-place overwrite
/// cannot tear across a sector; this keeps that shape rather than doing a
/// rename dance, and adds the explicit `fsync` Windows's `APSEQWRITE` implied.
pub fn write_defunct_with<D: Durability>(dir: &Path, value: u32, durability: &D) -> io::Result<()> {
    let path = dir.join(DEFUNCT_FILE);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)?;
    file.write_all(&encode_defunct(value))?;
    durability.sync_file(&file)?;
    durability.sync_dir(dir)
}
