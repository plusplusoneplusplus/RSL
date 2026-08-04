//! How bytes are made durable — the single seam every write in this crate goes
//! through.
//!
//! The C++ engine gets its guarantees from Windows: log and checkpoint handles
//! are opened `FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH` (`APSEQWRITE`,
//! `legislator.cpp:513`) so a returned write is already on the platter, and the
//! checkpoint is published with `MoveFileEx(..., MOVEFILE_WRITE_THROUGH)`
//! (`legislator.cpp:5645`) so the rename is durable before it returns.
//!
//! On Linux none of that is implicit. Buffered writes sit in the page cache
//! until an explicit `fdatasync`, and — the part that is easy to miss — a
//! `fdatasync` on ext4/xfs does **not** make the file's *directory entry*
//! durable. A newly created log can therefore be fully synced and still vanish
//! in a crash unless the containing directory is synced too. So this trait
//! carries three separate operations, not one:
//!
//! | Operation | Makes durable |
//! | --- | --- |
//! | [`sync_data`](Durability::sync_data) | the file's contents and its length |
//! | [`sync_file`](Durability::sync_file) | contents plus all inode metadata |
//! | [`sync_dir`](Durability::sync_dir) | the names in a directory: creations, renames, unlinks |
//!
//! and one composite, [`rename_durable`](Durability::rename_durable) — fsync
//! file, rename, fsync directory — which is the Linux spelling of
//! `MOVEFILE_WRITE_THROUGH`.
//!
//! ## Why the trait owns file *opening* too
//!
//! Crash-consistency cannot be tested by intercepting only the syncs: what a
//! crash exposes is the set of *writes* that had not reached the platter yet.
//! So every file this crate writes is opened through
//! [`Durability::open`] and written through [`StorageFile`], which lets
//! [`SimCrash`](crate::sim::SimCrash) record the whole write/sync/rename
//! sequence into a shadow filesystem and replay any prefix of it as a crash
//! state. The read/recovery paths ([`crate::log::scan_file`],
//! [`crate::checkpoint::CheckpointReader`], [`crate::dir::DataDir::scan`]) stay
//! on the real filesystem: the harness materializes a crashed directory to disk
//! and then runs the real recovery code against it.
//!
//! See `DURABILITY.md` for the guarantee each public API offers.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::Path;

/// How a file is opened. Deliberately only the three shapes this crate needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenMode {
    /// Create, truncating any existing file. Checkpoints (`.tmp` staging) and
    /// `defunct.txt`.
    Create,
    /// Open for read+write, creating it if missing and **never** truncating —
    /// the log's append mode, which must first scan what is already there.
    Append,
    /// Read only.
    Read,
}

impl OpenMode {
    fn options(self) -> OpenOptions {
        let mut options = OpenOptions::new();
        match self {
            OpenMode::Create => options.read(true).write(true).create(true).truncate(true),
            OpenMode::Append => options.read(true).write(true).create(true).truncate(false),
            OpenMode::Read => options.read(true),
        };
        options
    }
}

/// The file operations the storage writers need. `std::fs::File` implements it;
/// so does the simulator's shadow handle.
pub trait StorageFile: Read + Write + Seek {
    /// The file's current length.
    fn size(&self) -> io::Result<u64>;

    /// Truncate or extend the file to `len`.
    fn set_size(&mut self, len: u64) -> io::Result<()>;
}

impl StorageFile for File {
    fn size(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }

    fn set_size(&mut self, len: u64) -> io::Result<()> {
        self.set_len(len)
    }
}

/// The durability policy: how files are opened, written, synced and published.
pub trait Durability {
    /// The handle [`open`](Durability::open) hands back.
    type File: StorageFile;

    /// Open `path` in `mode`, creating it where the mode says so.
    fn open(&self, path: &Path, mode: OpenMode) -> io::Result<Self::File>;

    /// Does `path` name an existing file?
    fn exists(&self, path: &Path) -> bool;

    /// The file names directly in `dir`, in unspecified order.
    fn read_dir(&self, dir: &Path) -> io::Result<Vec<String>>;

    /// Unlink `path`. A path that is already gone is not an error.
    fn remove_file(&self, path: &Path) -> io::Result<()>;

    /// `fdatasync`: the file's contents and length reach stable storage. Enough
    /// for an append to an *already durable* directory entry, which is the
    /// log's steady state.
    fn sync_data(&self, file: &Self::File) -> io::Result<()>;

    /// `fsync`: contents plus every inode field.
    fn sync_file(&self, file: &Self::File) -> io::Result<()>;

    /// Publish `from` as `to`. Not durable on its own — see
    /// [`rename_durable`](Durability::rename_durable).
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;

    /// `fsync` a directory handle, so the names it holds — creations, renames
    /// and unlinks — survive a crash.
    fn sync_dir(&self, dir: &Path) -> io::Result<()>;

    /// The Linux spelling of `MOVEFILE_WRITE_THROUGH`: fsync the file, rename
    /// it, fsync the destination directory. After this returns, a reader sees
    /// either the whole old file or the whole new one, across power loss.
    ///
    /// `file` must be the open handle on `from`; it stays open across the
    /// rename (harmless on POSIX — the rename moves the name, not the inode).
    fn rename_durable(&self, file: &Self::File, from: &Path, to: &Path) -> io::Result<()> {
        self.sync_file(file)?;
        self.rename(from, to)?;
        self.sync_dir(parent_or_dot(to))
    }

    /// Unlink `path` and make the unlink itself durable.
    fn remove_durable(&self, path: &Path) -> io::Result<()> {
        self.remove_file(path)?;
        self.sync_dir(parent_or_dot(path))
    }

    /// Make a just-created file's *name* durable. Called once, at creation:
    /// afterwards [`sync_data`](Durability::sync_data) alone is enough, because
    /// the entry no longer changes.
    fn sync_new_file(&self, path: &Path) -> io::Result<()> {
        self.sync_dir(parent_or_dot(path))
    }
}

/// The directory holding `path`, with the empty parent of a bare filename
/// spelled `.` so it can actually be opened.
pub fn parent_or_dot(path: &Path) -> &Path {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

/// The real policy: every sync is a real syscall. This is what the engine runs.
#[derive(Clone, Copy, Debug, Default)]
pub struct SyncAll;

impl Durability for SyncAll {
    type File = File;

    fn open(&self, path: &Path, mode: OpenMode) -> io::Result<File> {
        mode.options().open(path)
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn read_dir(&self, dir: &Path) -> io::Result<Vec<String>> {
        real_read_dir(dir)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        real_remove_file(path)
    }

    fn sync_data(&self, file: &File) -> io::Result<()> {
        file.sync_data()
    }

    fn sync_file(&self, file: &File) -> io::Result<()> {
        file.sync_all()
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        // Opening a directory read-only and syncing it is the portable-on-Linux
        // way to flush its entries. Not supported everywhere (notably not on
        // Windows), so a failure to open the directory is not fatal: the
        // operation has still happened, only its durability is weaker.
        match File::open(dir) {
            Ok(handle) => match handle.sync_all() {
                Ok(()) => Ok(()),
                // Some filesystems reject fsync on a directory handle.
                Err(e) if e.kind() == io::ErrorKind::InvalidInput => Ok(()),
                Err(e) => Err(e),
            },
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// A no-op policy for tests and benchmarks: opens and renames for real, never
/// syncs.
///
/// Using this for real checkpoints or logs trades crash-consistency for speed —
/// a torn checkpoint can then be published under its final name, and an
/// "acknowledged" vote can be lost. It exists so a benchmark can isolate the
/// encode path from the disk, and so a test that only cares about bytes does not
/// pay for an `fsync` per file.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoSync;

impl Durability for NoSync {
    type File = File;

    fn open(&self, path: &Path, mode: OpenMode) -> io::Result<File> {
        mode.options().open(path)
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn read_dir(&self, dir: &Path) -> io::Result<Vec<String>> {
        real_read_dir(dir)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        real_remove_file(path)
    }

    fn sync_data(&self, _file: &File) -> io::Result<()> {
        Ok(())
    }

    fn sync_file(&self, _file: &File) -> io::Result<()> {
        Ok(())
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }

    fn sync_dir(&self, _dir: &Path) -> io::Result<()> {
        Ok(())
    }
}

fn real_read_dir(dir: &Path) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str() {
            names.push(name.to_string());
        }
    }
    Ok(names)
}

fn real_remove_file(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}
