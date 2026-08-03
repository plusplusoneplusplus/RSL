//! How a finished file is made durable.
//!
//! The C++ engine leans on Windows semantics — unbuffered `APSEQWRITE` plus
//! `MoveFileEx(..., MOVEFILE_WRITE_THROUGH)` (`legislator.cpp:5645`) — to get
//! "the file is on disk before the rename is". On Linux the equivalent is
//! explicit: **fsync the file before the rename, fsync the containing directory
//! after it**, which is what [`SyncAll`] does.
//!
//! This trait is the seam Phase 3d (durability + crash-consistency) will build
//! on; the log writer will be its second consumer. It is deliberately small:
//! only the operations the commit sequence needs.

use std::fs::File;
use std::io;
use std::path::Path;

/// The durability policy applied when publishing a file.
pub trait Durability {
    /// Flush the file's contents (and metadata) to stable storage.
    fn sync_file(&self, file: &File) -> io::Result<()>;

    /// Atomically publish `from` as `to`.
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;

    /// Flush a directory entry so the rename itself survives a crash.
    fn sync_dir(&self, dir: &Path) -> io::Result<()>;
}

/// The real policy: `fsync` the file, rename, then `fsync` the directory.
#[derive(Clone, Copy, Debug, Default)]
pub struct SyncAll;

impl Durability for SyncAll {
    fn sync_file(&self, file: &File) -> io::Result<()> {
        file.sync_all()
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        // Opening a directory read-only and syncing it is the portable-on-Linux
        // way to flush the rename. Not supported everywhere (notably not on
        // Windows), so a failure to open the directory is not fatal: the rename
        // has still happened, only its durability is weaker.
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

/// A no-op policy for tests and benchmarks: renames, never syncs.
///
/// Using this for real checkpoints trades crash-consistency for speed — a torn
/// checkpoint can then be published under its final name.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoSync;

impl Durability for NoSync {
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
