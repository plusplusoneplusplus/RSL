//! `SimCrash` — a shadow filesystem that can be crashed at every instant.
//!
//! This is the test half of [`crate::durability`]. A [`SimCrash`] is a
//! [`Durability`] policy whose files live in memory: every open, write,
//! truncate, sync, rename and unlink is appended to a **journal** instead of
//! touching a disk. Once a workload has run, the journal can be replayed to
//! *any* prefix and materialized into a real directory — the state the disk
//! would have been left in had power failed at exactly that point.
//!
//! ```text
//!   workload ──► SimCrash ──► journal [op0, op1, … opN]
//!                                │
//!                for each k in 0..=N, for each CrashPolicy:
//!                                ▼
//!                     materialize(k, policy, tmpdir)
//!                                │
//!                                ▼
//!                    real recovery code runs on real files
//! ```
//!
//! ## What the model gets right
//!
//! * **Unsynced writes are not durable.** A write is only guaranteed on disk
//!   after a [`sync_data`](Durability::sync_data)/[`sync_file`](Durability::sync_file)
//!   of that file returns.
//! * **Names are durable separately from contents.** Creating, renaming or
//!   unlinking a file is only durable after a
//!   [`sync_dir`](Durability::sync_dir) of the containing directory — the
//!   ext4/xfs behaviour that makes a missing directory fsync lose a file whose
//!   *contents* were faithfully synced.
//! * **The unsynced tail can fail in more ways than "lost".** Writes can land
//!   out of order, and a single write can be torn — or left holey — at
//!   512-byte sector granularity. See [`CrashPolicy`].
//!
//! ## What it does not model
//!
//! * Sector size is 512 bytes, matching the on-disk format's `s_PageSize`
//!   assumption. A 4K-native device tears at 4096 instead; every 512-torn state
//!   the model produces is a superset in the sense that it includes cuts a 4K
//!   device could not make, so it is the conservative choice — but a 4K device
//!   can also *lose* a whole 4 KiB region that the model would only partially
//!   damage. `DURABILITY.md` records the residual gap.
//! * Reads always see the process's own writes (there is no page-cache
//!   incoherence to model — a crash discards the process, not its reads).
//! * A handle is keyed by path, so writing through a handle *after* its file has
//!   been renamed would recreate the old name. No caller in this crate does
//!   that.

use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::durability::{parent_or_dot, Durability, OpenMode, StorageFile};
use crate::PAGE_SIZE;

/// The tear granularity, matching the format's `s_PageSize` sector assumption.
const SECTOR: usize = PAGE_SIZE as usize;

// ---------------------------------------------------------------------------
// The journal
// ---------------------------------------------------------------------------

/// One recorded filesystem operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// A file came into existence (an open that created it).
    Create {
        /// The new name.
        path: PathBuf,
    },
    /// The file was truncated or extended to `len`.
    Truncate {
        /// The file.
        path: PathBuf,
        /// Its new length.
        len: u64,
    },
    /// Bytes were written at an offset.
    Write {
        /// The file.
        path: PathBuf,
        /// Where the bytes go.
        offset: u64,
        /// The bytes.
        data: Vec<u8>,
    },
    /// `fdatasync`.
    SyncData {
        /// The file.
        path: PathBuf,
    },
    /// `fsync`.
    SyncFile {
        /// The file.
        path: PathBuf,
    },
    /// `rename(from, to)`.
    Rename {
        /// The old name.
        from: PathBuf,
        /// The new name.
        to: PathBuf,
    },
    /// `unlink`.
    Remove {
        /// The name removed.
        path: PathBuf,
    },
    /// `fsync` of a directory handle.
    SyncDir {
        /// The directory.
        dir: PathBuf,
    },
    /// A marker the workload placed: "everything up to here was acknowledged to
    /// the caller as durable". Not a filesystem operation; it is how the harness
    /// knows what must survive.
    Ack {
        /// What was acknowledged.
        label: String,
    },
}

impl std::fmt::Display for Op {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Op::Create { path } => write!(f, "create {}", name_of(path)),
            Op::Truncate { path, len } => write!(f, "truncate {} to {len}", name_of(path)),
            Op::Write { path, offset, data } => {
                write!(f, "write {} @{offset} +{}", name_of(path), data.len())
            }
            Op::SyncData { path } => write!(f, "fdatasync {}", name_of(path)),
            Op::SyncFile { path } => write!(f, "fsync {}", name_of(path)),
            Op::Rename { from, to } => write!(f, "rename {} -> {}", name_of(from), name_of(to)),
            Op::Remove { path } => write!(f, "unlink {}", name_of(path)),
            Op::SyncDir { dir } => write!(f, "fsync dir {}", dir.display()),
            Op::Ack { label } => write!(f, "ACK {label}"),
        }
    }
}

fn name_of(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

// ---------------------------------------------------------------------------
// Crash policies
// ---------------------------------------------------------------------------

/// How the *unsynced* part of the state fares in the crash.
///
/// Everything already synced is untouched by every policy — that is the whole
/// guarantee under test. These describe what happens to what was still in
/// flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashPolicy {
    /// Nothing in flight survives: no unsynced write, no unsynced name change.
    /// The strictest reading, and the one a real crash is most likely to give.
    Nothing,
    /// Everything in flight happened to reach the platter first — the luckiest
    /// crash. Included because a bug that *depends* on losing the tail is still
    /// a bug.
    Everything,
    /// Data writes landed but directory operations did not. This is the case
    /// that catches a missing `sync_dir`: a file whose contents were faithfully
    /// synced still disappears because its name never was.
    NoDirOps,
    /// Every in-flight write landed except the last, which is cut short at a
    /// 512-byte sector boundary — the classic torn tail.
    TornTail,
    /// The last in-flight write landed with alternate 512-byte sectors missing:
    /// the region is the right length but has zero-filled holes in it. Nastier
    /// than a tear, because the bytes *after* the hole are real data, so a
    /// reader cannot dismiss the damage as "a zero tail".
    HoleyTail,
    /// Only the last in-flight write of each file landed; earlier ones did not.
    /// Models the reordering a buffered filesystem is free to do.
    ReorderedTail,
}

impl CrashPolicy {
    /// Do unsynced directory operations (create / rename / unlink) survive?
    fn keeps_dir_ops(self) -> bool {
        !matches!(self, CrashPolicy::Nothing | CrashPolicy::NoDirOps)
    }
}

impl std::fmt::Display for CrashPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CrashPolicy::Nothing => "nothing-in-flight",
            CrashPolicy::Everything => "everything-in-flight",
            CrashPolicy::NoDirOps => "no-dir-ops",
            CrashPolicy::TornTail => "torn-tail",
            CrashPolicy::HoleyTail => "holey-tail",
            CrashPolicy::ReorderedTail => "reordered-tail",
        })
    }
}

/// Every crash policy, for exhaustive enumeration.
pub const POLICIES: &[CrashPolicy] = &[
    CrashPolicy::Nothing,
    CrashPolicy::Everything,
    CrashPolicy::NoDirOps,
    CrashPolicy::TornTail,
    CrashPolicy::HoleyTail,
    CrashPolicy::ReorderedTail,
];

// ---------------------------------------------------------------------------
// The simulator
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct SimState {
    /// Live contents, as the running process sees them.
    live: HashMap<PathBuf, Vec<u8>>,
    /// Every operation, in issue order.
    journal: Vec<Op>,
}

/// A [`Durability`] policy backed by a shadow filesystem, recording everything
/// it is asked to do so a crash can be replayed at any point.
///
/// Cloning shares the state, so a test can hand a clone to a writer and keep one
/// to inspect the journal.
#[derive(Clone, Debug, Default)]
pub struct SimCrash {
    state: Arc<Mutex<SimState>>,
}

impl SimCrash {
    /// A fresh, empty shadow filesystem.
    pub fn new() -> SimCrash {
        SimCrash::default()
    }

    fn with<T>(&self, f: impl FnOnce(&mut SimState) -> T) -> T {
        f(&mut self.state.lock().expect("sim state"))
    }

    fn record(&self, op: Op) {
        self.with(|state| state.journal.push(op));
    }

    /// Mark that everything issued so far has been acknowledged to the caller as
    /// durable. The harness asserts that no crash after this point can lose it.
    pub fn ack(&self, label: impl Into<String>) {
        self.record(Op::Ack {
            label: label.into(),
        });
    }

    /// The recorded journal.
    pub fn journal(&self) -> Vec<Op> {
        self.with(|state| state.journal.clone())
    }

    /// How many operations were recorded. Crash points are `0..=len()`: crashing
    /// at `k` means operations `0..k` were issued.
    pub fn len(&self) -> usize {
        self.with(|state| state.journal.len())
    }

    /// Was nothing recorded at all?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The acknowledgements that had already been made at crash point `upto`.
    pub fn acks_before(&self, upto: usize) -> Vec<String> {
        self.with(|state| {
            state.journal[..upto.min(state.journal.len())]
                .iter()
                .filter_map(|op| match op {
                    Op::Ack { label } => Some(label.clone()),
                    _ => None,
                })
                .collect()
        })
    }

    /// A one-line description of the crash point, for failure messages.
    pub fn describe(&self, upto: usize) -> String {
        self.with(
            |state| match upto.checked_sub(1).and_then(|i| state.journal.get(i)) {
                Some(op) => format!("after op {upto} ({op})"),
                None => "before any operation".to_string(),
            },
        )
    }

    /// Write the state the disk would hold, had power failed once operations
    /// `0..upto` had been issued, into `out` (which is created if missing and
    /// emptied first).
    ///
    /// Only files whose *names* are durable at that point appear; each one gets
    /// the contents its durable data plus the surviving in-flight writes give
    /// it.
    pub fn materialize(&self, upto: usize, policy: CrashPolicy, out: &Path) -> io::Result<()> {
        let journal = self.journal();
        let image = replay(&journal[..upto.min(journal.len())], policy);

        let _ = std::fs::remove_dir_all(out);
        std::fs::create_dir_all(out)?;
        for (path, bytes) in image {
            let name = path.file_name().unwrap_or(path.as_os_str());
            std::fs::write(out.join(name), &bytes)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

/// An in-flight change to a file's contents.
#[derive(Clone, Debug)]
enum Pending {
    Write { offset: u64, data: Vec<u8> },
    Truncate(u64),
}

/// An in-flight change to a directory's names.
#[derive(Clone, Debug)]
enum EntryOp {
    Link(PathBuf, usize),
    Rename(PathBuf, PathBuf),
    Unlink(PathBuf),
}

#[derive(Clone, Debug, Default)]
struct Inode {
    durable: Vec<u8>,
    pending: Vec<Pending>,
}

/// Replay a journal prefix and return the surviving `path -> contents` map.
fn replay(ops: &[Op], policy: CrashPolicy) -> Vec<(PathBuf, Vec<u8>)> {
    let mut inodes: Vec<Inode> = Vec::new();
    let mut live: HashMap<PathBuf, usize> = HashMap::new();
    let mut durable_names: HashMap<PathBuf, usize> = HashMap::new();
    let mut pending_names: Vec<EntryOp> = Vec::new();

    for op in ops {
        match op {
            Op::Create { path } => {
                inodes.push(Inode::default());
                let id = inodes.len() - 1;
                live.insert(path.clone(), id);
                pending_names.push(EntryOp::Link(path.clone(), id));
            }
            Op::Truncate { path, len } => {
                if let Some(&id) = live.get(path) {
                    inodes[id].pending.push(Pending::Truncate(*len));
                }
            }
            Op::Write { path, offset, data } => {
                if let Some(&id) = live.get(path) {
                    inodes[id].pending.push(Pending::Write {
                        offset: *offset,
                        data: data.clone(),
                    });
                }
            }
            // fdatasync and fsync differ only in inode metadata, which this
            // model does not carry (size is part of the data image), so both
            // make the file's contents durable.
            Op::SyncData { path } | Op::SyncFile { path } => {
                if let Some(&id) = live.get(path) {
                    let inode = &mut inodes[id];
                    for change in inode.pending.drain(..) {
                        apply(&mut inode.durable, &change);
                    }
                }
            }
            Op::Rename { from, to } => {
                if let Some(id) = live.remove(from) {
                    live.insert(to.clone(), id);
                }
                pending_names.push(EntryOp::Rename(from.clone(), to.clone()));
            }
            Op::Remove { path } => {
                live.remove(path);
                pending_names.push(EntryOp::Unlink(path.clone()));
            }
            Op::SyncDir { dir } => {
                // Only names in this directory become durable. Every path in a
                // replica's data directory is flat, so this is an exact match on
                // the parent.
                let mut kept = Vec::new();
                for entry in pending_names.drain(..) {
                    if in_dir(&entry, dir) {
                        apply_entry(&mut durable_names, &entry);
                    } else {
                        kept.push(entry);
                    }
                }
                pending_names = kept;
            }
            Op::Ack { .. } => {}
        }
    }

    let mut names = durable_names;
    if policy.keeps_dir_ops() {
        for entry in &pending_names {
            apply_entry(&mut names, entry);
        }
    }

    let mut out: Vec<(PathBuf, Vec<u8>)> = names
        .into_iter()
        .map(|(path, id)| (path, contents(&inodes[id], policy)))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn in_dir(entry: &EntryOp, dir: &Path) -> bool {
    let path = match entry {
        EntryOp::Link(path, _) | EntryOp::Unlink(path) => path,
        // A rename within one directory; cross-directory renames do not occur
        // in a data directory, and the destination is what matters.
        EntryOp::Rename(_, to) => to,
    };
    parent_or_dot(path) == dir
}

fn apply_entry(names: &mut HashMap<PathBuf, usize>, entry: &EntryOp) {
    match entry {
        EntryOp::Link(path, id) => {
            names.insert(path.clone(), *id);
        }
        EntryOp::Rename(from, to) => {
            if let Some(id) = names.remove(from) {
                names.insert(to.clone(), id);
            }
        }
        EntryOp::Unlink(path) => {
            names.remove(path);
        }
    }
}

/// The contents of one file after the crash: its durable bytes plus whichever
/// in-flight changes `policy` lets through.
fn contents(inode: &Inode, policy: CrashPolicy) -> Vec<u8> {
    let mut bytes = inode.durable.clone();
    if matches!(policy, CrashPolicy::Nothing) || inode.pending.is_empty() {
        return bytes;
    }

    let last = inode.pending.len() - 1;
    for (i, change) in inode.pending.iter().enumerate() {
        let is_last = i == last;
        match policy {
            CrashPolicy::Nothing => unreachable!("handled above"),
            CrashPolicy::Everything | CrashPolicy::NoDirOps => apply(&mut bytes, change),
            CrashPolicy::TornTail => {
                if is_last {
                    apply_torn(&mut bytes, change);
                } else {
                    apply(&mut bytes, change);
                }
            }
            CrashPolicy::HoleyTail => {
                if is_last {
                    apply_holey(&mut bytes, change);
                } else {
                    apply(&mut bytes, change);
                }
            }
            CrashPolicy::ReorderedTail => {
                // Truncations are metadata and are kept in order; only the last
                // data write survives, so an earlier one is "still in flight"
                // while a later one is on the platter.
                if is_last || matches!(change, Pending::Truncate(_)) {
                    apply(&mut bytes, change);
                }
            }
        }
    }
    bytes
}

fn apply(bytes: &mut Vec<u8>, change: &Pending) {
    match change {
        Pending::Truncate(len) => bytes.resize(*len as usize, 0),
        Pending::Write { offset, data } => write_at(bytes, *offset, data),
    }
}

/// The last write reached the platter only up to a sector boundary.
fn apply_torn(bytes: &mut Vec<u8>, change: &Pending) {
    match change {
        Pending::Truncate(_) => apply(bytes, change),
        Pending::Write { offset, data } => {
            // Cut roughly in half, rounded down to a sector. A one-sector write
            // therefore tears to nothing, which is the only tear it has.
            let cut = (data.len() / 2) & !(SECTOR - 1);
            write_at(bytes, *offset, &data[..cut]);
        }
    }
}

/// The last write reached the platter with alternate sectors missing: the
/// region is full-length but zero-filled where a sector was lost.
fn apply_holey(bytes: &mut Vec<u8>, change: &Pending) {
    match change {
        Pending::Truncate(_) => apply(bytes, change),
        Pending::Write { offset, data } => {
            // The file is extended to the full length first — a lost sector
            // inside a file reads back as zeros, not as a shorter file.
            let end = (*offset as usize).saturating_add(data.len());
            if bytes.len() < end {
                bytes.resize(end, 0);
            }
            for (i, sector) in data.chunks(SECTOR).enumerate() {
                if i % 2 == 0 {
                    write_at(bytes, *offset + (i * SECTOR) as u64, sector);
                }
            }
        }
    }
}

fn write_at(bytes: &mut Vec<u8>, offset: u64, data: &[u8]) {
    let start = offset as usize;
    let end = start.saturating_add(data.len());
    if bytes.len() < end {
        bytes.resize(end, 0);
    }
    bytes[start..end].copy_from_slice(data);
}

// ---------------------------------------------------------------------------
// The Durability impl
// ---------------------------------------------------------------------------

/// A handle on a file in the shadow filesystem.
#[derive(Debug)]
pub struct SimFile {
    sim: SimCrash,
    path: PathBuf,
    pos: u64,
}

impl SimFile {
    fn edit<T>(&self, f: impl FnOnce(&mut Vec<u8>) -> T) -> io::Result<T> {
        self.sim.with(|state| match state.live.get_mut(&self.path) {
            Some(bytes) => Ok(f(bytes)),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} was unlinked while open", self.path.display()),
            )),
        })
    }
}

impl Read for SimFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (n, bytes) = self.edit(|bytes| {
            let start = (self.pos as usize).min(bytes.len());
            let n = buf.len().min(bytes.len() - start);
            (n, bytes[start..start + n].to_vec())
        })?;
        buf[..n].copy_from_slice(&bytes);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Write for SimFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.edit(|bytes| write_at(bytes, self.pos, buf))?;
        self.sim.record(Op::Write {
            path: self.path.clone(),
            offset: self.pos,
            data: buf.to_vec(),
        });
        self.pos += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // Nothing is buffered above the shadow filesystem; durability is
        // `sync_data`/`sync_file`, not `flush`.
        Ok(())
    }
}

impl Seek for SimFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let len = self.edit(|bytes| bytes.len() as u64)?;
        let next = match pos {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::End(n) => len as i64 + n,
            SeekFrom::Current(n) => self.pos as i64 + n,
        };
        if next < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before the start of the file",
            ));
        }
        self.pos = next as u64;
        Ok(self.pos)
    }
}

impl StorageFile for SimFile {
    fn size(&self) -> io::Result<u64> {
        self.edit(|bytes| bytes.len() as u64)
    }

    fn set_size(&mut self, len: u64) -> io::Result<()> {
        self.edit(|bytes| bytes.resize(len as usize, 0))?;
        self.sim.record(Op::Truncate {
            path: self.path.clone(),
            len,
        });
        Ok(())
    }
}

impl Durability for SimCrash {
    type File = SimFile;

    fn open(&self, path: &Path, mode: OpenMode) -> io::Result<SimFile> {
        let existed = self.with(|state| state.live.contains_key(path));
        if mode == OpenMode::Read && !existed {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} does not exist", path.display()),
            ));
        }

        if !existed {
            self.with(|state| state.live.insert(path.to_path_buf(), Vec::new()));
            self.record(Op::Create {
                path: path.to_path_buf(),
            });
        } else if mode == OpenMode::Create {
            self.with(|state| {
                if let Some(bytes) = state.live.get_mut(path) {
                    bytes.clear();
                }
            });
            self.record(Op::Truncate {
                path: path.to_path_buf(),
                len: 0,
            });
        }

        Ok(SimFile {
            sim: self.clone(),
            path: path.to_path_buf(),
            pos: 0,
        })
    }

    fn exists(&self, path: &Path) -> bool {
        self.with(|state| state.live.contains_key(path))
    }

    fn read_dir(&self, dir: &Path) -> io::Result<Vec<String>> {
        Ok(self.with(|state| {
            state
                .live
                .keys()
                .filter(|path| parent_or_dot(path) == dir)
                .map(|path| name_of(path))
                .collect()
        }))
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        let existed = self.with(|state| state.live.remove(path).is_some());
        if existed {
            self.record(Op::Remove {
                path: path.to_path_buf(),
            });
        }
        Ok(())
    }

    fn sync_data(&self, file: &SimFile) -> io::Result<()> {
        self.record(Op::SyncData {
            path: file.path.clone(),
        });
        Ok(())
    }

    fn sync_file(&self, file: &SimFile) -> io::Result<()> {
        self.record(Op::SyncFile {
            path: file.path.clone(),
        });
        Ok(())
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let moved = self.with(|state| match state.live.remove(from) {
            Some(bytes) => {
                state.live.insert(to.to_path_buf(), bytes);
                true
            }
            None => false,
        });
        if !moved {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} does not exist", from.display()),
            ));
        }
        self.record(Op::Rename {
            from: from.to_path_buf(),
            to: to.to_path_buf(),
        });
        Ok(())
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        self.record(Op::SyncDir {
            dir: dir.to_path_buf(),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> PathBuf {
        PathBuf::from("/data")
    }

    /// A file that was written and synced, but whose *name* never was, is gone
    /// after a crash — the ext4/xfs trap the whole trait exists for.
    #[test]
    fn a_file_without_a_dir_fsync_can_vanish() {
        let sim = SimCrash::new();
        let path = dir().join("1.log");
        let mut file = sim.open(&path, OpenMode::Append).unwrap();
        file.write_all(b"hello").unwrap();
        sim.sync_data(&file).unwrap();

        let end = sim.len();
        assert!(replay(&sim.journal()[..end], CrashPolicy::NoDirOps).is_empty());
        // With the directory synced it survives.
        sim.sync_dir(&dir()).unwrap();
        let survivors = replay(&sim.journal(), CrashPolicy::NoDirOps);
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].1, b"hello");
    }

    /// Synced bytes are immune to every policy; unsynced bytes are not.
    #[test]
    fn only_the_unsynced_tail_is_at_risk() {
        let sim = SimCrash::new();
        let path = dir().join("1.log");
        let mut file = sim.open(&path, OpenMode::Append).unwrap();
        file.write_all(&[1u8; SECTOR]).unwrap();
        sim.sync_data(&file).unwrap();
        sim.sync_dir(&dir()).unwrap();
        file.write_all(&[2u8; 4 * SECTOR]).unwrap();

        for policy in POLICIES {
            let survivors = replay(&sim.journal(), *policy);
            assert_eq!(survivors.len(), 1, "{policy}");
            let bytes = &survivors[0].1;
            assert!(bytes.len() >= SECTOR, "{policy}: lost synced data");
            assert!(
                bytes[..SECTOR].iter().all(|&b| b == 1),
                "{policy}: corrupted synced data"
            );
        }
    }

    /// A torn write stops on a sector boundary; a holey one keeps its length.
    #[test]
    fn tears_and_holes_land_on_sector_boundaries() {
        let sim = SimCrash::new();
        let path = dir().join("1.log");
        let mut file = sim.open(&path, OpenMode::Append).unwrap();
        sim.sync_dir(&dir()).unwrap();
        file.write_all(&[7u8; 4 * SECTOR]).unwrap();

        let torn = replay(&sim.journal(), CrashPolicy::TornTail);
        assert_eq!(torn[0].1.len() % SECTOR, 0);
        assert!(torn[0].1.len() < 4 * SECTOR);

        let holey = replay(&sim.journal(), CrashPolicy::HoleyTail);
        assert_eq!(holey[0].1.len(), 4 * SECTOR);
        assert!(holey[0].1[..SECTOR].iter().all(|&b| b == 7));
        assert!(holey[0].1[SECTOR..2 * SECTOR].iter().all(|&b| b == 0));
        assert!(holey[0].1[2 * SECTOR..3 * SECTOR].iter().all(|&b| b == 7));
    }

    /// The publish sequence is old-or-new at every crash point.
    #[test]
    fn a_rename_is_all_or_nothing() {
        let sim = SimCrash::new();
        let old = dir().join("1.codex");
        let tmp = dir().join("2.codex.tmp");
        let new = dir().join("2.codex");

        let mut first = sim.open(&old, OpenMode::Create).unwrap();
        first.write_all(b"old").unwrap();
        sim.sync_file(&first).unwrap();
        sim.sync_dir(&dir()).unwrap();

        let mut second = sim.open(&tmp, OpenMode::Create).unwrap();
        second.write_all(b"new").unwrap();
        sim.rename_durable(&second, &tmp, &new).unwrap();

        for k in 0..=sim.len() {
            for policy in POLICIES {
                let survivors: HashMap<_, _> =
                    replay(&sim.journal()[..k], *policy).into_iter().collect();
                // The published name never holds a partial file.
                if let Some(bytes) = survivors.get(&new) {
                    assert_eq!(bytes, b"new", "hybrid checkpoint at k={k} {policy}");
                }
                // The old checkpoint is still there whenever the new name is not.
                if !survivors.contains_key(&new) && k >= 4 {
                    assert_eq!(survivors.get(&old).map(Vec::as_slice), Some(&b"old"[..]));
                }
            }
        }
    }
}
