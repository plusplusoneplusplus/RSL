//! [`SeqWriter`] — the sequential file writer, the port's answer to the C++
//! `APSEQWRITE` (`src/common/src/apdiskio.{h,cpp}`).
//!
//! # What it is
//!
//! A ring of write buffers drained behind the caller by a pool of writer
//! threads, over a handle opened *unbuffered* so the transfer leaves our buffer
//! for the device instead of accumulating in the page cache. The caller fills
//! slot `i % slots` and hands it off; a writer picks it up and issues it at
//! `i * block`. That is `APSEQWRITE`'s `m_rgWrites[]` / `m_iWrite` ring
//! (apdiskio.h:106) with `PrepareNext`'s issue-then-advance-then-wait
//! (apdiskio.cpp:797-831) expressed as a handoff rather than an overlapped
//! queue.
//!
//! It exposes [`Write`] and adds [`available`](SeqWriter::available) /
//! [`commit`](SeqWriter::commit) for callers that would rather marshal straight
//! into the ring.
//!
//! # Why it exists
//!
//! Measured against `APSEQWRITE` on the same LBAs with both sides ending
//! everything durable to the device, this reaches parity (99–105%) across three
//! runs at the default 4 x 4 x 4 MiB shape. `WRITEPATH.md` records the
//! measurements and the confounds.
//!
//! # The zero-copy pair is not decoration
//!
//! `RSLCheckpointStreamWriter` marshals straight into `APSEQWRITE`'s buffer
//! through `GetAvailable`/`CommitAvailable` (rsl.cpp:478, :487, :495) rather
//! than handing over a slice to be copied. Measured at the checkpoint's own
//! 4 MiB shape that is worth 15–18% (4519 against 3830 MiB/s), so
//! [`available`](SeqWriter::available) exists too. It is safe: the borrow
//! checker gives out the interior slice exclusively, and
//! [`commit`](SeqWriter::commit) only advances a counter.
//!
//! # What it deliberately does not reproduce
//!
//! `APSEQWRITE` has five rough edges this does not inherit, four of them
//! demonstrated by execution in `seqiobench` (see `WRITEPATH.md`):
//!
//! * **The crash tail.** `IssueWrite` always writes the full `m_cbBufSize`
//!   regardless of `m_cbUsed` (apdiskio.cpp:755) and only `Flush`'s
//!   `SetEndOfFile` establishes the length, over a handle that `OPEN_ALWAYS`
//!   never truncated (apdiskio.cpp:697). A crash before `Flush` therefore
//!   leaves either a file longer than its data or — rewriting a shorter stream
//!   over a longer file — new data seamlessly followed by the *old* file's
//!   stale tail, with nothing marking the join. Here the padding of a short
//!   final block is explicitly zeroed, and the file is created truncated;
//!   callers that need atomic publication still stage under a `.tmp` and
//!   rename, as [`crate::checkpoint::CheckpointWriter`] does.
//! * **Accounting that outruns the data.** The straddling path's
//!   `m_cbUsed += (cbWrite - cbUsed)` runs whether or not the preceding
//!   `PrepareNext` succeeded (apdiskio.cpp:899), so `BytesIssued()` can report
//!   bytes that were never copied anywhere. Here a failed write poisons the
//!   ring and every subsequent call returns the error.
//! * **A swallowed failure.** `if (!m_pbWrite) PrepareNext();`
//!   (apdiskio.cpp:885) discards its return value.
//! * **`RandomWrite`'s bound.** `offset + cbWrite >= m_offsetNext`
//!   (apdiskio.cpp:979) rejects the last byte of the issued region, and
//!   `m_offsetNext` excludes the buffer currently filling, so bytes already
//!   durable in the file can be refused. There is no `RandomWrite` here;
//!   rewriting a header is a plain positional write on the caller's own handle
//!   after [`finish`](SeqWriter::finish).
//! * **Depth 1.** `DoInit` accepts `maxWrites >= 1` (apdiskio.cpp:661), unlike
//!   the reader's `> 1`, so a caller can configure a ring with no overlap at
//!   all — measured at half the throughput of depth 2.
//!   [`SeqWriterConfig::validate`] requires `slots >= 2`.
//!
//! # Threads
//!
//! One OS thread per configured writer, right for checkpointing, which runs one
//! at a time. Size [`SeqWriterConfig::threads`] accordingly for anything that
//! runs many at once.
//!
//! # Where the blocks land
//!
//! The ring does not open files. It issues whole blocks at explicit offsets
//! through a [`BlockDevice`], so it can sit *behind*
//! [`crate::durability::Durability`] rather than beside it: production writes
//! through [`RealDevice`]'s unbuffered handles, and
//! [`crate::sim::SimCrash`] hands out shadow-filesystem handles, so
//! `tests/crash.rs` cuts power on the same writer the engine runs.

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

use crate::seqread::{AlignedBuf, SECTOR};

/// How the writer is sized. [`Default`] is 4 threads x 4 slots x 4 MiB, which
/// allocates 16 MiB and measured at or above `APSEQWRITE`'s best shape. The
/// block matches `s_ChecksumBlockSize` (`checkpoint.h:30`), so a checkpoint's
/// block boundaries and its write boundaries coincide.
#[derive(Clone, Copy, Debug)]
pub struct SeqWriterConfig {
    /// Writer threads, and therefore how many writes the device sees at once.
    pub threads: usize,
    /// Ring slots, and therefore how far the caller may run ahead of the
    /// device. Must be at least `threads`, and at least 2 — a ring of one is
    /// `APSEQWRITE` at depth 1, which measured half the throughput of depth 2.
    pub slots: usize,
    /// Bytes per write. Must be a multiple of [`SECTOR`].
    pub block: usize,
}

impl Default for SeqWriterConfig {
    fn default() -> SeqWriterConfig {
        SeqWriterConfig {
            threads: 4,
            slots: 4,
            block: 4 << 20,
        }
    }
}

impl SeqWriterConfig {
    fn validate(&self) -> io::Result<()> {
        if self.threads == 0 || self.block == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SeqWriterConfig: threads and block must be non-zero",
            ));
        }
        if self.slots < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SeqWriterConfig: slots must be >= 2; a ring of one is APSEQWRITE's \
                 legal-but-pointless depth 1 (apdiskio.cpp:661), which overlaps nothing",
            ));
        }
        if self.slots < self.threads {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "SeqWriterConfig: slots ({}) must be >= threads ({}), \
                     or writers idle waiting for slots the caller has not filled",
                    self.slots, self.threads
                ),
            ));
        }
        if !self.block.is_multiple_of(SECTOR) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "SeqWriterConfig: block ({}) must be a multiple of {SECTOR}; \
                     unbuffered writes are rejected outright when the length is not \
                     sector-aligned",
                    self.block
                ),
            ));
        }
        Ok(())
    }
}

/// One writer thread's exclusive handle on the file being filled.
///
/// Positional, so the order writers happen to finish in does not matter.
pub trait BlockWriter: Send + 'static {
    /// Write all of `data` at `offset`.
    fn write_block_at(&self, data: &[u8], offset: u64) -> io::Result<()>;
}

/// Where a [`SeqWriter`]'s blocks land.
///
/// The seam that lets the same ring serve production and the crash simulator.
/// See the [module docs](self).
pub trait BlockDevice {
    /// A handle one writer thread owns exclusively.
    type Handle: BlockWriter;

    /// Create `path`, truncating any existing file, and hand out `handles`
    /// independent handles — one per writer thread, because a shared
    /// synchronous handle serializes in the kernel and would give back the
    /// queue depth this design exists to get.
    fn create(&self, path: &Path, handles: usize) -> io::Result<Vec<Self::Handle>>;

    /// Establish the file's final length.
    ///
    /// This is what `APSEQWRITE::Flush`'s `SetEndOfFile` (apdiskio.cpp:1075) is
    /// for: writes must be sector multiples, so a length that is not one cannot
    /// be expressed by the writes alone.
    fn set_len_durable(&self, path: &Path, len: u64) -> io::Result<()>;

    /// Narrow `config` to what this device can actually use.
    ///
    /// The default changes nothing. A shadow filesystem overrides it because
    /// none of the sizing means anything without a device to overlap against.
    fn tune(&self, config: SeqWriterConfig) -> SeqWriterConfig {
        config
    }

    /// Issue every block on the caller's thread instead of on a pool.
    ///
    /// [`crate::sim::SimCrash`] takes this path: a journal that is replayed at
    /// every prefix has to record its writes in a deterministic order, which a
    /// pool cannot promise. Everything else — block boundaries, the zeroed pad,
    /// the final length — is unchanged, which is what keeps the crash harness
    /// on the production writer rather than a stand-in for it.
    fn inline(&self) -> bool {
        false
    }
}

/// The real filesystem: unbuffered positional writes, one handle per thread.
#[derive(Clone, Copy, Debug)]
pub struct RealDevice {
    sync: bool,
}

impl RealDevice {
    /// Establish the length and `fsync`. What the engine runs.
    pub const fn syncing() -> RealDevice {
        RealDevice { sync: true }
    }

    /// Establish the length and stop there — [`crate::durability::NoSync`]'s
    /// half of the bargain, for benchmarks and tests that do not need the file
    /// to survive power loss.
    pub const fn unsynced() -> RealDevice {
        RealDevice { sync: false }
    }
}

impl Default for RealDevice {
    fn default() -> RealDevice {
        RealDevice::syncing()
    }
}

impl BlockWriter for File {
    fn write_block_at(&self, data: &[u8], offset: u64) -> io::Result<()> {
        write_at(self, data, offset)
    }
}

impl BlockDevice for RealDevice {
    type Handle = File;

    fn create(&self, path: &Path, handles: usize) -> io::Result<Vec<File>> {
        // Truncate first, through an ordinary handle: an unbuffered handle can
        // set a length but is a clumsy way to ask for one.
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        (0..handles).map(|_| open_unbuffered(path)).collect()
    }

    fn set_len_durable(&self, path: &Path, len: u64) -> io::Result<()> {
        // `APSEQWRITE` needs a second, buffered handle open for the writer's
        // whole lifetime for this (`m_hfileSetEof`, apdiskio.cpp:711); an
        // ordinary handle opened here does the same job.
        let file = std::fs::OpenOptions::new().write(true).open(path)?;
        file.set_len(len)?;
        if self.sync {
            file.sync_all()
        } else {
            Ok(())
        }
    }
}

struct Ring {
    inner: Mutex<RingInner>,
    cv: Condvar,
}

struct RingInner {
    /// `None` while a buffer is out with the caller or with a writer.
    bufs: Vec<Option<AlignedBuf>>,
    /// The block index a filled slot is to be written at, or `None` if the slot
    /// is free for the caller to take.
    pending: Vec<Option<u64>>,
    /// Set once the caller has handed over its last block.
    closed: bool,
    /// The first write error. Poisons the ring: every later call returns it.
    err: Option<io::Error>,
}

/// A sequential writer that keeps a ring of writes in flight.
///
/// See the [module docs](self) for the design and for what it deliberately does
/// not inherit from `APSEQWRITE`.
pub struct SeqWriter<Dev: BlockDevice = RealDevice> {
    ring: Arc<Ring>,
    workers: Vec<JoinHandle<()>>,
    device: Dev,
    /// The single handle used on the caller's thread when the device asked for
    /// inline issue; `None` when a pool is doing the writing.
    inline: Option<Dev::Handle>,
    path: PathBuf,
    slots: usize,
    block: usize,
    /// The buffer the caller is filling, and the block index it will be written
    /// at.
    cur: Option<AlignedBuf>,
    cur_index: u64,
    /// Logical bytes accepted so far — the length [`finish`](Self::finish)
    /// truncates to.
    written: u64,
    finished: bool,
}

impl SeqWriter<RealDevice> {
    /// Create `path`, truncating any existing file, with the default sizing.
    ///
    /// Truncating is deliberate and is *not* what `APSEQWRITE` does
    /// (`OPEN_ALWAYS`, apdiskio.cpp:697, to avoid fragmentation). The C++ pays
    /// for that with a crash window in which a shorter rewrite leaves the older,
    /// longer file's tail attached to the new data; the port's writers stage
    /// under a temporary name and rename, so there is nothing to preserve.
    pub fn create(path: &Path) -> io::Result<SeqWriter> {
        SeqWriter::create_with(path, SeqWriterConfig::default())
    }

    /// [`create`](Self::create) with explicit sizing.
    pub fn create_with(path: &Path, config: SeqWriterConfig) -> io::Result<SeqWriter> {
        SeqWriter::create_on(RealDevice::syncing(), path, config)
    }
}

impl<Dev: BlockDevice> SeqWriter<Dev> {
    /// [`create_with`](SeqWriter::create_with) onto an explicit device.
    ///
    /// `config` is passed through [`BlockDevice::tune`] first, so a device that
    /// cannot use the caller's sizing gets to say so.
    pub fn create_on(
        device: Dev,
        path: &Path,
        config: SeqWriterConfig,
    ) -> io::Result<SeqWriter<Dev>> {
        let config = device.tune(config);
        config.validate()?;

        let inline_issue = device.inline();
        let threads = if inline_issue { 1 } else { config.threads };
        let mut handles = device.create(path, threads)?;

        let slots = config.slots;
        let block = config.block;
        let ring = Arc::new(Ring {
            inner: Mutex::new(RingInner {
                bufs: (0..slots).map(|_| Some(AlignedBuf::new(block))).collect(),
                pending: vec![None; slots],
                closed: false,
                err: None,
            }),
            cv: Condvar::new(),
        });

        let mut workers = Vec::new();
        let mut inline = None;
        if inline_issue {
            inline = Some(handles.pop().expect("one handle was requested"));
        } else {
            workers.reserve(threads);
            for handle in handles {
                let ring = Arc::clone(&ring);
                workers.push(std::thread::spawn(move || {
                    drain_loop(&handle, &ring, slots, block);
                }));
            }
        }

        let mut w = SeqWriter {
            ring,
            workers,
            device,
            inline,
            path: path.to_path_buf(),
            slots,
            block,
            cur: None,
            cur_index: 0,
            written: 0,
            finished: false,
        };
        w.cur = Some(w.take_slot(0)?);
        Ok(w)
    }

    /// Logical bytes accepted so far.
    ///
    /// Port of `APSEQWRITE::BytesIssued` (apdiskio.h:139), except that this
    /// counts only bytes that were actually copied into the ring: the C++
    /// advances its accounting past a failed issue (apdiskio.cpp:899).
    pub fn bytes_written(&self) -> u64 {
        self.written
    }

    /// The unwritten remainder of the current ring buffer, to marshal into
    /// directly. Follow with [`commit`](Self::commit).
    ///
    /// Port of `APSEQWRITE::GetAvailable` (apdiskio.cpp:1170). Never returns an
    /// empty slice: a full buffer is handed off first, so the caller always gets
    /// somewhere to write.
    pub fn available(&mut self) -> io::Result<&mut [u8]> {
        self.check_err()?;
        if self.cur.as_ref().is_none_or(|b| b.filled == self.block) {
            self.rotate()?;
        }
        let block = self.block;
        let buf = self.cur.as_mut().expect("rotate leaves a buffer");
        let filled = buf.filled;
        Ok(&mut buf.window()[filled..block])
    }

    /// Accept `n` bytes written into the slice [`available`](Self::available)
    /// handed back.
    ///
    /// Port of `APSEQWRITE::CommitAvailable` (apdiskio.cpp:1202).
    pub fn commit(&mut self, n: usize) -> io::Result<()> {
        let buf = self.cur.as_mut().expect("a buffer is always current");
        if n > self.block - buf.filled {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "commit({n}) exceeds the {} bytes available",
                    self.block - buf.filled
                ),
            ));
        }
        buf.filled += n;
        self.written += n as u64;
        Ok(())
    }

    /// Hand off every buffered byte, wait for the writers, and truncate the file
    /// to the bytes actually accepted.
    ///
    /// This is `APSEQWRITE::Flush` (apdiskio.cpp:1075) — including its
    /// `SetEndOfFile`, which is what makes a length that is not a block multiple
    /// representable at all when the writes must be sector multiples. Unlike the
    /// C++, calling it does not leave the writer able to continue: a `Flush`
    /// there does not advance `m_offsetNext` or clear `m_cbUsed`, so a
    /// Flush/Write/Flush loop re-issues the whole current buffer each time —
    /// measured at 33x write amplification for 4 KiB appends into a 128 KiB
    /// buffer. Making `finish` consume the writer removes the pattern rather
    /// than pricing it.
    pub fn finish(mut self) -> io::Result<u64> {
        self.finish_inner()?;
        Ok(self.written)
    }

    fn finish_inner(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;

        // Hand over the tail, if any. A partial block is padded to the sector
        // above with zeros -- explicitly, because the buffer is recycled and
        // would otherwise carry an older block's bytes past the logical end,
        // which is exactly the garbage `IssueWrite` writes (apdiskio.cpp:755).
        if let Some(mut buf) = self.cur.take() {
            if buf.filled > 0 {
                let filled = buf.filled;
                let pad = filled.next_multiple_of(SECTOR);
                buf.window()[filled..pad].fill(0);
                // The write must be a sector multiple; `written` keeps the
                // logical length, which the `set_len` below applies.
                buf.filled = pad;
                let index = self.cur_index;
                self.publish(index, buf)?;
            } else {
                let mut g = self.ring.inner.lock().expect("ring mutex");
                g.bufs[(self.cur_index % self.slots as u64) as usize] = Some(buf);
            }
        }

        {
            let mut g = self.ring.inner.lock().expect("ring mutex");
            g.closed = true;
            self.ring.cv.notify_all();
        }
        for w in self.workers.drain(..) {
            let _ = w.join();
        }
        self.check_err()?;

        // The logical length, which the sector-multiple writes could not
        // express. Dropping the handles first matters on Windows, where an open
        // unbuffered handle is not a spectator.
        self.inline = None;
        self.device.set_len_durable(&self.path, self.written)
    }

    /// Hand the current buffer to the writers and take the next free slot.
    fn rotate(&mut self) -> io::Result<()> {
        let buf = self.cur.take().expect("a buffer is always current");
        let index = self.cur_index;
        self.publish(index, buf)?;
        self.cur_index += 1;
        self.cur = Some(self.take_slot(self.cur_index)?);
        Ok(())
    }

    /// Publish a filled buffer for the writer that will issue it.
    fn publish(&mut self, index: u64, buf: AlignedBuf) -> io::Result<()> {
        let slot = (index % self.slots as u64) as usize;

        // Inline device: issue here, in order, and hand the slot straight back.
        if let Some(handle) = &self.inline {
            let result = handle.write_block_at(buf.data(), index * self.block as u64);
            let mut g = self.ring.inner.lock().expect("ring mutex");
            g.bufs[slot] = Some(buf);
            g.pending[slot] = None;
            if let Err(e) = &result {
                if g.err.is_none() {
                    g.err = Some(io::Error::new(e.kind(), e.to_string()));
                }
            }
            return result;
        }

        let mut g = self.ring.inner.lock().expect("ring mutex");
        if let Some(e) = g.err.take() {
            return Err(e);
        }
        g.bufs[slot] = Some(buf);
        g.pending[slot] = Some(index);
        self.ring.cv.notify_all();
        Ok(())
    }

    /// Block until the slot `index` lands in is free, and take its buffer.
    ///
    /// Released-then-waited in that order, so a writer always has work
    /// available — the same ordering as `PrepareNext` issuing before it waits
    /// on the slot it advances to (apdiskio.cpp:797-831).
    fn take_slot(&mut self, index: u64) -> io::Result<AlignedBuf> {
        let slot = (index % self.slots as u64) as usize;
        let mut g = self.ring.inner.lock().expect("ring mutex");
        loop {
            if let Some(e) = g.err.take() {
                return Err(e);
            }
            if g.pending[slot].is_none() && g.bufs[slot].is_some() {
                let mut buf = g.bufs[slot].take().expect("free slot holds its buffer");
                buf.filled = 0;
                return Ok(buf);
            }
            g = self.ring.cv.wait(g).expect("ring condvar");
        }
    }

    fn check_err(&mut self) -> io::Result<()> {
        let mut g = self.ring.inner.lock().expect("ring mutex");
        match g.err.take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

/// One writer thread: claim a filled slot, issue it, free the slot.
fn drain_loop<W: BlockWriter>(handle: &W, ring: &Ring, slots: usize, block: usize) {
    loop {
        let (slot, index, buf) = {
            let mut g = ring.inner.lock().expect("ring mutex");
            loop {
                if g.err.is_some() {
                    return;
                }
                if let Some(slot) = (0..slots).find(|&s| g.pending[s].is_some() && g.bufs[s].is_some())
                {
                    let index = g.pending[slot].expect("checked");
                    let buf = g.bufs[slot].take().expect("checked");
                    break (slot, index, buf);
                }
                if g.closed {
                    return;
                }
                g = ring.cv.wait(g).expect("ring condvar");
            }
        };

        // Positional, so the order writers happen to finish in does not matter.
        let result = handle.write_block_at(buf.data(), index * block as u64);

        let mut g = ring.inner.lock().expect("ring mutex");
        g.bufs[slot] = Some(buf);
        g.pending[slot] = None;
        if let Err(e) = result {
            if g.err.is_none() {
                g.err = Some(e);
            }
        }
        ring.cv.notify_all();
    }
}

impl<Dev: BlockDevice> Write for SeqWriter<Dev> {
    fn write(&mut self, mut data: &[u8]) -> io::Result<usize> {
        let total = data.len();
        while !data.is_empty() {
            let room = {
                let dst = self.available()?;
                dst.len().min(data.len())
            };
            let (head, rest) = data.split_at(room);
            self.available()?[..room].copy_from_slice(head);
            self.commit(room)?;
            data = rest;
        }
        Ok(total)
    }

    /// Nothing to do: bytes leave the caller's hands for the ring, and only
    /// [`finish`](SeqWriter::finish) establishes the file's length. Flushing
    /// mid-stream is what costs `APSEQWRITE` a whole re-issued buffer.
    fn flush(&mut self) -> io::Result<()> {
        self.check_err()
    }
}

impl<Dev: BlockDevice> std::fmt::Debug for SeqWriter<Dev> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeqWriter")
            .field("path", &self.path)
            .field("threads", &self.workers.len())
            .field("inline", &self.inline.is_some())
            .field("slots", &self.slots)
            .field("block", &self.block)
            .field("bytes_written", &self.written)
            .finish_non_exhaustive()
    }
}

impl<Dev: BlockDevice> Drop for SeqWriter<Dev> {
    /// Stop the writers and wait for them.
    ///
    /// Detaching them would be a real bug rather than untidiness: a writer
    /// blocked on the condvar holds an open handle, and on Windows an open
    /// handle blocks deleting the file — which is exactly what a
    /// `CheckpointWriter` dropped without `finish` does to its `.tmp`.
    fn drop(&mut self) {
        if !self.finished {
            // Dropped without `finish`: whatever reached the device stays, and
            // the file keeps whatever length it has. Callers that need
            // all-or-nothing publication stage under a temporary name.
            self.finished = true;
            {
                let mut g = self.ring.inner.lock().expect("ring mutex");
                g.closed = true;
                self.ring.cv.notify_all();
            }
            for w in self.workers.drain(..) {
                let _ = w.join();
            }
        }
    }
}

/// Open for writing, bypassing the page cache.
fn open_unbuffered(path: &Path) -> io::Result<File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(false);

    #[cfg(windows)]
    {
        // FILE_FLAG_NO_BUFFERING. `custom_flags` is a safe API, so the whole
        // unbuffered path stays inside this crate's `unsafe_code = "forbid"`.
        // Note the C++ adds no FILE_FLAG_WRITE_THROUGH here either
        // (apdiskio.cpp:698): this bypasses the page cache, not the device
        // write cache, which is why `finish` ends with a `sync_all`.
        use std::os::windows::fs::OpenOptionsExt;
        opts.custom_flags(0x2000_0000);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_DIRECT);
    }
    // macOS has no `O_DIRECT` (`F_NOCACHE` is a post-open fcntl), so there
    // the open falls through without the flag. Correctness is unaffected —
    // only the cache behaviour and the throughput are.

    opts.open(path)
}

/// Positional write, looping until the whole buffer is out. Both platform
/// spellings are safe APIs.
fn write_at(f: &File, buf: &[u8], offset: u64) -> io::Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::FileExt;
    #[cfg(windows)]
    use std::os::windows::fs::FileExt;

    let mut n = 0;
    while n < buf.len() {
        #[cfg(windows)]
        let r = f.seek_write(&buf[n..], offset + n as u64);
        #[cfg(unix)]
        let r = f.write_at(&buf[n..], offset + n as u64);
        match r {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "unbuffered write made no progress",
                ))
            }
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rsl-seqwrite-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    /// Distinguishable per position, so a misplaced write is a wrong byte
    /// rather than a coincidence.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn read_back(path: &Path) -> Vec<u8> {
        let mut out = Vec::new();
        File::open(path)
            .expect("open")
            .read_to_end(&mut out)
            .expect("read");
        out
    }

    fn cfg(threads: usize, slots: usize, block: usize) -> SeqWriterConfig {
        SeqWriterConfig {
            threads,
            slots,
            block,
        }
    }

    #[test]
    fn writes_a_whole_file_byte_for_byte() {
        let dir = scratch("whole");
        let p = dir.join("a.bin");
        // Deliberately not a block multiple, so the last block is short and the
        // file length is not sector-aligned either.
        let data = pattern(3 * (1 << 20) + 1234);

        let mut w = SeqWriter::create_with(&p, cfg(4, 4, 1 << 20)).expect("create");
        w.write_all(&data).expect("write");
        assert_eq!(w.bytes_written(), data.len() as u64);
        assert_eq!(w.finish().expect("finish"), data.len() as u64);

        assert_eq!(read_back(&p), data);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ring_shapes_all_agree() {
        let dir = scratch("shapes");
        let data = pattern(5 * SECTOR * 40 + 7);

        // Tightest legal ring, a deep ring, and a single writer must all
        // produce the same bytes.
        for (i, (t, s, b)) in [(1, 2, SECTOR), (8, 8, SECTOR), (2, 16, SECTOR * 4)]
            .into_iter()
            .enumerate()
        {
            let p = dir.join(format!("{i}.bin"));
            let mut w = SeqWriter::create_with(&p, cfg(t, s, b)).expect("create");
            w.write_all(&data).expect("write");
            w.finish().expect("finish");
            assert_eq!(read_back(&p), data, "threads={t} slots={s} block={b}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn many_small_writes_reassemble() {
        let dir = scratch("small");
        let p = dir.join("a.bin");
        let data = pattern(SECTOR * 37 + 11);

        let mut w = SeqWriter::create_with(&p, cfg(2, 4, SECTOR * 2)).expect("create");
        // Odd sizes, so records straddle block boundaries at every alignment.
        for chunk in data.chunks(97) {
            w.write_all(chunk).expect("write");
        }
        w.finish().expect("finish");
        assert_eq!(read_back(&p), data);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_zero_copy_pair_produces_the_same_file() {
        let dir = scratch("commit");
        let p = dir.join("a.bin");
        let data = pattern(SECTOR * 20 + 33);

        let mut w = SeqWriter::create_with(&p, cfg(2, 4, SECTOR * 2)).expect("create");
        let mut at = 0usize;
        while at < data.len() {
            let dst = w.available().expect("available");
            assert!(!dst.is_empty(), "available never hands back an empty slice");
            let take = dst.len().min(data.len() - at);
            dst[..take].copy_from_slice(&data[at..at + take]);
            w.commit(take).expect("commit");
            at += take;
        }
        w.finish().expect("finish");
        assert_eq!(read_back(&p), data);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn committing_more_than_available_is_rejected() {
        let dir = scratch("overcommit");
        let p = dir.join("a.bin");
        let mut w = SeqWriter::create_with(&p, cfg(1, 2, SECTOR)).expect("create");
        let room = w.available().expect("available").len();
        let e = w.commit(room + 1).expect_err("overcommit");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_file_is_empty() {
        let dir = scratch("empty");
        let p = dir.join("a.bin");
        let w = SeqWriter::create_with(&p, cfg(2, 4, SECTOR)).expect("create");
        assert_eq!(w.finish().expect("finish"), 0);
        assert_eq!(std::fs::metadata(&p).expect("stat").len(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_short_tail_is_zero_padded_not_garbage() {
        let dir = scratch("tail");
        let p = dir.join("a.bin");
        // Two full blocks of 0xFF, then a few bytes into a recycled buffer.
        // The pad the final sector-multiple write carries must be zeros, not
        // the 0xFFs the buffer held on its previous trip round the ring.
        let mut w = SeqWriter::create_with(&p, cfg(1, 2, SECTOR)).expect("create");
        w.write_all(&vec![0xFFu8; SECTOR * 2]).expect("write");
        w.write_all(&[1, 2, 3]).expect("write");
        w.finish().expect("finish");

        // The file is truncated to the logical length, so read the untruncated
        // sector through a fresh handle to see what actually landed.
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&p)
            .expect("open");
        file.set_len((SECTOR * 3) as u64).expect("extend");
        drop(file);
        let raw = read_back(&p);
        assert_eq!(&raw[SECTOR * 2..SECTOR * 2 + 3], &[1, 2, 3]);
        assert!(
            raw[SECTOR * 2 + 3..SECTOR * 3].iter().all(|&b| b == 0),
            "the pad past the logical end must be zeros, not a recycled buffer"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dropping_without_finish_releases_the_file() {
        let dir = scratch("drop");
        let p = dir.join("a.bin");

        // Abandon the writer with the ring still busy, then delete — which
        // fails on Windows if any writer thread still holds a handle.
        let mut w = SeqWriter::create_with(&p, cfg(4, 8, SECTOR)).expect("create");
        w.write_all(&pattern(SECTOR * 50)).expect("write");
        drop(w);

        std::fs::remove_file(&p).expect("no handle may outlive the writer");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The device-level comparison against `APSEQWRITE`, in the cross-language
    /// harness's own result format.
    ///
    /// Ignored by default and driven by the sweep's fixture, because it is a
    /// measurement rather than a test: it needs a real device, a file large
    /// enough to swamp the page cache, and — to be comparable with a
    /// `seqiobench write` row — the *same* pre-existing file so both land on
    /// the same LBAs.
    ///
    /// ```text
    /// $env:RSL_SEQWRITE_FIXTURE = "D:\rslbench\seqwrite-fixture.bin"
    /// cargo test --release -p rsl-storage --lib seqwrite -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "needs a device fixture; see RSL_SEQWRITE_FIXTURE"]
    fn measure_against_apseqwrite() {
        let Ok(path) = std::env::var("RSL_SEQWRITE_FIXTURE") else {
            eprintln!("RSL_SEQWRITE_FIXTURE unset; nothing to measure");
            return;
        };
        let path = PathBuf::from(path);
        let len: u64 = std::fs::metadata(&path).expect("fixture").len();
        let record = 4096usize;

        // The harness's FillPattern (main.cpp), so the fold column cross-checks
        // against a `seqiobench write` row over the same length.
        fn fill(buf: &mut [u8], offset: u64) {
            let mut x = offset.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
            for chunk in buf.chunks_exact_mut(8) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                chunk.copy_from_slice(&x.to_le_bytes());
            }
        }

        for (threads, slots, block) in [(2usize, 2usize, 4 << 20), (4, 4, 4 << 20), (4, 4, 1 << 20)]
        {
            for mode in ["copy", "commit"] {
                let t0 = std::time::Instant::now();
                let mut w = SeqWriter::create_with(
                    &path,
                    SeqWriterConfig {
                        threads,
                        slots,
                        block,
                    },
                )
                .expect("create");
                let mut fold = 0u64;
                let mut at = 0u64;
                let mut scratch = vec![0u8; record];
                while at + record as u64 <= len {
                    if mode == "commit" {
                        // Marshal straight into the ring, as
                        // RSLCheckpointStreamWriter does (rsl.cpp:478).
                        let mut left = record;
                        let mut off = at;
                        while left > 0 {
                            let dst = w.available().expect("available");
                            let take = dst.len().min(left);
                            fill(&mut dst[..take], off);
                            w.commit(take).expect("commit");
                            off += take as u64;
                            left -= take;
                        }
                    } else {
                        fill(&mut scratch, at);
                        w.write_all(&scratch).expect("write");
                    }
                    let mut head = [0u8; 8];
                    let mut x = at.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    head.copy_from_slice(&x.to_le_bytes());
                    fold = fold.wrapping_add(u64::from_le_bytes(head));
                    at += record as u64;
                }
                let written = w.finish().expect("finish");
                let secs = t0.elapsed().as_secs_f64();
                // `finish` ends in a sync_all, so this is the same durability
                // endpoint as `seqiobench write --fsync`.
                println!(
                    "SeqWriter\tseqwrite-{threads}x{slots}x{block}-{mode}-syncall\t{threads}\
                     \t{block}\t{record}\t{written}\t{secs:.4}\t{:.2}\t\t\t\t\t\t\t\t{fold}",
                    written as f64 / (1024.0 * 1024.0) / secs
                );
            }
        }
    }

    #[test]
    fn bad_configs_are_rejected_with_a_reason() {
        let dir = scratch("badcfg");
        let p = dir.join("a.bin");

        // Block not a sector multiple: unbuffered writes would fail deep in the
        // kernel with nothing to explain them.
        let e = SeqWriter::create_with(&p, cfg(2, 4, 1000)).expect_err("unaligned block");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        // A ring of one overlaps nothing — APSEQWRITE's legal depth 1.
        let e = SeqWriter::create_with(&p, cfg(1, 1, SECTOR)).expect_err("slots < 2");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        // Fewer slots than threads would have writers idle.
        let e = SeqWriter::create_with(&p, cfg(8, 4, SECTOR)).expect_err("slots < threads");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        let e = SeqWriter::create_with(&p, cfg(0, 4, SECTOR)).expect_err("zero threads");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
