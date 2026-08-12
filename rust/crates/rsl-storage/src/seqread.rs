//! [`SeqReader`] — the sequential file reader, the port's answer to the C++
//! `APSEQREAD` (`src/common/src/apdiskio.{h,cpp}`).
//!
//! # What it is
//!
//! A ring of read slots kept filled ahead of the caller by a pool of reader
//! threads, over a handle opened *unbuffered* so the transfer lands in our
//! buffer rather than in the page cache. Block `i` occupies slot `i % slots`,
//! so the caller walks the ring in order and a slot is reusable the moment the
//! caller passes it — the same invariant as `APSEQREAD`'s `m_rgReads[]` /
//! `m_iRead` (apdiskio.h:41).
//!
//! It exposes [`Read`], so it drops in wherever the crate currently wraps a
//! `File`, and adds [`file_size`](SeqReader::file_size) for the one piece of
//! `APSEQREAD` behaviour the protocol depends on.
//!
//! # Why it exists
//!
//! Measured cold against `APSEQREAD` on the same file, the same LBAs and the
//! same buffer memory (8 slots x 1 MiB against depth 8 x 1 MiB), this reaches
//! 99.5%–104.5% of it across three runs, with an indistinguishable latency
//! distribution out to p99.99.
//!
//! A `BufReader` does not get close. The crate's own default — `BufReader::new`,
//! 8 KiB — measures 17% of `APSEQREAD` on identical LBAs. Raising capacity to
//! 1 MiB is worth about 3.7x and then stops: a read-then-consume loop leaves the
//! device idle while the caller drains the buffer, and issues one read at a
//! time, which gives an NVMe a queue depth of one. Neither is a buffer-size
//! problem. `READPATH.md` records the measurements, and the three confounds that
//! make most of the obvious comparisons untrustworthy on real hardware.
//!
//! # What it deliberately does not reproduce
//!
//! `APSEQREAD` has three rough edges this does not inherit:
//!
//! * The lossy partial tail. `GetDataPointer` with `pcbRead == NULL` copies the
//!   straddling bytes into its scratch buffer and then returns
//!   `ERROR_HANDLE_EOF` without handing them back (apdiskio.cpp:460-479), and
//!   `GetData` always takes that path. Here a short read is just a short read.
//! * The `Skip` overshoot. Its large-skip branch resumes from the prefetch
//!   frontier rather than the caller's position (apdiskio.cpp:560), overshooting
//!   by `2 * m_cbLeft + (depth - 1) * block`. There is no `Skip` here; seeking
//!   is [`open_at`](SeqReader::open_at), which is expressed in caller-visible
//!   file offsets and has no notion of a frontier.
//! * Stale end-of-file flags on slots past an early `Reset` break
//!   (apdiskio.cpp:334-338). Slot state here is owned by the ring and reset per
//!   block, so there is nothing to go stale.
//!
//! # Threads
//!
//! One OS thread per configured reader. That is right for replay and checkpoint
//! reads, which run one at a time; it is the wrong shape for something serving
//! many concurrent streams, where the thread count multiplies. Size
//! [`SeqReaderConfig::threads`] accordingly, or keep using a plain `File` there.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

/// Alignment unbuffered I/O requires of the buffer address, the file offset and
/// the transfer length.
///
/// The true requirement is the volume's physical sector size — 512 on 512e
/// media, 4096 on 4Kn. 4096 satisfies both, so it is used unconditionally
/// rather than queried per volume.
///
/// Public because [`SeqReaderConfig::block`] must be a multiple of it, and a
/// caller computing a block size needs the number rather than a magic 4096.
pub const SECTOR: usize = 4096;

/// How the reader is sized. [`Default`] is 8 threads x 8 slots x 1 MiB, which
/// is the smallest configuration measured at parity with `APSEQREAD` and
/// allocates the same 8 MiB the C++ does at its own default shape.
#[derive(Clone, Copy, Debug)]
pub struct SeqReaderConfig {
    /// Reader threads, and therefore how many reads the device sees at once.
    /// This is the knob that matters for throughput: one thread gives an NVMe a
    /// queue depth of one no matter how deep the ring is.
    pub threads: usize,
    /// Ring slots, and therefore how far read-ahead may run. Must be at least
    /// `threads`, or readers would contend for slots the caller has not reached.
    pub slots: usize,
    /// Bytes per read. Must be a multiple of [`SECTOR`].
    pub block: usize,
}

impl Default for SeqReaderConfig {
    fn default() -> SeqReaderConfig {
        SeqReaderConfig {
            threads: 8,
            slots: 8,
            block: 1 << 20,
        }
    }
}

impl SeqReaderConfig {
    fn validate(&self) -> io::Result<()> {
        if self.threads == 0 || self.slots == 0 || self.block == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SeqReaderConfig: threads, slots and block must all be non-zero",
            ));
        }
        if self.slots < self.threads {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "SeqReaderConfig: slots ({}) must be >= threads ({}), \
                     or readers stall waiting for slots the caller has not reached",
                    self.slots, self.threads
                ),
            ));
        }
        if !self.block.is_multiple_of(SECTOR) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "SeqReaderConfig: block ({}) must be a multiple of {SECTOR}; \
                     unbuffered reads are rejected outright when the length is not \
                     sector-aligned",
                    self.block
                ),
            ));
        }
        Ok(())
    }
}

/// A buffer with a [`SECTOR`]-aligned interior window.
///
/// Obtained without `unsafe` and without an allocator crate: over-allocate by
/// one sector and slice at the first aligned offset. `as_ptr() as usize` only
/// reads the address, and the `Vec` is never resized afterwards, so the window
/// stays where it was found.
struct AlignedBuf {
    raw: Vec<u8>,
    off: usize,
    len: usize,
    filled: usize,
}

impl AlignedBuf {
    fn new(len: usize) -> AlignedBuf {
        let raw = vec![0u8; len + SECTOR];
        let off = (SECTOR - (raw.as_ptr() as usize % SECTOR)) % SECTOR;
        AlignedBuf {
            raw,
            off,
            len,
            filled: 0,
        }
    }

    fn window(&mut self) -> &mut [u8] {
        let (off, len) = (self.off, self.len);
        &mut self.raw[off..off + len]
    }

    fn data(&self) -> &[u8] {
        &self.raw[self.off..self.off + self.filled]
    }
}

struct Ring {
    inner: Mutex<RingInner>,
    cv: Condvar,
}

struct RingInner {
    /// `None` while the buffer is out being filled or drained.
    bufs: Vec<Option<AlignedBuf>>,
    ready: Vec<bool>,
    /// Next block index the caller wants.
    head: u64,
    /// Next block index a reader may claim.
    next: u64,
    blocks: u64,
    err: Option<io::Error>,
    /// Set on drop so readers blocked on the condvar can leave.
    stop: bool,
}

/// A sequential reader that keeps a ring of reads in flight.
///
/// See the [module docs](self) for the design and for what it deliberately does
/// not inherit from `APSEQREAD`.
pub struct SeqReader {
    ring: Arc<Ring>,
    workers: Vec<JoinHandle<()>>,
    slots: usize,
    cur: Option<AlignedBuf>,
    cur_slot: usize,
    pos: usize,
    /// Bytes to discard from the first block, when the requested start offset
    /// was not sector-aligned and the reads had to begin below it.
    skip: usize,
    done: bool,
    file_size: u64,
}

impl SeqReader {
    /// Open `path` and read it from the beginning with the default sizing.
    pub fn open(path: &Path) -> io::Result<SeqReader> {
        SeqReader::open_at(path, 0, SeqReaderConfig::default())
    }

    /// Open `path` and read it from the beginning with explicit sizing.
    pub fn open_with(path: &Path, config: SeqReaderConfig) -> io::Result<SeqReader> {
        SeqReader::open_at(path, 0, config)
    }

    /// Open `path` and read from `offset`.
    ///
    /// `offset` is a plain file offset and needs no alignment: unbuffered reads
    /// do, so the ring starts at the sector boundary at or below it and the
    /// prefix is discarded before the caller sees anything. This is what
    /// `APSEQREAD::Reset` does with `m_cbSkip` (apdiskio.cpp:320), except that
    /// here the discarded amount is derived from the caller's offset rather than
    /// from the prefetch frontier.
    ///
    /// The length is snapshotted here, once. A reader never sees bytes appended
    /// after this call, matching `APSEQREAD::DoInit` (apdiskio.cpp:146) — the
    /// learn protocol depends on that.
    pub fn open_at(path: &Path, offset: u64, config: SeqReaderConfig) -> io::Result<SeqReader> {
        config.validate()?;

        let file_size = std::fs::metadata(path)?.len();
        let start = offset.min(file_size);
        // Unbuffered reads must begin on a sector boundary.
        let aligned = start - (start % SECTOR as u64);
        let skip = (start - aligned) as usize;
        let want = file_size - aligned;
        let blocks = want.div_ceil(config.block as u64);

        let slots = config.slots;
        let block = config.block;
        let ring = Arc::new(Ring {
            inner: Mutex::new(RingInner {
                bufs: (0..slots).map(|_| Some(AlignedBuf::new(block))).collect(),
                ready: vec![false; slots],
                head: 0,
                next: 0,
                blocks,
                err: None,
                stop: false,
            }),
            cv: Condvar::new(),
        });

        let path_owned = path.to_path_buf();
        let mut workers = Vec::with_capacity(config.threads);
        for _ in 0..config.threads {
            // Each reader needs its own handle: a synchronous handle serializes
            // I/O in the kernel, so sharing one would give back the queue depth
            // this whole design exists to get.
            let file = open_unbuffered(&path_owned)?;
            let ring = Arc::clone(&ring);
            workers.push(std::thread::spawn(move || {
                fill_loop(&file, &ring, aligned, want, slots, block);
            }));
        }

        Ok(SeqReader {
            ring,
            workers,
            slots,
            cur: None,
            cur_slot: 0,
            pos: 0,
            skip,
            done: blocks == 0,
            file_size,
        })
    }

    /// The file's length as of [`open_at`](Self::open_at), not as of now.
    ///
    /// Port of `APSEQREAD::FileSize` over the `DoInit` snapshot
    /// (apdiskio.cpp:146). Appends made after the open are invisible, which is
    /// what lets a learner serve a stable byte range while the file grows.
    pub fn file_size(&self) -> u64 {
        self.file_size
    }
}

/// One reader thread: claim the next block, fill it, publish it.
fn fill_loop(file: &File, ring: &Ring, base: u64, want: u64, slots: usize, block: usize) {
    loop {
        let (idx, mut buf) = {
            let mut g = ring.inner.lock().expect("ring mutex");
            if g.stop || g.err.is_some() || g.next >= g.blocks {
                return;
            }
            let idx = g.next;
            g.next += 1;
            let slot = (idx % slots as u64) as usize;
            // Wait out whatever this slot held `slots` blocks ago.
            loop {
                if g.stop || g.err.is_some() {
                    return;
                }
                if !g.ready[slot] && g.bufs[slot].is_some() {
                    break;
                }
                g = ring.cv.wait(g).expect("ring condvar");
            }
            (
                idx,
                g.bufs[slot].take().expect("free slot holds its buffer"),
            )
        };

        let slot = (idx % slots as u64) as usize;
        let start = base + idx * block as u64;
        let take = (want - idx * block as u64).min(block as u64) as usize;
        let result = read_at(file, buf.window(), start);

        let mut g = ring.inner.lock().expect("ring mutex");
        match result {
            // A read may come back short at end of file; the caller's window is
            // the authority on how much of it counts.
            Ok(n) => buf.filled = n.min(take),
            Err(e) => {
                g.err = Some(e);
                g.bufs[slot] = Some(buf);
                ring.cv.notify_all();
                return;
            }
        }
        g.bufs[slot] = Some(buf);
        g.ready[slot] = true;
        ring.cv.notify_all();
    }
}

impl Read for SeqReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.cur.as_ref().is_none_or(|b| self.pos >= b.filled) {
                if self.done {
                    return Ok(0);
                }
                let mut g = self.ring.inner.lock().expect("ring mutex");

                // Return the drained buffer to its own slot, which is what frees
                // that slot for the block `slots` further along. Released before
                // blocking on the next one, so a reader always has somewhere to
                // work — the same ordering as `ReadNext` re-issuing before it
                // waits (apdiskio.cpp:252).
                if let Some(b) = self.cur.take() {
                    g.bufs[self.cur_slot] = Some(b);
                    g.ready[self.cur_slot] = false;
                    self.ring.cv.notify_all();
                }

                if g.head >= g.blocks {
                    self.done = true;
                    return Ok(0);
                }
                let slot = (g.head % self.slots as u64) as usize;
                loop {
                    if let Some(e) = g.err.take() {
                        self.done = true;
                        return Err(e);
                    }
                    if g.ready[slot] && g.bufs[slot].is_some() {
                        break;
                    }
                    g = self.ring.cv.wait(g).expect("ring condvar");
                }
                self.cur = Some(g.bufs[slot].take().expect("ready slot holds its buffer"));
                self.cur_slot = slot;
                self.pos = 0;
                g.head += 1;
                drop(g);

                // Discard the sector prefix below an unaligned start offset.
                if self.skip > 0 {
                    let buf_len = self.cur.as_ref().expect("just filled").filled;
                    let drop_now = self.skip.min(buf_len);
                    self.pos = drop_now;
                    self.skip -= drop_now;
                }
            }

            let data = self.cur.as_ref().expect("buffer present").data();
            if self.pos >= data.len() {
                // A short or fully-skipped block. Go round again rather than
                // reporting `Ok(0)`, which would look like end of file.
                if data.is_empty() {
                    self.done = true;
                    return Ok(0);
                }
                continue;
            }
            let n = out.len().min(data.len() - self.pos);
            self.pos += n;
            out[..n].copy_from_slice(&data[self.pos - n..self.pos]);
            return Ok(n);
        }
    }
}

impl std::fmt::Debug for SeqReader {
    /// Hand-written rather than derived: the ring holds live buffers and join
    /// handles, none of which are worth printing, and the fields a reader is
    /// actually identified by are these.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeqReader")
            .field("file_size", &self.file_size)
            .field("threads", &self.workers.len())
            .field("slots", &self.slots)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl Drop for SeqReader {
    /// Stop the readers and wait for them.
    ///
    /// Detaching them would be a real bug rather than untidiness: a reader
    /// blocked on the condvar holds an open handle, and on Windows an open
    /// handle blocks deleting the file — which log rotation and checkpoint GC
    /// both do.
    fn drop(&mut self) {
        {
            let mut g = self.ring.inner.lock().expect("ring mutex");
            g.stop = true;
            // Put back whatever the caller was holding, so a reader waiting on
            // that slot sees a buffer and can re-check `stop`.
            if let Some(b) = self.cur.take() {
                g.bufs[self.cur_slot] = Some(b);
                g.ready[self.cur_slot] = false;
            }
            self.ring.cv.notify_all();
        }
        for w in self.workers.drain(..) {
            let _ = w.join();
        }
    }
}

/// Open for reading, bypassing the page cache.
fn open_unbuffered(path: &Path) -> io::Result<File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);

    #[cfg(windows)]
    {
        // FILE_FLAG_NO_BUFFERING. `custom_flags` is a safe API, so the whole
        // unbuffered path stays inside this crate's `unsafe_code = "forbid"`.
        use std::os::windows::fs::OpenOptionsExt;
        opts.custom_flags(0x2000_0000);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_DIRECT);
    }
    // Elsewhere (macOS has no `O_DIRECT`; `F_NOCACHE` is a post-open fcntl)
    // this is an ordinary buffered open. Correctness is unaffected — only the
    // cache behaviour and the throughput are.

    opts.open(path)
}

/// Positional read, looping until the buffer is full or the file ends. Both
/// platform spellings are safe APIs.
///
/// The loop may only resume on a sector boundary. Unbuffered I/O rejects an
/// unaligned offset or buffer outright, so retrying from a non-sector-multiple
/// `n` would turn a perfectly good short read at end of file into
/// `ERROR_INVALID_PARAMETER`. A short read that is not a sector multiple can
/// only be end of file — the device does not do partial transfers otherwise —
/// so that is the signal to stop.
fn read_at(f: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    use std::os::unix::fs::FileExt;
    #[cfg(windows)]
    use std::os::windows::fs::FileExt;

    let mut n = 0;
    while n < buf.len() {
        #[cfg(windows)]
        let r = f.seek_read(&mut buf[n..], offset + n as u64);
        #[cfg(unix)]
        let r = f.read_at(&mut buf[n..], offset + n as u64);
        match r {
            Ok(0) => break,
            Ok(k) => {
                n += k;
                if !n.is_multiple_of(SECTOR) {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rsl-seqread-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    /// Distinguishable per position, so a misplaced read is a wrong byte rather
    /// than a coincidence.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = dir.join(name);
        let mut f = File::create(&p).expect("create");
        f.write_all(bytes).expect("write");
        f.sync_all().expect("sync");
        p
    }

    fn read_all(r: &mut SeqReader) -> Vec<u8> {
        let mut out = Vec::new();
        r.read_to_end(&mut out).expect("read_to_end");
        out
    }

    fn cfg(threads: usize, slots: usize, block: usize) -> SeqReaderConfig {
        SeqReaderConfig {
            threads,
            slots,
            block,
        }
    }

    #[test]
    fn reads_a_whole_file_byte_for_byte() {
        let dir = scratch("whole");
        // Deliberately not a block multiple, so the last block is short.
        let data = pattern(3 * (1 << 20) + 1234);
        let p = write_file(&dir, "a.bin", &data);

        let mut r = SeqReader::open_with(&p, cfg(4, 8, 1 << 20)).expect("open");
        assert_eq!(r.file_size(), data.len() as u64);
        assert_eq!(read_all(&mut r), data);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ring_shapes_all_agree() {
        let dir = scratch("shapes");
        let data = pattern(5 * SECTOR * 40 + 7);
        let p = write_file(&dir, "a.bin", &data);

        // Tightest possible ring (slots == threads, no slack), a deep ring, and
        // a single reader must all produce the same bytes.
        for (t, s, b) in [(1, 1, SECTOR), (8, 8, SECTOR), (2, 16, SECTOR * 4)] {
            let mut r = SeqReader::open_with(&p, cfg(t, s, b)).expect("open");
            assert_eq!(read_all(&mut r), data, "threads={t} slots={s} block={b}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unaligned_offsets_skip_exactly_the_prefix() {
        let dir = scratch("offset");
        let data = pattern(SECTOR * 10 + 99);
        let p = write_file(&dir, "a.bin", &data);

        // 0 and SECTOR are aligned; the rest force a skip, including one past
        // the first block and one inside the short final block.
        for off in [
            0usize,
            1,
            17,
            SECTOR - 1,
            SECTOR,
            SECTOR + 5,
            SECTOR * 9 + 3,
        ] {
            let mut r = SeqReader::open_at(&p, off as u64, cfg(4, 8, SECTOR * 2)).expect("open_at");
            assert_eq!(read_all(&mut r), data[off..], "offset {off}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn offset_at_or_past_end_reads_nothing() {
        let dir = scratch("past-end");
        let data = pattern(SECTOR + 10);
        let p = write_file(&dir, "a.bin", &data);

        for off in [data.len() as u64, data.len() as u64 + 1, 1 << 30] {
            let mut r = SeqReader::open_at(&p, off, cfg(2, 4, SECTOR)).expect("open_at");
            assert!(read_all(&mut r).is_empty(), "offset {off}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_file_is_immediately_eof() {
        let dir = scratch("empty");
        let p = write_file(&dir, "a.bin", &[]);
        let mut r = SeqReader::open(&p).expect("open");
        assert_eq!(r.file_size(), 0);
        assert!(read_all(&mut r).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_shorter_than_one_block_still_reads() {
        let dir = scratch("short");
        let data = pattern(7);
        let p = write_file(&dir, "a.bin", &data);
        let mut r = SeqReader::open_with(&p, cfg(4, 8, 1 << 20)).expect("open");
        assert_eq!(read_all(&mut r), data);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn size_is_snapshotted_at_open() {
        let dir = scratch("snapshot");
        let data = pattern(SECTOR * 4);
        let p = write_file(&dir, "a.bin", &data);

        let mut r = SeqReader::open_with(&p, cfg(2, 4, SECTOR)).expect("open");
        // Append after the open. `APSEQREAD` never sees this and neither may we;
        // the learn protocol serves a stable range from a growing file.
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(&pattern(SECTOR * 4)).unwrap();
        f.sync_all().unwrap();

        assert_eq!(r.file_size(), data.len() as u64);
        assert_eq!(read_all(&mut r).len(), data.len());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dropping_mid_stream_releases_the_file() {
        let dir = scratch("drop");
        let data = pattern(SECTOR * 200);
        let p = write_file(&dir, "a.bin", &data);

        // Abandon the reader with most of the ring still queued, then delete —
        // which fails on Windows if any reader thread still holds a handle.
        let mut r = SeqReader::open_with(&p, cfg(8, 16, SECTOR)).expect("open");
        let mut buf = [0u8; 64];
        r.read_exact(&mut buf).expect("first read");
        drop(r);

        std::fs::remove_file(&p).expect("no handle may outlive the reader");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_file_fails_at_open() {
        let dir = scratch("missing");
        let err = SeqReader::open(&dir.join("nope.bin")).expect_err("should fail");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bad_configs_are_rejected_with_a_reason() {
        let dir = scratch("badcfg");
        let p = write_file(&dir, "a.bin", &pattern(SECTOR));

        // Block not a sector multiple: unbuffered reads would fail deep in the
        // kernel with nothing to explain them.
        let e = SeqReader::open_with(&p, cfg(2, 4, 1000)).expect_err("unaligned block");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        // Fewer slots than threads would have readers contending for slots the
        // caller has not reached.
        let e = SeqReader::open_with(&p, cfg(8, 4, SECTOR)).expect_err("slots < threads");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        let e = SeqReader::open_with(&p, cfg(0, 4, SECTOR)).expect_err("zero threads");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
