//! `rsl-storage` — the RSL on-disk formats in pure Rust.
//!
//! Phase 3b of the port covers the checkpoint (`<decree>.codex`) file: the
//! [`checkpoint::CheckpointHeader`] and the block-checksummed user-state stream
//! written by [`checkpoint::CheckpointWriter`] and read back by
//! [`checkpoint::CheckpointReader`]. Files written here are byte-compatible with
//! `RSLCheckpointStreamWriter` (`src/RSL/src/rsl.cpp`) and
//! `CheckpointHeader::Marshal` (`src/RSL/src/legislator.cpp`). Compatibility
//! with literal production files and recovery verdicts is checked against
//! `RSLWindowsOracle`; `tools/linux-proxy` adds supplemental POSIX/model cases.
//!
//! Phase 3c adds the rest of the data directory: the log (`<decree>.log`)
//! writer, its decree→offset index and the startup recovery scan ([`log`]);
//! file naming, enumeration and `defunct.txt` ([`dir`]); and the log/checkpoint
//! retention rule ([`gc`]).
//!
//! Phase 4c adds the read side the learn port serves from: [`log::LogSet`], a
//! snapshot of every log in a data directory, and the [`log::FileSpan`]s a
//! `FetchVotes` response is made of. The snapshot semantics are the interesting
//! part — see that type's docs.
//!
//! Phase 3d makes it *provably* durable. Every write goes through the
//! [`durability`] policy, which spells out on Linux what the C++ gets implicitly
//! from `FILE_FLAG_WRITE_THROUGH` and `MOVEFILE_WRITE_THROUGH`: `fdatasync` per
//! commit, an `fsync` of the *directory* when a file is created, and
//! fsync→rename→fsync-dir to publish a checkpoint. [`sim::SimCrash`] is a
//! shadow filesystem that journals every operation so `tests/crash.rs` can cut
//! power at every point in a workload and run the real recovery code on the
//! wreckage. `DURABILITY.md` states the guarantee each public API offers; that
//! is the contract the Phase-5 engine acknowledges decrees against.
//!
//! [`seqread::SeqReader`] is the read-side counterpart to all of that: the port
//! of `APSEQREAD` (`src/common/src/apdiskio.cpp`), a ring of unbuffered reads
//! kept in flight by a pool of reader threads. It exists because a `BufReader`
//! does not get close: the 8 KiB default measures 17% of `APSEQREAD` on
//! identical LBAs, and raising capacity is worth about 3.7x but no more — a
//! read-then-consume loop leaves the device idle while the caller drains, and
//! one read at a time gives an NVMe a queue depth of one. `READPATH.md` records
//! the measurements, and the three confounds that make most of the obvious
//! comparisons untrustworthy on real hardware.
//!
//! [`seqwrite::SeqWriter`] is the same answer in the other direction, for
//! `APSEQWRITE` — a ring of write buffers drained by a pool of writer threads,
//! including the zero-copy `GetAvailable`/`CommitAvailable` pair, which
//! measured 17% at the checkpoint's block size. It exists because the read
//! side's fix does not transfer: raising a `BufWriter`'s capacity is worth only
//! 1.3x and then the page cache is the ceiling at ~1.6 GB/s, where the
//! unbuffered ring reaches 4.4. `WRITEPATH.md` records the measurements, the
//! four `APSEQWRITE` defects demonstrated by execution, and the two candidates
//! that did not survive.
//!
//! The checkpoint engine runs on both: [`checkpoint::CheckpointWriter`] streams
//! state into the write ring through `available`/`commit`, and
//! [`checkpoint::CheckpointReader`] streams it back out of the read ring. The
//! write ring reaches the crash harness too — it issues its blocks through a
//! [`seqwrite::BlockDevice`] supplied by the durability policy, so
//! [`sim::SimCrash`] journals the same writer production runs rather than a
//! stand-in for it.
//!
//! ## Design
//! * **Blocking `std::fs`**, no async: checkpoint I/O is a background activity in
//!   the C++ engine model, so a plain blocking API is the faithful shape.
//! * **Bounded memory**: neither direction ever buffers a whole checkpoint. The
//!   writer streams user bytes straight through while folding them into the
//!   running block checksum; the reader holds exactly one block.
//! * **Durability** is behind the [`durability`] trait — which owns opening and
//!   writing files, not just syncing them, so [`sim::SimCrash`] can substitute a
//!   whole filesystem and a benchmark can substitute none of it.
//! * **Reader-permissive, writer-strict**: where the C++ `LogAssert`-aborts on a
//!   malformed file, this crate returns an error instead; where the C++ would
//!   emit a shape no reader accepts, the writer refuses. Every such site is
//!   listed in the differential whitelist below.
//!
//! ## Differential whitelist (intentional divergences from C++)
//!
//! * **Non-page-multiple `checksumBlockSize`** — the C++ `LogAssert`s
//!   (`blockSize % s_PageSize == 0`, `rsl.cpp:467`/`:200`) on both the write and
//!   read paths. The writer here returns
//!   [`checkpoint::WriteError::BlockSizeNotPageMultiple`]; the *reader* accepts
//!   such a header (it only needs the value to walk blocks) rather than aborting.
//! * **Short trailing block** — a final block of `<= 8` bytes cannot carry its
//!   checksum. The C++ reader reports `ERROR_CRC` from `Init` (its arithmetic
//!   path) or `LogAssert`s in `ReadNextDataBlock`; here it is a plain
//!   [`checkpoint::RejectReason::BlockTooShort`] rejection.
//! * **`m_checksum` in the header is never computed** — the C++ marshals the
//!   field but leaves the value at whatever the caller set ("Jay Lorch doesn't
//!   understand how to make checksumming work", `legislator.cpp:951`), and no
//!   reader verifies it. This port marshals it identically (a plain `u64` field
//!   under the writer's control) so the bytes match; header integrity comes from
//!   the embedded next-vote's own Rabin-64, which *is* verified.
//! * **Zeroed log record pads** — the C++ log writer hands `WriteFileGather`
//!   whatever its marshal buffer held past the message (zero for votes, heap
//!   garbage elsewhere). [`log::LogWriter`] always zeroes the pad, because the
//!   recovery scan reads an all-zero header page as a clean end-of-log. Readers
//!   on both sides tolerate non-zero pads (the checksum covers only the message
//!   body) — the Phase-3a `garbage-pad` sample pins that.
//! * **Out-of-sequence vote in the decree index** — the C++ `LogFile::AddMessage`
//!   `LogAssert`s (`legislator.cpp:722`);
//!   [`log::DecreeIndex::add_message`] returns [`log::IndexError`], and
//!   [`log::LogWriter::append_batch`] refuses the batch before writing anything.
//! * **Out-of-range decree lookup** — `LogFile::GetOffset` `LogAssert`s
//!   (`legislator.cpp:738`); [`log::DecreeIndex::offset`] returns `None`.
//! * **Log GC with no checkpoint present** — `CleanupLogsAndCheckpoint` reads
//!   `checkpoints[0]` from a possibly-empty vector (`legislator.cpp:5713`);
//!   [`gc::plan`] deletes no logs in that case.
//! * **Unparsable `*.log`/`*.codex` name** — both sides fail the enumeration;
//!   [`dir::DataDir::scan`] reports [`dir::DirError::UnparsableName`] where the
//!   C++ returns `ERROR_INVALID_PARAMETER`, and this parser takes leading ASCII
//!   digits only where `sscanf("%I64u")` would also accept whitespace or a sign.
//! * **Multi-buffer next-vote** — a C++ `Vote` that grew past one marshal buffer
//!   is emitted by `CheckpointHeader::Marshal` as `sum(RoundUpToPage(buf_i))`
//!   bytes while `GetMarshalLen` reserved only `RoundUpToPage(sum(buf_i))` — the
//!   two disagree, so that shape is already inconsistent in the C++. This port
//!   always emits the single-buffer form (one page-rounded vote), which is what
//!   every parsed or single-buffer vote produces.

pub mod checkpoint;
pub mod dir;
pub mod durability;
pub mod gc;
pub mod log;
pub mod seqread;
pub mod seqwrite;
pub mod sim;

/// `s_PageSize` (`legislator.h:16`) — every on-disk record is padded to a
/// multiple of this.
pub const PAGE_SIZE: u32 = 512;

/// `s_ChecksumBlockSize` (`checkpoint.h:31`) — checkpoint user state is written
/// in blocks of this size, each ending in an 8-byte Rabin-64 of its data.
pub const CHECKSUM_BLOCK_SIZE: u32 = 4 * 1024 * 1024;

/// `CHECKSUM_SIZE` (`rsl.h`) — the per-block checksum token is a `u64`.
pub const CHECKSUM_SIZE: u32 = 8;

/// `RoundUpToPage` (`legislator.h:23`). Saturates instead of wrapping; the C++
/// wraps to 0, but no caller can reach that (a `u32` length that close to
/// `2^32` never fits a message).
pub const fn round_up_to_page(x: u32) -> u32 {
    let page = PAGE_SIZE;
    match x.checked_add(page - 1) {
        Some(v) => v & !(page - 1),
        None => !(page - 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_rounding_matches_the_cpp_macro() {
        assert_eq!(round_up_to_page(0), 0);
        assert_eq!(round_up_to_page(1), 512);
        assert_eq!(round_up_to_page(512), 512);
        assert_eq!(round_up_to_page(513), 1024);
        assert_eq!(round_up_to_page(1024), 1024);
        // Saturating tail (the C++ wraps here; unreachable for real lengths).
        assert_eq!(round_up_to_page(u32::MAX), !(PAGE_SIZE - 1));
    }
}
