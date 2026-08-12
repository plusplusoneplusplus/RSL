//
// seqiobench -- measures the sequential I/O classes in
// src/common/src/apdiskio.cpp, so the Rust port has a baseline to be compared
// against. APSEQREAD is covered by the `read` subcommand, APSEQWRITE by
// `write`; the `gen` fixture and the tab-separated result format are shared.
//
// The write side has its own cache asymmetry, inverted from the read side:
// APSEQWRITE opens FILE_FLAG_NO_BUFFERING (no page cache) but NOT
// FILE_FLAG_WRITE_THROUGH (device write cache still absorbs), while a buffered
// Rust writer goes through the page cache and, with a final sync, through the
// device cache too. Neither default is a fair comparison, so `write` takes
// --fsync and the sweep script states the sync discipline of every row.
//
// `write` never truncates -- that is APSEQWRITE's own OPEN_ALWAYS behaviour
// (apdiskio.cpp:697) -- so rewriting an existing fixture of exactly --length
// bytes in place keeps every run of a sweep on the same LBAs, the same trick
// the read sweep plays with windows.
//
// APSEQREAD opens with FILE_FLAG_NO_BUFFERING, so it never sees the OS page
// cache. Every Rust read path does. A warm-cache comparison therefore measures
// nothing useful, and this harness is built to be driven cold: `gen` writes its
// fixture unbuffered so laying it down does not warm it, and `read` takes an
// --offset/--length window so a caller can stripe a larger-than-RAM file and
// never revisit a region while it is still resident.
//
// Usage:
//   seqiobench gen  <path> <sizeMiB>
//   seqiobench read <path> [--offset B] [--length B] [--depth N]
//                          [--block B] [--record B] [--label S]
//   seqiobench write <path> [--length B] [--depth N] [--block B] [--record B]
//                           [--mode copy|commit] [--fsync] [--label S]
//   seqiobench tailtest <scratchpath> [--block B] [--depth N] [--bytes B]
//                           [--precreate B]
//   seqiobench rwbound <scratchpath> [--block B]
//   seqiobench reflush <scratchpath> [--block B] [--append B] [--appends N]
//   seqiobench accounting <scratchpath>
//
// `read` prints one tab-separated RESULT line (plus a header on request) giving
// throughput and the per-GetData latency distribution. The distribution is the
// point: most calls are a memcpy out of an already-filled buffer, and one call
// in (block/record) has to wait on the oldest overlapped read. A mean hides
// that; p50 and p99 do not.
//

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <vector>

#include <apdiskio.h>

using namespace RSLibImpl;

static const DWORD c_genChunk = 8 * 1024 * 1024;

//
// A pattern that is cheap to produce, not compressible enough for NTFS
// compression to change what the disk does, and distinguishable per offset so a
// misplaced read would show up as a checksum mismatch rather than silently.
//
static void FillPattern(BYTE* pb, DWORD cb, DWORD64 offset)
{
    DWORD64 x = offset * 0x9E3779B97F4A7C15ULL + 1;
    for (DWORD i = 0; i < cb; i += 8)
    {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        memcpy(pb + i, &x, 8);
    }
}

static int Generate(const char* path, DWORD64 sizeBytes)
{
    // Unbuffered, so writing an 80 GiB fixture does not leave 64 GiB of it warm
    // in the page cache and quietly invalidate the first cold run.
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "gen: CreateFile('%s') failed: %u\n", path, GetLastError());
        return 1;
    }

    BYTE* buf = (BYTE*)VirtualAlloc(NULL, c_genChunk, MEM_COMMIT, PAGE_READWRITE);
    if (buf == NULL)
    {
        fprintf(stderr, "gen: VirtualAlloc failed: %u\n", GetLastError());
        CloseHandle(h);
        return 1;
    }

    DWORD64 written = 0;
    while (written < sizeBytes)
    {
        DWORD cb = (DWORD)((sizeBytes - written) < c_genChunk ? (sizeBytes - written) : c_genChunk);
        // Unbuffered writes must stay sector-aligned; round the tail up rather
        // than falling back to a buffered write for it.
        cb = (cb + 4095) & ~4095u;
        FillPattern(buf, cb, written);

        DWORD cbWrote = 0;
        if (!WriteFile(h, buf, cb, &cbWrote, NULL) || cbWrote != cb)
        {
            fprintf(stderr, "gen: WriteFile failed at %llu: %u\n", written, GetLastError());
            VirtualFree(buf, 0, MEM_RELEASE);
            CloseHandle(h);
            return 1;
        }
        written += cbWrote;

        if ((written % (4ULL * 1024 * 1024 * 1024)) < c_genChunk)
        {
            fprintf(stderr, "gen: %llu MiB\n", written / (1024 * 1024));
            fflush(stderr);
        }
    }

    VirtualFree(buf, 0, MEM_RELEASE);
    FlushFileBuffers(h);
    CloseHandle(h);
    fprintf(stderr, "gen: wrote %llu bytes to %s\n", written, path);
    return 0;
}

static double PercentileNs(std::vector<double>& sorted, double q)
{
    if (sorted.empty())
    {
        return 0.0;
    }
    size_t i = (size_t)(q * (double)(sorted.size() - 1) + 0.5);
    return sorted[i];
}

struct RunOptions
{
    const char* path;
    const char* label;
    DWORD64     offset;
    DWORD64     length;
    int         depth;
    DWORD32     block;
    DWORD       record;
    bool        header;
};

static int Run(const RunOptions& o)
{
    APSEQREAD reader;

    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    const double nsPerTick = 1e9 / (double)freq.QuadPart;

    DWORD32 ec = reader.DoInit(o.path, o.depth, o.block);
    if (ec != NO_ERROR)
    {
        fprintf(stderr, "run: DoInit failed: %u\n", ec);
        return 1;
    }

    DWORD64 fileSize = reader.FileSize();
    if (o.offset >= fileSize)
    {
        fprintf(stderr, "run: offset %llu past end of file %llu\n", o.offset, fileSize);
        return 1;
    }
    DWORD64 want = o.length ? o.length : (fileSize - o.offset);
    if (o.offset + want > fileSize)
    {
        want = fileSize - o.offset;
    }

    if (o.offset != 0)
    {
        ec = reader.Reset(o.offset);
        if (ec != NO_ERROR)
        {
            fprintf(stderr, "run: Reset(%llu) failed: %u\n", o.offset, ec);
            return 1;
        }
    }

    std::vector<BYTE> dst(o.record);
    std::vector<double> lat;
    lat.reserve((size_t)(want / o.record) + 1);

    DWORD64 read = 0;
    DWORD64 fold = 0;

    LARGE_INTEGER t0;
    QueryPerformanceCounter(&t0);

    while (read + o.record <= want)
    {
        LARGE_INTEGER a, b;
        QueryPerformanceCounter(&a);
        ec = reader.GetData(dst.data(), o.record);
        QueryPerformanceCounter(&b);

        if (ec != NO_ERROR)
        {
            if (ec == ERROR_HANDLE_EOF)
            {
                break;
            }
            fprintf(stderr, "run: GetData failed at %llu: %u\n", read, ec);
            return 1;
        }

        lat.push_back((double)(b.QuadPart - a.QuadPart) * nsPerTick);
        read += o.record;
        // Keep the copy observable so the optimizer cannot delete it, without
        // adding work that would show up next to the I/O.
        fold += *(const DWORD64*)dst.data();
    }

    LARGE_INTEGER t1;
    QueryPerformanceCounter(&t1);

    double seconds = (double)(t1.QuadPart - t0.QuadPart) / (double)freq.QuadPart;
    double mib = (double)read / (1024.0 * 1024.0);

    std::sort(lat.begin(), lat.end());

    // A stall only lands on one call in (block / record) -- for a 10 MiB block
    // and a 4 KiB record that is 1 call in 2560, or 0.039%. p99 does not reach
    // it. The deep percentiles are what make prefetching visible at all.
    if (o.header)
    {
        printf("impl\tlabel\tdepth\tblock\trecord\tbytes\tseconds\tmibps\tcalls"
               "\tp50_ns\tp90_ns\tp99_ns\tp999_ns\tp9999_ns\tmax_ns\tfold\n");
    }
    printf("APSEQREAD\t%s\t%d\t%u\t%u\t%llu\t%.4f\t%.2f\t%zu"
           "\t%.0f\t%.0f\t%.0f\t%.0f\t%.0f\t%.0f\t%llu\n",
           o.label, o.depth, o.block, o.record, read, seconds,
           seconds > 0 ? mib / seconds : 0.0, lat.size(),
           PercentileNs(lat, 0.50), PercentileNs(lat, 0.90),
           PercentileNs(lat, 0.99), PercentileNs(lat, 0.999),
           PercentileNs(lat, 0.9999), lat.empty() ? 0.0 : lat.back(), fold);
    fflush(stdout);
    return 0;
}

static DWORD64 ParseSize(const char* s)
{
    return _strtoui64(s, NULL, 0);
}

//
// Demonstrates where APSEQREAD::Skip lands, as opposed to where it was asked to
// land. Writes a scratch file whose every 8-byte word holds its own byte
// offset, so a single GetData after the Skip reports the reader's actual
// logical position.
//
// The large-skip branch (apdiskio.cpp:560) resumes at
//     Reset(m_offsetNext + m_cbLeft + dwNumBytes)
// but m_offsetNext is the *prefetch frontier*, not the caller's position. After
// Reset primes the ladder, the frontier sits m_numReads whole buffers ahead of
// what the caller has consumed, and m_cbLeft is what is left of the current
// buffer -- so it needs subtracting, not adding. Expect an overshoot of
//     2 * m_cbLeft + (m_numReads - 1) * m_readBufSize
//
static int SkipTest(const char* path, int depth, DWORD32 block, DWORD skip, DWORD prefix)
{
    // Every word is its own offset, so decoding one word gives the position.
    const DWORD64 cbFile = 64 * 1024 * 1024;
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "skiptest: CreateFile failed: %u\n", GetLastError());
        return 1;
    }
    BYTE* buf = (BYTE*)VirtualAlloc(NULL, c_genChunk, MEM_COMMIT, PAGE_READWRITE);
    if (buf == NULL)
    {
        CloseHandle(h);
        return 1;
    }
    for (DWORD64 off = 0; off < cbFile; off += c_genChunk)
    {
        for (DWORD i = 0; i < c_genChunk; i += 8)
        {
            DWORD64 v = off + i;
            memcpy(buf + i, &v, 8);
        }
        DWORD cbWrote = 0;
        if (!WriteFile(h, buf, c_genChunk, &cbWrote, NULL) || cbWrote != c_genChunk)
        {
            fprintf(stderr, "skiptest: WriteFile failed: %u\n", GetLastError());
            VirtualFree(buf, 0, MEM_RELEASE);
            CloseHandle(h);
            return 1;
        }
    }
    VirtualFree(buf, 0, MEM_RELEASE);
    CloseHandle(h);

    APSEQREAD reader;
    DWORD32 ec = reader.DoInit(path, depth, block);
    if (ec != NO_ERROR)
    {
        fprintf(stderr, "skiptest: DoInit failed: %u\n", ec);
        return 1;
    }

    // Consume a prefix so the caller's position and the prefetch frontier have
    // visibly diverged before the Skip.
    std::vector<BYTE> dst(prefix);
    ec = reader.GetData(dst.data(), prefix);
    if (ec != NO_ERROR)
    {
        fprintf(stderr, "skiptest: priming GetData failed: %u\n", ec);
        return 1;
    }

    ec = reader.Skip(skip);
    if (ec != NO_ERROR)
    {
        fprintf(stderr, "skiptest: Skip failed: %u\n", ec);
        return 1;
    }

    DWORD64 landed = 0;
    ec = reader.GetData(&landed, sizeof(landed));
    if (ec != NO_ERROR)
    {
        fprintf(stderr, "skiptest: post-Skip GetData failed: %u\n", ec);
        return 1;
    }

    DWORD64 expected = (DWORD64)prefix + skip;
    const char* branch = (skip < block) ? "in-buffer/next-buffer" : "large-skip (Reset)";

    printf("SKIPTEST\tdepth=%d\tblock=%u\tprefix=%u\tskip=%u\tbranch=%s\n",
           depth, block, prefix, skip, branch);
    printf("SKIPTEST\texpected_offset=%llu\tactual_offset=%llu\tdelta=%lld\n",
           expected, landed, (INT64)landed - (INT64)expected);

    if (landed != expected)
    {
        DWORD64 cbLeft = block - (prefix % block);
        printf("SKIPTEST\tpredicted_overshoot=%llu\t(2*m_cbLeft=%llu + (depth-1)*block=%llu)\n",
               2 * cbLeft + (DWORD64)(depth - 1) * block,
               2 * cbLeft, (DWORD64)(depth - 1) * block);
    }
    fflush(stdout);
    return 0;
}

//
// The first 8-byte word FillPattern lays down for a record starting at
// `offset`. Summed (wrapping) over every record it is the `fold` column, which
// must agree exactly with the Rust writer for the same window and record size
// -- a mismatch means the two sides did not produce the same logical stream.
//
static DWORD64 PatternHead(DWORD64 offset)
{
    DWORD64 x = offset * 0x9E3779B97F4A7C15ULL + 1;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return x;
}

struct WriteOptions
{
    const char* path;
    const char* label;
    DWORD64     length;
    int         depth;
    DWORD32     block;
    DWORD       record;
    bool        commit;   // GetAvailable/CommitAvailable instead of Write
    bool        fsync;    // FlushFileBuffers after Flush
    bool        header;
};

//
// One APSEQWRITE run: --length bytes of pattern in --record sized calls,
// then Flush (and optionally FlushFileBuffers). Per-record latency is the
// point: most calls are a memcpy into the current ring buffer, and one call in
// (block / record) has to issue the filled buffer and wait on the slot it
// advances to.
//
// --mode copy   goes through Write(), one pattern fill plus one memcpy per
//               record -- the shape RSLCheckpointStreamWriter would have
//               without its zero-copy marshaling.
// --mode commit goes through GetAvailable/CommitAvailable, the pattern filled
//               straight into the ring buffer -- the zero-copy API
//               RSLCheckpointStreamWriter actually uses (rsl.cpp:478).
// The difference between the two modes is the memcpy, measured.
//
static int RunWrite(const WriteOptions& o)
{
    APSEQWRITE writer;

    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    const double nsPerTick = 1e9 / (double)freq.QuadPart;

    DWORD32 ec = writer.DoInit(o.path, o.block, o.depth);
    if (ec != NO_ERROR)
    {
        fprintf(stderr, "write: DoInit failed: %u\n", ec);
        return 1;
    }

    std::vector<BYTE> scratch(o.record);
    std::vector<double> lat;
    lat.reserve((size_t)(o.length / o.record) + 1);

    DWORD64 written = 0;
    DWORD64 fold = 0;

    LARGE_INTEGER t0;
    QueryPerformanceCounter(&t0);

    while (written + o.record <= o.length)
    {
        LARGE_INTEGER a, b;
        QueryPerformanceCounter(&a);
        if (o.commit)
        {
            // Marshal straight into the ring, in as many pieces as the
            // remaining space dictates -- exactly what
            // RSLCheckpointStreamWriter::Write does with its m_buffer.
            DWORD left = o.record;
            DWORD64 at = written;
            while (left > 0)
            {
                void* pb = NULL;
                DWORD cb = 0;
                ec = writer.GetAvailable(&pb, &cb);
                if (ec != NO_ERROR)
                {
                    fprintf(stderr, "write: GetAvailable failed at %llu: %u\n", written, ec);
                    return 1;
                }
                DWORD take = cb < left ? cb : left;
                FillPattern((BYTE*)pb, take, at);
                ec = writer.CommitAvailable(take);
                if (ec != NO_ERROR)
                {
                    fprintf(stderr, "write: CommitAvailable failed at %llu: %u\n", written, ec);
                    return 1;
                }
                at += take;
                left -= take;
            }
        }
        else
        {
            FillPattern(scratch.data(), o.record, written);
            ec = writer.Write(scratch.data(), o.record);
            if (ec != NO_ERROR)
            {
                fprintf(stderr, "write: Write failed at %llu: %u\n", written, ec);
                return 1;
            }
        }
        QueryPerformanceCounter(&b);

        lat.push_back((double)(b.QuadPart - a.QuadPart) * nsPerTick);
        fold += PatternHead(written);
        written += o.record;
    }

    // Flush is part of the wall clock -- SetEndOfFile and the waits on the
    // outstanding overlapped writes are real work the caller pays -- but not a
    // per-record latency, so it is reported separately on stderr.
    LARGE_INTEGER f0, f1;
    QueryPerformanceCounter(&f0);
    ec = writer.Flush();
    if (ec != NO_ERROR)
    {
        fprintf(stderr, "write: Flush failed: %u\n", ec);
        return 1;
    }
    if (o.fsync)
    {
        // NO_BUFFERING put the data past the page cache but not necessarily
        // past the device write cache; this is the write-side equivalent of
        // the Rust side's sync_all.
        if (!FlushFileBuffers(writer.FileHandle()))
        {
            fprintf(stderr, "write: FlushFileBuffers failed: %u\n", GetLastError());
            return 1;
        }
    }
    QueryPerformanceCounter(&f1);

    LARGE_INTEGER t1;
    QueryPerformanceCounter(&t1);

    double seconds = (double)(t1.QuadPart - t0.QuadPart) / (double)freq.QuadPart;
    double mib = (double)written / (1024.0 * 1024.0);

    fprintf(stderr, "write: flush%s took %.1f ms\n", o.fsync ? "+fsync" : "",
            (double)(f1.QuadPart - f0.QuadPart) * nsPerTick / 1e6);

    std::sort(lat.begin(), lat.end());

    if (o.header)
    {
        printf("impl\tlabel\tdepth\tblock\trecord\tbytes\tseconds\tmibps\tcalls"
               "\tp50_ns\tp90_ns\tp99_ns\tp999_ns\tp9999_ns\tmax_ns\tfold\n");
    }
    printf("APSEQWRITE\t%s\t%d\t%u\t%u\t%llu\t%.4f\t%.2f\t%zu"
           "\t%.0f\t%.0f\t%.0f\t%.0f\t%.0f\t%.0f\t%llu\n",
           o.label, o.depth, o.block, o.record, written, seconds,
           seconds > 0 ? mib / seconds : 0.0, lat.size(),
           PercentileNs(lat, 0.50), PercentileNs(lat, 0.90),
           PercentileNs(lat, 0.99), PercentileNs(lat, 0.999),
           PercentileNs(lat, 0.9999), lat.empty() ? 0.0 : lat.back(), fold);
    fflush(stdout);
    return 0;
}

//
// Demonstrates what is on disk if the process dies after writing but before
// Flush. IssueWrite always writes the full m_cbBufSize regardless of m_cbUsed
// (apdiskio.cpp:755) while m_offsetNext advances by m_cbUsed, and only
// Flush's SetEndOfFile establishes the logical length -- so a crash leaves the
// file (a) longer than the data if it was fresh, ending in whatever the last
// full-block write carried past the logical end, and (b) at its OLD length
// with the OLD tail if a shorter stream was being rewritten over a longer
// existing file, because OPEN_ALWAYS never truncated it (apdiskio.cpp:697).
//
// "Dies before Flush" is simulated by leaking the writer -- no Flush, no
// destructor -- which leaves the file exactly as a crash at that instant
// would, then inspecting through a separate handle.
//
static int TailTest(const char* path, DWORD32 block, int depth, DWORD64 bytes, DWORD64 precreate)
{
    if (precreate > 0)
    {
        // Lay down a longer file of marker words first, properly flushed.
        APSEQWRITE pre;
        DWORD32 ec = pre.DoInit(path, block, depth);
        if (ec != NO_ERROR)
        {
            fprintf(stderr, "tailtest: precreate DoInit failed: %u\n", ec);
            return 1;
        }
        std::vector<DWORD64> marker(4096 / 8, 0x5A5A5A5A5A5A5A5AULL);
        for (DWORD64 at = 0; at < precreate; at += 4096)
        {
            ec = pre.Write(marker.data(), 4096);
            if (ec != NO_ERROR)
            {
                fprintf(stderr, "tailtest: precreate Write failed: %u\n", ec);
                return 1;
            }
        }
        ec = pre.Flush();
        if (ec != NO_ERROR)
        {
            fprintf(stderr, "tailtest: precreate Flush failed: %u\n", ec);
            return 1;
        }
        pre.DoDispose();
    }

    // The "crashing" writer: every 8-byte word holds its own offset, so
    // inspection can tell new data, stale marker and garbage apart. Leaked
    // deliberately -- DoDispose would Flush.
    APSEQWRITE* w = new APSEQWRITE();
    DWORD32 ec = w->DoInit(path, block, depth);
    if (ec != NO_ERROR)
    {
        fprintf(stderr, "tailtest: DoInit failed: %u\n", ec);
        return 1;
    }
    std::vector<DWORD64> rec(4096 / 8);
    for (DWORD64 at = 0; at < bytes; at += 4096)
    {
        DWORD cb = (DWORD)((bytes - at) < 4096 ? (bytes - at) : 4096);
        for (DWORD i = 0; i < cb; i += 8)
            rec[i / 8] = at + i;
        ec = w->Write(rec.data(), cb);
        if (ec != NO_ERROR)
        {
            fprintf(stderr, "tailtest: Write failed: %u\n", ec);
            return 1;
        }
    }
    // Let the issued overlapped writes complete; the point is the writes that
    // were never issued and the SetEndOfFile that never ran, not a race.
    Sleep(500);

    HANDLE h = CreateFileA(path, FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "tailtest: inspect open failed: %u\n", GetLastError());
        return 1;
    }
    DDWORD size;
    size.dw.low = GetFileSize(h, &size.dw.high);

    // Walk the file classifying each word: fresh data (word == its offset),
    // stale precreate marker, or something else.
    DWORD64 freshEnd = 0;      // end of the longest fresh prefix
    DWORD64 firstStale = ~0ULL;
    std::vector<BYTE> buf(1 << 20);
    DWORD64 at = 0;
    bool prefix = true;
    while (at < size.ddw)
    {
        DWORD want = (DWORD)((size.ddw - at) < buf.size() ? (size.ddw - at) : buf.size());
        DWORD got = 0;
        if (!ReadFile(h, buf.data(), want, &got, NULL) || got == 0)
            break;
        for (DWORD i = 0; i + 8 <= got; i += 8)
        {
            DWORD64 word;
            memcpy(&word, buf.data() + i, 8);
            if (prefix && word == at + i)
                freshEnd = at + i + 8;
            else
                prefix = false;
            if (word == 0x5A5A5A5A5A5A5A5AULL && firstStale == ~0ULL)
                firstStale = at + i;
        }
        at += got;
    }
    CloseHandle(h);

    printf("TAILTEST\tblock=%u\tdepth=%d\tlogical_bytes=%llu\tprecreate=%llu\n",
           block, depth, bytes, precreate);
    printf("TAILTEST\tfile_size=%llu\tfresh_prefix=%llu\tfirst_stale_marker=%lld\n",
           size.ddw, freshEnd, firstStale == ~0ULL ? -1 : (INT64)firstStale);
    // What SetEndOfFile would have made it, had Flush run.
    printf("TAILTEST\texpected_size_after_flush=%llu\texcess=%lld\n",
           bytes, (INT64)size.ddw - (INT64)bytes);
    fflush(stdout);
    // Leak `w` on purpose; the OS reclaims the handles at exit without running
    // Flush, which is the whole point.
    return 0;
}

//
// Demonstrates RandomWrite's bound (apdiskio.cpp:979):
//     if (offset + cbWrite >= m_offsetNext) return ERROR_INVALID_PARAMETER;
// The >= makes the last byte of the issued region unreachable, and
// m_offsetNext only advances when a buffer is ISSUED (PrepareNext), not when
// it is filled -- and Flush issues the current buffer without advancing it --
// so after write(2 blocks)+Flush the file holds 2 blocks durably yet only the
// first block minus one byte is RandomWrite-able.
//
static int RwBoundTest(const char* path, DWORD32 block)
{
    APSEQWRITE w;
    DWORD32 ec = w.DoInit(path, block, 2);
    if (ec != NO_ERROR)
    {
        fprintf(stderr, "rwbound: DoInit failed: %u\n", ec);
        return 1;
    }
    std::vector<BYTE> two(2 * (size_t)block, 0xCD);
    ec = w.Write(two.data(), (DWORD)two.size());
    if (ec != NO_ERROR)
    {
        fprintf(stderr, "rwbound: Write failed: %u\n", ec);
        return 1;
    }
    ec = w.Flush();
    if (ec != NO_ERROR)
    {
        fprintf(stderr, "rwbound: Flush failed: %u\n", ec);
        return 1;
    }

    HANDLE h = CreateFileA(path, FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);
    DDWORD size;
    size.dw.low = GetFileSize(h, &size.dw.high);
    CloseHandle(h);

    BYTE patch[4] = { 1, 2, 3, 4 };
    struct Probe { const char* what; DWORD64 offset; };
    Probe probes[] = {
        { "start of file",                        0 },
        { "last 4 bytes of first block",          (DWORD64)block - 4 },
        { "first 4 bytes of second block",        (DWORD64)block },
        { "last 4 bytes of durable data",         2 * (DWORD64)block - 4 },
    };
    printf("RWBOUND\tblock=%u\tfile_size=%llu\tdurable_bytes=%llu\n",
           block, size.ddw, 2 * (DWORD64)block);
    for (const Probe& p : probes)
    {
        ec = w.RandomWrite(p.offset, patch, sizeof(patch));
        printf("RWBOUND\toffset=%llu\t%s\t-> %s (%u)\n", p.offset, p.what,
               ec == NO_ERROR ? "ok" : "REJECTED", ec);
    }
    w.DoDispose();
    fflush(stdout);
    return 0;
}

//
// Characterises the Flush/Write/Flush pattern. Flush issues the current
// partial buffer -- all m_cbBufSize bytes of it (apdiskio.cpp:755) -- without
// advancing m_offsetNext or resetting m_cbUsed, so the NEXT Flush re-issues
// the same buffer, grown, at the same offset. Per incremental flush that is
// one full-buffer device write regardless of how little was appended: linear
// in flush count, not quadratic, but with a bufsize/append amplification.
// GetProcessIoCounters supplies the ground truth for device bytes.
//
// No caller in the tree does this today (Flush is called once, at close:
// rsl.cpp:583,:614,:618, learn_protocol.cpp:307) -- this exists to check
// whether the pattern would be safe and what it would cost, not to indict a
// caller.
//
static int ReflushTest(const char* path, DWORD32 block, DWORD append, int appends)
{
    APSEQWRITE w;
    DWORD32 ec = w.DoInit(path, block, 2);
    if (ec != NO_ERROR)
    {
        fprintf(stderr, "reflush: DoInit failed: %u\n", ec);
        return 1;
    }

    IO_COUNTERS before, after;
    GetProcessIoCounters(GetCurrentProcess(), &before);

    std::vector<BYTE> rec(append);
    DWORD64 at = 0;
    for (int i = 0; i < appends; i++)
    {
        for (DWORD j = 0; j + 8 <= append; j += 8)
        {
            DWORD64 word = at + j;
            memcpy(rec.data() + j, &word, 8);
        }
        ec = w.Write(rec.data(), append);
        if (ec == NO_ERROR)
            ec = w.Flush();
        if (ec != NO_ERROR)
        {
            fprintf(stderr, "reflush: append %d failed: %u\n", i, ec);
            return 1;
        }
        at += append;
    }
    w.DoDispose();

    GetProcessIoCounters(GetCurrentProcess(), &after);
    DWORD64 device = after.WriteTransferCount - before.WriteTransferCount;
    DWORD64 logical = (DWORD64)append * appends;

    // Verify the file still holds exactly the appended stream -- the repeated
    // rewrite must be idempotent for the pattern to be merely wasteful rather
    // than wrong.
    bool intact = true;
    DWORD64 fileSize = 0;
    {
        HANDLE h = CreateFileA(path, FILE_READ_DATA, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);
        DDWORD size;
        size.dw.low = GetFileSize(h, &size.dw.high);
        fileSize = size.ddw;
        std::vector<BYTE> buf((size_t)logical);
        DWORD got = 0;
        ReadFile(h, buf.data(), (DWORD)logical, &got, NULL);
        CloseHandle(h);
        if (got != logical)
            intact = false;
        else
            for (DWORD64 j = 0; j + 8 <= logical; j += 8)
            {
                DWORD64 word;
                memcpy(&word, buf.data() + j, 8);
                if (word != j) { intact = false; break; }
            }
    }

    printf("REFLUSH\tblock=%u\tappend=%u\tappends=%d\n", block, append, appends);
    printf("REFLUSH\tlogical_bytes=%llu\tdevice_bytes=%llu\tamplification=%.1fx"
           "\tper_flush_device_bytes=%llu\n",
           logical, device, logical ? (double)device / (double)logical : 0.0,
           device / (appends ? appends : 1));
    printf("REFLUSH\tfile_size=%llu\tcontent_intact=%s\n",
           fileSize, intact ? "yes" : "NO");
    fflush(stdout);
    return 0;
}

//
// Demonstrates the unguarded accounting in WriteInternal's straddling path
// (apdiskio.cpp:899): the memcpy after PrepareNext is guarded by `if (!ec)`
// but `m_cbUsed += (cbWrite - cbUsed)` runs regardless, so a failed issue
// leaves m_cbUsed counting bytes that were never copied anywhere --
// observable through the public BytesIssued(), which afterwards exceeds the
// bytes the caller ever successfully handed in, and can exceed the buffer
// size itself.
//
// The induced failure is real but cheap: DoInit accepts any cbWrite (no
// sector-multiple validation -- itself worth knowing), and an unbuffered
// WriteFile of a non-sector-multiple length fails synchronously with
// ERROR_INVALID_PARAMETER, which is IssueWrite's error path -- the same path
// a genuinely full disk would take.
//
static int AccountingTest(const char* path)
{
    APSEQWRITE w;
    const DWORD32 bufsize = 1000;   // legal per DoInit; no write can ever succeed
    DWORD32 ec = w.DoInit(path, bufsize, 2);
    printf("ACCOUNTING\tDoInit(cbWrite=%u)\t-> %u (accepted a non-sector-multiple buffer)\n",
           bufsize, ec);
    if (ec != NO_ERROR)
        return 1;

    std::vector<BYTE> rec(600, 0xEE);
    ec = w.Write(rec.data(), 600);
    printf("ACCOUNTING\tWrite(600)\t-> %u\tBytesIssued=%llu\n", ec, w.BytesIssued());

    // Straddles the 1000-byte buffer: copies 400, tries to issue the full
    // buffer, the issue fails, and the remaining 200 are accounted anyway.
    ec = w.Write(rec.data(), 600);
    printf("ACCOUNTING\tWrite(600)\t-> %u\tBytesIssued=%llu"
           "\t(1000 accepted into the buffer, 0 on disk)\n",
           ec, w.BytesIssued());
    fflush(stdout);
    return 0;
}

static void Usage()
{
    fprintf(stderr,
            "usage:\n"
            "  seqiobench gen  <path> <sizeMiB>\n"
            "  seqiobench read <path> [--offset B] [--length B] [--depth N]\n"
            "                         [--block B] [--record B] [--label S] [--header]\n"
            "  seqiobench write <path> [--length B] [--depth N] [--block B] [--record B]\n"
            "                         [--mode copy|commit] [--fsync] [--label S] [--header]\n"
            "  seqiobench skiptest <scratchpath> [--depth N] [--block B]\n"
            "                         [--skip B] [--prefix B]\n"
            "  seqiobench tailtest <scratchpath> [--block B] [--depth N] [--bytes B]\n"
            "                         [--precreate B]\n"
            "  seqiobench rwbound <scratchpath> [--block B]\n"
            "  seqiobench reflush <scratchpath> [--block B] [--append B] [--appends N]\n"
            "  seqiobench accounting <scratchpath>\n");
}

int __cdecl main(int argc, char** argv)
{
    if (argc < 3)
    {
        Usage();
        return 2;
    }

    if (strcmp(argv[1], "gen") == 0)
    {
        if (argc != 4)
        {
            Usage();
            return 2;
        }
        return Generate(argv[2], ParseSize(argv[3]) * 1024 * 1024);
    }

    if (strcmp(argv[1], "skiptest") == 0)
    {
        int     depth = 4;
        DWORD32 block = APSEQREAD::c_readBufSize;
        DWORD   skip = 100000;
        DWORD   prefix = 1000;
        for (int i = 3; i + 1 < argc; i += 2)
        {
            if (strcmp(argv[i], "--depth") == 0)        depth = atoi(argv[i + 1]);
            else if (strcmp(argv[i], "--block") == 0)   block = (DWORD32)ParseSize(argv[i + 1]);
            else if (strcmp(argv[i], "--skip") == 0)    skip = (DWORD)ParseSize(argv[i + 1]);
            else if (strcmp(argv[i], "--prefix") == 0)  prefix = (DWORD)ParseSize(argv[i + 1]);
            else
            {
                fprintf(stderr, "unknown argument %s\n", argv[i]);
                return 2;
            }
        }
        return SkipTest(argv[2], depth, block, skip, prefix);
    }

    if (strcmp(argv[1], "tailtest") == 0)
    {
        DWORD32 block = APSEQWRITE::c_writeBufSizeDefault;
        int     depth = APSEQWRITE::c_maxWritesDefault;
        DWORD64 bytes = 1000000;      // deliberately not a block multiple
        DWORD64 precreate = 0;
        for (int i = 3; i + 1 < argc; i += 2)
        {
            if (strcmp(argv[i], "--block") == 0)          block = (DWORD32)ParseSize(argv[i + 1]);
            else if (strcmp(argv[i], "--depth") == 0)     depth = atoi(argv[i + 1]);
            else if (strcmp(argv[i], "--bytes") == 0)     bytes = ParseSize(argv[i + 1]);
            else if (strcmp(argv[i], "--precreate") == 0) precreate = ParseSize(argv[i + 1]);
            else { fprintf(stderr, "unknown argument %s\n", argv[i]); return 2; }
        }
        return TailTest(argv[2], block, depth, bytes, precreate);
    }

    if (strcmp(argv[1], "rwbound") == 0)
    {
        DWORD32 block = APSEQWRITE::c_writeBufSizeDefault;
        for (int i = 3; i + 1 < argc; i += 2)
        {
            if (strcmp(argv[i], "--block") == 0) block = (DWORD32)ParseSize(argv[i + 1]);
            else { fprintf(stderr, "unknown argument %s\n", argv[i]); return 2; }
        }
        return RwBoundTest(argv[2], block);
    }

    if (strcmp(argv[1], "reflush") == 0)
    {
        DWORD32 block = APSEQWRITE::c_writeBufSizeDefault;
        DWORD   append = 4096;
        int     appends = 256;
        for (int i = 3; i + 1 < argc; i += 2)
        {
            if (strcmp(argv[i], "--block") == 0)        block = (DWORD32)ParseSize(argv[i + 1]);
            else if (strcmp(argv[i], "--append") == 0)  append = (DWORD)ParseSize(argv[i + 1]);
            else if (strcmp(argv[i], "--appends") == 0) appends = atoi(argv[i + 1]);
            else { fprintf(stderr, "unknown argument %s\n", argv[i]); return 2; }
        }
        return ReflushTest(argv[2], block, append, appends);
    }

    if (strcmp(argv[1], "accounting") == 0)
    {
        return AccountingTest(argv[2]);
    }

    if (strcmp(argv[1], "write") == 0)
    {
        WriteOptions o;
        o.path = argv[2];
        o.label = "";
        o.length = 0;
        o.depth = APSEQWRITE::c_maxWritesDefault;
        o.block = APSEQWRITE::c_writeBufSizeDefault;
        o.record = 4096;
        o.commit = false;
        o.fsync = false;
        o.header = false;

        for (int i = 3; i < argc; i++)
        {
            bool hasValue = (i + 1 < argc);
            if (strcmp(argv[i], "--header") == 0)
            {
                o.header = true;
            }
            else if (strcmp(argv[i], "--fsync") == 0)
            {
                o.fsync = true;
            }
            else if (!hasValue)
            {
                fprintf(stderr, "missing value for %s\n", argv[i]);
                return 2;
            }
            else if (strcmp(argv[i], "--length") == 0)
            {
                o.length = ParseSize(argv[++i]);
            }
            else if (strcmp(argv[i], "--depth") == 0)
            {
                o.depth = atoi(argv[++i]);
            }
            else if (strcmp(argv[i], "--block") == 0)
            {
                o.block = (DWORD32)ParseSize(argv[++i]);
            }
            else if (strcmp(argv[i], "--record") == 0)
            {
                o.record = (DWORD)ParseSize(argv[++i]);
            }
            else if (strcmp(argv[i], "--mode") == 0)
            {
                const char* m = argv[++i];
                if (strcmp(m, "copy") == 0)        o.commit = false;
                else if (strcmp(m, "commit") == 0) o.commit = true;
                else
                {
                    fprintf(stderr, "unknown write mode %s (want copy|commit)\n", m);
                    return 2;
                }
            }
            else if (strcmp(argv[i], "--label") == 0)
            {
                o.label = argv[++i];
            }
            else
            {
                fprintf(stderr, "unknown argument %s\n", argv[i]);
                return 2;
            }
        }

        // Unlike the reader, DoInit accepts maxWrites >= 1 (apdiskio.cpp:661),
        // so depth 1 -- a ring with no overlap at all -- IS a point on the
        // write curve, and the sweep covers it.
        if (o.depth < 1 || o.depth > APSEQWRITE::c_maxWrites)
        {
            fprintf(stderr, "depth must be in [1, %d]\n", APSEQWRITE::c_maxWrites);
            return 2;
        }
        if (o.length == 0)
        {
            fprintf(stderr, "--length is required for write\n");
            return 2;
        }
        if (o.record == 0 || (o.record % 8) != 0)
        {
            fprintf(stderr, "record must be non-zero and a multiple of 8\n");
            return 2;
        }
        return RunWrite(o);
    }

    if (strcmp(argv[1], "read") != 0)
    {
        Usage();
        return 2;
    }

    RunOptions o;
    o.path = argv[2];
    o.label = "";
    o.offset = 0;
    o.length = 0;
    o.depth = APSEQREAD::c_maxReadsDefault;
    o.block = APSEQREAD::c_readBufSize;
    o.record = 4096;
    o.header = false;

    for (int i = 3; i < argc; i++)
    {
        bool hasValue = (i + 1 < argc);
        if (strcmp(argv[i], "--header") == 0)
        {
            o.header = true;
        }
        else if (!hasValue)
        {
            fprintf(stderr, "missing value for %s\n", argv[i]);
            return 2;
        }
        else if (strcmp(argv[i], "--offset") == 0)
        {
            o.offset = ParseSize(argv[++i]);
        }
        else if (strcmp(argv[i], "--length") == 0)
        {
            o.length = ParseSize(argv[++i]);
        }
        else if (strcmp(argv[i], "--depth") == 0)
        {
            o.depth = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--block") == 0)
        {
            o.block = (DWORD32)ParseSize(argv[++i]);
        }
        else if (strcmp(argv[i], "--record") == 0)
        {
            o.record = (DWORD)ParseSize(argv[++i]);
        }
        else if (strcmp(argv[i], "--label") == 0)
        {
            o.label = argv[++i];
        }
        else
        {
            fprintf(stderr, "unknown argument %s\n", argv[i]);
            return 2;
        }
    }

    // DoInit rejects maxReads <= 1 (apdiskio.cpp:90), so depth 1 is not a point
    // on the curve -- the shallowest APSEQREAD that exists is depth 2.
    if (o.depth < 2 || o.depth > APSEQREAD::c_maxReads)
    {
        fprintf(stderr, "depth must be in [2, %d]\n", APSEQREAD::c_maxReads);
        return 2;
    }
    if (o.record == 0 || o.record > o.block)
    {
        fprintf(stderr, "record must be in (0, block]\n");
        return 2;
    }

    return Run(o);
}
