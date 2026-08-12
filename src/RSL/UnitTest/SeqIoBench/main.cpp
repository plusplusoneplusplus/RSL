//
// seqiobench -- measures the sequential I/O classes in
// src/common/src/apdiskio.cpp, so the Rust port has a baseline to be compared
// against. Today that is APSEQREAD, via the `read` subcommand; APSEQWRITE
// belongs here too, under a `write` subcommand, and the `gen` fixture and the
// result format are already shared so adding it does not disturb `read`.
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

static void Usage()
{
    fprintf(stderr,
            "usage:\n"
            "  seqiobench gen  <path> <sizeMiB>\n"
            "  seqiobench read <path> [--offset B] [--length B] [--depth N]\n"
            "                         [--block B] [--record B] [--label S] [--header]\n"
            "  seqiobench skiptest <scratchpath> [--depth N] [--block B]\n"
            "                         [--skip B] [--prefix B]\n");
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
