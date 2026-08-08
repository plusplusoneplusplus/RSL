// Supplemental Linux storage format/recovery model.
//
// Selected format class methods are copied and line-cited for drift auditing.
//
// The namespace rsl_storage helpers underneath are ports (NOT verbatim copies)
// of the format-bearing I/O paths -- LogFile write/AddMessage,
// Legislator::ReadNextMessage, RSLCheckpointStreamWriter/Reader,
// CheckpointHeader::Marshal(const char*), Read/UpdateDefunctFile. The Windows
// unbuffered/overlapped/WriteFileGather mechanism is replaced by in-memory
// buffers. Outcomes belong to this model, not production Windows recovery.
#include "storage_model.h"

#include "msg_engine_compat.h"   // RoundUpToPage, MemberSet, s_PageSize
#include "utils.h"               // Utils::CalculateChecksum
#include "fingerprint.h"         // FingerPrint64
#include "DynamicBuffer.h"       // DynamicBuffer<>

#include <cstring>

using namespace RSLib;
using namespace RSLibImpl;

// ===========================================================================
// VERBATIM extracts from RSL/src/legislator.cpp
// ===========================================================================

// --- ConfigurationInfo (legislator.cpp:784-818) ----------------------------
void
ConfigurationInfo::Marshal(MarshalData *marshal, RSLProtocolVersion version)
{
    marshal->WriteUInt32(m_configurationNumber);
    marshal->WriteUInt64(m_initialDecree);
    m_memberSet->Marshal(marshal, version);
}

bool
ConfigurationInfo::UnMarshal(MarshalData *marshal, RSLProtocolVersion version)
{
    if (!marshal->ReadUInt32(&m_configurationNumber))
    {
        return false;
    }

    if (!marshal->ReadUInt64(&m_initialDecree))
    {
        return false;
    }

    m_memberSet = new MemberSet();
    if (!m_memberSet->UnMarshal(marshal, version))
    {
        return false;
    }

    return true;
}

UInt32
ConfigurationInfo::GetMarshalLen(RSLProtocolVersion version)
{
    return 4 + 8 + m_memberSet->GetMarshalLen(version);
}

// --- CheckpointHeader::GetMarshalLen (legislator.cpp:820-844) ---------------
UInt32
CheckpointHeader::GetMarshalLen()
{
    UInt32 len = RoundUpToPage(m_nextVote->GetMarshalLen());

    if (m_version >= RSLProtocolVersion_3)
    {
        len +=
            2 + // version
            4 + // length
            8 + // old checksum
            MemberId::GetBaseSize(m_version) + // memberId
            8 + // last execute decree
            BallotNumber::GetBaseSize(m_version) + // max ballot
            m_stateConfiguration->GetMarshalLen(m_version); // replica set
    }
    if (m_version >= RSLProtocolVersion_4)
    {
        len +=
            1 + // stateSaved
            8 + // checkpoint size
            4;  // checksum block size
    }
    return RoundUpToPage(len);
}

// --- CheckpointHeader::Marshal(MarshalData*) (legislator.cpp:893-922) --------
void
CheckpointHeader::Marshal(MarshalData *marshal)
{
    UInt32 marshalLen = GetMarshalLen();
    marshal->EnsureBuffer(marshalLen);
    if (m_version >= RSLProtocolVersion_3)
    {
        marshal->WriteUInt16((UInt16) m_version);
        marshal->WriteUInt32(marshalLen);
        // compute the checksum
        marshal->WriteUInt64(m_checksum);
        m_memberId.Marshal(marshal, m_version);
        marshal->WriteUInt64(m_lastExecutedDecree);
        m_maxBallot.Marshal(marshal, m_version);
        m_stateConfiguration->Marshal(marshal, m_version);
    }
    if (m_version >= RSLProtocolVersion_4)
    {
        marshal->WriteBool(m_stateSaved);
        marshal->WriteUInt64(m_size);
        marshal->WriteUInt32(m_checksumBlockSize);
    }
    DynamicBuffer<SIZED_BUFFER, 1024> buffers(m_nextVote->GetNumBuffers());
    m_nextVote->GetBuffers(buffers, buffers.Size());
    for (size_t i = 0; i < (size_t) m_nextVote->GetNumBuffers(); i++)
    {
        marshal->WriteData(buffers[i].m_len, buffers[i].m_buf);
    }
    marshal->SetMarshaledLength(marshalLen);
}

// --- CheckpointHeader::UnMarshal(MarshalData*) (legislator.cpp:948-1030) -----
bool
CheckpointHeader::UnMarshal(MarshalData *marshal)
{
    UInt16 version;
    if (!marshal->ReadUInt16(&version))
    {
        return false;
    }

    if (!Message::IsVersionValid(version))
    {
        return false;
    }

    m_version = (RSLProtocolVersion) version;
    // if the version is greater than 1, then is the new format, otherwise only the vote has been
    // marshaled

    if (m_version >= RSLProtocolVersion_3)
    {
        m_stateConfiguration = new ConfigurationInfo();
        // Jay Lorch doesn't understand how to make checksumming work.  We
        // should verify the checksum here.
        if (!marshal->ReadUInt32(&m_unMarshalLen) ||
            !marshal->ReadUInt64(&m_checksum) ||
            !m_memberId.UnMarshal(marshal, m_version) ||
            !marshal->ReadUInt64(&m_lastExecutedDecree) ||
            !m_maxBallot.UnMarshal(marshal, m_version) ||
            !m_stateConfiguration->UnMarshal(marshal, m_version))
        {
            return false;
        }
        if (m_version >= RSLProtocolVersion_4)
        {
            if (!marshal->ReadBool(&m_stateSaved) ||
                !marshal->ReadUInt64(&m_size) ||
                !marshal->ReadUInt32(&m_checksumBlockSize))
            {
                return false;
            }
        }
    }
    else
    {
        // set the read pointer back to the beginning of the message
        marshal->RewindReadPointer(2);
        m_stateConfiguration = NULL;
        m_stateSaved = true;
    }

    // TODO: assert that vote->decree == checkpointdecree+1
    UInt32 startOffset = marshal->GetReadPointer();
    m_nextVote = new Vote();
    if (!m_nextVote->UnMarshal(marshal))
    {
        return false;
    }
    LogAssert(startOffset + m_nextVote->m_unMarshalLen <= marshal->GetMarshaledLength());
    bool verified = m_nextVote->VerifyChecksum(
        (char *) marshal->GetMarshaled() + startOffset,
        m_nextVote->m_unMarshalLen);

    if (!verified)
    {
        return false;
    }

    if (m_version >= RSLProtocolVersion_3)
    {
        if (m_maxBallot < m_nextVote->m_ballot)
        {
            return false;
        }
    }
    else
    {
        m_memberId = m_nextVote->m_memberId;

        m_maxBallot = m_nextVote->m_ballot;
        m_lastExecutedDecree = m_nextVote->m_decree-1;
    }
    return true;
}

// ===========================================================================
// Linux ports of the format-bearing I/O paths (namespace rsl_storage)
// ===========================================================================
namespace rsl_storage
{

const char* OutcomeName(Outcome o)
{
    switch (o)
    {
    case Accept: return "accept";
    case Stop:   return "stop-at-offset";
    case Reject: return "reject";
    }
    return "?";
}

namespace {

// Marshal a message and patch the Rabin-64 checksum into its header, matching
// tools/linux-proxy/src/main.cpp's MarshalWithChecksum (which mirrors
// Message/Vote::CalculateChecksum). Returns the exact marshaled bytes (no pad).
std::vector<char> MarshalMessage(Message& msg)
{
    UInt32 len = msg.GetMarshalLen();
    std::vector<char> buf(len);

    FixedMarshalMemoryManager manager(buf.data(), len);
    MarshalData marshal(&manager);
    msg.Marshal(&marshal);

    UInt32 mlen = marshal.GetMarshaledLength();
    buf.resize(mlen);

    UInt32 dataOffset = s_ChecksumOffset + sizeof(UInt64);
    UInt64 checksum = Utils::CalculateChecksum(buf.data() + dataOffset, mlen - dataOffset);

    FixedMarshalMemoryManager cmanager(buf.data() + s_ChecksumOffset, mlen - s_ChecksumOffset);
    MarshalData cmarshal(&cmanager);
    cmarshal.WriteUInt64(checksum);

    return buf;
}

bool IsAllZero(const char* p, size_t n)
{
    for (size_t i = 0; i < n; ++i)
    {
        if (p[i] != 0) { return false; }
    }
    return true;
}

// Read a little-endian u64 (the on-disk form of both message checksum fields
// and checkpoint block checksums on the x86 engine).
UInt64 ReadLE64(const char* p)
{
    UInt64 v = 0;
    for (int i = 7; i >= 0; --i)
    {
        v = (v << 8) | (unsigned char) p[i];
    }
    return v;
}

void AppendLE64(std::vector<char>& out, UInt64 v)
{
    for (int i = 0; i < 8; ++i)
    {
        out.push_back((char)(v & 0xff));
        v >>= 8;
    }
}

// Linux port of CheckpointHeader::Marshal(const char*) (legislator.cpp:846):
// marshal the header into a page-rounded buffer. DEVIATION: the buffer is
// zero-initialized before marshaling, so the pad between the header body and
// its RoundUpToPage boundary is deterministic zero. The Windows path marshals
// into a fresh malloc'd MarshalData and leaves that tail uninitialized; the
// bytes are never read back (UnMarshal stops after the vote), and the Rust
// writer zeroes it too, so this is a determinism fix, not a format change.
std::vector<char> MarshalCheckpointHeader(CheckpointHeader& header)
{
    UInt32 marshalLen = header.GetMarshalLen(); // page-rounded
    std::vector<char> buf(marshalLen, 0);

    FixedMarshalMemoryManager manager(buf.data(), marshalLen);
    MarshalData marshal(&manager);
    header.Marshal(&marshal);
    LogAssert(marshal.GetMarshaledLength() == marshalLen);
    return buf;
}

} // namespace

// ---------------------------------------------------------------------------
// Log records
// ---------------------------------------------------------------------------
std::vector<char> EncodeLogRecord(Message& msg)
{
    std::vector<char> buf = MarshalMessage(msg);
    // LogFile::AddMessage sizes each record at RoundUpToPage(GetMarshalLen())
    // (legislator.cpp:714); Vote::GetBuffers page-rounds each buffer
    // (message.cpp:1052). For the single-buffer messages the corpus logs, that
    // is RoundUpToPage of the whole marshaled length. Zero-pad the tail.
    UInt32 padded = RoundUpToPage((UInt32) buf.size());
    buf.resize(padded, 0);
    return buf;
}

LogScanResult ScanLog(const char* buf, size_t len)
{
    LogScanResult r;
    r.outcome = Accept;
    r.stopOffset = len;

    size_t cur = 0;
    while (cur < len)
    {
        size_t remaining = len - cur;

        // Legislator::ReadNextMessage reads a s_PageSize header page first
        // (legislator.cpp:3865). A trailing region smaller than a page cannot
        // be a record header; the engine's short read fails hard -> reject.
        if (remaining < s_PageSize)
        {
            r.outcome = Reject;
            r.stopOffset = cur;
            r.detail = "partial header page (< s_PageSize) at tail";
            return r;
        }

        const char* page = buf + cur;
        Message hdr;
        if (!hdr.UnMarshalBuf((char*) page, s_PageSize))
        {
            // legislator.cpp:3879 -- header unmarshal failed. If this page and
            // everything after it is zero, this is the clean zero-EOF that
            // VerifyZeroStream accepts (return true / msg NULL -> stop).
            if (IsAllZero(page, s_PageSize) && IsAllZero(buf + cur, len - cur))
            {
                r.outcome = Stop;
                r.stopOffset = cur;
                r.detail = "zero region (clean EOF)";
                return r;
            }
            r.outcome = Reject;
            r.stopOffset = cur;
            r.detail = "unmarshal failed on non-zero page (corrupt stream)";
            return r;
        }

        // legislator.cpp:3897 -- only these three ids are ever logged.
        if (hdr.m_msgId != Message_Vote &&
            hdr.m_msgId != Message_Prepare &&
            hdr.m_msgId != Message_ReconfigurationDecision)
        {
            r.outcome = Reject;
            r.stopOffset = cur;
            r.detail = "unknown message id in log";
            return r;
        }

        UInt32 paddedLen = RoundUpToPage(hdr.m_unMarshalLen);
        if (cur + paddedLen > len)
        {
            // legislator.cpp:3930 -- body read hit EOF: with restore=true this
            // is the tolerated "last incomplete message" -> stop.
            r.outcome = Stop;
            r.stopOffset = cur;
            r.detail = "incomplete trailing message (torn tail)";
            return r;
        }

        if (!hdr.VerifyChecksum((char*)(buf + cur), hdr.m_unMarshalLen))
        {
            // legislator.cpp:3952 -- checksum mismatch. If everything from the
            // end of this (page-rounded) record to EOF is zero, VerifyZeroStream
            // succeeds and the record is discarded as the last incomplete one
            // -> stop; otherwise the stream is corrupt -> reject.
            size_t after = cur + paddedLen;
            if (IsAllZero(buf + after, len - after))
            {
                r.outcome = Stop;
                r.stopOffset = cur;
                r.detail = "trailing checksum mismatch over zero tail (discarded)";
                return r;
            }
            r.outcome = Reject;
            r.stopOffset = cur;
            r.detail = "checksum mismatch with non-zero data following (corrupt)";
            return r;
        }

        ScannedRecord rec;
        rec.offset = cur;
        rec.msgId = hdr.m_msgId;
        rec.decree = hdr.m_decree;
        rec.unMarshalLen = hdr.m_unMarshalLen;
        rec.paddedLen = paddedLen;
        rec.checksum = hdr.m_checksum;
        r.records.push_back(rec);

        cur += paddedLen;
    }

    // Consumed exactly to EOF with every record valid.
    r.outcome = Accept;
    r.stopOffset = len;
    r.detail = "all records valid to EOF";
    return r;
}

// ---------------------------------------------------------------------------
// Checkpoint files
// ---------------------------------------------------------------------------
std::vector<char> BuildCheckpointFile(CheckpointHeader& header,
                                      const char* userState, size_t stateLen)
{
    UInt32 headerLen = header.GetMarshalLen(); // page-rounded, fixed

    std::vector<char> blocks;
    if (header.m_version >= RSLProtocolVersion_4 && header.m_checksumBlockSize > 0)
    {
        // RSLCheckpointStreamWriter block layout (rsl.cpp:501/577): each block
        // holds up to (blockSize - CHECKSUM_SIZE) data bytes followed by an
        // 8-byte Rabin-64 fingerprint of that data. Empty state -> no blocks
        // (Close with m_dataWrittenOffset==0 writes nothing, rsl.cpp:589).
        UInt32 blockSize = header.m_checksumBlockSize;
        UInt32 dataOnly = blockSize - CHECKSUM_SIZE;
        size_t off = 0;
        while (off < stateLen)
        {
            size_t chunk = stateLen - off;
            if (chunk > dataOnly) { chunk = dataOnly; }
            blocks.insert(blocks.end(), userState + off, userState + off + chunk);
            UInt64 cs = FingerPrint64::GetInstance()->GetFingerPrint(userState + off, chunk);
            AppendLE64(blocks, cs);
            off += chunk;
        }
    }
    else
    {
        // Version 3 (or block size 0): raw user state, no per-block checksum
        // (rsl.cpp:505 backwards-compatible path).
        blocks.insert(blocks.end(), userState, userState + stateLen);
    }

    // header.SetBytesIssued(writer) sets m_size to the whole file size
    // (rsl.cpp:1076 / BytesIssued rsl.cpp:609): reserved header + blocks.
    header.m_size = (unsigned long long) headerLen + blocks.size();

    std::vector<char> file = MarshalCheckpointHeader(header);
    LogAssert(file.size() == headerLen);
    file.insert(file.end(), blocks.begin(), blocks.end());
    return file;
}

CheckpointVerifyResult VerifyCheckpointFile(const char* buf, size_t len)
{
    CheckpointVerifyResult r;
    r.outcome = Reject;
    r.version = 0;
    r.headerLen = 0;
    r.fileSize = len;
    r.userDataSize = 0;
    r.checksumBlockSize = 0;
    r.stateSaved = false;

    // CheckpointHeader::UnMarshal(StreamReader) (legislator.cpp:1032): read the
    // first page, pull version + marshalLen, then read RoundUpToPage(marshalLen)
    // and unmarshal the header out of it.
    if (len < s_PageSize)
    {
        r.detail = "file shorter than one page";
        return r;
    }

    MarshalData hdrPeek((void*)buf, s_PageSize, false /* don't copy */);
    UInt16 version;
    UInt32 marshalLen;
    hdrPeek.ReadUInt16(&version);
    hdrPeek.ReadUInt32(&marshalLen);
    if (!Message::IsVersionValid(version))
    {
        r.detail = "invalid checkpoint version";
        return r;
    }

    UInt32 writeSize = RoundUpToPage(marshalLen);
    if (len < writeSize)
    {
        r.detail = "file shorter than header length (truncated)";
        return r;
    }

    MarshalData marshal((void*)buf, writeSize, false /* don't copy */);
    marshal.SetMarshaledLength(marshalLen);
    CheckpointHeader header;
    if (!header.UnMarshal(&marshal))
    {
        r.detail = "checkpoint header unmarshal failed";
        return r;
    }

    r.version = (UInt16) header.m_version;
    r.headerLen = header.GetMarshalLen();
    r.checksumBlockSize = header.m_checksumBlockSize;
    r.stateSaved = header.m_stateSaved;

    if (header.m_version >= RSLProtocolVersion_4 && header.m_checksumBlockSize > 0)
    {
        // RSLCheckpointStreamReader::Init (rsl.cpp:211): fileSize must equal the
        // size recorded in the header.
        if ((unsigned long long) len != header.m_size)
        {
            r.detail = "file size differs from header m_size";
            return r;
        }

        UInt32 blockSize = header.m_checksumBlockSize;
        size_t off = r.headerLen;
        while (off < len)
        {
            size_t blk = len - off;
            if (blk > blockSize) { blk = blockSize; }
            // ReadNextDataBlock (rsl.cpp:306): a block must carry at least the
            // checksum token.
            if (blk <= (size_t) CHECKSUM_SIZE)
            {
                r.detail = "trailing block smaller than a checksum token";
                return r;
            }
            size_t dataLen = blk - CHECKSUM_SIZE;
            UInt64 calc = FingerPrint64::GetInstance()->GetFingerPrint(buf + off, dataLen);
            UInt64 stored = ReadLE64(buf + off + dataLen);
            if (calc != stored)
            {
                r.detail = "block checksum mismatch";
                return r;
            }
            r.userDataSize += dataLen;
            off += blk;
        }
    }
    else
    {
        // Version 3: no per-block checksum; user data is everything past the
        // header (rsl.cpp:437 backwards-compatible Size()).
        r.userDataSize = (unsigned long long) len - r.headerLen;
    }

    r.outcome = Accept;
    r.detail = "checkpoint valid";
    return r;
}

// ---------------------------------------------------------------------------
// defunct.txt
// ---------------------------------------------------------------------------
std::vector<char> EncodeDefunct(UInt32 highestDefunctConfigurationNumber)
{
    std::vector<char> buf;
    UInt32 v = highestDefunctConfigurationNumber;
    for (int i = 0; i < 4; ++i)
    {
        buf.push_back((char)(v & 0xff));
        v >>= 8;
    }
    return buf;
}

bool DecodeDefunct(const char* buf, size_t len, UInt32* out)
{
    if (len < 4) { return false; }
    UInt32 v = 0;
    for (int i = 3; i >= 0; --i)
    {
        v = (v << 8) | (unsigned char) buf[i];
    }
    *out = v;
    return true;
}

} // namespace rsl_storage
