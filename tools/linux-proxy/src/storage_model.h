// storage_model.h -- the Linux storage-format API used by the rsl-linux-proxy driver.
//
// The class methods (ConfigurationInfo / CheckpointHeader marshal & unmarshal)
// are extracted VERBATIM from legislator.cpp into storage_model.cpp. The helper
// functions declared below in namespace rsl_storage are ports of the
// format-bearing I/O paths in legislator.cpp / rsl.cpp, with the Windows
// unbuffered/overlapped I/O mechanism replaced by plain in-memory byte buffers.
// The *mechanism* changes; the *bytes produced/consumed* do not. Every helper
// cites the legislator.cpp / rsl.cpp lines it mirrors.
#pragma once

#include "storage_compat.h"   // ConfigurationInfo, CheckpointHeader, constants
#include "message.h"          // Message, Vote, RSLProtocolVersion

#include <string>
#include <vector>

namespace rsl_storage
{
    using namespace RSLib;
    using namespace RSLibImpl;

    // Recovery / verification outcome, mirroring the accept / stop-at-offset /
    // reject decisions Legislator::ReadNextMessage and the checkpoint reader
    // make. This is the machine-readable classification the MANIFEST records.
    enum Outcome { Accept, Stop, Reject };
    const char* OutcomeName(Outcome o);

    // -------------------------------------------------------------------------
    // Log records
    // -------------------------------------------------------------------------
    // One log record as it lands on disk: the marshaled message (Rabin-64
    // checksum patched into its header) zero-padded up to RoundUpToPage.
    // Mirrors LogFile::AddMessage's RoundUpToPage(msg->GetMarshalLen()) sizing
    // (legislator.cpp:714) and Vote::GetBuffers' per-buffer page rounding
    // (message.cpp:1052). NOTE (deliberate deviation): the Windows engine leaves
    // whatever the marshal buffer held in the pad tail (VirtualAlloc-zeroed for
    // votes, malloc-garbage elsewhere); we ALWAYS zero the pad so the corpus is
    // deterministic and so the Rust writer -- which also zero-pads -- reproduces
    // it. Readers tolerate non-zero pads (see the garbage-pad sample).
    std::vector<char> EncodeLogRecord(Message& msg);

    struct ScannedRecord
    {
        UInt64 offset;    // byte offset of the record within the log
        UInt16 msgId;     // Vote / Prepare / ReconfigurationDecision
        UInt64 decree;
        UInt32 unMarshalLen; // declared message length (checksum-covered region)
        UInt32 paddedLen;    // RoundUpToPage(unMarshalLen) -- on-disk footprint
        UInt64 checksum;     // Rabin-64 from the message header
    };

    struct LogScanResult
    {
        Outcome outcome;
        UInt64 stopOffset;                  // bytes consumed before stop/reject
        std::vector<ScannedRecord> records; // recovered records (before stopOffset)
        std::string detail;
    };

    // Port of the Legislator::ReadNextMessage recovery loop (legislator.cpp:3851
    // + the driving loop at 5993) over an in-memory log image, restore=true.
    // Accept  -> every record valid, consumed exactly to EOF.
    // Stop    -> valid records then a tolerated tail (all-zero region, torn last
    //            message, or trailing checksum-mismatch record over zeros);
    //            recovery keeps records before stopOffset, discards the tail.
    // Reject  -> hard corruption (non-zero unmarshalable page, unknown msg id,
    //            or checksum mismatch with non-zero data following).
    LogScanResult ScanLog(const char* buf, size_t len);

    // -------------------------------------------------------------------------
    // Checkpoint (.codex) files
    // -------------------------------------------------------------------------
    // Build a full checkpoint image: the page-rounded CheckpointHeader followed
    // by the user state. For version >= 4 the state is split into
    // m_checksumBlockSize (4 MiB) blocks, each ending in an 8-byte Rabin-64 of
    // its data (RSLCheckpointStreamWriter::Write/Close, rsl.cpp:501/577); for
    // version 3 the state is written raw with no per-block checksum. Fills
    // header.m_size with the resulting file size (== BytesIssued, rsl.cpp:609).
    std::vector<char> BuildCheckpointFile(CheckpointHeader& header,
                                          const char* userState, size_t stateLen);

    struct CheckpointVerifyResult
    {
        Outcome outcome;         // Accept or Reject
        UInt16 version;
        UInt32 headerLen;        // RoundUpToPage header footprint
        UInt64 fileSize;
        UInt64 userDataSize;     // recovered user bytes (blocks minus checksums)
        UInt32 checksumBlockSize;
        bool stateSaved;
        std::string detail;
    };

    // Port of RSLCheckpointStreamReader::Init + CheckpointHeader::UnMarshal +
    // ReadNextDataBlock (rsl.cpp:192/271, legislator.cpp:948) over an in-memory
    // checkpoint image. Validates fileSize == header.m_size and every block
    // checksum (version >= 4); version 3 has no user-data integrity check.
    CheckpointVerifyResult VerifyCheckpointFile(const char* buf, size_t len);

    // -------------------------------------------------------------------------
    // defunct.txt
    // -------------------------------------------------------------------------
    // The highest defunct configuration number, as a 4-byte little-endian u32 --
    // exactly the bytes Legislator::UpdateDefunctInfo writes (legislator.cpp:7357
    // writes 4 bytes) and ReadDefunctFile reads (legislator.cpp:7211 reads 4).
    // NOTE (deviation): the Windows unbuffered APSEQWRITE may pad the file to a
    // 512-byte page; only the leading 4 bytes are meaningful and the reader
    // consumes just those, so the corpus emits the minimal 4-byte form.
    std::vector<char> EncodeDefunct(UInt32 highestDefunctConfigurationNumber);
    bool DecodeDefunct(const char* buf, size_t len, UInt32* out);
}
