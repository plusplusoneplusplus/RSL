#pragma once

#include "basic_types.h"

#include <string>
#include <vector>

namespace RSLib
{
    class RSLCheckpointStreamWriter;
}

namespace RSLibImpl
{
    class CheckpointHeader;
    class Message;

    enum InteropStorageOutcome
    {
        InteropStorageAccept,
        InteropStorageStop,
        InteropStorageReject
    };

    struct InteropLogRecord
    {
        UInt64 offset;
        UInt16 msgId;
        UInt64 decree;
        UInt32 unMarshalLen;
        UInt32 paddedLen;
        UInt64 checksum;
    };

    struct InteropLogVerdict
    {
        InteropStorageOutcome outcome;
        UInt64 fileSize;
        UInt64 stopOffset;
        std::vector<InteropLogRecord> records;
        std::string detail;
    };

    struct InteropCheckpointVerdict
    {
        InteropStorageOutcome outcome;
        UInt16 version;
        UInt32 headerLen;
        UInt64 fileSize;
        UInt64 userDataSize;
        UInt32 checksumBlockSize;
        bool stateSaved;
        std::string detail;
    };

    class RSLInteropTestFacade
    {
    public:
        static DWORD32 WriteLog(
            const char *directory,
            UInt64 fileDecree,
            Message *const *messages,
            size_t messageCount);

        static bool ScanLog(const char *fileName, InteropLogVerdict *verdict);

        static DWORD32 WriteCheckpoint(
            const char *fileName,
            CheckpointHeader *header,
            const void *state,
            UInt64 stateLength);

        static bool VerifyCheckpoint(
            const char *fileName,
            InteropCheckpointVerdict *verdict);
    };
}
