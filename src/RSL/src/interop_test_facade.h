#pragma once

#include "basic_types.h"
#include "message.h"

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
    class StatusResponse;

    enum InteropStorageOutcome
    {
        InteropStorageAccept,
        InteropStorageStop,
        InteropStorageReject
    };

    struct InteropLogRecord
    {
        UInt64 offset;
        UInt16 version;
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

        static int RunLearnServer(
            UInt16 port,
            const char *directory,
            int connections,
            RSLProtocolVersion version);

        static bool QueryLearnStatus(
            UInt32 ip,
            UInt16 port,
            RSLProtocolVersion version,
            StatusResponse *response);

        static bool FetchLearnVotes(
            UInt32 ip,
            UInt16 port,
            RSLProtocolVersion version,
            UInt64 decree,
            std::vector<InteropLogRecord> *records);

        static bool CopyLearnCheckpoint(
            UInt32 ip,
            UInt16 port,
            RSLProtocolVersion version,
            UInt64 decree,
            UInt64 size,
            const BallotNumber& localMaxBallot,
            const char *outputFile,
            BallotNumber *sourceMaxBallot,
            BallotNumber *writtenMaxBallot);
    };
}
