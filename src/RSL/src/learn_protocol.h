#pragma once

#include "message.h"

#include <string>
#include <vector>

namespace RSLibImpl
{
    struct LearnLogFile
    {
        std::string fileName;
        UInt64 minDecree;
        std::vector<UInt64> decreeOffsets;
    };

    struct LearnServerState
    {
        LearnServerState();

        bool relinquishing;
        RSLProtocolVersion version;
        MemberId memberId;
        UInt64 decree;
        UInt32 configurationNumber;
        BallotNumber ballot;
        UInt64 lastReceivedAgo;
        UInt64 checkpointedDecree;
        UInt64 checkpointSize;
        BallotNumber maxBallot;
        UInt32 state;
        std::string checkpointFile;
        std::vector<LearnLogFile> logs;
    };

    struct LearnCheckpointCopyResult
    {
        LearnCheckpointCopyResult();

        enum Outcome
        {
            Success,
            InvalidArgument,
            CreateFailed,
            ConnectFailed,
            HeaderRejected,
            HeaderWriteFailed,
            ReadFailed,
            BodyWriteFailed,
            FlushFailed,
            VerificationFailed
        };

        Outcome outcome;
        UInt64 bytesWritten;
        BallotNumber sourceMaxBallot;
        BallotNumber writtenMaxBallot;
        std::string detail;
    };

    typedef BallotNumber (*LearnMaxBallotCallback)(void* context);

    struct LearnFileMetrics
    {
        LearnFileMetrics();

        UInt64 fileReads;
        UInt64 bytesRead;
        UInt64 readMicroseconds;
        UInt64 maxReadMicroseconds;
    };

    void BuildLearnStatusResponse(
        const LearnServerState& state,
        const Message& request,
        StatusResponse* response);

    DWORD32 SendLearnFile(
        const char* fileName,
        UInt64 offset,
        Int64 length,
        StreamSocket* socket,
        LearnFileMetrics* metrics);

    DWORD32 ServeLearnRequest(
        const Message& request,
        StreamSocket* socket,
        const LearnServerState& state,
        LearnFileMetrics* metrics);

    bool CopyLearnCheckpointFile(
        UInt32 ip,
        UInt16 port,
        RSLProtocolVersion version,
        const MemberId& memberId,
        UInt64 checkpointedDecree,
        UInt64 size,
        LearnMaxBallotCallback maxBallotCallback,
        void* maxBallotContext,
        DWORD receiveTimeout,
        DWORD sendTimeout,
        const char* outputFile,
        LearnCheckpointCopyResult* result);
}
