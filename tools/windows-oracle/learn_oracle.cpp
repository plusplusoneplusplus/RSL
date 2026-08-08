#include "learn_oracle.h"

#include "interop_test_facade.h"

#include <winsock2.h>

#include <cstdio>
#include <cstring>
#include <vector>

using namespace RSLibImpl;

namespace rsl_oracle
{
namespace
{
    bool ValidVersion(int version)
    {
        return Message::IsVersionValid(static_cast<UInt16>(version));
    }
}

int RunLearnServer(
    int port,
    const char *directory,
    int connections,
    int version)
{
    if (port < 0 || port > 65535 || connections <= 0 || !ValidVersion(version))
    {
        fprintf(stderr, "invalid learn server arguments\n");
        return 2;
    }
    int error = RSLInteropTestFacade::RunLearnServer(
        static_cast<UInt16>(port),
        directory,
        connections,
        static_cast<RSLProtocolVersion>(version));
    if (error != NO_ERROR)
    {
        fprintf(stderr, "production learn server failed: %d\n", error);
        return 1;
    }
    return 0;
}

int RunLearnClient(
    const char *host,
    int port,
    const char *mode,
    int version,
    unsigned long long decree,
    unsigned long long size,
    const char *outputFile,
    unsigned int maxBallot)
{
    if (port <= 0 || port > 65535 || !ValidVersion(version))
    {
        fprintf(stderr, "invalid learn client arguments\n");
        return 2;
    }
    UInt32 ip = inet_addr(host);
    if (ip == INADDR_NONE)
    {
        fprintf(stderr, "learn client requires an IPv4 address\n");
        return 2;
    }
    RSLProtocolVersion protocolVersion = static_cast<RSLProtocolVersion>(version);

    if (strcmp(mode, "status") == 0)
    {
        StatusResponse response;
        if (!RSLInteropTestFacade::QueryLearnStatus(
                ip,
                static_cast<UInt16>(port),
                protocolVersion,
                &response))
        {
            printf("ERROR closed\n");
            return 1;
        }
        printf(
            "STATUS version=%u decree=%I64u minDecree=%I64u "
            "checkpointDecree=%I64u checkpointSize=%I64u maxBallot=%u\n",
            static_cast<unsigned int>(response.m_version),
            response.m_decree,
            response.m_minDecreeInLog,
            response.m_checkpointedDecree,
            response.m_checkpointSize,
            response.m_maxBallot.m_ballotId);
        return 0;
    }

    if (strcmp(mode, "votes") == 0)
    {
        std::vector<InteropLogRecord> records;
        if (!RSLInteropTestFacade::FetchLearnVotes(
                ip,
                static_cast<UInt16>(port),
                protocolVersion,
                decree,
                &records))
        {
            printf("ERROR invalid vote stream\n");
            return 1;
        }
        for (size_t i = 0; i < records.size(); ++i)
        {
            printf(
                "VOTE version=%u msgId=%u decree=%I64u len=%u checksum=%016I64x\n",
                records[i].version,
                records[i].msgId,
                records[i].decree,
                records[i].unMarshalLen,
                records[i].checksum);
        }
        printf("VOTES %Iu\n", records.size());
        return records.empty() ? 3 : 0;
    }

    if (strcmp(mode, "checkpoint") == 0)
    {
        if (outputFile == NULL || outputFile[0] == '\0' || size == 0)
        {
            fprintf(stderr, "checkpoint mode needs --size and --out\n");
            return 2;
        }
        BallotNumber sourceMaxBallot;
        BallotNumber writtenMaxBallot;
        bool success = RSLInteropTestFacade::CopyLearnCheckpoint(
            ip,
            static_cast<UInt16>(port),
            protocolVersion,
            decree,
            size,
            BallotNumber(maxBallot, MemberId("999")),
            outputFile,
            &sourceMaxBallot,
            &writtenMaxBallot);
        printf(
            "CHECKPOINT outcome=%s size=%I64u sourceMaxBallot=%u "
            "writtenMaxBallot=%u\n",
            success ? "accept" : "reject",
            size,
            sourceMaxBallot.m_ballotId,
            writtenMaxBallot.m_ballotId);
        return success ? 0 : 1;
    }

    fprintf(stderr, "invalid learn client mode\n");
    return 2;
}
}
