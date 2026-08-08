#include "learn_protocol.h"

#include "apdiskio.h"
#include "legislator.h"
#include "rsl.h"

#include <memory>
#include <new>

using namespace RSLib;

namespace RSLibImpl
{
namespace
{
    bool VerifyCheckpointFile(const char* fileName)
    {
        CheckpointHeader header;
        if (!header.UnMarshal(fileName))
        {
            return false;
        }
        RSLCheckpointStreamReader reader;
        return reader.Init(fileName, &header) == NO_ERROR;
    }
}

LearnServerState::LearnServerState() :
    relinquishing(false),
    version(RSLProtocolVersion_1),
    decree(0),
    configurationNumber(0),
    lastReceivedAgo(0),
    checkpointedDecree(0),
    checkpointSize(0),
    state(0)
{
}

LearnCheckpointCopyResult::LearnCheckpointCopyResult() :
    outcome(InvalidArgument),
    bytesWritten(0)
{
}

LearnFileMetrics::LearnFileMetrics() :
    fileReads(0),
    bytesRead(0),
    readMicroseconds(0),
    maxReadMicroseconds(0)
{
}

void BuildLearnStatusResponse(
    const LearnServerState& state,
    const Message& request,
    StatusResponse* response)
{
    response->~StatusResponse();
    new (response) StatusResponse(
        state.version,
        state.memberId,
        state.decree,
        state.configurationNumber,
        state.ballot);
    response->m_queryDecree = request.m_decree;
    response->m_queryBallot = request.m_ballot;
    response->m_lastReceivedAgo = state.lastReceivedAgo;
    response->m_minDecreeInLog = state.logs.empty() ? 0 : state.logs.front().minDecree;
    response->m_checkpointedDecree = state.checkpointedDecree;
    response->m_checkpointSize = state.checkpointSize;
    response->m_maxBallot = state.maxBallot;
    response->m_state = state.state;
}

DWORD32 SendLearnFile(
    const char* fileName,
    UInt64 offset,
    Int64 length,
    StreamSocket* socket,
    LearnFileMetrics* metrics)
{
    std::unique_ptr<APSEQREAD> reader(new APSEQREAD());
    DWORD32 error = reader->DoInit(
        fileName,
        APSEQREAD::c_maxReadsDefault,
        APSEQREAD::c_readBufSize,
        true);
    if (error != NO_ERROR)
    {
        return error;
    }
    if (offset > 0)
    {
        error = reader->Reset(offset);
        if (error != NO_ERROR)
        {
            return error;
        }
    }
    if (length < 0)
    {
        length = reader->FileSize() - offset;
    }

    void* buffer;
    DWORD bytesRead = 0;
    UInt64 readMicroseconds = 0;
    for (Int64 remaining = length; remaining > 0; remaining -= bytesRead)
    {
        Int64 started = GetHiResTime();
        error = reader->GetDataPointer(&buffer, APSEQREAD::c_readBufSize, &bytesRead);
        readMicroseconds += GetHiResTime() - started;
        if (error != NO_ERROR)
        {
            return error;
        }
        error = socket->Write(buffer, bytesRead);
        if (error != NO_ERROR)
        {
            return error;
        }
    }
    if (metrics != NULL)
    {
        ++metrics->fileReads;
        metrics->bytesRead += length;
        metrics->readMicroseconds += readMicroseconds;
        if (readMicroseconds > metrics->maxReadMicroseconds)
        {
            metrics->maxReadMicroseconds = readMicroseconds;
        }
    }
    return NO_ERROR;
}

DWORD32 ServeLearnRequest(
    const Message& request,
    StreamSocket* socket,
    const LearnServerState& state,
    LearnFileMetrics* metrics)
{
    if (request.m_msgId == Message_StatusQuery)
    {
        if (state.relinquishing)
        {
            return NO_ERROR;
        }
        StatusResponse response;
        BuildLearnStatusResponse(state, request, &response);
        StandardMarshalMemoryManager memory(response.GetMarshalLen());
        MarshalData marshal(&memory);
        response.Marshal(&marshal);
        return socket->Write(marshal.GetMarshaled(), marshal.GetMarshaledLength());
    }

    if (request.m_msgId == Message_FetchVotes)
    {
        size_t firstLog = state.logs.size();
        UInt64 offset = 0;
        for (size_t i = 0; i < state.logs.size(); ++i)
        {
            const LearnLogFile& log = state.logs[i];
            if (request.m_decree >= log.minDecree)
            {
                UInt64 index = request.m_decree - log.minDecree;
                if (index < log.decreeOffsets.size())
                {
                    firstLog = i;
                    offset = log.decreeOffsets[static_cast<size_t>(index)];
                    break;
                }
            }
        }
        if (firstLog == state.logs.size())
        {
            return NO_ERROR;
        }
        for (size_t i = firstLog; i < state.logs.size(); ++i)
        {
            DWORD32 error = SendLearnFile(
                state.logs[i].fileName.c_str(),
                offset,
                -1,
                socket,
                metrics);
            if (error != NO_ERROR)
            {
                return error;
            }
            offset = 0;
        }
        return NO_ERROR;
    }

    if (request.m_msgId == Message_FetchCheckpoint)
    {
        if (request.m_decree != state.checkpointedDecree ||
            state.checkpointFile.empty())
        {
            return NO_ERROR;
        }
        return SendLearnFile(state.checkpointFile.c_str(), 0, -1, socket, metrics);
    }

    return ERROR_INVALID_DATA;
}

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
    LearnCheckpointCopyResult* result)
{
    LearnCheckpointCopyResult localResult;
    if (result == NULL)
    {
        result = &localResult;
    }
    *result = LearnCheckpointCopyResult();

    MarshalData marshal;
    StandardMarshalMemoryManager memory(APSEQWRITE::c_writeBufSizeDefault);
    std::unique_ptr<StreamSocket> socket(StreamSocket::CreateStreamSocket());
    SocketStreamReader reader(socket.get());
    std::unique_ptr<APSEQWRITE> writer(new APSEQWRITE());
    CheckpointHeader header;
    BallotNumber localMaxBallot;

    DWORD32 error = writer->DoInit(outputFile);
    if (error != NO_ERROR)
    {
        result->outcome = LearnCheckpointCopyResult::CreateFailed;
        result->detail = "failed to create output";
        return false;
    }

    Message request(
        version,
        Message_FetchCheckpoint,
        memberId,
        checkpointedDecree,
        1,
        BallotNumber());
    request.Marshal(&marshal);

    error = socket->Connect(ip, port, receiveTimeout, sendTimeout);
    if (error != NO_ERROR ||
        socket->Write(marshal.GetMarshaled(), marshal.GetMarshaledLength()) != NO_ERROR)
    {
        result->outcome = LearnCheckpointCopyResult::ConnectFailed;
        result->detail = "connect or request failed";
        goto Error;
    }
    if (!header.UnMarshal(&reader))
    {
        result->outcome = LearnCheckpointCopyResult::HeaderRejected;
        result->detail = "checkpoint header rejected";
        goto Error;
    }

    result->sourceMaxBallot = header.m_maxBallot;
    localMaxBallot =
        maxBallotCallback == NULL ?
        BallotNumber() :
        maxBallotCallback(maxBallotContext);
    if (header.m_maxBallot < localMaxBallot)
    {
        header.m_maxBallot = localMaxBallot;
    }
    result->writtenMaxBallot = header.m_maxBallot;

    marshal.Clear(false);
    header.Marshal(&marshal);
    if (writer->Write(marshal.GetMarshaled(), marshal.GetMarshaledLength()) != NO_ERROR)
    {
        result->outcome = LearnCheckpointCopyResult::HeaderWriteFailed;
        result->detail = "checkpoint header write failed";
        goto Error;
    }

    while (reader.BytesRead() < size)
    {
        UInt32 bytesRead;
        error = reader.Read(memory.GetBuffer(), memory.GetBufferLength(), &bytesRead);
        if (error != NO_ERROR)
        {
            result->outcome = LearnCheckpointCopyResult::ReadFailed;
            result->detail = "incomplete checkpoint";
            goto Error;
        }
        if (writer->Write(memory.GetBuffer(), bytesRead) != NO_ERROR)
        {
            result->outcome = LearnCheckpointCopyResult::BodyWriteFailed;
            result->detail = "checkpoint body write failed";
            goto Error;
        }
    }
    if (writer->Flush() != NO_ERROR)
    {
        result->outcome = LearnCheckpointCopyResult::FlushFailed;
        result->detail = "checkpoint flush failed";
        goto Error;
    }
    result->bytesWritten = writer->BytesIssued();
    writer->DoDispose();

    if (!VerifyCheckpointFile(outputFile))
    {
        result->outcome = LearnCheckpointCopyResult::VerificationFailed;
        result->detail = "copied checkpoint rejected";
        DeleteFileA(outputFile);
        return false;
    }

    result->outcome = LearnCheckpointCopyResult::Success;
    result->detail = "checkpoint valid";
    return true;

Error:
    writer->DoDispose();
    DeleteFileA(outputFile);
    return false;
}
}
