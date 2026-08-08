#include "interop_test_facade.h"

#include "apdiskio.h"
#include "legislator.h"
#include "learn_protocol.h"
#include "rsl.h"

#include <algorithm>
#include <cstdlib>

using namespace RSLib;

namespace RSLibImpl
{
namespace
{
    const UInt64 MaxCheckpointWriteSize = 32 * 1024 * 1024;

    BallotNumber FixedMaxBallot(void *context)
    {
        return *static_cast<BallotNumber *>(context);
    }

    int ReserveLoopbackPort()
    {
        SOCKET socketHandle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (socketHandle == INVALID_SOCKET)
        {
            return 0;
        }
        sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = inet_addr("127.0.0.1");
        address.sin_port = 0;
        int port = 0;
        if (bind(socketHandle, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0)
        {
            int length = sizeof(address);
            if (getsockname(
                    socketHandle,
                    reinterpret_cast<sockaddr *>(&address),
                    &length) == 0)
            {
                port = ntohs(address.sin_port);
            }
        }
        closesocket(socketHandle);
        return port;
    }

    bool EndsWith(const std::string& value, const char* suffix)
    {
        size_t suffixLength = strlen(suffix);
        return value.size() >= suffixLength &&
            value.compare(value.size() - suffixLength, suffixLength, suffix) == 0;
    }

    std::string JoinPath(const char* directory, const std::string& name)
    {
        std::string path(directory);
        if (!path.empty() && path[path.size() - 1] != '\\')
        {
            path += '\\';
        }
        path += name;
        return path;
    }

    bool BuildLearnState(
        const char* directory,
        RSLProtocolVersion version,
        LearnServerState* state)
    {
        state->version = version;
        state->memberId = MemberId("101");
        state->configurationNumber = 7;
        state->ballot = BallotNumber(3, MemberId("202"));
        state->maxBallot = BallotNumber(9, MemberId("202"));

        std::vector<std::pair<UInt64, std::string> > logs;
        std::vector<std::pair<UInt64, std::string> > checkpoints;
        WIN32_FIND_DATAA data;
        HANDLE find = FindFirstFileA(JoinPath(directory, "*").c_str(), &data);
        if (find == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        do
        {
            if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {
                continue;
            }
            std::string name = data.cFileName;
            char* end = NULL;
            UInt64 decree = _strtoui64(name.c_str(), &end, 10);
            if (end == name.c_str())
            {
                continue;
            }
            if (EndsWith(name, ".log"))
            {
                logs.push_back(std::make_pair(decree, name));
            }
            else if (EndsWith(name, ".codex"))
            {
                checkpoints.push_back(std::make_pair(decree, name));
            }
        } while (FindNextFileA(find, &data));
        FindClose(find);

        std::sort(logs.begin(), logs.end());
        for (size_t i = 0; i < logs.size(); ++i)
        {
            InteropLogVerdict verdict;
            std::string path = JoinPath(directory, logs[i].second);
            if (!RSLInteropTestFacade::ScanLog(path.c_str(), &verdict) ||
                verdict.outcome == InteropStorageReject)
            {
                return false;
            }
            LearnLogFile log;
            log.fileName = path;
            for (size_t j = 0; j < verdict.records.size(); ++j)
            {
                if (verdict.records[j].msgId == Message_Vote)
                {
                    if (log.decreeOffsets.empty())
                    {
                        log.minDecree = verdict.records[j].decree;
                    }
                    log.decreeOffsets.push_back(verdict.records[j].offset);
                    if (verdict.records[j].decree > state->decree)
                    {
                        state->decree = verdict.records[j].decree;
                    }
                }
            }
            if (!log.decreeOffsets.empty())
            {
                state->logs.push_back(log);
            }
        }

        std::sort(checkpoints.begin(), checkpoints.end());
        if (!checkpoints.empty())
        {
            state->checkpointedDecree = checkpoints.back().first;
            state->checkpointFile = JoinPath(directory, checkpoints.back().second);
            InteropCheckpointVerdict verdict;
            if (!RSLInteropTestFacade::VerifyCheckpoint(
                    state->checkpointFile.c_str(),
                    &verdict) ||
                verdict.outcome != InteropStorageAccept)
            {
                return false;
            }
            state->checkpointSize = verdict.fileSize;
        }
        return !state->logs.empty() || !state->checkpointFile.empty();
    }

    UInt64 FileSize(const char *fileName)
    {
        WIN32_FILE_ATTRIBUTE_DATA data;
        if (!GetFileAttributesExA(fileName, GetFileExInfoStandard, &data))
        {
            return 0;
        }

        ULARGE_INTEGER size;
        size.LowPart = data.nFileSizeLow;
        size.HighPart = data.nFileSizeHigh;
        return size.QuadPart;
    }
}

DWORD32
RSLInteropTestFacade::WriteLog(
    const char *directory,
    UInt64 fileDecree,
    Message *const *messages,
    size_t messageCount)
{
    LogFile log;
    DWORD32 error = log.Open(directory, fileDecree);
    if (error != NO_ERROR)
    {
        return error;
    }

    for (size_t i = 0; i < messageCount; ++i)
    {
        UInt32 bytesWritten;
        if (!log.WriteMessage(messages[i], &bytesWritten))
        {
            DWORD32 writeError = GetLastError();
            return writeError == NO_ERROR ? ERROR_WRITE_FAULT : writeError;
        }
        log.AddMessage(messages[i]);
    }

    return FlushFileBuffers(log.m_hFile) ? NO_ERROR : GetLastError();
}

bool
RSLInteropTestFacade::ScanLog(const char *fileName, InteropLogVerdict *verdict)
{
    if (verdict == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    APSEQREAD seqRead;
    DWORD32 error = seqRead.DoInit(fileName, 2, s_AvgMessageLen, true);
    if (error != NO_ERROR)
    {
        SetLastError(error);
        return false;
    }

    verdict->outcome = InteropStorageAccept;
    verdict->fileSize = seqRead.FileSize();
    verdict->stopOffset = 0;
    verdict->records.clear();
    verdict->detail.clear();

    DiskStreamReader reader(&seqRead);
    StandardMarshalMemoryManager memory(s_AvgMessageLen);
    for (;;)
    {
        UInt64 offset = reader.BytesRead();
        Message *message = NULL;
        if (!Legislator::ReadNextMessage(&reader, &memory, &message, true))
        {
            verdict->outcome = InteropStorageReject;
            verdict->stopOffset = offset;
            verdict->detail = "rejected by Legislator::ReadNextMessage";
            return true;
        }

        if (message == NULL)
        {
            verdict->stopOffset = offset;
            if (offset == verdict->fileSize)
            {
                verdict->outcome = InteropStorageAccept;
                verdict->detail = "all records valid to EOF";
            }
            else
            {
                verdict->outcome = InteropStorageStop;
                verdict->detail = "production recovery stopped at tolerated tail";
            }
            return true;
        }

        InteropLogRecord record;
        record.offset = offset;
        record.version = static_cast<UInt16>(message->m_version);
        record.msgId = message->m_msgId;
        record.decree = message->m_decree;
        record.unMarshalLen = message->m_unMarshalLen;
        record.paddedLen = RoundUpToPage(message->m_unMarshalLen);
        record.checksum = message->m_checksum;
        verdict->records.push_back(record);
        verdict->stopOffset = offset + record.paddedLen;
        delete message;
    }
}

DWORD32
RSLInteropTestFacade::WriteCheckpoint(
    const char *fileName,
    CheckpointHeader *header,
    const void *state,
    UInt64 stateLength)
{
    if (header == NULL || (state == NULL && stateLength != 0))
    {
        return ERROR_INVALID_PARAMETER;
    }

    RSLCheckpointStreamWriter writer;
    DWORD32 error = writer.Init(fileName, header);
    if (error != NO_ERROR)
    {
        return error;
    }

    const char *next = static_cast<const char *>(state);
    UInt64 remaining = stateLength;
    while (remaining != 0)
    {
        DWORD chunk = static_cast<DWORD>(
            std::min<UInt64>(remaining, MaxCheckpointWriteSize));
        error = writer.Write(next, chunk);
        if (error != NO_ERROR)
        {
            writer.Close();
            return error;
        }
        next += chunk;
        remaining -= chunk;
    }

    header->SetBytesIssued(&writer);
    error = writer.Close();
    if (error != NO_ERROR)
    {
        return error;
    }
    header->Marshal(fileName);
    return NO_ERROR;
}

bool
RSLInteropTestFacade::VerifyCheckpoint(
    const char *fileName,
    InteropCheckpointVerdict *verdict)
{
    if (verdict == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    verdict->outcome = InteropStorageReject;
    verdict->version = 0;
    verdict->headerLen = 0;
    verdict->fileSize = FileSize(fileName);
    verdict->userDataSize = 0;
    verdict->checksumBlockSize = 0;
    verdict->stateSaved = false;
    verdict->detail.clear();

    CheckpointHeader header;
    if (!header.UnMarshal(fileName))
    {
        verdict->detail = "rejected by CheckpointHeader::UnMarshal";
        return true;
    }

    verdict->version = static_cast<UInt16>(header.m_version);
    verdict->headerLen = header.GetMarshalLen();
    verdict->checksumBlockSize = header.m_checksumBlockSize;
    verdict->stateSaved = header.m_stateSaved;

    RSLCheckpointStreamReader reader;
    DWORD32 error = reader.Init(fileName, &header);
    if (error != NO_ERROR)
    {
        verdict->detail = "rejected by RSLCheckpointStreamReader::Init";
        return true;
    }

    verdict->userDataSize = reader.Size();
    UInt64 remaining = verdict->userDataSize;
    while (remaining != 0)
    {
        DWORD requested = static_cast<DWORD>(
            std::min<UInt64>(remaining, static_cast<UInt64>(64 * 1024)));
        void *data;
        DWORD bytesRead;
        error = reader.GetDataPointer(&data, requested, &bytesRead);
        if (error != NO_ERROR || bytesRead == 0)
        {
            verdict->detail = "rejected by RSLCheckpointStreamReader::GetDataPointer";
            return true;
        }
        remaining -= bytesRead;
    }

    verdict->outcome = InteropStorageAccept;
    verdict->detail = "checkpoint valid";
    return true;
}

int
RSLInteropTestFacade::RunLearnServer(
    UInt16 port,
    const char *directory,
    int connections,
    RSLProtocolVersion version)
{
    if (connections <= 0)
    {
        return ERROR_INVALID_PARAMETER;
    }
    LearnServerState state;
    if (!BuildLearnState(directory, version, &state))
    {
        return ERROR_INVALID_DATA;
    }
    if (port == 0)
    {
        port = static_cast<UInt16>(ReserveLoopbackPort());
    }

    std::unique_ptr<StreamSocket> listener(StreamSocket::CreateStreamSocket());
    DWORD32 error = listener->BindAndListen(
        inet_addr("127.0.0.1"),
        port,
        16,
        1,
        10);
    if (error != NO_ERROR)
    {
        return error;
    }
    printf("PORT %u\n", static_cast<unsigned int>(port));
    fflush(stdout);

    for (int i = 0; i < connections; ++i)
    {
        std::unique_ptr<StreamSocket> socket(StreamSocket::CreateStreamSocket());
        error = listener->Accept(socket.get(), 30000, 30000);
        if (error != NO_ERROR)
        {
            return error;
        }
        Message request;
        if (!request.ReadFromSocket(socket.get(), s_AvgMessageLen))
        {
            continue;
        }
        error = ServeLearnRequest(request, socket.get(), state, NULL);
        if (error != NO_ERROR && error != ERROR_INVALID_DATA)
        {
            return error;
        }
    }
    return NO_ERROR;
}

bool
RSLInteropTestFacade::QueryLearnStatus(
    UInt32 ip,
    UInt16 port,
    RSLProtocolVersion version,
    StatusResponse *response)
{
    std::unique_ptr<StreamSocket> socket(StreamSocket::CreateStreamSocket());
    Message request(
        version,
        Message_StatusQuery,
        MemberId("102"),
        0,
        7,
        BallotNumber(3, MemberId("202")));
    MarshalData marshal;
    request.Marshal(&marshal);
    return
        socket->Connect(ip, port, 30000, 30000) == NO_ERROR &&
        socket->Write(marshal.GetMarshaled(), marshal.GetMarshaledLength()) == NO_ERROR &&
        response->ReadFromSocket(socket.get(), s_AvgMessageLen);
}

bool
RSLInteropTestFacade::FetchLearnVotes(
    UInt32 ip,
    UInt16 port,
    RSLProtocolVersion version,
    UInt64 decree,
    std::vector<InteropLogRecord> *records)
{
    records->clear();
    std::unique_ptr<StreamSocket> socket(StreamSocket::CreateStreamSocket());
    Message request(
        version,
        Message_FetchVotes,
        MemberId("102"),
        decree,
        7,
        BallotNumber(3, MemberId("202")));
    MarshalData marshal;
    request.Marshal(&marshal);
    if (socket->Connect(ip, port, 30000, 30000) != NO_ERROR ||
        socket->Write(marshal.GetMarshaled(), marshal.GetMarshaledLength()) != NO_ERROR)
    {
        return false;
    }

    SocketStreamReader reader(socket.get());
    StandardMarshalMemoryManager memory(s_AvgMessageLen);
    for (;;)
    {
        UInt64 offset = reader.BytesRead();
        Message *message = NULL;
        if (!Legislator::ReadNextMessage(&reader, &memory, &message, false))
        {
            return false;
        }
        if (message == NULL)
        {
            return true;
        }
        InteropLogRecord record;
        record.offset = offset;
        record.version = static_cast<UInt16>(message->m_version);
        record.msgId = message->m_msgId;
        record.decree = message->m_decree;
        record.unMarshalLen = message->m_unMarshalLen;
        record.paddedLen = RoundUpToPage(message->m_unMarshalLen);
        record.checksum = message->m_checksum;
        records->push_back(record);
        delete message;
    }
}

bool
RSLInteropTestFacade::CopyLearnCheckpoint(
    UInt32 ip,
    UInt16 port,
    RSLProtocolVersion version,
    UInt64 decree,
    UInt64 size,
    const BallotNumber& localMaxBallot,
    const char *outputFile,
    BallotNumber *sourceMaxBallot,
    BallotNumber *writtenMaxBallot)
{
    LearnCheckpointCopyResult result;
    bool success = CopyLearnCheckpointFile(
        ip,
        port,
        version,
        MemberId("102"),
        decree,
        size,
        &FixedMaxBallot,
        const_cast<BallotNumber *>(&localMaxBallot),
        30000,
        30000,
        outputFile,
        &result);
    if (sourceMaxBallot != NULL)
    {
        *sourceMaxBallot = result.sourceMaxBallot;
    }
    if (writtenMaxBallot != NULL)
    {
        *writtenMaxBallot = result.writtenMaxBallot;
    }
    return success;
}
}
