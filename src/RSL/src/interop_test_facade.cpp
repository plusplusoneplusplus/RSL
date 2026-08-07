#include "interop_test_facade.h"

#include "apdiskio.h"
#include "legislator.h"
#include "rsl.h"

#include <algorithm>

using namespace RSLib;

namespace RSLibImpl
{
namespace
{
    const UInt64 MaxCheckpointWriteSize = 32 * 1024 * 1024;

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
}
