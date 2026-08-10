#include "logfile.h"
#include "rsldebug.h"
#include "DynamicBuffer.h"
#include <strsafe.h>
#include <windows.h>

using namespace std;
using namespace RSLibImpl;

LogFile::LogFile() : m_hFile(INVALID_HANDLE_VALUE), m_overlapEvent(nullptr),
                     m_minDecree(0), m_dataLen(0)
{
}

LogFile::~LogFile()
{
    if (m_hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(m_hFile);
    }
    if (m_overlapEvent != nullptr)
    {
        CloseHandle(m_overlapEvent);
    }
}

DWORD32
LogFile::Open(const char *dir, UInt64 decree)
{
    HRESULT ret;
    ret = StringCchPrintfA(m_fileName, sizeof(m_fileName), "%s%I64u.log", dir, decree);
    LogAssert(SUCCEEDED(ret));
    m_hFile = CreateFileA(m_fileName,
                          GENERIC_WRITE|FILE_READ_DATA,
                          FILE_SHARE_READ,
                          NULL,
                          OPEN_ALWAYS,
                          FILE_FLAG_NO_BUFFERING|FILE_FLAG_WRITE_THROUGH|FILE_FLAG_OVERLAPPED,
                          NULL);

    if (m_hFile == INVALID_HANDLE_VALUE)
    {
        int ec = GetLastError();
        RSLError("Failed to open log", LogTag_Filename, m_fileName, LogTag_ErrorCode, ec);
        return ec;
    }

    m_overlapEvent =  CreateEvent(NULL, TRUE, FALSE, NULL);
    if (m_overlapEvent == nullptr)
    {
        int ec = GetLastError();
        RSLError("Failed to create event", LogTag_ErrorCode, ec);
        return ec;
    }

    RSLInfo("Opened log File", LogTag_Filename, m_fileName);
    return NO_ERROR;
}

bool
LogFile::Write(SIZED_BUFFER *bufs, UInt32 count)
{
    DWORD bytesToWrite = 0;
    int numTotalPages = 0;
    UInt64 offset = m_dataLen;

    DynamicBuffer<FILE_SEGMENT_ELEMENT, PAGES_PER_WRITE+1> segments;

    for (UInt32 i = 0; i < count; i++)
    {
        LogAssert((bufs[i].m_len % s_PageSize) == 0);
        bytesToWrite += bufs[i].m_len;

        UInt32 numPages = bufs[i].m_len/s_SystemPageSize;
        UInt32 remainingBytes = bufs[i].m_len % s_SystemPageSize;
        if (remainingBytes)
        {
            numPages++;
        }
        LogAssert(i == count-1 || remainingBytes == 0);

        for (UInt32 j = 0; j < numPages; j++)
        {
            BYTE *buffer = (BYTE *) bufs[i].m_buf + j*s_SystemPageSize;
            segments[numTotalPages++].Buffer = (PVOID64) buffer;
            if (numTotalPages == PAGES_PER_WRITE)
            {
                segments[numTotalPages].Buffer = (PVOID64) NULL;
                DWORD toWrite = min(PAGES_PER_WRITE*s_SystemPageSize, bytesToWrite);
                if (!IssueWriteFileGather(segments.Begin(), offset, toWrite))
                {
                    return false;
                }
                numTotalPages = 0;
                bytesToWrite -= toWrite;
                offset += toWrite;
            }
        }
    }
    if (numTotalPages > 0)
    {
        segments[numTotalPages].Buffer = (PVOID64) NULL;
        if (!IssueWriteFileGather(segments.Begin(), offset, bytesToWrite))
        {
            return false;
        }
    }
    return true;
}

bool
LogFile::WriteMessage(Message *msg, UInt32 *bytesWritten)
{
    LogAssert(msg != NULL);
    LogAssert(bytesWritten != NULL);

    if (msg->m_msgId == Message_Vote)
    {
        Vote *vote = static_cast<Vote *>(msg);
        vote->CalculateChecksum();
        DynamicBuffer<SIZED_BUFFER, 1024> buffers(vote->GetNumBuffers());
        vote->GetBuffers(buffers, buffers.Size());

        *bytesWritten = 0;
        for (UInt32 i = 0; i < vote->GetNumBuffers(); i++)
        {
            *bytesWritten += buffers[(Int32)i].m_len;
        }
        return Write(buffers, vote->GetNumBuffers());
    }

    UInt32 toWrite = RoundUpToPage(msg->GetMarshalLen());
    char *buf = (char *) VirtualAlloc(NULL, toWrite, MEM_COMMIT, PAGE_READWRITE);
    LogAssert(buf);
    msg->MarshalBuf(buf, toWrite);
    msg->CalculateChecksum(buf, msg->GetMarshalLen());

    SIZED_BUFFER buffer;
    buffer.m_buf = buf;
    buffer.m_len = toWrite;
    bool success = Write(&buffer, 1);
    VirtualFree(buf, 0, MEM_RELEASE);

    *bytesWritten = toWrite;
    return success;
}

bool
LogFile::IssueWriteFileGather(FILE_SEGMENT_ELEMENT *segments, UInt64 offset, DWORD bytesToWrite)
{
    LARGE_INTEGER i;
    i.QuadPart = offset;

    OVERLAPPED overlap;
    memset(&overlap, 0, sizeof(OVERLAPPED));
    overlap.Offset = i.LowPart;
    overlap.OffsetHigh = i.HighPart;
    overlap.hEvent = m_overlapEvent;

    BOOL ret = ::WriteFileGather(
        m_hFile,
        segments,
        bytesToWrite,
        0,
        &overlap);

    if (FALSE == ret)
    {
        DWORD cbRead;
        if (GetLastError() == ERROR_IO_PENDING)
        {
            ret = GetOverlappedResult(m_hFile, &overlap, &cbRead, TRUE);

            if (ret && bytesToWrite != cbRead)
            {
                ret = FALSE;
            }
        }
    }
    if (FALSE == ret)
    {
        DWORD ec = ::GetLastError();
        RSLError("Disk I/O error writing to log file",
                 LogTag_Filename, m_fileName,
                 LogTag_ErrorCode, ec,
                 LogTag_Offset, offset,
                 LogTag_UInt1, bytesToWrite);
    }
    return (ret != FALSE);
}

bool
LogFile::Read(void* buf, UInt32 numBytes, UInt64 offset, HANDLE event)
{
    while (numBytes != 0)
    {
        OVERLAPPED Overlapped;
        DWORD dwBytesRead;
        DWORD dwBytesToRead;
        BOOL  fResult;

        dwBytesToRead = numBytes;
        if (dwBytesToRead > MAX_SINGLE_IO_SIZE)
        {
            dwBytesToRead = MAX_SINGLE_IO_SIZE;
            if (numBytes < 2*MAX_SINGLE_IO_SIZE)
            {
                //
                // if we need to read more than MAX_SINGLE_IO_SIZE but less than 2*MAX_SINGLE_IO_SIZE,
                // we'd better read two large blocks of approximately numBytes/2 bytes instead of
                // one large (MAX_SINGLE_IO_SIZE) block and then one small block (numBytes - MAX_SINGLE_IO_SIZE).
                //
                dwBytesToRead = ((numBytes >> 1) + SAFE_IO_ALIGNMENT - 1) & ~(SAFE_IO_ALIGNMENT - 1);
            }
        }

        //
        // Use async overlapped IO and wait for completion immediately;
        // it is equivalent to synchronous IO but it doesn't cause modification of
        // current file pointer
        //
        Overlapped.hEvent     = event;
        Overlapped.Offset     = (ULONG) offset;
        Overlapped.OffsetHigh = (ULONG) (offset >> 32);

        dwBytesRead = 0;

        fResult = ReadFile (m_hFile, buf, dwBytesToRead, &dwBytesRead, &Overlapped);
        if (!fResult)
        {
            if (GetLastError () == ERROR_IO_PENDING)
            {
                fResult = GetOverlappedResult (m_hFile, &Overlapped, &dwBytesRead, TRUE);
            }
        }

        if (!fResult || dwBytesToRead != dwBytesRead)
        {
            Log (
                LogID_RSLLIB,
                LogLevel_Error,
                "Read failed",
                "fResult=%d m_hFile=%p buf=%p BytesToRead=0x%x BytesRead=0x%x GetLastError()=%d numBytes=0x%x",
                fResult,
                m_hFile,
                buf,
                dwBytesToRead,
                dwBytesRead,
                GetLastError (),
                numBytes
            );

            return false;
        }

        offset   += dwBytesToRead;
        numBytes -= dwBytesToRead;
        buf       = (void *) (((char *) buf) + dwBytesToRead);
    }
    return true;
}

void
LogFile::AddMessage(Message *msg)
{
    UInt32 messageLen =  RoundUpToPage(msg->GetMarshalLen());
    RSLDebug("Adding Message to Log", LogTag_RSLMsg, msg, LogTag_RSLMsgLen, messageLen,
             LogTag_Offset, m_dataLen);

    if (msg->m_msgId == Message_Vote)
    {
        if (m_decreeOffsets.size() == 0)
        {
            m_minDecree = msg->m_decree;
        }
        else
        {
            LogAssert(msg->m_decree == MaxDecree() || msg->m_decree == MaxDecree()+1);
            if (MaxDecree() == msg->m_decree)
            {
                m_decreeOffsets.pop_back();
            }
        }
        m_decreeOffsets.push_back(m_dataLen);
    }
    m_dataLen += messageLen;
}

UInt64
LogFile::GetOffset(UInt64 decree)
{
    LogAssert(decree >= m_minDecree && decree <= MaxDecree());
    UInt32 offset = (UInt32) (decree - m_minDecree);
    return (m_decreeOffsets.size() ? m_decreeOffsets[offset] : 0);
}

bool
LogFile::HasDecree(UInt64 decree)
{
    return (m_minDecree <= decree && MaxDecree() >= decree);
}

UInt32
LogFile::GetLengthOfDecree(UInt64 decree)
{
    if (decree < MaxDecree())
    {
        return (UInt32) (GetOffset(decree+1) - GetOffset(decree));
    }
    return (UInt32) (m_dataLen - GetOffset(decree));
}

UInt64
LogFile::MaxDecree()
{
    UInt32 size = (UInt32) m_decreeOffsets.size();
    return ((size) ? m_minDecree+size-1 : 0);
}

DWORD32
LogFile::SetWritePointer()
{
    LARGE_INTEGER offset;
    offset.QuadPart = m_dataLen;
    if (!SetFilePointerEx(m_hFile, offset, NULL, FILE_BEGIN))
    {
        int ec = GetLastError();
        RSLError("SetFilePointer Failed",
                 LogTag_Filename, m_fileName, LogTag_ErrorCode, ec);
        return ec;
    }
    return NO_ERROR;

}
