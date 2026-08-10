#pragma once

#include "message.h"
#include <vector>

#define MAX_SINGLE_IO_SIZE      (32*1024*1024)      // max size we can pass to unbuffered ReadFile/WriteFile (MDL size limit of XP kernel :-)
#define SAFE_IO_ALIGNMENT       (1024*1024)         // safe alignment for buffer & size (shall be multiple of page size and sector size)

namespace RSLibImpl
{
    static const UInt32 s_PageSize = 512;
    static const UInt32 s_SystemPageSize = 4096;
    static const UInt32 PAGES_PER_WRITE = 512;

    inline UInt32 RoundUpToPage(UInt32 x)
    {
        return ((x + (s_PageSize - 1)) & ~(s_PageSize - 1));
    }

    inline UInt32 RoundUpToSystemPage(UInt32 x)
    {
        return ((x + (s_SystemPageSize - 1)) & ~(s_SystemPageSize - 1));
    }

    class LogFile
    {
    public:

        HANDLE m_hFile;
        HANDLE m_overlapEvent;

        std::vector<UInt64> m_decreeOffsets;
        UInt64 m_dataLen;
        char m_fileName[MAX_PATH + 1];
        UInt64 m_minDecree;

        LogFile();
        ~LogFile();
        DWORD32 Open(const char *dir, UInt64 decree);

        bool Write(SIZED_BUFFER* bufs, UInt32 count);
        bool WriteMessage(Message *msg, UInt32 *bytesWritten);
        bool Read(void* buf, UInt32 numBytes, UInt64 offset, HANDLE event);
        void AddMessage(Message *msg);
        DWORD32 SetWritePointer();
        UInt64 GetOffset(UInt64 decree);
        bool HasDecree(UInt64 decree);
        UInt32 GetLengthOfDecree(UInt64 decree);

        UInt64 MaxDecree();

    private:
        bool IssueWriteFileGather(FILE_SEGMENT_ELEMENT *segments, UInt64 offset,
            DWORD bytesToWrite);
    };
}
