// Logging stub for the rsl-linux-proxy Linux slice.
//
// The real logging.cpp (~2.6k lines, SEH/minidump) is deliberately NOT ported.
// This header satisfies the handful of logging macros the marshal/message code
// uses: asserts abort(), and RSL{Error,Info,Debug,...} print the message text
// to stderr. The variadic LogTag/value pairs are accepted and ignored.
#pragma once

#include <cstdio>
#include <cstdlib>

namespace RSLibImpl
{
    // Log tags are only used to annotate diagnostic output; for the slice we
    // just need every referenced name to exist as an int-valued constant.
    enum LogTag
    {
        LogTag_End = 0,
        LogTag_UInt1,
        LogTag_UInt2,
        LogTag_Int1,
        LogTag_Int2,
        LogTag_U32X1,
        LogTag_U32X2,
        LogTag_U64X1,
        LogTag_U64X2,
        LogTag_ErrorCode,
        LogTag_RSLMsg,
        LogTag_RSLMsgLen,
        LogTag_RSLMsgVersion,
        LogTag_RSLMemberId,
        LogTag_String1,
        LogTag_String2,
        LogTag_Ptr1,
        LogTag_Filename,
        LogTag_Numeric1,
    };

    inline void PalLogLine(const char* level, const char* msg, ...)
    {
        fprintf(stderr, "[%s] %s\n", level, msg ? msg : "");
    }

    inline void PalFailFast(const char* file, int line, const char* expr)
    {
        fprintf(stderr, "Assert failed: (%s) at %s:%d\n", expr, file, line);
        abort();
    }
}

#define LogAssert(exp, ...)                                                    \
    do {                                                                       \
        if (!(exp)) {                                                          \
            ::RSLibImpl::PalFailFast(__FILE__, __LINE__, #exp);                \
        }                                                                      \
    } while (0)

#define RSLError(...) ::RSLibImpl::PalLogLine("ERROR", __VA_ARGS__)
#define RSLAlert(...) ::RSLibImpl::PalLogLine("ALERT", __VA_ARGS__)
#define RSLWarning(...) ::RSLibImpl::PalLogLine("WARN", __VA_ARGS__)
#define RSLInfo(...) ::RSLibImpl::PalLogLine("INFO", __VA_ARGS__)
#define RSLStatus(...) ::RSLibImpl::PalLogLine("STATUS", __VA_ARGS__)
#define RSLDebug(...) ::RSLibImpl::PalLogLine("DEBUG", __VA_ARGS__)
