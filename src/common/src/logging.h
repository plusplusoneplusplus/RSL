#pragma once

#ifdef _WIN32

#define LogAssertInternal(exp, ...)  \
do { \
LogInternal(LogID_Common, LogLevel_Assert, exp, __VA_ARGS__); \
char assertMessage[1024]; \
sprintf_s(assertMessage, "Assert -- %s, %d: %s", __FILE__, __LINE__, exp); \
printf("%s\n", assertMessage); \
RSLibImpl::Logger::FailFast(assertMessage); \
} while (0)

#include "logging_old.h"

#else
// Linux rsl-linux-proxy slice: the full logging.cpp (SEH/minidump) is not ported.
// Use a small stub that aborts on assert and prints diagnostics to stderr.
#include <pal_logging.h>
#endif
