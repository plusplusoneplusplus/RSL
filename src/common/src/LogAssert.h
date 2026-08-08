#pragma once

#include "logging.h"
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <crtdbg.h>

#define LogAssert(exp, ...) \
do { \
   if (!(exp)) { \
        LogAssertInternal(#exp, __VA_ARGS__ ); \
    } \
} while (0)
#else
// Linux rsl-linux-proxy slice: <crtdbg.h> does not exist and the LogAssert macro is
// already provided by pal_logging.h (pulled in through logging.h above). Don't
// redefine it here. This keeps DynamicBuffer.h -- which includes this header --
// compilable on Linux. No effect on the Windows build.
#endif

