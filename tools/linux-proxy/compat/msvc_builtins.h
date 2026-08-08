// MSVC fixed-width builtin keyword spellings, for the Linux rsl-linux-proxy slice.
// Force-included into every TU (see CMakeLists) so even freestanding files like
// msn_fprint.cpp/.h -- which use `unsigned __int64` without including
// windows.h -- compile on gcc/clang.
#pragma once

#ifndef _WIN32
#ifndef __int8
#define __int8  char
#endif
#ifndef __int16
#define __int16 short
#endif
#ifndef __int32
#define __int32 int
#endif
#ifndef __int64
#define __int64 long long
#endif
#endif
