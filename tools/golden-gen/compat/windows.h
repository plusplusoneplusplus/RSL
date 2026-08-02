// Minimal <windows.h> substitute for the Phase-1 golden-vector slice on Linux.
//
// This header is ONLY on the include path for the Linux golden-gen build (see
// tools/golden-gen/CMakeLists.txt). The real Windows build never sees it. It
// supplies just enough of the Win32 type/function surface for basic_types.h,
// inc/rsl.h, RefCount.h, message.{h,cpp} and marshal.{h,cpp} to compile and run.
//
// Nothing here needs to be behaviourally complete beyond what the marshal /
// message / fingerprint code actually executes at runtime; the rest only has
// to parse.
#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cwchar>
#include <ctime>

// libstdc++ uses `__in` / `__out` as ordinary parameter names (e.g. in
// <ostream>, <istream>, <locale>). We are about to #define those as empty SAL
// annotations for the engine headers, so pull in the standard headers that
// reference them FIRST; once parsed they are include-guarded and the macros
// can no longer harm them.
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <utility>
#include <ostream>
#include <istream>
#include <sstream>
#include <locale>

// ---------------------------------------------------------------------------
// Calling-convention / declspec / SAL annotations -> no-ops on Linux.
// ---------------------------------------------------------------------------
#ifndef _WIN32
#define __stdcall
#define __cdecl
#define __fastcall
#define __declspec(x)
#define WINAPI
#define CALLBACK
#endif

// Only __out is actually used by the engine headers in this slice (rsl.h), but
// define the common SAL annotations for robustness. Safe now that the STL
// headers above are already parsed.
#ifndef __in
#define __in
#define __in_opt
#define __out
#define __out_opt
#define __inout
#define __inout_opt
#define __reserved
#define __deref_out
#endif

// MSVC fixed-width builtin spellings used by basic_types.h.
#include "msvc_builtins.h"

// ---------------------------------------------------------------------------
// Basic Win32 integer / handle typedefs (LP64-correct: DWORD == uint32_t).
// ---------------------------------------------------------------------------
typedef unsigned char       BYTE;
typedef unsigned char       UCHAR;
typedef char                CHAR;
typedef unsigned short      WORD;
typedef unsigned short      USHORT;
typedef short               SHORT;
typedef int                 INT;
typedef unsigned int        UINT;
typedef long                LONG;
typedef unsigned long       ULONG;
typedef unsigned int        DWORD;
typedef unsigned int        DWORD32;
typedef unsigned long long  DWORD64;
typedef int                 LONG32;
typedef long long           LONG64;
typedef long long           LONGLONG;
typedef unsigned long long  ULONGLONG;
typedef int                 INT32;
typedef long long           INT64;
typedef unsigned int        UINT32;
typedef unsigned long long  UINT64;
typedef int                 BOOL;

typedef void*               PVOID;
typedef void*               LPVOID;
typedef const void*         LPCVOID;
typedef void*               HANDLE;
typedef char*               LPSTR;
typedef const char*         LPCSTR;
typedef size_t              SIZE_T;

#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

// ---------------------------------------------------------------------------
// HRESULT / error codes.
// ---------------------------------------------------------------------------
typedef long HRESULT;
#ifndef S_OK
#define S_OK          ((HRESULT)0L)
#define S_FALSE       ((HRESULT)1L)
#define E_FAIL        ((HRESULT)0x80004005L)
#define E_INVALIDARG  ((HRESULT)0x80070057L)
#endif
#ifndef SUCCEEDED
#define SUCCEEDED(hr) (((HRESULT)(hr)) >= 0)
#define FAILED(hr)    (((HRESULT)(hr)) < 0)
#endif
#ifndef NO_ERROR
#define NO_ERROR 0L
#endif

// ---------------------------------------------------------------------------
// FILETIME / SYSTEMTIME (only structurally needed).
// ---------------------------------------------------------------------------
typedef struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME, *PFILETIME;

typedef struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
} SYSTEMTIME, *PSYSTEMTIME;

inline void GetSystemTime(SYSTEMTIME* st)
{
    if (st) { memset(st, 0, sizeof(*st)); }
}

// ---------------------------------------------------------------------------
// Memory helpers.
// ---------------------------------------------------------------------------
#ifndef ZeroMemory
#define ZeroMemory(dst, len) memset((dst), 0, (len))
#endif

// VirtualAlloc/VirtualFree: MEM_COMMIT zero-fills, so calloc matches semantics
// closely enough for the marshaling path (the Vote code only reads back bytes
// it explicitly wrote).
#define MEM_COMMIT    0x00001000
#define MEM_RESERVE   0x00002000
#define MEM_RELEASE   0x00008000
#define PAGE_READWRITE 0x04

inline LPVOID VirtualAlloc(LPVOID /*addr*/, SIZE_T size, DWORD /*type*/, DWORD /*protect*/)
{
    return calloc(1, size);
}

inline BOOL VirtualFree(LPVOID addr, SIZE_T /*size*/, DWORD /*type*/)
{
    free(addr);
    return TRUE;
}

// ---------------------------------------------------------------------------
// Interlocked* (RefCount.h) -> GCC/Clang atomics.
// ---------------------------------------------------------------------------
inline long InterlockedIncrement(volatile long* p)
{
    return __atomic_add_fetch(p, 1, __ATOMIC_SEQ_CST);
}

inline long InterlockedDecrement(volatile long* p)
{
    return __atomic_sub_fetch(p, 1, __ATOMIC_SEQ_CST);
}

inline PVOID InterlockedExchangePointer(volatile PVOID* dst, PVOID val)
{
    PVOID prev = nullptr;
    __atomic_exchange((void* volatile*)dst, &val, &prev, __ATOMIC_SEQ_CST);
    return prev;
}

inline void DebugBreak() { abort(); }

// ---------------------------------------------------------------------------
// Critical sections (basic_types.h CRITSEC parses these; never executed here).
// ---------------------------------------------------------------------------
typedef struct _CRITICAL_SECTION { void* unused; } CRITICAL_SECTION;

inline void InitializeCriticalSection(CRITICAL_SECTION*) {}
inline void DeleteCriticalSection(CRITICAL_SECTION*) {}
inline void EnterCriticalSection(CRITICAL_SECTION*) {}
inline BOOL TryEnterCriticalSection(CRITICAL_SECTION*) { return TRUE; }
inline void LeaveCriticalSection(CRITICAL_SECTION*) {}
inline DWORD SetCriticalSectionSpinCount(CRITICAL_SECTION*, DWORD) { return 0; }

// ---------------------------------------------------------------------------
// MSVC-only CRT spellings used by the engine code.
// ---------------------------------------------------------------------------
#ifndef _WIN32
#define _strtoui64(nptr, endptr, base) strtoull((nptr), (endptr), (base))
#endif
