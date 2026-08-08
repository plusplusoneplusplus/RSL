// Minimal <strsafe.h> substitute for the rsl-linux-proxy Linux slice.
//
// Only the StringC{b,ch}* entry points that message.cpp / rsl.cpp (engine_support)
// actually reference are provided. Byte-for-byte behaviour matters for the
// StringCbPrintfA path that renders numeric member ids, so MSVC width
// specifiers ("%I64u"/"%I64d"/"%I64x") are translated to their Linux
// equivalents before formatting.
#pragma once

#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>

#ifndef STRSAFE_E_INSUFFICIENT_BUFFER
#define STRSAFE_E_INSUFFICIENT_BUFFER ((HRESULT)0x8007007AL)
#define STRSAFE_E_INVALID_PARAMETER   ((HRESULT)0x80070057L)
#endif

namespace rsl_strsafe_detail {

// Translate MSVC-only printf width specifiers to the glibc spelling so that
// e.g. "%I64u" formats a 64-bit value instead of printing the literal text.
inline std::string TranslateFormat(const char* fmt)
{
    std::string out;
    for (const char* p = fmt; p && *p; )
    {
        if (p[0] == '%' && p[1] == 'I' && p[2] == '6' && p[3] == '4')
        {
            out += '%';
            out += 'l';
            out += 'l';
            out += p[4]; // conversion char (u/d/x/o/...)
            p += 5;
        }
        else if (p[0] == '%' && p[1] == 'I' && p[2] == '3' && p[3] == '2')
        {
            out += '%';
            out += p[4];
            p += 5;
        }
        else
        {
            out += *p++;
        }
    }
    return out;
}

inline HRESULT VPrintf(char* dst, size_t cbDst, const char* fmt, va_list args)
{
    if (dst == nullptr || cbDst == 0) { return STRSAFE_E_INVALID_PARAMETER; }
    std::string tfmt = TranslateFormat(fmt);
    int n = vsnprintf(dst, cbDst, tfmt.c_str(), args);
    if (n < 0 || (size_t)n >= cbDst) { return STRSAFE_E_INSUFFICIENT_BUFFER; }
    return S_OK;
}

} // namespace rsl_strsafe_detail

inline HRESULT StringCbLengthA(const char* psz, size_t cbMax, size_t* pcbLength)
{
    if (psz == nullptr) { return STRSAFE_E_INVALID_PARAMETER; }
    size_t len = ::strnlen(psz, cbMax);
    if (len >= cbMax) { return STRSAFE_E_INVALID_PARAMETER; }
    if (pcbLength) { *pcbLength = len; }
    return S_OK;
}

inline HRESULT StringCchLengthA(const char* psz, size_t cchMax, size_t* pcchLength)
{
    return StringCbLengthA(psz, cchMax, pcchLength);
}

inline HRESULT StringCbCopyA(char* dst, size_t cbDst, const char* src)
{
    if (dst == nullptr || cbDst == 0) { return STRSAFE_E_INVALID_PARAMETER; }
    size_t srcLen = src ? ::strlen(src) : 0;
    if (srcLen >= cbDst) { return STRSAFE_E_INSUFFICIENT_BUFFER; }
    // Zero-fill the whole destination, then copy. The engine marshals fixed-size
    // member-id fields (char[64]) whose tail past the null terminator is
    // otherwise uninitialized; zeroing here makes the proxy vectors
    // deterministic and matches the canonical zero-padded wire form that the
    // pure-Rust port produces.
    ::memset(dst, 0, cbDst);
    if (src) { ::memcpy(dst, src, srcLen); }
    return S_OK;
}

inline HRESULT StringCbPrintfA(char* dst, size_t cbDst, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    HRESULT hr = rsl_strsafe_detail::VPrintf(dst, cbDst, fmt, args);
    va_end(args);
    return hr;
}

inline HRESULT StringCchPrintfA(char* dst, size_t cchDst, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    HRESULT hr = rsl_strsafe_detail::VPrintf(dst, cchDst, fmt, args);
    va_end(args);
    return hr;
}

// End-pointer / remaining variant used by the LogString helpers.
inline HRESULT StringCchPrintfExA(char* dst, size_t cchDst, char** end,
                                  size_t* remaining, unsigned long /*flags*/,
                                  const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    HRESULT hr = rsl_strsafe_detail::VPrintf(dst, cchDst, fmt, args);
    va_end(args);
    if (SUCCEEDED(hr))
    {
        size_t len = ::strlen(dst);
        if (end) { *end = dst + len; }
        if (remaining) { *remaining = cchDst - len; }
    }
    return hr;
}

// The generic (TCHAR) spellings resolve to the ANSI variants in this ASCII-only
// slice.
#ifndef StringCbLength
#define StringCbLength  StringCbLengthA
#define StringCchLength StringCchLengthA
#define StringCbCopy    StringCbCopyA
#define StringCbPrintf  StringCbPrintfA
#define StringCchPrintf StringCchPrintfA
#endif
