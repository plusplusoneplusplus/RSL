// Stub: basic_types.h includes <Winsock2.h> before <windows.h>. The rsl-linux-proxy
// slice never touches any sockets, so we only need the Win32 base types, which
// the windows.h shim already provides.
#pragma once
#include <windows.h>
