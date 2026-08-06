// tls_peer.h -- see tls_peer.cpp.
//
// Built only when CMake finds OpenSSL; `main.cpp` guards every call with
// RSL_GOLDEN_TLS and tells the caller to install libssl-dev otherwise.
#pragma once

namespace rsl_tls
{

// TLS 1.2 server on `port` (0 = ephemeral, printed as "PORT <n>"). Accepts one
// connection with mutual authentication against `caPem`, then runs the RSL
// packet framing over it. `mode` is "echo" or "log".
int RunServer(int port, const char* certPem, const char* keyPem, const char* caPem,
              const char* mode);

// TLS 1.2 client: connect to `host:port`, authenticate both ways, send `count`
// packets carrying `payload`, and print "ECHOED <n>". Exit status is 0 only if
// every packet came back.
int RunClient(const char* host, int port, const char* certPem, const char* keyPem,
              const char* caPem, const char* payload, int count);

} // namespace rsl_tls
