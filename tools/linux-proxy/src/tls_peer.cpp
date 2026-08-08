// Supplemental Linux packet-model peer over OpenSSL TLS 1.2.
//
// This is supplemental foreign-stack coverage. Production RSL speaks TLS
// through SChannel (src/NetworkLib/src/SSLImpl.cpp), which
// cannot be executed on Linux. OpenSSL is the closest executable stand-in: it
// lets the Rust port's rustls configuration be tested against a *different*
// TLS implementation, which catches the class of bug where two rustls peers
// agree with each other and with nobody else -- version, cipher suite,
// certificate-chain encoding, client-certificate request handling.
//
// What it does NOT establish is SChannel compatibility. See TLS.md for the
// residual risk and the Windows verification checklist that closes it.
//
// Everything above the TLS record layer is the same code the plaintext peer
// runs: ScanPackets / SerializePacket out of packet_model.h, which are the
// verbatim C++ decisions.

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "packet_model.h"

namespace rsl_tls
{

using rsl_packet::OutcomeName;
using rsl_packet::RejectChecksum;
using rsl_packet::RejectHeader;
using rsl_packet::ScanPackets;
using rsl_packet::ScanResult;
using rsl_packet::SerializePacket;

// The TLS 1.2 suites the Rust port pins (rsl_net::tls::tls12_suites), spelled
// the way OpenSSL spells them. This list is the intersection of rustls' TLS 1.2
// suites with SChannel's SCH_USE_STRONG_CRYPTO defaults; keeping the two
// spellings side by side is the only way the pin is checkable from here.
static const char* kCipherList =
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES128-GCM-SHA256";

static void Fail(const char* what)
{
    fprintf(stderr, "tls-peer: %s\n", what);
    ERR_print_errors_fp(stderr);
}

// A context for either role. `caPem` is the trust anchor used to verify the
// peer -- mutual authentication is mandatory in both directions, as
// ASC_REQ_MUTUAL_AUTH makes it in the C++ (SSLImpl.cpp:1113).
static SSL_CTX* MakeContext(bool server, const char* certPem, const char* keyPem,
                            const char* caPem)
{
    SSL_CTX* ctx = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    if (!ctx) { Fail("SSL_CTX_new"); return NULL; }

    // TLS 1.2 exactly: SP_PROT_TLS1_2_CLIENT / _SERVER (SSLImpl.cpp:850, :878).
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) ||
        !SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION))
    {
        Fail("set_proto_version");
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (!SSL_CTX_set_cipher_list(ctx, kCipherList))
    {
        Fail("set_cipher_list");
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_certificate_chain_file(ctx, certPem) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, keyPem, SSL_FILETYPE_PEM) != 1)
    {
        Fail("load own credential");
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_load_verify_locations(ctx, caPem, NULL) != 1)
    {
        Fail("load CA");
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    if (server)
    {
        // Tell the client which CA we will accept a certificate from, the way
        // SChannel's certificate_authorities hint does.
        STACK_OF(X509_NAME)* names = SSL_load_client_CA_file(caPem);
        if (names) { SSL_CTX_set_client_CA_list(ctx, names); }
    }
    return ctx;
}

// Read one chunk into `buf`. False on clean close or error.
static bool ReadSome(SSL* ssl, std::vector<char>* buf)
{
    char tmp[64 * 1024];
    int n = SSL_read(ssl, tmp, (int)sizeof(tmp));
    if (n <= 0) { return false; }
    buf->insert(buf->end(), tmp, tmp + n);
    return true;
}

static bool WriteAll(SSL* ssl, const char* data, size_t len)
{
    size_t off = 0;
    while (off < len)
    {
        int n = SSL_write(ssl, data + off, (int)(len - off));
        if (n <= 0) { return false; }
        off += (size_t)n;
    }
    return true;
}

// The plaintext peer's ServePackets, over a TLS stream.
static bool ServePackets(SSL* ssl, std::vector<char>* buf, bool echo, int* count)
{
    ScanResult r = ScanPackets(buf->data(), buf->size(), 0, 0);
    for (size_t i = 0; i < r.payloads.size(); ++i)
    {
        ++*count;
        fprintf(stderr, "tls-peer: packet %d accepted, payload %zu bytes\n",
                *count, r.payloads[i].size());
        if (echo)
        {
            std::vector<char> frame =
                SerializePacket(r.payloads[i].data(), r.payloads[i].size());
            if (!WriteAll(ssl, frame.data(), frame.size())) { return false; }
        }
    }
    buf->erase(buf->begin(), buf->begin() + r.consumed);

    if (r.outcome == RejectHeader || r.outcome == RejectChecksum)
    {
        fprintf(stderr, "tls-peer: %s (%s) -- closing connection\n",
                OutcomeName(r.outcome), r.detail.c_str());
        return false;
    }
    return true;
}

static void PrintPeerCert(SSL* ssl)
{
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert)
    {
        fprintf(stderr, "tls-peer: peer presented no certificate\n");
        return;
    }
    char name[512];
    X509_NAME_oneline(X509_get_subject_name(cert), name, (int)sizeof(name));
    fprintf(stderr, "tls-peer: negotiated %s / %s with %s\n", SSL_get_version(ssl),
            SSL_get_cipher(ssl), name);
    X509_free(cert);
}

// Drive the packet loop until the peer closes.
static void Pump(SSL* ssl, bool echo)
{
    std::vector<char> buf;
    int count = 0;
    for (;;)
    {
        if (!ServePackets(ssl, &buf, echo, &count)) { break; }
        if (!ReadSome(ssl, &buf))
        {
            ServePackets(ssl, &buf, echo, &count);
            break;
        }
    }
    fprintf(stderr, "tls-peer: %d packet(s) accepted\n", count);
}

// Server: accept one TLS connection and echo packets. Prints "PORT <n>" before
// blocking, exactly as the plaintext peer does.
int RunServer(int port, const char* certPem, const char* keyPem, const char* caPem,
              const char* mode)
{
    bool echo = strcmp(mode, "echo") == 0;
    if (!echo && strcmp(mode, "log") != 0)
    {
        fprintf(stderr, "unknown --tls-peer mode '%s' (echo|log)\n", mode);
        return 2;
    }

    SSL_CTX* ctx = MakeContext(true, certPem, keyPem, caPem);
    if (!ctx) { return 1; }

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) { perror("socket"); SSL_CTX_free(ctx); return 1; }
    int one = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)port);
    if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
        listen(listener, 1) < 0)
    {
        perror("bind/listen");
        close(listener);
        SSL_CTX_free(ctx);
        return 1;
    }
    socklen_t alen = sizeof(addr);
    getsockname(listener, (struct sockaddr*)&addr, &alen);
    printf("PORT %u\n", (unsigned)ntohs(addr.sin_port));
    fflush(stdout);

    int fd;
    do { fd = accept(listener, NULL, NULL); } while (fd < 0 && errno == EINTR);
    close(listener);
    if (fd < 0) { perror("accept"); SSL_CTX_free(ctx); return 1; }
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    int rc = SSL_accept(ssl);
    if (rc != 1)
    {
        Fail("SSL_accept");
        SSL_free(ssl);
        close(fd);
        SSL_CTX_free(ctx);
        return 1;
    }
    PrintPeerCert(ssl);
    Pump(ssl, echo);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);
    return 0;
}

// Client: connect, handshake, send `count` packets carrying `payload`, and
// report every packet echoed back.
int RunClient(const char* host, int port, const char* certPem, const char* keyPem,
              const char* caPem, const char* payload, int count)
{
    SSL_CTX* ctx = MakeContext(false, certPem, keyPem, caPem);
    if (!ctx) { return 1; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1)
    {
        fprintf(stderr, "tls-peer: '%s' is not an IPv4 address\n", host);
        SSL_CTX_free(ctx);
        return 1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); SSL_CTX_free(ctx); return 1; }
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        perror("connect");
        close(fd);
        SSL_CTX_free(ctx);
        return 1;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    // No SNI and no hostname verification: the C++ passes pwszServerName = NULL
    // and validates the certificate itself (SSLImpl.cpp:387).
    if (SSL_connect(ssl) != 1)
    {
        Fail("SSL_connect");
        SSL_free(ssl);
        close(fd);
        SSL_CTX_free(ctx);
        return 1;
    }
    PrintPeerCert(ssl);

    for (int i = 0; i < count; ++i)
    {
        std::vector<char> frame = SerializePacket(payload, strlen(payload));
        if (!WriteAll(ssl, frame.data(), frame.size()))
        {
            Fail("SSL_write");
            break;
        }
    }

    // Read whatever comes back until the peer closes, reporting each packet.
    std::vector<char> buf;
    int echoed = 0;
    while (ReadSome(ssl, &buf))
    {
        ScanResult r = ScanPackets(buf.data(), buf.size(), 0, 0);
        for (size_t i = 0; i < r.payloads.size(); ++i)
        {
            ++echoed;
            fprintf(stderr, "tls-peer: echo %d, payload %zu bytes\n", echoed,
                    r.payloads[i].size());
        }
        buf.erase(buf.begin(), buf.begin() + r.consumed);
        if (r.outcome == RejectHeader || r.outcome == RejectChecksum)
        {
            fprintf(stderr, "tls-peer: %s -- closing\n", OutcomeName(r.outcome));
            break;
        }
        if (echoed >= count) { break; }
    }
    printf("ECHOED %d\n", echoed);
    fflush(stdout);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);
    return echoed == count ? 0 : 1;
}

} // namespace rsl_tls
