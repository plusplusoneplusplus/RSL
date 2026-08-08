#pragma once

namespace rsl_oracle
{
    int RunNetworkServer(
        int port,
        const char *mode,
        int count,
        bool waitForDisconnect,
        const char *rotateThumbprintA,
        const char *rotateThumbprintB,
        bool validateChain,
        bool checkRevocation);
    int RunNetworkClient(
        const char *host,
        int port,
        const char *payloadHex,
        int count,
        const char *expect,
        bool reconnectEach);
}
