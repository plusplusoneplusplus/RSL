#pragma once

namespace rsl_oracle
{
    int RunNetworkServer(int port, const char *mode, int count, bool waitForDisconnect);
    int RunNetworkClient(
        const char *host,
        int port,
        const char *payloadHex,
        int count,
        const char *expect,
        bool reconnectEach);
}
