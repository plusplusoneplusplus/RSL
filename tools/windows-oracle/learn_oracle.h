#pragma once

namespace rsl_oracle
{
    int RunLearnServer(
        int port,
        const char *directory,
        int connections,
        int version);

    int RunLearnClient(
        const char *host,
        int port,
        const char *mode,
        int version,
        unsigned long long decree,
        unsigned long long size,
        const char *outputFile,
        unsigned int maxBallot);
}
