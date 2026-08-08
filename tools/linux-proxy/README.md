# RSL Linux supplemental proxy

`rsl-linux-proxy` is a Linux-only model used for fast portable tests. It is not
an implementation or oracle for production Windows storage, IOCP networking,
learn-port state transfer, or SChannel.

The production authority is
[`tools/windows-oracle`](../windows-oracle/README.md). Windows CI generates
versioned, hashed authority artifacts; Linux Rust CI downloads and consumes
those artifacts before running the proxy tests described here.

## Scope

The tool combines two kinds of code:

- selected production wire translation units: Rabin-64 fingerprinting,
  `MarshalData`, utility checksums, and message marshaling;
- copied or ported Linux models for member-set dependencies, storage,
  packet receive behavior, learn transfer, POSIX sockets/files, and an
  optional OpenSSL peer.

The proxy models provide distinct coverage for deterministic vector generation,
POSIX filesystem semantics, malformed-input decisions, bidirectional socket
conversations, and a TLS stack other than rustls. Their outcomes are evidence
about the model only. They do not establish production Windows decisions.

## Build

```sh
cmake -S tools/linux-proxy -B tools/linux-proxy/build
cmake --build tools/linux-proxy/build -j
```

The executable is `tools/linux-proxy/build/rsl-linux-proxy`.
Install `libssl-dev` to enable the supplemental OpenSSL commands.

## Commands

```sh
# Deterministic wire/container/model vectors.
./tools/linux-proxy/build/rsl-linux-proxy \
  > tools/linux-proxy/corpus/proxy-vectors.txt

# Linux storage-model corpus and reverse model verification.
./tools/linux-proxy/build/rsl-linux-proxy --storage <directory>
./tools/linux-proxy/build/rsl-linux-proxy --verify-storage <directory>

# Packet receive-model peer.
./tools/linux-proxy/build/rsl-linux-proxy --packet-peer 0 --mode echo
./tools/linux-proxy/build/rsl-linux-proxy --packet-peer 0 --mode log

# Ported learn model in both directions.
./tools/linux-proxy/build/rsl-linux-proxy \
  --learn-server 0 --dir <directory> --connections 3
./tools/linux-proxy/build/rsl-linux-proxy \
  --learn-client 127.0.0.1 <port> --mode status
./tools/linux-proxy/build/rsl-linux-proxy \
  --learn-client 127.0.0.1 <port> --mode votes --decree 101
./tools/linux-proxy/build/rsl-linux-proxy \
  --learn-client 127.0.0.1 <port> --mode checkpoint \
  --decree 500 --size <bytes> --out copy.codex

# Supplemental mutual TLS 1.2 over OpenSSL.
./tools/linux-proxy/build/rsl-linux-proxy \
  --tls-peer 0 --cert <chain.pem> --key <key.pem> --ca <root.pem> --mode echo
./tools/linux-proxy/build/rsl-linux-proxy \
  --tls-client 127.0.0.1 <port> \
  --cert <chain.pem> --key <key.pem> --ca <root.pem>
```

Servers print `PORT <n>` before accepting. `--verify-storage` exits `0` when
every file is accepted or reaches a tolerated model stop, `3` when any file is
rejected, and `1` for I/O failure.

## Corpora

`corpus/proxy-vectors.txt` contains deterministic wire, fingerprint, container,
packet-model, and learn-model vectors. Wire message bytes come from production
marshaling translation units; packet and learn outcomes come from proxy models.

`corpus/storage/MANIFEST.json` records Linux storage-model file hashes and
outcomes. The generated binaries are ignored because large Windows authority
corpora are published separately as workflow artifacts.

## Limitations

- No production Windows unbuffered/overlapped storage I/O.
- No `Packet`, `NetCxn`, `NetPacketSvc`, Winsock, or IOCP execution.
- No production Legislator state, log selection, or checkpoint rewrite.
- No SChannel/CryptoAPI. OpenSSL is supplemental foreign-stack coverage only.
- Deterministic zero-filled padding differs from literal Windows allocator
  padding where the format permits either.

Rust tests that require production behavior use `RSLWindowsOracle`. Optional
local proxy tests use `RSL_LINUX_PROXY` and print a precise skip reason when the
proxy is not built. CI always provides both.
