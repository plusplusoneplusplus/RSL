// packet_min.cpp -- see packet_min.h.
//
// The class methods are copied verbatim from src/NetworkLib/src/NetPacket.cpp
// (line-cited); the free functions are ports that keep every decision and byte
// but swap NetBuffer/BufferPool/StreamSocket for plain buffers, the same way
// storage_min.cpp treats the storage I/O paths.

// System headers first (the compat windows.h shim collides with the POSIX
// headers if it is included first -- same ordering rule as main.cpp).
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "packet_min.h"

#include "marshal.h"
#include "utils.h"

// ---------------------------------------------------------------------------
// PacketHdr -- NetPacket.cpp:19-118, verbatim (LogAssert calls dropped: the
// callers below always pass a >= SerialLen buffer, and this tool must report
// rather than abort).
//
// The golden-gen binary does not link NetPacket.cpp, so we provide the
// PacketHdr method bodies here.  The class itself now lives in PacketHdr.h
// (RSLibImpl namespace); the `using` in packet_min.h brings it into
// rsl_packet.
// ---------------------------------------------------------------------------
namespace RSLibImpl
{

PacketHdr::PacketHdr()
{
    m_Size = 0;
    m_ProtoVersion = 0;
    m_Xid = 0;
    m_Checksum = 0;
}

PacketHdr::PacketHdr(UInt32 size, UInt32 protoVersion, UInt32 xid)
{
    m_Size = size;
    m_ProtoVersion = protoVersion;
    m_Xid = xid;
    m_Checksum = 0;
}

bool PacketHdr::Serialize(void* buffer, UInt32 bufferLength)
{
    MarshalData marshalData(buffer, bufferLength, false);
    marshalData.SetMarshaledLength(0);

    marshalData.WriteUInt32(m_Size);
    marshalData.WriteUInt32(m_ProtoVersion);
    marshalData.WriteUInt32(m_Xid);
    marshalData.WriteUInt64(m_Checksum);
    return true;
}

bool PacketHdr::Serialize(NetBuffer*)
{
    // Unused in the golden-gen slice; the full implementation lives in
    // NetPacket.cpp and depends on NetBuffer.
    return false;
}

void PacketHdr::SetChecksum(UInt64 checksum, void* hdrBuffer, UInt32 bufferLength)
{
    UInt32 offset = sizeof(UInt32) * 3;

    MarshalData marshalData(hdrBuffer, bufferLength, false);
    marshalData.SetMarshaledLength(offset);
    marshalData.WriteUInt64(checksum);
}

bool PacketHdr::DeSerialize(void* buffer, UInt32 bufferLength)
{
    MarshalData marshalData(buffer, bufferLength, false);
    marshalData.SetMarshaledLength(bufferLength);

    if (!marshalData.ReadUInt32(&m_Size) ||
        !marshalData.ReadUInt32(&m_ProtoVersion) ||
        !marshalData.ReadUInt32(&m_Xid) ||
        !marshalData.ReadUInt64(&m_Checksum))
    {
        return false;
    }
    return true;
}

} // namespace RSLibImpl

namespace rsl_packet
{

const char* OutcomeName(Outcome o)
{
    switch (o)
    {
        case Accept:         return "accept";
        case NeedMore:       return "need-more";
        case RejectHeader:   return "reject-header";
        case RejectChecksum: return "reject-checksum";
    }
    return "?";
}

const char* LearnOutcomeName(LearnOutcome o)
{
    switch (o)
    {
        case LearnAccept:      return "accept";
        case LearnShortHeader: return "reject-short-header";
        case LearnBadVersion:  return "reject-version";
        case LearnTooLarge:    return "reject-too-large";
        case LearnShortBody:   return "reject-short-body";
        case LearnBadMessage:  return "reject-unmarshal";
    }
    return "?";
}

// Packet::Serialize -- NetPacket.cpp:389-412. The PacketMarshalMemoryManager
// keeps the header and the payload in one contiguous buffer with the header
// first; a vector<char> laid out the same way is byte-identical.
std::vector<char> SerializePacket(const void* payload, size_t payloadLen,
                                  UInt32 protoVersion, UInt32 xid)
{
    std::vector<char> frame(SerialLen + payloadLen);
    if (payloadLen > 0)
    {
        memcpy(frame.data() + SerialLen, payload, payloadLen);
    }

    PacketHdr hdr;
    hdr.m_ProtoVersion = protoVersion;
    hdr.m_Xid = xid;

    // this->m_Hdr.m_Size = PacketHdr::SerialLen + GetValidLength();
    hdr.m_Size = SerialLen + (UInt32)payloadLen;
    hdr.m_Checksum = 0;
    hdr.Serialize(frame.data(), SerialLen);

    // Checksum covers the whole packet -- header (with a zero checksum field)
    // plus payload -- i.e. GetPacketLength() == m_Size bytes.
    UInt64 checksum = Utils::CalculateChecksum(frame.data(), (size_t)frame.size());
    PacketHdr::SetChecksum(checksum, frame.data(), SerialLen);
    return frame;
}

// Packet::DeSerializeHeader(void*, UInt32) -- NetPacket.cpp:450-477. The
// DynString hex dump and the two Log() calls become `detail` text.
bool DeSerializeHeader(PacketHdr* hdr, const void* buffer, UInt32 bufferLength,
                       UInt32 maxSize, UInt32 maxAlertSize, std::string* detail)
{
    // Packet's constructor: `m_MaxPacketSize((maxSize) ? maxSize : MaxNetPacketSize)`
    // (NetPacket.cpp:302-305) -- zero means "use the header default".
    UInt32 maxPacketSize = maxSize ? maxSize : MaxNetPacketSize;
    UInt32 maxPacketAlertSize = maxAlertSize ? maxAlertSize : MaxNetPacketAlertSize;

    if (!hdr->DeSerialize(const_cast<void*>(buffer), bufferLength))
    {
        if (detail) { *detail = "header deserialize failed"; }
        return false;
    }

    if (maxPacketAlertSize > 0 && hdr->m_Size > maxPacketAlertSize)
    {
        // Log(..., LogLevel_Alert, "Malformed Packet", ...) -- alert only, the
        // packet is *not* rejected on this path.
        if (detail)
        {
            char buf[128];
            snprintf(buf, sizeof(buf), "alert: size %u > alert size %u; ",
                     (unsigned)hdr->m_Size, (unsigned)maxPacketAlertSize);
            *detail += buf;
        }
    }
    if (hdr->m_Size < SerialLen || hdr->m_Size > maxPacketSize)
    {
        if (detail)
        {
            char buf[128];
            snprintf(buf, sizeof(buf), "invalid packet size %u (min %u max %u)",
                     (unsigned)hdr->m_Size, (unsigned)SerialLen, (unsigned)maxPacketSize);
            *detail += buf;
        }
        return false;
    }
    return true;
}

// Packet::VerifyChecksum -- NetPacket.cpp:502-521, over a full frame that has
// already been header-validated (so frame length == m_Size).
static bool VerifyChecksum(const PacketHdr& hdr, const char* frame, size_t frameLen,
                           UInt64* computed)
{
    std::vector<char> copy(frame, frame + frameLen);
    PacketHdr::SetChecksum(0, copy.data(), SerialLen);
    UInt64 newChecksum = Utils::CalculateChecksum(copy.data(), (size_t)frameLen);
    if (computed) { *computed = newChecksum; }
    return hdr.m_Checksum == newChecksum;
}

// NetCxn::ReadReadyInternal -- NetCxn.cpp:177-250. The loop, the two
// CloseConnection() exits, and the "not a full packet yet" break are the whole
// receive decision table.
ScanResult ScanPackets(const char* data, size_t len, UInt32 maxSize, UInt32 maxAlertSize)
{
    ScanResult res;
    res.outcome = NeedMore;
    res.consumed = 0;

    size_t off = 0;
    while (len - off >= (size_t)SerialLen)
    {
        PacketHdr hdr;
        std::string detail;
        if (!DeSerializeHeader(&hdr, data + off, SerialLen, maxSize, maxAlertSize, &detail))
        {
            // "Invalid packet" -> CloseConnection(); return;
            res.outcome = RejectHeader;
            res.rejected = hdr;
            res.detail += detail;
            return res;
        }

        res.detail += detail; // carries the "alert size exceeded" note, if any

        UInt32 packetLength = hdr.m_Size;
        if ((size_t)packetLength > len - off)
        {
            // Header is valid but the body has not arrived; wait for more data.
            break;
        }

        UInt64 computed = 0;
        if (!VerifyChecksum(hdr, data + off, packetLength, &computed))
        {
            // pktValid == false -> "Invalid packet" -> CloseConnection(); return;
            char buf[160];
            snprintf(buf, sizeof(buf), "checksum mismatch: header %016llx computed %016llx",
                     (unsigned long long)hdr.m_Checksum, (unsigned long long)computed);
            res.outcome = RejectChecksum;
            res.rejected = hdr;
            res.detail += buf;
            return res;
        }

        res.payloads.push_back(std::vector<char>(data + off + SerialLen,
                                                 data + off + packetLength));
        off += packetLength;
        res.consumed = off;
        res.outcome = Accept;
    }

    if (off < len && res.outcome == Accept)
    {
        // Accepted packets followed by a partial one: the connection stays open.
        res.outcome = NeedMore;
    }
    return res;
}

// Message::ReadFromSocket -- message.cpp:639-689, with StreamSocket::Read
// replaced by a cursor over `data`. StreamSocket::Read fills the whole request
// or reports bytesRead < requested; both are rejected identically there, so a
// short buffer here maps to the same `bytesRead != requested` branch.
LearnResult ReadMessage(const char* data, size_t len, UInt32 maxMessageSize, Message* out)
{
    LearnResult res;
    res.outcome = LearnShortHeader;
    res.version = 0;
    res.length = 0;

    const UInt32 HeaderSize = LearnHeaderSize;

    if (len < (size_t)HeaderSize)
    {
        res.detail = "short read of the 6-byte header";
        return res;
    }

    char header[LearnHeaderSize];
    memcpy(header, data, HeaderSize);

    MarshalData marshal(header, HeaderSize, false);
    marshal.SetMarshaledLength(HeaderSize);

    UInt16 version = 0;
    UInt32 length = 0;
    if (!marshal.ReadUInt16(&version) ||
        !marshal.ReadUInt32(&length) ||
        !Message::IsVersionValid(version))
    {
        res.outcome = LearnBadVersion;
        res.version = version;
        res.length = length;
        res.detail = "unknown message version";
        return res;
    }
    res.version = version;
    res.length = length;

    if (length > maxMessageSize)
    {
        res.outcome = LearnTooLarge;
        res.detail = "discarding large message";
        return res;
    }

    // The original allocates `length` bytes here and memcpy's the 6-byte header
    // into it. For length < HeaderSize that memcpy overflows the allocation, so
    // this port refuses the length instead of reproducing the overflow; the
    // corpus records such vectors as not-executed (see main.cpp).
    if (length < HeaderSize)
    {
        res.outcome = LearnShortBody;
        res.detail = "length below the 6-byte header (C++ would overflow its buffer)";
        return res;
    }

    if (len < (size_t)length)
    {
        res.outcome = LearnShortBody;
        res.detail = "short read of the message body";
        return res;
    }

    std::vector<char> msgBuf(data, data + length);
    if (!out->UnMarshalBuf(msgBuf.data(), length))
    {
        res.outcome = LearnBadMessage;
        res.detail = "failed to unmarshal message";
        return res;
    }

    res.outcome = LearnAccept;
    res.detail = "ok";
    return res;
}

// ---------------------------------------------------------------------------
// Live peer
// ---------------------------------------------------------------------------
namespace
{

// Read up to `want` bytes, appending to `buf`. Returns false on EOF/error.
bool ReadSome(int fd, std::vector<char>* buf, size_t want)
{
    char tmp[64 * 1024];
    if (want > sizeof(tmp)) { want = sizeof(tmp); }
    ssize_t n;
    do { n = recv(fd, tmp, want, 0); } while (n < 0 && errno == EINTR);
    if (n <= 0) { return false; }
    buf->insert(buf->end(), tmp, tmp + n);
    return true;
}

bool WriteAll(int fd, const char* data, size_t len)
{
    size_t off = 0;
    while (off < len)
    {
        ssize_t n;
        do { n = send(fd, data + off, len - off, 0); } while (n < 0 && errno == EINTR);
        if (n <= 0) { return false; }
        off += (size_t)n;
    }
    return true;
}

// NetPacket framing: consume whole packets out of `buf` with the real C++ path.
// Returns false when the connection must be closed (the C++ CloseConnection).
bool ServePackets(int fd, std::vector<char>* buf, bool echo, int* packetCount)
{
    ScanResult r = ScanPackets(buf->data(), buf->size(), 0, 0);
    for (size_t i = 0; i < r.payloads.size(); ++i)
    {
        ++*packetCount;
        fprintf(stderr, "peer: packet %d accepted, payload %zu bytes\n",
                *packetCount, r.payloads[i].size());
        if (echo)
        {
            std::vector<char> frame =
                SerializePacket(r.payloads[i].data(), r.payloads[i].size());
            if (!WriteAll(fd, frame.data(), frame.size())) { return false; }
        }
    }
    buf->erase(buf->begin(), buf->begin() + r.consumed);

    if (r.outcome == RejectHeader || r.outcome == RejectChecksum)
    {
        fprintf(stderr, "peer: %s (%s) -- closing connection\n",
                OutcomeName(r.outcome), r.detail.c_str());
        return false;
    }
    return true;
}

// NetPacket framing: echo the first packet, then answer the second with only
// half a frame and close. This is a peer that dies mid-packet -- the receiver
// must treat it as a disconnect, not as a framing error, and must not surface
// the half packet.
void ServeTruncate(int fd)
{
    std::vector<char> buf;
    int count = 0;
    for (;;)
    {
        ScanResult r = ScanPackets(buf.data(), buf.size(), 0, 0);
        for (size_t i = 0; i < r.payloads.size(); ++i)
        {
            std::vector<char> frame =
                SerializePacket(r.payloads[i].data(), r.payloads[i].size());
            if (++count == 1)
            {
                if (!WriteAll(fd, frame.data(), frame.size())) { return; }
                continue;
            }
            size_t half = frame.size() / 2;
            fprintf(stderr, "peer: writing %zu of %zu bytes then closing\n",
                    half, frame.size());
            WriteAll(fd, frame.data(), half);
            return;
        }
        buf.erase(buf.begin(), buf.begin() + r.consumed);
        if (r.outcome == RejectHeader || r.outcome == RejectChecksum)
        {
            fprintf(stderr, "peer: %s (%s) -- closing connection\n",
                    OutcomeName(r.outcome), r.detail.c_str());
            return;
        }
        if (!ReadSome(fd, &buf, 64 * 1024)) { return; }
    }
}

// Learn-port framing: read one Message and answer with a StatusResponse.
void ServeFetchStub(int fd)
{
    std::vector<char> buf;
    Message request;
    for (;;)
    {
        LearnResult r = ReadMessage(buf.data(), buf.size(), DefaultMaxMessageSize, &request);
        if (r.outcome == LearnAccept)
        {
            fprintf(stderr, "peer: learn message accepted, version %u length %u msgId %u\n",
                    (unsigned)r.version, (unsigned)r.length, (unsigned)request.m_msgId);
            break;
        }
        // Short header/body just means "not all the bytes are here yet"; every
        // other outcome is a hard reject.
        if (r.outcome != LearnShortHeader && r.outcome != LearnShortBody)
        {
            fprintf(stderr, "peer: learn %s (%s) -- closing connection\n",
                    LearnOutcomeName(r.outcome), r.detail.c_str());
            return;
        }
        if (!ReadSome(fd, &buf, 64 * 1024))
        {
            fprintf(stderr, "peer: connection closed before a full learn message\n");
            return;
        }
    }

    StatusResponse response((RSLProtocolVersion)request.m_version, request.m_memberId,
                            request.m_decree, request.m_configurationNumber, request.m_ballot);
    response.m_queryDecree = request.m_decree;
    response.m_queryBallot = request.m_ballot;
    response.m_lastReceivedAgo = 0;
    response.m_minDecreeInLog = 1;
    response.m_checkpointedDecree = 0;
    response.m_checkpointSize = 0;
    response.m_maxBallot = request.m_ballot;
    response.m_state = 0;

    // Same sequence as main.cpp's MarshalWithChecksum: marshal, then patch the
    // Rabin-64 over everything after the 8-byte checksum field.
    UInt32 len = response.GetMarshalLen();
    std::vector<char> out(len);
    FixedMarshalMemoryManager manager(out.data(), len);
    MarshalData marshal(&manager);
    response.Marshal(&marshal);
    UInt32 mlen = marshal.GetMarshaledLength();
    out.resize(mlen);
    UInt32 dataOffset = s_ChecksumOffset + sizeof(UInt64);
    UInt64 checksum = Utils::CalculateChecksum(out.data() + dataOffset, mlen - dataOffset);
    FixedMarshalMemoryManager cmanager(out.data() + s_ChecksumOffset, mlen - s_ChecksumOffset);
    MarshalData cmarshal(&cmanager);
    cmarshal.WriteUInt64(checksum);
    len = mlen;

    // The learn port carries the bare marshaled message: its own first 6 bytes
    // (version + length) are the framing.
    WriteAll(fd, out.data(), out.size());
    fprintf(stderr, "peer: sent StatusResponse (%u bytes)\n", (unsigned)len);
}

} // namespace

int RunPeer(int port, const char* mode)
{
    bool echo = strcmp(mode, "echo") == 0;
    bool log = strcmp(mode, "log") == 0;
    bool fetch = strcmp(mode, "fetch-stub") == 0;
    bool truncate = strcmp(mode, "truncate") == 0;
    if (!echo && !log && !fetch && !truncate)
    {
        fprintf(stderr,
                "unknown --packet-peer mode '%s' (echo|log|fetch-stub|truncate)\n", mode);
        return 2;
    }

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)port);
    if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        close(listener);
        return 1;
    }
    if (listen(listener, 1) < 0)
    {
        perror("listen");
        close(listener);
        return 1;
    }

    socklen_t alen = sizeof(addr);
    if (getsockname(listener, (struct sockaddr*)&addr, &alen) < 0)
    {
        perror("getsockname");
        close(listener);
        return 1;
    }
    // Announce the (possibly ephemeral) port before blocking in accept(), so a
    // harness can start this without racing on a fixed port.
    printf("PORT %u\n", (unsigned)ntohs(addr.sin_port));
    fflush(stdout);

    int fd;
    do { fd = accept(listener, NULL, NULL); } while (fd < 0 && errno == EINTR);
    close(listener);
    if (fd < 0) { perror("accept"); return 1; }
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    if (fetch)
    {
        ServeFetchStub(fd);
    }
    else if (truncate)
    {
        ServeTruncate(fd);
    }
    else
    {
        std::vector<char> buf;
        int packetCount = 0;
        for (;;)
        {
            if (!ServePackets(fd, &buf, echo, &packetCount)) { break; }
            if (!ReadSome(fd, &buf, 64 * 1024))
            {
                // EOF: drain whatever completed packets are already buffered.
                ServePackets(fd, &buf, echo, &packetCount);
                break;
            }
        }
        fprintf(stderr, "peer: %d packet(s) accepted\n", packetCount);
    }

    close(fd);
    return 0;
}

} // namespace rsl_packet
