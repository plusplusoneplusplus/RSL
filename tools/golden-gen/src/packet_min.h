// packet_min.h -- Phase-4a extract of the RSL wire *framing* layer.
//
// Two independent framings live in the original code, and this header exposes
// both over plain byte buffers (no IOCP, no BufferPool, no sockets in the core
// entry points):
//
//   1. The 20-byte NetPacket frame (`PacketHdr` + payload) used by
//      NetPacketSvc for all replica-to-replica traffic.
//      Source: src/NetworkLib/inc/NetPacket.h, src/NetworkLib/src/NetPacket.cpp,
//              src/NetworkLib/src/NetCxn.cpp (the read loop's decision table).
//
//   2. The "learn port" framing used by the fetch/status TCP sockets, where a
//      message is preceded by nothing at all -- its own first 6 bytes
//      (UInt16 version + UInt32 length) are read first and used to size the
//      rest of the read.
//      Source: Message::ReadFromSocket, src/RSL/src/message.cpp:639.
//
// As with storage_min.h (Phase 3a), the *decisions* are copied verbatim and
// line-cited; only the buffer plumbing is replaced (NetBuffer/Buffer pool ->
// std::vector<char>, StreamSocket -> a byte cursor). The bytes produced and
// consumed, and every accept/reject outcome, are unchanged.
#pragma once

#include <string>
#include <vector>

#include "PacketHdr.h"
#include "message.h"

namespace rsl_packet
{

// PacketHdr, MaxNetPacketSize, MaxNetPacketAlertSize are defined in
// PacketHdr.h (RSLibImpl namespace) and pulled in by the using-directive below.
using namespace RSLibImpl;

const UInt32 SerialLen = PacketHdr::SerialLen;

// The checksum field's offset inside the serialized header (PacketHdr::SetChecksum,
// NetPacket.cpp:79: `UInt32 offset = sizeof(UInt32) * 3;`).
const UInt32 ChecksumOffset = 12;

// RSLConfig::s_MaxMessageLen (rslconfig.h:62) fed through ConfigParam::Init
// (rslconfig.cpp:118-119): MB * 1024 * 1024 + 1024.
const UInt32 DefaultMaxMessageSize = 100u * 1024 * 1024 + 1024;

// Message::ReadFromSocket's `const int HeaderSize = 6;` (message.cpp:641).
const UInt32 LearnHeaderSize = 6;

// Packet::Serialize (NetPacket.cpp:389) over a plain payload buffer: builds the
// full frame (header + payload) with m_Size and the Rabin-64 checksum filled in.
// m_ProtoVersion/m_Xid are never assigned by RSL (PacketHdr's constructor zeroes
// them and nothing else writes them), so they go out as zeroes -- but they are
// still covered by the checksum.
std::vector<char> SerializePacket(const void* payload, size_t payloadLen,
                                  UInt32 protoVersion = 0, UInt32 xid = 0);

// The executed outcome of feeding a byte stream to the C++ receive path.
enum Outcome
{
    // A complete, valid packet (or run of packets) was accepted.
    Accept,
    // Bytes remain but do not yet form a complete packet: the connection stays
    // open waiting for more (NetCxn.cpp:186 `while (ReadAvail() >= SerialLen)`
    // and the `packetLength <= ReadAvail()` guard at NetCxn.cpp:210).
    NeedMore,
    // Packet::DeSerializeHeader returned false -> NetCxn::CloseConnection
    // (NetCxn.cpp:193-206). Never a resync: the connection dies.
    RejectHeader,
    // Packet::DeSerialize (i.e. VerifyChecksum) returned false -> CloseConnection
    // (NetCxn.cpp:217-229).
    RejectChecksum
};

const char* OutcomeName(Outcome o);

struct ScanResult
{
    Outcome outcome;
    // Payloads of the packets accepted before the stream ended or was rejected.
    std::vector<std::vector<char> > payloads;
    // Bytes consumed by those accepted packets.
    size_t consumed;
    // The header of the packet that caused a reject (valid only for Reject*).
    PacketHdr rejected;
    std::string detail;
};

// Packet::DeSerializeHeader(void*, UInt32) -- NetPacket.cpp:450, verbatim apart
// from the logging. `maxSize`/`maxAlertSize` are the PacketFactory's
// m_MaxPacketSize / m_MaxPacketAlertSize (legislator.cpp:6372 passes
// RSLConfig::MaxMessageSize() / MaxMessageAlertSize()); zero means "use the
// NetPacket.h default", exactly as the Packet constructor does.
bool DeSerializeHeader(PacketHdr* hdr, const void* buffer, UInt32 bufferLength,
                       UInt32 maxSize, UInt32 maxAlertSize, std::string* detail);

// NetCxn::ReadReadyInternal (NetCxn.cpp:177-250): the whole receive decision
// table, including several packets per read buffer.
ScanResult ScanPackets(const char* data, size_t len, UInt32 maxSize, UInt32 maxAlertSize);

// ---------------------------------------------------------------------------
// Learn-port framing -- Message::ReadFromSocket (message.cpp:639)
// ---------------------------------------------------------------------------
enum LearnOutcome
{
    LearnAccept,
    // socket->Read of the 6-byte header returned short (message.cpp:648-654).
    LearnShortHeader,
    // !Message::IsVersionValid (message.cpp:658-664).
    LearnBadVersion,
    // length > maxMessageSize (message.cpp:666-670).
    LearnTooLarge,
    // socket->Read of the body returned short (message.cpp:675-681).
    LearnShortBody,
    // UnMarshalBuf failed (message.cpp:682-686).
    LearnBadMessage
};

const char* LearnOutcomeName(LearnOutcome o);

struct LearnResult
{
    LearnOutcome outcome;
    UInt16 version;
    UInt32 length;
    std::string detail;
};

// Message::ReadFromSocket with the StreamSocket replaced by a byte cursor: a
// read of n bytes succeeds only if n bytes remain, mirroring StreamSocket::Read's
// read-fully contract (a short read there sets bytesRead < n and is rejected).
//
// `out` is unmarshaled into on LearnAccept. Note that ReadFromSocket does *not*
// verify the message checksum -- only Message::UnMarshal runs -- so neither does
// this.
LearnResult ReadMessage(const char* data, size_t len, UInt32 maxMessageSize, Message* out);

// ---------------------------------------------------------------------------
// Live peer (blocking, single-threaded, Linux-only)
// ---------------------------------------------------------------------------
// Serves exactly one connection on `port` (0 = pick an ephemeral port), then
// returns. The chosen port is printed to stdout as "PORT <n>\n" and flushed
// before the accept, so a test harness can start it without a fixed port.
//
//   echo       -- NetPacket framing: read packets with the real C++ path and
//                 write each accepted payload back as a freshly serialized packet.
//   log        -- NetPacket framing: read and report, never respond.
//   fetch-stub -- learn-port framing: read one Message with the real
//                 ReadFromSocket decision table and reply with a marshaled
//                 StatusResponse echoing the request's decree/ballot.
int RunPeer(int port, const char* mode);

} // namespace rsl_packet
