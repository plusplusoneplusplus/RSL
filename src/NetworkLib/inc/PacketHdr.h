#pragma once

//
// PacketHdr.h
//      The 20-byte wire header shared by the full NetworkLib (NetPacket.h) and
//      the supplemental Linux proxy model (packet_model.h).
//
//      Only depends on basic_types.h -- no sockets, no BufferPool, no NetBuffer.
//

#include "basic_types.h"

namespace RSLibImpl
{

const UInt32 MaxNetPacketSize = 100 * 1024 * 1024;       // 100MB - max packet size
const UInt32 MaxNetPacketAlertSize = 0;                  // 0 means no alert

class NetBuffer;

class PacketHdr
{
public:

    // IMPORTANT: Update SerialLen and SetChecksum if you add or remove fields.
    UInt32  m_Size;
    UInt32  m_ProtoVersion;
    UInt32  m_Xid;
    UInt64  m_Checksum;

    static const UInt32 SerialLen = sizeof(UInt32) * 3 + sizeof(UInt64);

    PacketHdr();
    PacketHdr(UInt32 size, UInt32 protoVersion, UInt32 xid);

    bool Serialize(void *buffer, UInt32 bufferLength);
    bool Serialize(NetBuffer *netBuf);

    static void SetChecksum(UInt64 checksum, void *hdrBuffer,
                    UInt32 bufferLength);

    bool DeSerialize(void *buffer, UInt32 bufferLength);
};

} // namespace RSLibImpl
