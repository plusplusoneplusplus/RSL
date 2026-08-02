// Minimal stand-in for NetworkLib/inc/NetPacket.h, for the golden-gen slice.
//
// marshal.h derives MarshalMemoryManager from IMarshalMemoryManager, which is
// declared in NetPacket.h. That header otherwise drags in the whole networking
// stack (NetBuffer/BufferPool/PacketUtil), so we reproduce just the one
// abstract base class here, verbatim.
#pragma once

#include "basic_types.h"

namespace RSLibImpl
{

class IMarshalMemoryManager
{
public:
    virtual UInt32 GetBufferLength() = 0;
    virtual void* GetBuffer() = 0;
    virtual void EnsureBuffer(UInt32 writePtr, UInt32 lengthDelta) = 0;
    virtual void ResizeBuffer(UInt32 length) = 0;
    virtual UInt32 GetReadPointer() = 0;
    virtual void SetReadPointer(UInt32 readPointer) = 0;
    virtual UInt32 GetValidLength() = 0;
    virtual void SetValidLength(UInt32 validLength) = 0;
    virtual ~IMarshalMemoryManager() {};
};

} // namespace RSLibImpl
