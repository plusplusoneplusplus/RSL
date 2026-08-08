// Linux prerequisites for the shared storage-format declarations.
//
// The ConfigurationInfo / CheckpointHeader declarations themselves are NOT
// duplicated here: they live in RSL/src/checkpoint.h and are shared verbatim
// with the Windows engine (legislator.h includes the same header), so the
// on-disk .codex layout can never drift between the two builds. This file just
// supplies what that header needs on the rsl-linux-proxy slice and the constants the
// Windows build gets from elsewhere.
//
// checkpoint.h omits CheckpointHeader's Windows-only file/stream entry
// points (Marshal(const char*), UnMarshal(const char*), UnMarshal(StreamReader*),
// SetBytesIssued, GetCheckpointFileName) under #ifdef _WIN32 -- they take types
// that only exist in the engine build. The rsl-linux-proxy driver marshals to /
// unmarshals from an in-memory MarshalData with plain buffered POSIX I/O, so the
// byte-producing methods -- GetMarshalLen(), Marshal(MarshalData*),
// UnMarshal(MarshalData*) -- are all it requires.
#pragma once

#include "msg_engine_compat.h"  // MemberSet, RoundUpToPage, s_PageSize, ...
#include "message.h"            // MemberId, BallotNumber, Vote, RSLProtocolVersion
#include "RefCount.h"           // RefCount, Ptr

#include "checkpoint.h"         // ConfigurationInfo, CheckpointHeader (shared)

namespace RSLibImpl
{
    // On Windows this is a static member of RSLCheckpointStreamReader/Writer
    // (rsl.h); those classes are not part of the Linux slice, so expose the same
    // value at namespace scope for the extracted checkpoint block code.
    static const int CHECKSUM_SIZE = (int)sizeof(unsigned long long);
}
