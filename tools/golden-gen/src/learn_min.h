// learn_min.h -- Phase-4c extract of the RSL *learn port*: the state-transfer
// protocols (StatusQuery / FetchVotes / FetchCheckpoint) a lagging replica uses
// to catch up.
//
// Source: src/RSL/src/legislator.cpp --
//   server  FetchServerLoop        :5300
//           HandleFetchRequest     :5330
//           HandleStatusQueryMsg   :3300
//           HandleFetchVotesMsg    :3633
//           HandleFetchCheckpointMsg :3681
//           SendFile               :4484
//   client  SendStatusRequestMessage / the status+copy loop :1367
//           LearnVotes             :3719
//           ReadNextMessage        :3851
//           CopyCheckpoint         :5485
//
// As in packet_min.h and storage_min.h, the *decisions* are the original's,
// line-cited; only the plumbing is replaced. Specifically:
//
//   * StreamSocket        -> a raw POSIX fd with blocking read/write helpers.
//   * APSEQREAD/APSEQWRITE (unbuffered overlapped Windows I/O) -> stdio reads
//     and writes. The snapshot semantics are preserved exactly: SendFile takes
//     the file's size ONCE, when it opens it (APSEQREAD::DoInit,
//     apdiskio.cpp:146, feeding `length = reader->FileSize() - offset` at
//     legislator.cpp:4515), and never looks at it again.
//   * The Legislator's in-memory m_logFiles vector -> the log files found in a
//     directory, indexed by re-running rsl_storage::ScanLog (itself the verbatim
//     ReadNextMessage recovery loop) over each one. The decree->offset mapping
//     that comes out is LogFile::m_decreeOffsets by construction.
//
// Both entry points speak the real wire protocol over a real socket, so they
// can be pointed at the Rust implementation in either direction.
#pragma once

#include "message.h"

#include <string>

namespace rsl_learn
{
    using namespace RSLib;
    using namespace RSLibImpl;

    // ---------------------------------------------------------------------
    // Server -- FetchServerLoop + HandleFetchRequest over `dir`
    // ---------------------------------------------------------------------
    // Serves the log and checkpoint files in `dir` on `port` (0 = ephemeral,
    // announced as "PORT <n>\n" on stdout before the accept, like RunPeer).
    // Handles `connections` connections, one after another, then returns.
    //
    // The engine state the handlers consult (m_checkpointedDecree,
    // m_logFiles.front()->m_minDecree, m_maxAcceptedVote) is derived from the
    // directory: the newest <decree>.codex is the checkpointed decree, and the
    // logs supply the decree range.
    int RunServer(int port, const char* dir, int connections);

    // ---------------------------------------------------------------------
    // Client -- the three catch-up paths
    // ---------------------------------------------------------------------
    // mode:
    //   "status"     -- one StatusQuery; prints
    //                   "STATUS minDecree=<n> checkpointDecree=<n>
    //                    checkpointSize=<n> decree=<n>".
    //   "votes"      -- FetchVotes(decree) and run the ReadNextMessage loop
    //                   (restore=false) over the response; prints one
    //                   "VOTE msgId=<n> decree=<n> len=<n> checksum=<hex>" line
    //                   per record, then "VOTES <count>" or "ERROR <detail>".
    //   "checkpoint" -- FetchCheckpoint(decree), copy `size` bytes to `outFile`,
    //                   verify it (VerifyCheckpointFile) and print
    //                   "CHECKPOINT size=<n> fp64=<hex> outcome=<accept|reject>".
    //
    // Returns 0 when the protocol ran to completion, 1 otherwise -- and prints
    // "ERROR <detail>" in the failure cases, including the silent-close ones
    // (an empty response stream is reported as "ERROR closed").
    int RunClient(const char* host, int port, const char* mode,
                  UInt64 decree, UInt64 size, const char* outFile);
}
