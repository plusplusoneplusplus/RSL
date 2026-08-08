// learn_model.cpp -- see learn_model.h.
//
// Handlers and client loops are line-cited ports of selected Legislator paths.
// POSIX socket/file plumbing and directory-derived state make this a model, not
// the shipping learn implementation.

// System headers first (the compat windows.h shim collides with the POSIX
// headers if it is included first -- same ordering rule as packet_model.cpp).
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <arpa/inet.h>
#include <dirent.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <vector>

#include "learn_model.h"

#include "packet_model.h"    // ReadMessage (Message::ReadFromSocket's decisions)
#include "storage_model.h"   // ScanLog, VerifyCheckpointFile
#include "fingerprint.h"
#include "marshal.h"
#include "msg_engine_compat.h"
#include "utils.h"

namespace rsl_learn
{
namespace
{

// ---------------------------------------------------------------------------
// Socket plumbing (StreamSocket's read-fully / write-fully contract)
// ---------------------------------------------------------------------------

bool WriteAll(int fd, const void* data, size_t len)
{
    const char* p = (const char*)data;
    size_t off = 0;
    while (off < len)
    {
        ssize_t n;
        do { n = send(fd, p + off, len - off, 0); } while (n < 0 && errno == EINTR);
        if (n <= 0) { return false; }
        off += (size_t)n;
    }
    return true;
}

// Read exactly `len` bytes. Returns the number read; a short return is EOF,
// which is how StreamSocket::Read reports a peer that closed.
size_t ReadFully(int fd, void* data, size_t len)
{
    char* p = (char*)data;
    size_t off = 0;
    while (off < len)
    {
        ssize_t n;
        do { n = recv(fd, p + off, len - off, 0); } while (n < 0 && errno == EINTR);
        if (n <= 0) { break; }
        off += (size_t)n;
    }
    return off;
}

// Read up to `want` more bytes onto `buf`. False on EOF/error.
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

int Listen(int port, unsigned short* chosen)
{
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) { perror("socket"); return -1; }
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
        return -1;
    }
    // BindAndListen(port, 1024, ...) -- legislator.cpp:6395.
    if (listen(listener, 1024) < 0)
    {
        perror("listen");
        close(listener);
        return -1;
    }
    socklen_t alen = sizeof(addr);
    if (getsockname(listener, (struct sockaddr*)&addr, &alen) < 0)
    {
        perror("getsockname");
        close(listener);
        return -1;
    }
    *chosen = ntohs(addr.sin_port);
    return listener;
}

int Connect(const char* host, int port)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) { return -1; }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { return -1; }
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        close(fd);
        return -1;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return fd;
}

// ---------------------------------------------------------------------------
// Marshaling a message onto the learn port
// ---------------------------------------------------------------------------
// The learn port carries the bare marshaled message: its own first 6 bytes
// (version + length) are the framing. Same sequence as main.cpp's
// MarshalWithChecksum -- marshal, then patch the Rabin-64 over everything after
// the 8-byte checksum field (Message::CalculateChecksum).
std::vector<char> MarshalWithChecksum(Message& msg)
{
    UInt32 len = msg.GetMarshalLen();
    std::vector<char> out(len);
    FixedMarshalMemoryManager manager(out.data(), len);
    MarshalData marshal(&manager);
    msg.Marshal(&marshal);
    UInt32 mlen = marshal.GetMarshaledLength();
    out.resize(mlen);

    UInt32 dataOffset = s_ChecksumOffset + sizeof(UInt64);
    UInt64 checksum = Utils::CalculateChecksum(out.data() + dataOffset, mlen - dataOffset);
    FixedMarshalMemoryManager cmanager(out.data() + s_ChecksumOffset,
                                       mlen - s_ChecksumOffset);
    MarshalData cmarshal(&cmanager);
    cmarshal.WriteUInt64(checksum);
    return out;
}

// Read one whole message off `fd` with the real ReadFromSocket decision table
// (rsl_packet::ReadMessage). False when the peer closed or the message was
// rejected -- both of which mean "close the connection", as in the C++.
bool ReadOneMessage(int fd, Message* out, std::string* detail)
{
    std::vector<char> buf;
    for (;;)
    {
        rsl_packet::LearnResult r =
            rsl_packet::ReadMessage(buf.data(), buf.size(),
                                    rsl_packet::DefaultMaxMessageSize, out);
        if (r.outcome == rsl_packet::LearnAccept) { return true; }
        if (r.outcome != rsl_packet::LearnShortHeader &&
            r.outcome != rsl_packet::LearnShortBody)
        {
            *detail = r.detail;
            return false;
        }
        if (!ReadSome(fd, &buf, 64 * 1024))
        {
            *detail = "connection closed before a full message";
            return false;
        }
    }
}

// ---------------------------------------------------------------------------
// The data directory -- the stand-in for Legislator::m_logFiles / m_checkpoints
// ---------------------------------------------------------------------------

struct LogFileInfo
{
    UInt64 fileDecree;
    std::string path;
    UInt64 dataLen;                                  // LogFile::m_dataLen
    std::vector<rsl_storage::ScannedRecord> records; // the recovered records
    UInt64 minDecree;                                // LogFile::m_minDecree
    UInt64 maxDecree;
};

struct DataDir
{
    std::vector<LogFileInfo> logs;      // ascending by file decree
    UInt64 checkpointedDecree;          // newest <decree>.codex, 0 if none
    UInt64 checkpointSize;
    std::string checkpointPath;
    bool haveCheckpoint;
};

bool ReadWholeFile(const std::string& path, std::vector<char>* out)
{
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) { return false; }
    char chunk[64 * 1024];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0)
    {
        out->insert(out->end(), chunk, chunk + n);
    }
    fclose(f);
    return true;
}

// GetFileNumbers(dir, "*.log" | "*.codex") -- legislator.cpp:5766. The decree is
// the leading decimal run of the name; entries starting with '.' are skipped.
bool ParseNumberedName(const char* name, const char* ext, UInt64* decree)
{
    if (name[0] == '.') { return false; }
    size_t nameLen = strlen(name);
    size_t extLen = strlen(ext);
    if (nameLen < extLen + 2) { return false; }
    if (strcmp(name + nameLen - extLen, ext) != 0) { return false; }
    if (name[nameLen - extLen - 1] != '.') { return false; }
    if (name[0] < '0' || name[0] > '9') { return false; }
    *decree = strtoull(name, NULL, 10);
    return true;
}

bool ScanDataDir(const char* dir, DataDir* out)
{
    out->checkpointedDecree = 0;
    out->checkpointSize = 0;
    out->haveCheckpoint = false;

    DIR* d = opendir(dir);
    if (!d)
    {
        fprintf(stderr, "learn-server: cannot open %s\n", dir);
        return false;
    }
    struct dirent* e;
    while ((e = readdir(d)) != NULL)
    {
        UInt64 decree = 0;
        std::string path = std::string(dir) + "/" + e->d_name;
        if (ParseNumberedName(e->d_name, "log", &decree))
        {
            LogFileInfo info;
            info.fileDecree = decree;
            info.path = path;
            info.dataLen = 0;
            info.minDecree = 0;
            info.maxDecree = 0;
            out->logs.push_back(info);
        }
        else if (ParseNumberedName(e->d_name, "codex", &decree))
        {
            // The newest checkpoint on disk is this replica's
            // m_checkpointedDecree (CheckpointDone, legislator.cpp:5620).
            if (!out->haveCheckpoint || decree > out->checkpointedDecree)
            {
                struct stat st;
                if (stat(path.c_str(), &st) != 0) { continue; }
                out->haveCheckpoint = true;
                out->checkpointedDecree = decree;
                out->checkpointSize = (UInt64)st.st_size;
                out->checkpointPath = path;
            }
        }
    }
    closedir(d);

    std::sort(out->logs.begin(), out->logs.end(),
              [](const LogFileInfo& a, const LogFileInfo& b)
              { return a.fileDecree < b.fileDecree; });

    // Index each log by re-running the recovery scan -- the same walk that
    // builds LogFile::m_decreeOffsets via AddMessage (legislator.cpp:712).
    for (size_t i = 0; i < out->logs.size(); ++i)
    {
        std::vector<char> bytes;
        if (!ReadWholeFile(out->logs[i].path, &bytes)) { return false; }
        rsl_storage::LogScanResult scan = rsl_storage::ScanLog(bytes.data(), bytes.size());
        if (scan.outcome == rsl_storage::Reject)
        {
            fprintf(stderr, "learn-server: %s is corrupt (%s)\n",
                    out->logs[i].path.c_str(), scan.detail.c_str());
            return false;
        }
        out->logs[i].records = scan.records;
        out->logs[i].dataLen = scan.stopOffset;
        for (size_t r = 0; r < scan.records.size(); ++r)
        {
            if (scan.records[r].msgId != Message_Vote) { continue; }
            if (out->logs[i].maxDecree == 0 || scan.records[r].decree > out->logs[i].maxDecree)
            {
                out->logs[i].maxDecree = scan.records[r].decree;
            }
            if (out->logs[i].minDecree == 0 || scan.records[r].decree < out->logs[i].minDecree)
            {
                out->logs[i].minDecree = scan.records[r].decree;
            }
        }
        if (out->logs[i].minDecree == 0) { out->logs[i].minDecree = out->logs[i].fileDecree; }
    }
    return true;
}

// LogFile::HasDecree / GetOffset (legislator.cpp:730/738). A re-vote on the
// same decree replaces the earlier entry, so the LAST matching record wins --
// that is what AddMessage's pop-then-push does.
bool OffsetOfDecree(const LogFileInfo& log, UInt64 decree, UInt64* offset)
{
    bool found = false;
    for (size_t i = 0; i < log.records.size(); ++i)
    {
        if (log.records[i].msgId == Message_Vote && log.records[i].decree == decree)
        {
            *offset = log.records[i].offset;
            found = true;
        }
    }
    return found;
}

// ---------------------------------------------------------------------------
// Legislator::SendFile -- legislator.cpp:4484
// ---------------------------------------------------------------------------
// `length < 0` means "to the end of the file as it was when we opened it":
// APSEQREAD::DoInit captures GetFileSize once (apdiskio.cpp:146) and
// legislator.cpp:4515 computes `length = reader->FileSize() - offset` from that
// snapshot. This model also fixes length at open.
bool SendFile(const std::string& path, UInt64 offset, Int64 length, int fd)
{
    FILE* f = fopen(path.c_str(), "rb");
    if (!f)
    {
        fprintf(stderr, "learn-server: open %s failed\n", path.c_str());
        return false;
    }
    struct stat st;
    if (fstat(fileno(f), &st) != 0) { fclose(f); return false; }
    UInt64 fileSize = (UInt64)st.st_size;   // <- the snapshot, taken at open

    if (offset > 0) { fseeko(f, (off_t)offset, SEEK_SET); }
    if (length < 0) { length = (Int64)(fileSize - offset); }

    std::vector<char> buf(256 * 1024);
    Int64 toRead = length;
    while (toRead > 0)
    {
        size_t want = (size_t)((toRead < (Int64)buf.size()) ? toRead : (Int64)buf.size());
        size_t got = fread(buf.data(), 1, want, f);
        if (got == 0) { break; }
        if (!WriteAll(fd, buf.data(), got))
        {
            // "Write to socket failed" (legislator.cpp:4530) -- give up on the
            // whole modeled response.
            fclose(f);
            return false;
        }
        toRead -= (Int64)got;
    }
    fclose(f);
    return true;
}

// ---------------------------------------------------------------------------
// The three handlers
// ---------------------------------------------------------------------------

// Legislator::HandleStatusQueryMsg (legislator.cpp:3300), sock != NULL branch.
void HandleStatusQuery(int fd, Message* msg, const DataDir& dir)
{
    UInt64 maxDecree = 0;
    for (size_t i = 0; i < dir.logs.size(); ++i)
    {
        if (dir.logs[i].maxDecree > maxDecree) { maxDecree = dir.logs[i].maxDecree; }
    }

    StatusResponse resp((RSLProtocolVersion)msg->m_version, msg->m_memberId,
                        maxDecree, msg->m_configurationNumber, msg->m_ballot);
    resp.m_queryDecree = msg->m_decree;
    resp.m_queryBallot = msg->m_ballot;
    resp.m_lastReceivedAgo = 0;
    // resp.m_minDecreeInLog = m_logFiles.front()->m_minDecree (legislator.cpp:3323)
    resp.m_minDecreeInLog = dir.logs.empty() ? 0 : dir.logs.front().minDecree;
    resp.m_checkpointedDecree = dir.checkpointedDecree;
    resp.m_checkpointSize = dir.checkpointSize;
    resp.m_maxBallot = msg->m_ballot;
    resp.m_state = 0;

    std::vector<char> out = MarshalWithChecksum(resp);
    WriteAll(fd, out.data(), out.size());
    fprintf(stderr, "learn-server: StatusResponse (%zu bytes)\n", out.size());
}

// Legislator::HandleFetchVotesMsg (legislator.cpp:3633).
void HandleFetchVotes(int fd, Message* msg, const DataDir& dir)
{
    // "ignore the ballot number / send all proposals >= msg->Decree() / if we
    // don't have the starting decree, close the connection"
    size_t start = dir.logs.size();
    UInt64 offset = 0;
    for (size_t i = 0; i < dir.logs.size(); ++i)
    {
        if (OffsetOfDecree(dir.logs[i], msg->m_decree, &offset))
        {
            start = i;
            break;
        }
    }
    if (start == dir.logs.size())
    {
        // "Requested message not found" -- return, i.e. close with no reply.
        fprintf(stderr, "learn-server: decree %llu not in the log -- closing\n",
                (unsigned long long)msg->m_decree);
        return;
    }

    for (size_t i = start; i < dir.logs.size(); ++i)
    {
        fprintf(stderr, "learn-server: sending %s from offset %llu\n",
                dir.logs[i].path.c_str(), (unsigned long long)offset);
        if (!SendFile(dir.logs[i].path, offset, -1, fd)) { return; }
        offset = 0;   // legislator.cpp:3676
    }
}

// Legislator::HandleFetchCheckpointMsg (legislator.cpp:3681).
void HandleFetchCheckpoint(int fd, Message* msg, const DataDir& dir)
{
    // "if (m_checkpointedDecree != decree) ... return;" -- an exact match, or
    // the connection closes with nothing written.
    if (!dir.haveCheckpoint || dir.checkpointedDecree != msg->m_decree)
    {
        fprintf(stderr, "learn-server: checkpoint %llu not found (have %llu) -- closing\n",
                (unsigned long long)msg->m_decree,
                (unsigned long long)dir.checkpointedDecree);
        return;
    }
    fprintf(stderr, "learn-server: sending %s (%llu bytes)\n",
            dir.checkpointPath.c_str(), (unsigned long long)dir.checkpointSize);
    SendFile(dir.checkpointPath, 0, -1, fd);
}

// ---------------------------------------------------------------------------
// Legislator::ReadNextMessage -- legislator.cpp:3851, restore = false
// ---------------------------------------------------------------------------
// This is the client's parser for a FetchVotes response. With restore false
// there is no tolerated tail: the zero-stream escapes at :3886 and :3958 and the
// incomplete-message escape at :3930 are all unreachable, so every anomaly is a
// hard failure that ends the catch-up.
//
// Returns: 1 = a message was read (in *msg, caller deletes), 0 = clean EOF,
// -1 = failure (detail filled in).
int ReadNextMessage(int fd, Message** msg, std::string* detail)
{
    *msg = NULL;
    std::vector<char> buf(s_PageSize);

    size_t got = ReadFully(fd, buf.data(), s_PageSize);
    if (got == 0)
    {
        // ERROR_HANDLE_EOF -- "Reached end of file" (legislator.cpp:3869).
        return 0;
    }
    if (got != s_PageSize)
    {
        char text[128];
        snprintf(text, sizeof(text), "short header page: %zu of %u bytes",
                 got, (unsigned)s_PageSize);
        *detail = text;
        return -1;
    }

    Message msgHdr;
    if (!msgHdr.UnMarshalBuf(buf.data(), s_PageSize))
    {
        // restore == false, so the all-zero escape at :3886 does not apply.
        *detail = "failed to unmarshal message, possibly corrupt stream";
        return -1;
    }
    if (msgHdr.m_msgId != Message_Vote &&
        msgHdr.m_msgId != Message_Prepare &&
        msgHdr.m_msgId != Message_ReconfigurationDecision)
    {
        char text[128];
        snprintf(text, sizeof(text), "unknown message id %u", (unsigned)msgHdr.m_msgId);
        *detail = text;
        return -1;
    }

    UInt32 paddedLen = RoundUpToPage(msgHdr.m_unMarshalLen);
    UInt32 bodyLen = paddedLen - s_PageSize;
    if (bodyLen > 0)
    {
        buf.resize(paddedLen);
        size_t bodyGot = ReadFully(fd, buf.data() + s_PageSize, bodyLen);
        if (bodyGot != bodyLen)
        {
            char text[128];
            snprintf(text, sizeof(text), "short body: %zu of %u bytes",
                     bodyGot, (unsigned)bodyLen);
            *detail = text;
            return -1;
        }
    }

    if (msgHdr.VerifyChecksum(buf.data(), msgHdr.m_unMarshalLen) == false)
    {
        *detail = "checksum mis-match, corrupt stream";
        return -1;
    }

    // Legislator::UnMarshalMessage (legislator.cpp:1481) for the three ids a
    // log can hold.
    Message* out = NULL;
    switch (msgHdr.m_msgId)
    {
        case Message_Vote:                    out = new Vote(); break;
        case Message_Prepare:                 out = new PrepareMsg(); break;
        case Message_ReconfigurationDecision: out = new Message(); break;
        default:                              return -1;
    }
    if (!out->UnMarshalBuf(buf.data(), msgHdr.m_unMarshalLen))
    {
        delete out;
        *detail = "failed to unmarshal message";
        return -1;
    }
    *msg = out;
    return 1;
}

// ---------------------------------------------------------------------------
// The client bodies
// ---------------------------------------------------------------------------

int ClientStatus(int fd)
{
    StatusResponse resp;
    std::string detail;
    // StatusResponse::ReadFromSocket (legislator.cpp:1396) -- the virtual
    // UnMarshal makes this parse as a StatusResponse.
    if (!ReadOneMessage(fd, &resp, &detail))
    {
        printf("ERROR %s\n", detail.c_str());
        return 1;
    }
    printf("STATUS minDecree=%llu checkpointDecree=%llu checkpointSize=%llu decree=%llu\n",
           (unsigned long long)resp.m_minDecreeInLog,
           (unsigned long long)resp.m_checkpointedDecree,
           (unsigned long long)resp.m_checkpointSize,
           (unsigned long long)resp.m_decree);
    return 0;
}

// Legislator::LearnVotes' read loop (legislator.cpp:3760). The engine's
// vote-sequencing checks belong to the state machine (Phase 5) and are left
// out; what is exercised here is the stream parser and the message types.
int ClientVotes(int fd)
{
    int count = 0;
    for (;;)
    {
        Message* msg = NULL;
        std::string detail;
        int r = ReadNextMessage(fd, &msg, &detail);
        if (r < 0)
        {
            printf("ERROR %s\n", detail.c_str());
            return 1;
        }
        if (r == 0 || msg == NULL) { break; }
        printf("VOTE msgId=%u decree=%llu len=%u checksum=%016llx\n",
               (unsigned)msg->m_msgId,
               (unsigned long long)msg->m_decree,
               (unsigned)msg->m_unMarshalLen,
               (unsigned long long)msg->m_checksum);
        ++count;
        delete msg;
    }
    if (count == 0)
    {
        // An empty stream is the server's way of saying no.
        printf("ERROR closed\n");
        return 1;
    }
    printf("VOTES %d\n", count);
    return 0;
}

// Legislator::CopyCheckpoint's copy loop (legislator.cpp:5545-5570): read until
// `size` bytes have come off the socket, then verify before publishing.
//
// Deviation: the C++ additionally re-marshals the header with a raised
// m_maxBallot (legislator.cpp:5535) before writing it. That step is engine
// state, not protocol, and it would make the copy differ from the source; this
// proxy copies verbatim so the supplemental test can compare bytes. The Rust client
// defaults to the same verbatim copy and offers the rewrite explicitly.
int ClientCheckpoint(int fd, UInt64 size, const char* outFile)
{
    FILE* f = fopen(outFile, "wb");
    if (!f)
    {
        printf("ERROR cannot create %s\n", outFile);
        return 1;
    }
    std::vector<char> buf(256 * 1024);
    UInt64 read = 0;
    while (read < size)
    {
        size_t want = (size_t)((size - read < (UInt64)buf.size()) ? (size - read) : (UInt64)buf.size());
        size_t got = ReadFully(fd, buf.data(), want);
        if (got == 0)
        {
            fclose(f);
            remove(outFile);   // DeleteFileA(file) at the lError label
            printf("ERROR %s\n", read == 0 ? "closed" : "incomplete checkpoint");
            return 1;
        }
        fwrite(buf.data(), 1, got, f);
        read += got;
    }
    fclose(f);

    std::vector<char> whole;
    if (!ReadWholeFile(outFile, &whole))
    {
        printf("ERROR cannot re-read %s\n", outFile);
        return 1;
    }
    rsl_storage::CheckpointVerifyResult v =
        rsl_storage::VerifyCheckpointFile(whole.data(), whole.size());
    printf("CHECKPOINT size=%llu fp64=%016llx outcome=%s\n",
           (unsigned long long)whole.size(),
           (unsigned long long)FingerPrint64::GetInstance()->GetFingerPrint(
               whole.data(), (unsigned int)whole.size()),
           rsl_storage::OutcomeName(v.outcome));
    return v.outcome == rsl_storage::Accept ? 0 : 1;
}

} // namespace

int RunServer(int port, const char* dir, int connections)
{
    unsigned short chosen = 0;
    int listener = Listen(port, &chosen);
    if (listener < 0) { return 1; }

    // Announce the (possibly ephemeral) port before blocking in accept(), so a
    // harness can start this without racing on a fixed port.
    printf("PORT %u\n", (unsigned)chosen);
    fflush(stdout);

    for (int i = 0; i < connections; ++i)
    {
        int fd;
        do { fd = accept(listener, NULL, NULL); } while (fd < 0 && errno == EINTR);
        if (fd < 0) { perror("accept"); close(listener); return 1; }
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        // The directory is re-scanned per request: that is what gives each
        // response its own snapshot of the log set, matching the engine reading
        // m_logFiles under the lock at the top of each handler.
        DataDir data;
        if (!ScanDataDir(dir, &data))
        {
            close(fd);
            close(listener);
            return 1;
        }

        Message msg;
        std::string detail;
        if (!ReadOneMessage(fd, &msg, &detail))
        {
            fprintf(stderr, "learn-server: %s -- closing\n", detail.c_str());
            close(fd);
            continue;
        }

        // HandleFetchRequest's dispatch (legislator.cpp:5346-5362).
        if (msg.m_msgId == Message_FetchVotes)
        {
            HandleFetchVotes(fd, &msg, data);
        }
        else if (msg.m_msgId == Message_FetchCheckpoint)
        {
            HandleFetchCheckpoint(fd, &msg, data);
        }
        else if (msg.m_msgId == Message_StatusQuery)
        {
            HandleStatusQuery(fd, &msg, data);
        }
        else
        {
            fprintf(stderr, "learn-server: invalid message id %u -- closing\n",
                    (unsigned)msg.m_msgId);
        }
        close(fd);
    }
    close(listener);
    return 0;
}

int RunClient(const char* host, int port, const char* mode,
              UInt64 decree, UInt64 size, const char* outFile)
{
    UInt16 msgId;
    if (strcmp(mode, "status") == 0)          { msgId = Message_StatusQuery; }
    else if (strcmp(mode, "votes") == 0)      { msgId = Message_FetchVotes; }
    else if (strcmp(mode, "checkpoint") == 0) { msgId = Message_FetchCheckpoint; }
    else
    {
        fprintf(stderr, "unknown --learn-client mode '%s' "
                        "(status|votes|checkpoint)\n", mode);
        return 2;
    }

    int fd = Connect(host, port);
    if (fd < 0)
    {
        printf("ERROR cannot connect to %s:%d\n", host, port);
        return 1;
    }

    // The request the corresponding Legislator path builds. FetchCheckpoint
    // uses a dummy configuration number of 1 (legislator.cpp:5510); the others
    // carry another value, which this proxy fixes at 7 to match its fixtures.
    Message req(RSLProtocolVersion_6, msgId, MemberId("102"), decree,
                (msgId == Message_FetchCheckpoint) ? 1 : 7,
                BallotNumber(3, MemberId("202")));
    std::vector<char> out = MarshalWithChecksum(req);
    if (!WriteAll(fd, out.data(), out.size()))
    {
        printf("ERROR failed to send request\n");
        close(fd);
        return 1;
    }

    int rc;
    if (msgId == Message_StatusQuery)          { rc = ClientStatus(fd); }
    else if (msgId == Message_FetchVotes)      { rc = ClientVotes(fd); }
    else                                       { rc = ClientCheckpoint(fd, size, outFile); }

    fflush(stdout);
    close(fd);
    return rc;
}

} // namespace rsl_learn
