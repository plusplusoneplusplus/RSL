// golden-gen -- Phase-1 golden-vector generator.
//
// Constructs RSL messages of every type, across every protocol version that
// affects their layout, marshals them with the original C++ marshaling code,
// and prints a corpus of (description, version, marshaled bytes, Rabin-64
// checksum) records. It also emits raw fingerprint vectors for a handful of
// fixed byte strings so the Rust port can validate the Rabin-64 implementation
// directly.
//
// Output is a simple line-oriented text format on stdout (see EmitRecord); one
// record per blank-line-separated block. Redirect to a file to capture the
// corpus.

// System headers first: the compat windows.h shim (pulled in transitively by
// message.h) redefines identifiers that collide with <sys/stat.h>/<dirent.h> if
// they are included afterwards, so include the POSIX headers up front.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <cerrno>
#include <dirent.h>
#include <sys/stat.h>

#include "message.h"
#include "msg_engine_compat.h"
#include "utils.h"
#include "fingerprint.h"
#include "storage_min.h"       // Phase 3a: storage corpus + reverse verify
#include "packet_min.h"        // Phase 4a: packet + learn-port framing
#include "learn_min.h"         // Phase 4c: the live learn port, both directions
#ifdef RSL_GOLDEN_TLS
#include "tls_peer.h"          // Phase 4d: the TLS 1.2 interop oracle (OpenSSL)
#endif

using namespace RSLib;
using namespace RSLibImpl;

namespace {

std::string ToHex(const void* data, size_t len)
{
    static const char* kHex = "0123456789abcdef";
    const unsigned char* p = static_cast<const unsigned char*>(data);
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i)
    {
        out += kHex[p[i] >> 4];
        out += kHex[p[i] & 0xf];
    }
    return out;
}

// ---------------------------------------------------------------------------
// FIELDS metadata (plan item 7). Alongside the marshaled BYTES, each RECORD
// carries a machine-readable JSON description of the constructor parameters the
// message was built from. The Rust port then *independently constructs* each
// message from these fields and must reproduce BYTES exactly -- closing the
// round-trip loophole where a reader bug could be masked by a mirrored writer
// bug. This block only builds strings; it never affects the marshaled bytes.
// ---------------------------------------------------------------------------
std::string JStr(const std::string& v)
{
    std::string out = "\"";
    for (char c : v)
    {
        if (c == '\\' || c == '"') { out += '\\'; }
        out += c;
    }
    out += "\"";
    return out;
}

// Minimal JSON object builder: appends "key":value pairs with correct commas.
struct Json
{
    std::string s;
    bool first;
    Json() : s("{"), first(true) {}
    Json& key(const char* k) { if (!first) { s += ","; } first = false; s += "\""; s += k; s += "\":"; return *this; }
    Json& num(const char* k, long long v) { key(k); char b[32]; snprintf(b, sizeof(b), "%lld", v); s += b; return *this; }
    Json& hex64(const char* k, UInt64 v) { key(k); char b[32]; snprintf(b, sizeof(b), "\"0x%016llx\"", (unsigned long long)v); s += b; return *this; }
    Json& str(const char* k, const std::string& v) { key(k); s += JStr(v); return *this; }
    Json& boolean(const char* k, bool v) { key(k); s += (v ? "true" : "false"); return *this; }
    Json& bytes(const char* k, const void* p, size_t n) { key(k); s += "\""; s += ToHex(p, n); s += "\""; return *this; }
    Json& rawval(const char* k, const std::string& v) { key(k); s += v; return *this; }
    std::string done() { return s + "}"; }
};

void AddHeaderFields(Json& j, UInt16 msgId, const std::string& memberId, UInt64 decree,
                     UInt32 config, UInt32 ballotId, const std::string& ballotMember, UInt64 payload)
{
    j.num("msgId", msgId);
    j.str("memberId", memberId);
    j.hex64("decree", decree);
    j.num("configurationNumber", (long long)(unsigned long long)config);
    j.num("ballotId", (long long)(unsigned long long)ballotId);
    j.str("ballotMember", ballotMember);
    j.hex64("payload", payload);
}

std::string NodeJson(const RSLNode& n)
{
    Json j;
    j.str("memberId", n.m_memberIdString);
    j.num("ip", (long long)(unsigned long long)n.m_ip);
    j.num("rslPort", n.m_rslPort);
    j.num("rslLearnPort", n.m_rslLearnPort);
    j.num("appPort", n.m_appPort);
    j.str("hostName", n.m_hostName);
    return j.done();
}

std::string MembersJson(const RSLNodeCollection& members)
{
    std::string out = "[";
    for (size_t i = 0; i < members.Count(); ++i)
    {
        if (i) { out += ","; }
        out += NodeJson(members[i]);
    }
    out += "]";
    return out;
}

std::string RequestsJson(const std::vector<std::string>& requests)
{
    std::string out = "[";
    for (size_t i = 0; i < requests.size(); ++i)
    {
        if (i) { out += ","; }
        out += "\"" + ToHex(requests[i].data(), requests[i].size()) + "\"";
    }
    out += "]";
    return out;
}

// Full JSON object for a Vote (also used for the nested vote in PrepareAccepted).
std::string VoteObjectJson(
    const std::string& memberId, UInt64 decree, UInt32 config,
    UInt32 ballotId, const std::string& ballotMember, UInt64 payload,
    const std::string& primaryCookie, bool isReconf,
    const std::string& membersJson, const std::string& cookie,
    bool relinquish, const std::vector<std::string>& requests)
{
    Json j;
    AddHeaderFields(j, Message_Vote, memberId, decree, config, ballotId, ballotMember, payload);
    j.bytes("primaryCookie", primaryCookie.data(), primaryCookie.size());
    j.boolean("isReconfiguration", isReconf);
    j.rawval("members", membersJson.empty() ? std::string("[]") : membersJson);
    j.bytes("cookie", cookie.data(), cookie.size());
    j.boolean("relinquishPrimary", relinquish);
    j.rawval("requests", RequestsJson(requests));
    return j.done();
}

// Marshal a message-derived object exactly as the engine would put it on the
// wire, then fill in the Rabin-64 checksum over the post-checksum region.
// Returns the final buffer (checksum field patched in) and the checksum value.
std::vector<char> MarshalWithChecksum(Message& msg, UInt64* checksumOut)
{
    UInt32 len = msg.GetMarshalLen();
    std::vector<char> buf(len);

    FixedMarshalMemoryManager manager(buf.data(), len);
    MarshalData marshal(&manager);
    msg.Marshal(&marshal); // writes header (checksum field == current m_checksum == 0)

    UInt32 mlen = marshal.GetMarshaledLength();
    buf.resize(mlen);

    // Checksum covers everything after the 8-byte checksum field, matching
    // Message::CalculateChecksum / VerifyChecksum and Vote::CalculateChecksum.
    UInt32 dataOffset = s_ChecksumOffset + sizeof(UInt64);
    UInt64 checksum = Utils::CalculateChecksum(buf.data() + dataOffset, mlen - dataOffset);

    FixedMarshalMemoryManager cmanager(buf.data() + s_ChecksumOffset, mlen - s_ChecksumOffset);
    MarshalData cmarshal(&cmanager);
    cmarshal.WriteUInt64(checksum);

    if (checksumOut) { *checksumOut = checksum; }
    return buf;
}

int g_selfCheckPassed = 0;
int g_selfCheckFailed = 0;

// Round-trip validation: parse the common header back out of the emitted bytes
// and re-verify the checksum. The checksum covers the whole post-checksum
// region regardless of message subtype, so a base Message unmarshal is enough
// to validate any record.
void SelfCheck(const char* desc, std::vector<char>& buf)
{
    Message check;
    if (!check.UnMarshalBuf(buf.data(), (UInt32)buf.size()) ||
        !check.VerifyChecksum(buf.data(), (UInt32)buf.size()))
    {
        fprintf(stderr, "SELFCHECK FAILED: %s\n", desc);
        ++g_selfCheckFailed;
    }
    else
    {
        ++g_selfCheckPassed;
    }
}

// Every message emitted as a RECORD is kept here so the Phase-4a packet and
// learn-port vectors can frame real corpus messages rather than inventing new
// payloads.
struct CorpusMsg
{
    std::string type;
    std::string desc;
    int version;
    std::vector<char> bytes;
};
std::vector<CorpusMsg> g_corpusMessages;

void EmitRecord(const char* type, const char* desc, int version, Message& msg,
                const std::string& fields)
{
    UInt64 checksum = 0;
    std::vector<char> buf = MarshalWithChecksum(msg, &checksum);
    SelfCheck(desc, buf);

    CorpusMsg keep;
    keep.type = type;
    keep.desc = desc;
    keep.version = version;
    keep.bytes = buf;
    g_corpusMessages.push_back(keep);

    printf("RECORD\n");
    printf("TYPE %s\n", type);
    printf("DESC %s\n", desc);
    printf("VERSION %d\n", version);
    printf("LEN %zu\n", buf.size());
    printf("CHECKSUM %016llx\n", (unsigned long long)checksum);
    printf("BYTES %s\n", ToHex(buf.data(), buf.size()).c_str());
    printf("FIELDS %s\n", fields.c_str());
    printf("\n");
}

void EmitFingerprint(const char* desc, const void* data, size_t len)
{
    UInt64 fp = FingerPrint64::GetInstance()->GetFingerPrint(data, len);
    printf("FPRINT\n");
    printf("DESC %s\n", desc);
    printf("LEN %zu\n", len);
    printf("INPUT %s\n", ToHex(data, len).c_str());
    printf("CHECKSUM %016llx\n", (unsigned long long)fp);
    printf("\n");
}

// Convenience: a fixed, deterministic member id / ballot for reproducibility.
MemberId Member(const char* id) { return MemberId(id); }

BallotNumber Ballot(UInt32 id, const char* member)
{
    return BallotNumber(id, Member(member));
}

RSLNode MakeNode(const char* id, unsigned int ip, unsigned short port,
                 unsigned short learnPort, const char* host)
{
    RSLNode n;
    strncpy(n.m_memberIdString, id, sizeof(n.m_memberIdString) - 1);
    strncpy(n.m_hostName, host, sizeof(n.m_hostName) - 1);
    n.m_ip = ip;
    n.m_rslPort = port;
    n.m_rslLearnPort = learnPort;
    n.m_appPort = (unsigned short)(port + 2);
    return n;
}

// The protocol versions supported by the engine.
const RSLProtocolVersion kVersions[] = {
    RSLProtocolVersion_1, RSLProtocolVersion_2, RSLProtocolVersion_3,
    RSLProtocolVersion_4, RSLProtocolVersion_5, RSLProtocolVersion_6,
};

// Message ids that are carried by the plain Message base class (no subclass).
struct BaseMsg { UInt16 id; const char* name; };
const BaseMsg kBaseMsgs[] = {
    { Message_None,                    "None" },
    { Message_VoteAccepted,            "VoteAccepted" },
    { Message_Prepare,                 "Prepare_base" },
    { Message_PrepareAccepted,         "PrepareAccepted_base" },
    { Message_NotAccepted,             "NotAccepted" },
    { Message_StatusQuery,             "StatusQuery" },
    { Message_StatusResponse,          "StatusResponse_base" },
    { Message_FetchVotes,              "FetchVotes" },
    { Message_FetchCheckpoint,         "FetchCheckpoint" },
    { Message_ReconfigurationDecision, "ReconfigurationDecision" },
    { Message_DefunctConfiguration,    "DefunctConfiguration" },
    { Message_JoinRequest,             "JoinRequest" },
};

void GenerateBaseMessages()
{
    for (const BaseMsg& bm : kBaseMsgs)
    {
        // None is only valid with version 0 in the default ctor; skip it in the
        // versioned loop and emit it once via the (version, msg) ctor at v1+.
        for (RSLProtocolVersion v : kVersions)
        {
            Message msg(v, bm.id, Member("101"), /*decree*/ 0x1122334455667788ULL,
                        /*config*/ 0x0a0b0c0d, Ballot(0x00c0ffee, "202"),
                        /*payload*/ 0xf0e1d2c3b4a59687ULL);
            char desc[128];
            snprintf(desc, sizeof(desc), "%s decree=large ballot=set payload=set", bm.name);
            Json j;
            AddHeaderFields(j, bm.id, "101", 0x1122334455667788ULL, 0x0a0b0c0d,
                            0x00c0ffee, "202", 0xf0e1d2c3b4a59687ULL);
            EmitRecord("Message", desc, (int)v, msg, j.done());
        }
    }
}

void GenerateVotes()
{
    for (RSLProtocolVersion v : kVersions)
    {
        // Plain vote with no requests.
        {
            PrimaryCookie cookie;
            Vote vote(v, Member("101"), 0x0000000000abcdefULL, 7,
                      Ballot(42, "202"), &cookie);
            char desc[128];
            snprintf(desc, sizeof(desc), "Vote empty (no requests)");
            std::string fields = VoteObjectJson("101", 0x0000000000abcdefULL, 7, 42, "202", 0,
                                                "", false, "[]", "", false, {});
            EmitRecord("Vote", desc, (int)v, vote, fields);
        }

        // Vote carrying two client requests.
        {
            PrimaryCookie cookie;
            Vote vote(v, Member("101"), 0x0000000000abcdf0ULL, 7,
                      Ballot(43, "202"), &cookie);
            const char req1[] = "hello-decree";
            const char req2[] = "second-request-payload";
            vote.AddRequest((char*)req1, (UInt32)sizeof(req1) - 1, NULL);
            vote.AddRequest((char*)req2, (UInt32)sizeof(req2) - 1, NULL);
            std::vector<std::string> reqs = {
                std::string(req1, sizeof(req1) - 1),
                std::string(req2, sizeof(req2) - 1),
            };
            std::string fields = VoteObjectJson("101", 0x0000000000abcdf0ULL, 7, 43, "202", 0,
                                                "", false, "[]", "", false, reqs);
            EmitRecord("Vote", "Vote with 2 requests", (int)v, vote, fields);
        }

        // Vote with a non-empty primary cookie (v>=2 marshals the cookie).
        if (v >= RSLProtocolVersion_2)
        {
            const char cookieData[] = "primary-cookie-bytes";
            PrimaryCookie cookie((void*)cookieData, (UInt32)sizeof(cookieData) - 1, true);
            Vote vote(v, Member("101"), 0x1000ULL, 7, Ballot(44, "202"), &cookie);
            const char req[] = "req-with-cookie";
            vote.AddRequest((char*)req, (UInt32)sizeof(req) - 1, NULL);
            std::vector<std::string> reqs = { std::string(req, sizeof(req) - 1) };
            std::string fields = VoteObjectJson(
                "101", 0x1000ULL, 7, 44, "202", 0,
                std::string(cookieData, sizeof(cookieData) - 1), false, "[]", "", false, reqs);
            EmitRecord("Vote", "Vote with primary cookie + 1 request", (int)v, vote, fields);
        }

        // Reconfiguration vote (v>=3): carries a MemberSet, no requests.
        if (v >= RSLProtocolVersion_3)
        {
            RSLNodeCollection members;
            members.Append(MakeNode("101", 0x0100007f, 8080, 8081, "host-a"));
            members.Append(MakeNode("202", 0x0100017f, 9090, 9091, "host-b"));
            const char cfgCookie[] = "cfg";
            MemberSet* ms = new MemberSet(members, (void*)cfgCookie,
                                          (UInt32)sizeof(cfgCookie) - 1);
            PrimaryCookie cookie;
            Vote vote(v, ms, /*reconfigCookie*/ NULL, &cookie);
            // The reconfiguration Vote ctor uses the base Message(version, msg)
            // ctor: empty member id, zero decree/config, default ballot.
            std::string fields = VoteObjectJson(
                "", 0, 0, 0, "", 0, "", true, MembersJson(members),
                std::string(cfgCookie, sizeof(cfgCookie) - 1), false, {});
            EmitRecord("Vote", "Reconfiguration vote (2 members)", (int)v, vote, fields);
        }

        // Relinquish-primary vote (v>=5).
        if (v >= RSLProtocolVersion_5)
        {
            PrimaryCookie cookie;
            Vote vote(v, Member("101"), 0x2000ULL, 7, Ballot(45, "202"),
                      &cookie, /*relinquishPrimary*/ true);
            std::string fields = VoteObjectJson("101", 0x2000ULL, 7, 45, "202", 0,
                                                "", false, "[]", "", true, {});
            EmitRecord("Vote", "Vote relinquishPrimary=true", (int)v, vote, fields);
        }
    }
}

void GenerateJoinMessages()
{
    for (RSLProtocolVersion v : kVersions)
    {
        JoinMessage msg(v, Member("101"), 0x5566778899aabbccULL, 3);
        msg.m_learnPort = 0xbeef;
        msg.m_minDecreeInLog = 0x1000;
        msg.m_checkpointedDecree = 0x0fff;
        msg.m_checkpointSize = 0x123456789aULL;
        Json j;
        // JoinMessage ctor uses a default (zero) ballot.
        AddHeaderFields(j, Message_Join, "101", 0x5566778899aabbccULL, 3, 0, "", 0);
        j.num("learnPort", 0xbeef);
        j.hex64("minDecreeInLog", 0x1000);
        j.hex64("checkpointedDecree", 0x0fff);
        j.hex64("checkpointSize", 0x123456789aULL);
        EmitRecord("JoinMessage", "Join with log/checkpoint fields", (int)v, msg, j.done());
    }
}

void GeneratePrepareMessages()
{
    for (RSLProtocolVersion v : kVersions)
    {
        const char cookieData[] = "prep-cookie";
        PrimaryCookie cookie((void*)cookieData, (UInt32)sizeof(cookieData) - 1, true);
        PrepareMsg msg(v, Member("101"), 0xdeadbeefULL, 4, Ballot(7, "202"), &cookie);
        Json j;
        AddHeaderFields(j, Message_Prepare, "101", 0xdeadbeefULL, 4, 7, "202", 0);
        j.bytes("primaryCookie", cookieData, sizeof(cookieData) - 1);
        EmitRecord("PrepareMsg", "Prepare with cookie", (int)v, msg, j.done());
    }
}

void GeneratePrepareAccepted()
{
    for (RSLProtocolVersion v : kVersions)
    {
        PrimaryCookie cookie;
        Vote* vote = new Vote(v, Member("101"), 0xcafeULL, 4, Ballot(7, "202"), &cookie);
        const char req[] = "accepted-vote-request";
        vote->AddRequest((char*)req, (UInt32)sizeof(req) - 1, NULL);

        PrepareAccepted msg(v, Member("101"), 0xcafeULL, 4, Ballot(8, "202"), vote);
        std::vector<std::string> reqs = { std::string(req, sizeof(req) - 1) };
        std::string voteObj = VoteObjectJson("101", 0xcafeULL, 4, 7, "202", 0,
                                             "", false, "[]", "", false, reqs);
        Json j;
        AddHeaderFields(j, Message_PrepareAccepted, "101", 0xcafeULL, 4, 8, "202", 0);
        j.rawval("vote", voteObj);
        EmitRecord("PrepareAccepted", "PrepareAccepted wrapping a vote", (int)v, msg, j.done());
    }
}

void GenerateStatusResponse()
{
    for (RSLProtocolVersion v : kVersions)
    {
        StatusResponse msg(v, Member("101"), 0x11ULL, 5, Ballot(9, "202"));
        msg.m_queryDecree = 0x22;
        msg.m_queryBallot = Ballot(10, "303");
        msg.m_lastReceivedAgo = 0x33;
        msg.m_minDecreeInLog = 0x44;
        msg.m_checkpointedDecree = 0x55;
        msg.m_checkpointSize = 0x66;
        msg.m_maxBallot = Ballot(11, "404");
        msg.m_state = 0x77;
        Json j;
        AddHeaderFields(j, Message_StatusResponse, "101", 0x11ULL, 5, 9, "202", 0);
        j.hex64("queryDecree", 0x22);
        j.num("queryBallotId", 10);
        j.str("queryBallotMember", "303");
        j.hex64("lastReceivedAgo", 0x33);
        j.hex64("minDecreeInLog", 0x44);
        j.hex64("checkpointedDecree", 0x55);
        j.hex64("checkpointSize", 0x66);
        j.num("maxBallotId", 11);
        j.str("maxBallotMember", "404");
        j.num("state", 0x77);
        EmitRecord("StatusResponse", "StatusResponse full", (int)v, msg, j.done());
    }
}

void GenerateBootstrap()
{
    // Bootstrap was introduced with v4; emit for v4+.
    for (RSLProtocolVersion v : kVersions)
    {
        if (v < RSLProtocolVersion_4) { continue; }
        RSLNodeCollection members;
        members.Append(MakeNode("101", 0x0100007f, 8080, 8081, "host-a"));
        members.Append(MakeNode("202", 0x0100017f, 9090, 9091, "host-b"));
        members.Append(MakeNode("303", 0x0100027f, 7070, 7071, "host-c"));
        const char cfgCookie[] = "bootstrap-cfg";
        MemberSet ms(members, (void*)cfgCookie, (UInt32)sizeof(cfgCookie) - 1);
        BootstrapMsg msg(v, Member("101"), ms);
        // BootstrapMsg ctor uses zero decree/config and a default ballot.
        Json j;
        AddHeaderFields(j, Message_Bootstrap, "101", 0, 0, 0, "", 0);
        j.rawval("members", MembersJson(members));
        j.bytes("cookie", cfgCookie, sizeof(cfgCookie) - 1);
        EmitRecord("BootstrapMsg", "Bootstrap (3 members)", (int)v, msg, j.done());
    }
}

// ---------------------------------------------------------------------------
// Raw MarshalData container vectors (Phase-2 gap closure, item 4a). The
// StartContainer/CloseContainer back-patch rule (1-byte vs 4-byte length is
// caller-chosen) has no message-level coverage until checkpoint headers arrive
// in Phase 3, so emit it directly here. CONTAINER blocks carry no checksum:
// they are raw MarshalData output, not messages. The Rust harness rebuilds each
// scenario by DESC with its Writer and must match BYTES exactly.
// ---------------------------------------------------------------------------
void EmitContainer(const char* desc, MarshalData& marshal)
{
    printf("CONTAINER\n");
    printf("DESC %s\n", desc);
    printf("LEN %u\n", (unsigned)marshal.GetMarshaledLength());
    printf("BYTES %s\n",
           ToHex(marshal.GetMarshaled(), marshal.GetMarshaledLength()).c_str());
    printf("\n");
}

void GenerateContainers()
{
    // 1-byte (short) length: empty body.
    {
        MarshalData m;
        MarshalStartPlaceHolder* ph = m.StartContainer(true);
        m.CloseContainer(ph);
        EmitContainer("short-empty", m);
    }
    // 1-byte length: small body.
    {
        MarshalData m;
        MarshalStartPlaceHolder* ph = m.StartContainer(true);
        m.WriteData(5, (void*)"hello");
        m.CloseContainer(ph);
        EmitContainer("short-hello", m);
    }
    // 1-byte length at its 255-byte maximum (LogAssert(length < 256) boundary).
    {
        unsigned char ramp[255];
        for (int i = 0; i < 255; ++i) { ramp[i] = (unsigned char)i; }
        MarshalData m;
        MarshalStartPlaceHolder* ph = m.StartContainer(true);
        m.WriteData(sizeof(ramp), ramp);
        m.CloseContainer(ph);
        EmitContainer("short-max-255", m);
    }
    // 4-byte (long) length: empty body.
    {
        MarshalData m;
        MarshalStartPlaceHolder* ph = m.StartContainer(false);
        m.CloseContainer(ph);
        EmitContainer("long-empty", m);
    }
    // 4-byte length: small body (shows the same body under the other rule).
    {
        MarshalData m;
        MarshalStartPlaceHolder* ph = m.StartContainer(false);
        m.WriteData(5, (void*)"hello");
        m.CloseContainer(ph);
        EmitContainer("long-hello", m);
    }
    // 4-byte length: body larger than a short container could hold.
    {
        unsigned char ramp[300];
        for (int i = 0; i < 300; ++i) { ramp[i] = (unsigned char)(i & 0xff); }
        MarshalData m;
        MarshalStartPlaceHolder* ph = m.StartContainer(false);
        m.WriteData(sizeof(ramp), ramp);
        m.CloseContainer(ph);
        EmitContainer("long-300", m);
    }
    // Nested: a long outer holding a mixed body with a short inner container;
    // exercises inner-before-outer back-patch ordering.
    {
        MarshalData m;
        MarshalStartPlaceHolder* outer = m.StartContainer(false);
        m.WriteUInt32(0xdeadbeef);
        MarshalStartPlaceHolder* inner = m.StartContainer(true);
        m.WriteData(3, (void*)"abc");
        m.CloseContainer(inner);
        m.WriteUInt16(0xbeef);
        m.CloseContainer(outer);
        EmitContainer("nested-long-short", m);
    }
}

void GenerateFingerprints()
{
    // Empty string -> the "empty" fingerprint (== the polynomial itself).
    EmitFingerprint("empty", "", 0);

    static const char* kStrings[] = {
        "a", "abc", "message digest",
        "The quick brown fox jumps over the lazy dog",
        "\x00\x01\x02\x03\x04\x05\x06\x07",
    };
    static const size_t kLens[] = { 1, 3, 14, 43, 8 };
    for (size_t i = 0; i < sizeof(kStrings) / sizeof(kStrings[0]); ++i)
    {
        char desc[64];
        snprintf(desc, sizeof(desc), "string#%zu", i);
        EmitFingerprint(desc, kStrings[i], kLens[i]);
    }

    // A 256-byte ramp exercises the aligned 8-byte fast path.
    unsigned char ramp[256];
    for (int i = 0; i < 256; ++i) { ramp[i] = (unsigned char)i; }
    EmitFingerprint("ramp-256", ramp, sizeof(ramp));
}

// ===========================================================================
// Phase 4a: packet framing vectors (PACKET) and learn-port framing vectors
// (LEARN). As everywhere else in this tool, the OUTCOME lines are produced by
// RUNNING the extracted C++ receive path over the bytes emitted -- never by
// reading the spec.
// ===========================================================================

void EmitPacket(const char* desc, const std::vector<char>& frame,
                UInt32 maxSize, UInt32 maxAlert)
{
    rsl_packet::ScanResult r =
        rsl_packet::ScanPackets(frame.data(), frame.size(), maxSize, maxAlert);

    printf("PACKET\n");
    printf("DESC %s\n", desc);
    printf("MAXSIZE %u\n", (unsigned)maxSize);
    printf("MAXALERT %u\n", (unsigned)maxAlert);
    printf("LEN %zu\n", frame.size());
    printf("BYTES %s\n", ToHex(frame.data(), frame.size()).c_str());
    printf("OUTCOME %s\n", rsl_packet::OutcomeName(r.outcome));
    printf("CONSUMED %zu\n", r.consumed);
    printf("PAYLOADS %zu\n", r.payloads.size());
    for (size_t i = 0; i < r.payloads.size(); ++i)
    {
        printf("PAYLOAD %s\n", ToHex(r.payloads[i].data(), r.payloads[i].size()).c_str());
    }
    printf("DETAIL %s\n", r.detail.empty() ? "-" : r.detail.c_str());
    printf("\n");
}

// Rewrite the header's size field and recompute the frame checksum, so a
// size-range vector is rejected for its size and nothing else.
std::vector<char> PatchSize(const std::vector<char>& frame, UInt32 size)
{
    std::vector<char> out = frame;
    rsl_packet::PacketHdr hdr;
    hdr.DeSerialize(out.data(), rsl_packet::SerialLen);
    hdr.m_Size = size;
    hdr.m_Checksum = 0;
    hdr.Serialize(out.data(), rsl_packet::SerialLen);
    UInt64 checksum = Utils::CalculateChecksum(out.data(), out.size());
    rsl_packet::PacketHdr::SetChecksum(checksum, out.data(), rsl_packet::SerialLen);
    return out;
}

void GeneratePackets()
{
    // ---- positives: real corpus messages wrapped in a packet --------------
    // A fixed, deterministic selection: the first record of each message type
    // at its highest emitted version, so the payloads stay small but cover
    // every marshaling path.
    static const char* kWanted[] = {
        "Message", "Vote", "JoinMessage", "PrepareMsg",
        "PrepareAccepted", "StatusResponse", "BootstrapMsg",
    };
    for (const char* type : kWanted)
    {
        const CorpusMsg* best = NULL;
        for (const CorpusMsg& m : g_corpusMessages)
        {
            if (m.type == type && (!best || m.version > best->version))
            {
                best = &m;
            }
        }
        if (!best) { continue; }
        char desc[192];
        snprintf(desc, sizeof(desc), "packet wrapping %s v%d (%s)",
                 best->type.c_str(), best->version, best->desc.c_str());
        EmitPacket(desc, rsl_packet::SerializePacket(best->bytes.data(), best->bytes.size()), 0, 0);
    }

    // Payload edge cases: the minimum legal packet is a bare 20-byte header.
    EmitPacket("packet with empty payload (size == header)",
               rsl_packet::SerializePacket("", 0), 0, 0);
    {
        char one = (char)0xff;
        EmitPacket("packet with 1-byte payload", rsl_packet::SerializePacket(&one, 1), 0, 0);
    }
    {
        std::vector<char> ramp(1024);
        for (size_t i = 0; i < ramp.size(); ++i) { ramp[i] = (char)(i & 0xff); }
        EmitPacket("packet with 1 KiB ramp payload",
                   rsl_packet::SerializePacket(ramp.data(), ramp.size()), 0, 0);
    }

    // A reference frame reused by the stream and negative vectors below.
    const CorpusMsg* ref = NULL;
    for (const CorpusMsg& m : g_corpusMessages)
    {
        if (m.type == "Message") { ref = &m; break; }
    }
    if (!ref) { return; }
    std::vector<char> frame = rsl_packet::SerializePacket(ref->bytes.data(), ref->bytes.size());

    // ---- several packets in one read buffer -------------------------------
    {
        std::vector<char> three;
        for (int i = 0; i < 3; ++i)
        {
            three.insert(three.end(), frame.begin(), frame.end());
        }
        EmitPacket("three packets back to back in one buffer", three, 0, 0);

        // ... and the same buffer cut short mid-third-packet: the first two are
        // accepted, the connection waits for the rest.
        std::vector<char> partial(three.begin(), three.end() - 7);
        EmitPacket("two whole packets plus a truncated third", partial, 0, 0);
    }

    // ---- incomplete input (never a rejection) -----------------------------
    EmitPacket("empty buffer", std::vector<char>(), 0, 0);
    EmitPacket("19 bytes -- one short of a header",
               std::vector<char>(frame.begin(), frame.begin() + 19), 0, 0);
    EmitPacket("header only, payload missing",
               std::vector<char>(frame.begin(), frame.begin() + rsl_packet::SerialLen), 0, 0);
    EmitPacket("frame missing its last byte",
               std::vector<char>(frame.begin(), frame.end() - 1), 0, 0);

    // ---- size out of range ------------------------------------------------
    EmitPacket("size field 0", PatchSize(frame, 0), 0, 0);
    EmitPacket("size field 19 (below the 20-byte header)", PatchSize(frame, 19), 0, 0);
    EmitPacket("size field exactly 20 with a payload present", PatchSize(frame, 20), 0, 0);
    EmitPacket("size field above the 100 MB default cap",
               PatchSize(frame, rsl_packet::MaxNetPacketSize + 1), 0, 0);
    EmitPacket("size field 0xffffffff", PatchSize(frame, 0xffffffffu), 0, 0);

    // The configured cap: RSLConfig 1 MB -> 1*1024*1024 + 1024 (rslconfig.cpp:118).
    const UInt32 oneMbCap = 1u * 1024 * 1024 + 1024;
    EmitPacket("size just above a 1 MB configured cap", PatchSize(frame, oneMbCap + 1),
               oneMbCap, 0);
    EmitPacket("size exactly at a 1 MB configured cap -- accepted header, body pending",
               PatchSize(frame, oneMbCap), oneMbCap, 0);
    EmitPacket("in-range frame with a small configured cap", frame, oneMbCap, 0);

    // The alert threshold only logs; it never rejects.
    EmitPacket("size above the alert threshold but within the cap", frame, oneMbCap, 64);

    // ---- checksum ---------------------------------------------------------
    {
        std::vector<char> flipped = frame;
        flipped[rsl_packet::SerialLen] ^= 0x01; // first payload byte
        EmitPacket("payload byte flipped (outer checksum fails)", flipped, 0, 0);
    }
    {
        std::vector<char> flipped = frame;
        flipped[rsl_packet::ChecksumOffset] ^= 0x80; // checksum field itself
        EmitPacket("checksum field corrupted", flipped, 0, 0);
    }
    {
        // The two checksum domains are different: the packet checksum covers the
        // whole frame with a zeroed checksum field, the message checksum covers
        // the message after its own checksum field. Flipping a byte of the
        // header's proto-version field breaks the outer one while the inner
        // message is untouched and still verifies.
        std::vector<char> outerBad = frame;
        outerBad[4] ^= 0x01; // m_ProtoVersion, which RSL always sends as zero
        EmitPacket("outer checksum invalid, inner message checksum valid", outerBad, 0, 0);
    }
    {
        // ... and the reverse: corrupt the message's own checksum field, then
        // re-frame. The packet layer never inspects the payload, so it accepts.
        std::vector<char> badMsg = ref->bytes;
        badMsg[s_ChecksumOffset] ^= 0x01;
        EmitPacket("outer checksum valid, inner message checksum invalid",
                   rsl_packet::SerializePacket(badMsg.data(), badMsg.size()), 0, 0);
    }
    {
        // A valid packet followed by a corrupt one: the first is delivered, then
        // the connection dies. Proves that acceptance is not rolled back.
        std::vector<char> two = frame;
        std::vector<char> bad = frame;
        bad[rsl_packet::SerialLen] ^= 0x01;
        two.insert(two.end(), bad.begin(), bad.end());
        EmitPacket("good packet followed by a corrupt one", two, 0, 0);
    }
}

void EmitLearn(const char* desc, const std::vector<char>& stream, UInt32 maxMessageSize,
               bool executedFaithfully)
{
    Message msg;
    rsl_packet::LearnResult r =
        rsl_packet::ReadMessage(stream.data(), stream.size(), maxMessageSize, &msg);

    printf("LEARN\n");
    printf("DESC %s\n", desc);
    printf("MAXSIZE %u\n", (unsigned)maxMessageSize);
    printf("LEN %zu\n", stream.size());
    printf("BYTES %s\n", ToHex(stream.data(), stream.size()).c_str());
    printf("EXEC %s\n", executedFaithfully ? "yes" : "no");
    printf("OUTCOME %s\n", rsl_packet::LearnOutcomeName(r.outcome));
    printf("VERSION %u\n", (unsigned)r.version);
    printf("MSGLEN %u\n", (unsigned)r.length);
    printf("DETAIL %s\n", r.detail.c_str());
    printf("\n");
}

// Patch the u16 version / u32 length that make up the learn port's 6-byte
// framing header (they are the message's own first two fields).
std::vector<char> PatchLearnHeader(const std::vector<char>& msg, UInt16 version, UInt32 length)
{
    std::vector<char> out = msg;
    if (out.size() < rsl_packet::LearnHeaderSize)
    {
        out.resize(rsl_packet::LearnHeaderSize, 0);
    }
    MarshalData marshal(out.data(), rsl_packet::LearnHeaderSize, false);
    marshal.SetMarshaledLength(0);
    marshal.WriteUInt16(version);
    marshal.WriteUInt32(length);
    return out;
}

void GenerateLearn()
{
    const CorpusMsg* base = NULL;
    const CorpusMsg* status = NULL;
    for (const CorpusMsg& m : g_corpusMessages)
    {
        if (!base && m.type == "Message") { base = &m; }
        if (m.type == "StatusResponse" && (!status || m.version > status->version))
        {
            status = &m;
        }
    }
    if (!base || !status) { return; }

    const UInt32 kMax = rsl_packet::DefaultMaxMessageSize;

    EmitLearn("learn stream: a whole base Message", base->bytes, kMax, true);
    EmitLearn("learn stream: a whole StatusResponse", status->bytes, kMax, true);

    {
        // Trailing bytes are ignored: only `length` bytes are consumed.
        std::vector<char> extra = base->bytes;
        for (int i = 0; i < 8; ++i) { extra.push_back((char)0xaa); }
        EmitLearn("message followed by trailing bytes", extra, kMax, true);
    }

    EmitLearn("empty stream", std::vector<char>(), kMax, true);
    EmitLearn("3 bytes -- half a framing header",
              std::vector<char>(base->bytes.begin(), base->bytes.begin() + 3), kMax, true);
    EmitLearn("header present, body truncated",
              std::vector<char>(base->bytes.begin(), base->bytes.end() - 1), kMax, true);

    EmitLearn("version 0", PatchLearnHeader(base->bytes, 0, (UInt32)base->bytes.size()),
              kMax, true);
    EmitLearn("version 7 (one past the last valid version)",
              PatchLearnHeader(base->bytes, 7, (UInt32)base->bytes.size()), kMax, true);
    EmitLearn("version 0xffff", PatchLearnHeader(base->bytes, 0xffff,
              (UInt32)base->bytes.size()), kMax, true);

    EmitLearn("length above the configured cap",
              PatchLearnHeader(base->bytes, 6, 0x7fffffff), kMax, true);
    EmitLearn("length one above a 1 KB cap",
              PatchLearnHeader(base->bytes, 6, 1025), 1024, true);
    EmitLearn("length exactly at a small cap, body missing",
              PatchLearnHeader(base->bytes, 6, 1024), 1024, true);

    // Below the 6-byte framing header the original memcpy's 6 bytes into a
    // `malloc(length)` buffer (message.cpp:672-674) -- a heap overflow. The
    // port refuses the length instead, so this outcome is NOT the executed
    // original's; EXEC says so.
    EmitLearn("length below the 6-byte header (C++ overflows its buffer)",
              PatchLearnHeader(base->bytes, 6, 5), kMax, false);

    {
        // Version and length are fine, the message body is not: the magic
        // number is wrong, so UnMarshal rejects it.
        std::vector<char> badMagic = base->bytes;
        badMagic[14] ^= 0xff; // magic sits after version+length+checksum
        EmitLearn("valid framing, bad magic in the message", badMagic, kMax, true);
    }
    {
        // A learn message whose own checksum is wrong is still ACCEPTED:
        // ReadFromSocket only unmarshals, it never calls VerifyChecksum.
        std::vector<char> badChecksum = base->bytes;
        badChecksum[s_ChecksumOffset] ^= 0x01;
        EmitLearn("valid framing, wrong message checksum (accepted -- no verify)",
                  badChecksum, kMax, true);
    }
}

// ===========================================================================
// Phase 3a: storage corpus generation (--storage) and reverse verification
// (--verify-storage). The extracted C++ readers in storage_min.cpp are the
// ground truth: every MANIFEST outcome is produced by RUNNING them over the
// bytes just written, never by reading the format spec (plan item 6 caution).
// ===========================================================================
using rsl_storage::Outcome;
using rsl_storage::OutcomeName;

std::string Hex16(UInt64 v)
{
    char buf[24];
    snprintf(buf, sizeof(buf), "%016llx", (unsigned long long)v);
    return buf;
}

std::string Fp64Hex(const std::vector<char>& b)
{
    return Hex16(FingerPrint64::GetInstance()->GetFingerPrint(b.data(), b.size()));
}

bool WriteBinaryFile(const std::string& path, const std::vector<char>& bytes)
{
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) { return false; }
    bool ok = bytes.empty() || fwrite(bytes.data(), 1, bytes.size(), f) == bytes.size();
    fclose(f);
    return ok;
}

bool ReadBinaryFile(const std::string& path, std::vector<char>& out)
{
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) { return false; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    out.resize(n > 0 ? (size_t)n : 0);
    bool ok = (n <= 0) || fread(out.data(), 1, (size_t)n, f) == (size_t)n;
    fclose(f);
    return ok;
}

// A deterministic, compressible user-state pattern (a byte ramp). The MANIFEST
// records "ramp" + length so the Rust port can regenerate the large checkpoint
// samples without shipping multi-MiB binaries.
std::vector<char> RampState(size_t n)
{
    std::vector<char> s(n);
    for (size_t i = 0; i < n; ++i) { s[i] = (char)(i & 0xff); }
    return s;
}

// Build a checkpoint header (with its nextVote + ConfigurationInfo) for a given
// version. Objects are heap-allocated and intentionally leaked -- this is a
// short-lived generator.
CheckpointHeader* MakeCheckpointHeader(RSLProtocolVersion v, UInt64 cpDecree)
{
    PrimaryCookie cookie; // consumed during Vote::Init; safe as a local
    Vote* vote = new Vote(v, Member("101"), cpDecree + 1, /*config*/ 7,
                          Ballot(5, "202"), &cookie);
    vote->CalculateChecksum(); // header.Marshal emits the vote's own buffers

    CheckpointHeader* h = new CheckpointHeader();
    h->m_version = v;
    h->m_memberId = Member("101");
    h->m_lastExecutedDecree = cpDecree;
    h->m_maxBallot = Ballot(9, "202"); // must be >= nextVote's ballot
    h->m_nextVote = vote;
    h->m_stateSaved = true;
    if (v >= RSLProtocolVersion_3)
    {
        RSLNodeCollection members;
        members.Append(MakeNode("101", 0x0100007f, 8080, 8081, "host-a"));
        members.Append(MakeNode("202", 0x0100017f, 9090, 9091, "host-b"));
        const char cfgCookie[] = "cfg";
        MemberSet* ms = new MemberSet(members, (void*)cfgCookie, (UInt32)sizeof(cfgCookie) - 1);
        h->m_stateConfiguration = new ConfigurationInfo(0x0a0b0c0d, cpDecree + 1, ms);
    }
    if (v >= RSLProtocolVersion_4)
    {
        h->m_checksumBlockSize = s_ChecksumBlockSize;
    }
    return h;
}

// --- MANIFEST accumulation -------------------------------------------------
struct Manifest
{
    std::string entries; // one compact JSON object per file, comma+newline joined
    bool first = true;

    void Add(const std::string& obj)
    {
        if (!first) { entries += ",\n"; }
        first = false;
        entries += "    ";
        entries += obj;
    }
};

std::string RecordsJson(const rsl_storage::LogScanResult& scan)
{
    std::string out = "[";
    for (size_t i = 0; i < scan.records.size(); ++i)
    {
        const rsl_storage::ScannedRecord& r = scan.records[i];
        if (i) { out += ","; }
        Json j;
        j.num("offset", (long long)r.offset);
        j.num("msgId", r.msgId);
        j.hex64("decree", r.decree);
        j.num("unMarshalLen", r.unMarshalLen);
        j.num("paddedLen", r.paddedLen);
        j.str("checksum", Hex16(r.checksum));
        out += j.done();
    }
    out += "]";
    return out;
}

void EmitLog(Manifest& man, const std::string& outdir, const char* name,
             const std::vector<char>& bytes)
{
    std::string file = std::string(name) + ".log";
    LogAssert(WriteBinaryFile(outdir + "/" + file, bytes));

    rsl_storage::LogScanResult scan = rsl_storage::ScanLog(bytes.data(), bytes.size());

    Json j;
    j.str("name", name);
    j.str("file", file);
    j.str("kind", "log");
    j.num("size", (long long)bytes.size());
    j.str("fp64", Fp64Hex(bytes));
    j.str("outcome", OutcomeName(scan.outcome));
    j.num("stopOffset", (long long)scan.stopOffset);
    j.num("recordCount", (long long)scan.records.size());
    j.str("detail", scan.detail);
    j.rawval("records", RecordsJson(scan));
    man.Add(j.done());
}

void EmitCheckpoint(Manifest& man, const std::string& outdir, const char* name,
                    const std::vector<char>& bytes, const char* statePattern,
                    size_t stateLen)
{
    std::string file = std::string(name) + ".codex";
    LogAssert(WriteBinaryFile(outdir + "/" + file, bytes));

    rsl_storage::CheckpointVerifyResult vr =
        rsl_storage::VerifyCheckpointFile(bytes.data(), bytes.size());

    Json j;
    j.str("name", name);
    j.str("file", file);
    j.str("kind", "checkpoint");
    j.num("size", (long long)bytes.size());
    j.str("fp64", Fp64Hex(bytes));
    j.str("outcome", OutcomeName(vr.outcome));
    j.num("version", vr.version);
    j.num("headerLen", vr.headerLen);
    j.num("userDataSize", (long long)vr.userDataSize);
    j.num("checksumBlockSize", vr.checksumBlockSize);
    j.boolean("stateSaved", vr.stateSaved);
    j.str("statePattern", statePattern);
    j.num("stateLen", (long long)stateLen);
    j.str("detail", vr.detail);
    man.Add(j.done());
}

void EmitDefunct(Manifest& man, const std::string& outdir, const char* name,
                 UInt32 value)
{
    std::vector<char> bytes = rsl_storage::EncodeDefunct(value);
    std::string file = std::string(name) + ".txt";
    LogAssert(WriteBinaryFile(outdir + "/" + file, bytes));

    UInt32 decoded = 0;
    LogAssert(rsl_storage::DecodeDefunct(bytes.data(), bytes.size(), &decoded));
    LogAssert(decoded == value);

    Json j;
    j.str("name", name);
    j.str("file", file);
    j.str("kind", "defunct");
    j.num("size", (long long)bytes.size());
    j.str("fp64", Fp64Hex(bytes));
    j.str("outcome", "accept");
    j.num("value", (long long)(unsigned long long)value);
    man.Add(j.done());
}

// Concatenate encoded log records into one log image.
std::vector<char> CatRecords(const std::vector<std::vector<char> >& recs)
{
    std::vector<char> out;
    for (const std::vector<char>& r : recs) { out.insert(out.end(), r.begin(), r.end()); }
    return out;
}

int GenerateStorage(const char* outdir)
{
    if (mkdir(outdir, 0777) != 0 && errno != EEXIST)
    {
        fprintf(stderr, "failed to create %s (errno=%d)\n", outdir, errno);
        return 1;
    }

    Manifest man;

    // ---- Log samples ------------------------------------------------------
    // empty log: no records, clean accept at offset 0.
    EmitLog(man, outdir, "empty", std::vector<char>());

    // single vote (v6).
    {
        PrimaryCookie c;
        Vote vote(RSLProtocolVersion_6, Member("101"), 0x00000000000abcdeULL, 7,
                  Ballot(3, "202"), &c);
        EmitLog(man, outdir, "single-vote", rsl_storage::EncodeLogRecord(vote));
    }

    // one vote per protocol version (v1..v6): exercises per-version layout.
    for (RSLProtocolVersion v : kVersions)
    {
        PrimaryCookie c;
        Vote vote(v, Member("101"), 0x100ULL + (UInt64)v, 7, Ballot(3, "202"), &c);
        char name[32];
        snprintf(name, sizeof(name), "vote-v%d", (int)v);
        EmitLog(man, outdir, name, rsl_storage::EncodeLogRecord(vote));
    }

    // a single Prepare record (another logged message type).
    {
        PrimaryCookie c;
        PrepareMsg prep(RSLProtocolVersion_6, Member("101"), 0x200ULL, 7,
                        Ballot(4, "202"), &c);
        EmitLog(man, outdir, "prepare", rsl_storage::EncodeLogRecord(prep));
    }

    // multi-record log spanning pad boundaries: Prepare + Vote + a Vote with a
    // request (multi-page), + a ReconfigurationDecision base message.
    {
        std::vector<std::vector<char> > recs;
        {
            PrimaryCookie c;
            PrepareMsg prep(RSLProtocolVersion_6, Member("101"), 0x300ULL, 7, Ballot(4, "202"), &c);
            recs.push_back(rsl_storage::EncodeLogRecord(prep));
        }
        {
            PrimaryCookie c;
            Vote vote(RSLProtocolVersion_6, Member("101"), 0x301ULL, 7, Ballot(5, "202"), &c);
            recs.push_back(rsl_storage::EncodeLogRecord(vote));
        }
        {
            PrimaryCookie c;
            Vote vote(RSLProtocolVersion_6, Member("101"), 0x302ULL, 7, Ballot(5, "202"), &c);
            std::vector<char> big(600, 'x');
            vote.AddRequest(big.data(), (UInt32)big.size(), NULL);
            recs.push_back(rsl_storage::EncodeLogRecord(vote));
        }
        {
            Message dec(RSLProtocolVersion_6, Message_ReconfigurationDecision, Member("101"),
                        0x303ULL, 7, Ballot(6, "202"), 0);
            recs.push_back(rsl_storage::EncodeLogRecord(dec));
        }
        EmitLog(man, outdir, "multi-record", CatRecords(recs));
    }

    // garbage-pad tolerance: a valid vote whose pad bytes are non-zero. The
    // checksum only covers the message body, so the record still verifies.
    {
        PrimaryCookie c;
        Vote vote(RSLProtocolVersion_6, Member("101"), 0x400ULL, 7, Ballot(3, "202"), &c);
        std::vector<char> rec = rsl_storage::EncodeLogRecord(vote);
        UInt32 body = vote.GetMarshalLen();
        for (size_t i = body; i < rec.size(); ++i) { rec[i] = (char)0xAA; }
        EmitLog(man, outdir, "garbage-pad", rec);
    }

    // clean zero tail after a valid record: recovery stops at the zero region.
    {
        PrimaryCookie c;
        Vote vote(RSLProtocolVersion_6, Member("101"), 0x500ULL, 7, Ballot(3, "202"), &c);
        std::vector<char> rec = rsl_storage::EncodeLogRecord(vote);
        std::vector<char> img = rec;
        img.resize(rec.size() + s_PageSize, 0); // one zero page
        EmitLog(man, outdir, "zero-tail", img);
    }

    // torn tail: a valid vote followed by a truncated multi-page record (full
    // header page + partial body). Recovery discards the incomplete tail.
    {
        PrimaryCookie c1;
        Vote v1(RSLProtocolVersion_6, Member("101"), 0x600ULL, 7, Ballot(3, "202"), &c1);
        std::vector<char> rec1 = rsl_storage::EncodeLogRecord(v1);

        PrimaryCookie c2;
        Vote v2(RSLProtocolVersion_6, Member("101"), 0x601ULL, 7, Ballot(3, "202"), &c2);
        std::vector<char> big(600, 'y');
        v2.AddRequest(big.data(), (UInt32)big.size(), NULL);
        std::vector<char> rec2 = rsl_storage::EncodeLogRecord(v2); // >= 1024 bytes

        std::vector<char> img = rec1;
        // header page + 188 body bytes of the second record (< its padded len).
        img.insert(img.end(), rec2.begin(), rec2.begin() + s_PageSize + 188);
        EmitLog(man, outdir, "torn-tail", img);
    }

    // corrupt record checksum in a middle record, valid record following:
    // non-zero data after the bad checksum means hard reject.
    {
        PrimaryCookie c1;
        Vote v1(RSLProtocolVersion_6, Member("101"), 0x700ULL, 7, Ballot(3, "202"), &c1);
        std::vector<char> rec1 = rsl_storage::EncodeLogRecord(v1);

        PrimaryCookie c2;
        Vote v2(RSLProtocolVersion_6, Member("101"), 0x701ULL, 7, Ballot(3, "202"), &c2);
        std::vector<char> rec2 = rsl_storage::EncodeLogRecord(v2);
        rec2[20] ^= 0xff; // flip a body byte (past the 8-byte checksum field)

        PrimaryCookie c3;
        Vote v3(RSLProtocolVersion_6, Member("101"), 0x702ULL, 7, Ballot(3, "202"), &c3);
        std::vector<char> rec3 = rsl_storage::EncodeLogRecord(v3);

        std::vector<std::vector<char> > recs = { rec1, rec2, rec3 };
        EmitLog(man, outdir, "corrupt-checksum", CatRecords(recs));
    }

    // unknown message id: a non-logged message type in the log stream -> reject.
    {
        Message bad(RSLProtocolVersion_6, Message_VoteAccepted, Member("101"),
                    0x800ULL, 7, Ballot(3, "202"), 0);
        EmitLog(man, outdir, "unknown-msgid", rsl_storage::EncodeLogRecord(bad));
    }

    // ---- Checkpoint samples ----------------------------------------------
    // Per-version headers (v3..v6; the checkpoint header format is a v>=3
    // construct -- v1/v2 checkpoints are a bare page-rounded vote, out of scope,
    // analogous to Bootstrap only existing at v4+). Minimal empty user state.
    for (RSLProtocolVersion v = RSLProtocolVersion_3; v <= RSLProtocolVersion_6;
         v = (RSLProtocolVersion)(v + 1))
    {
        CheckpointHeader* h = MakeCheckpointHeader(v, 0x1000ULL);
        std::vector<char> img = rsl_storage::BuildCheckpointFile(*h, nullptr, 0);
        char name[32];
        snprintf(name, sizeof(name), "cp-v%d-empty", (int)v);
        EmitCheckpoint(man, outdir, name, img, "empty", 0);
    }

    const UInt32 kBlock = s_ChecksumBlockSize;
    const UInt32 kDataOnly = kBlock - (UInt32)rsl_storage::CHECKSUM_SIZE;

    // small user state: single partial block (data + 8-byte checksum).
    {
        CheckpointHeader* h = MakeCheckpointHeader(RSLProtocolVersion_6, 0x2000ULL);
        std::vector<char> st = RampState(100);
        std::vector<char> img = rsl_storage::BuildCheckpointFile(*h, st.data(), st.size());
        EmitCheckpoint(man, outdir, "cp-small", img, "ramp", st.size());
    }

    // exactly one full 4 MiB block (state == dataOnly).
    {
        CheckpointHeader* h = MakeCheckpointHeader(RSLProtocolVersion_6, 0x3000ULL);
        std::vector<char> st = RampState(kDataOnly);
        std::vector<char> img = rsl_storage::BuildCheckpointFile(*h, st.data(), st.size());
        EmitCheckpoint(man, outdir, "cp-4mib", img, "ramp", st.size());
    }

    // 4 MiB + 1: one full block + a 1-byte partial block.
    {
        CheckpointHeader* h = MakeCheckpointHeader(RSLProtocolVersion_6, 0x4000ULL);
        std::vector<char> st = RampState((size_t)kDataOnly + 1);
        std::vector<char> img = rsl_storage::BuildCheckpointFile(*h, st.data(), st.size());
        EmitCheckpoint(man, outdir, "cp-4mib-plus1", img, "ramp", st.size());
    }

    // multi-block: 2 full blocks + a partial (2*dataOnly + 50).
    {
        CheckpointHeader* h = MakeCheckpointHeader(RSLProtocolVersion_6, 0x5000ULL);
        std::vector<char> st = RampState((size_t)kDataOnly * 2 + 50);
        std::vector<char> img = rsl_storage::BuildCheckpointFile(*h, st.data(), st.size());
        EmitCheckpoint(man, outdir, "cp-multiblock", img, "ramp", st.size());
    }

    // corrupt block checksum: flip a byte inside the block data of a small cp.
    {
        CheckpointHeader* h = MakeCheckpointHeader(RSLProtocolVersion_6, 0x6000ULL);
        std::vector<char> st = RampState(100);
        std::vector<char> img = rsl_storage::BuildCheckpointFile(*h, st.data(), st.size());
        img[h->GetMarshalLen() + 10] ^= 0xff; // flip a user-data byte in the block
        EmitCheckpoint(man, outdir, "cp-corrupt-block", img, "ramp", st.size());
    }

    // truncated file: valid small cp with its final bytes dropped -> size !=
    // header m_size -> reject.
    {
        CheckpointHeader* h = MakeCheckpointHeader(RSLProtocolVersion_6, 0x7000ULL);
        std::vector<char> st = RampState(100);
        std::vector<char> img = rsl_storage::BuildCheckpointFile(*h, st.data(), st.size());
        img.resize(img.size() - 8); // drop the trailing checksum + a byte's worth
        EmitCheckpoint(man, outdir, "cp-truncated", img, "ramp", st.size());
    }

    // ---- defunct.txt samples ---------------------------------------------
    EmitDefunct(man, outdir, "defunct-zero", 0);
    EmitDefunct(man, outdir, "defunct-42", 42);
    EmitDefunct(man, outdir, "defunct-large", 0xdeadbeef);

    // ---- MANIFEST ---------------------------------------------------------
    std::string manifest;
    manifest += "{\n";
    manifest += "  \"generator\": \"golden-gen --storage (Phase 3a)\",\n";
    char nums[64];
    snprintf(nums, sizeof(nums), "  \"pageSize\": %u,\n", (unsigned)s_PageSize);
    manifest += nums;
    snprintf(nums, sizeof(nums), "  \"checksumBlockSize\": %u,\n", (unsigned)s_ChecksumBlockSize);
    manifest += nums;
    snprintf(nums, sizeof(nums), "  \"checksumSize\": %d,\n", (int)rsl_storage::CHECKSUM_SIZE);
    manifest += nums;
    manifest += "  \"files\": [\n";
    manifest += man.entries;
    manifest += "\n  ]\n}\n";

    std::string manifestPath = std::string(outdir) + "/MANIFEST.json";
    FILE* mf = fopen(manifestPath.c_str(), "wb");
    if (!mf) { fprintf(stderr, "cannot write %s\n", manifestPath.c_str()); return 1; }
    fwrite(manifest.data(), 1, manifest.size(), mf);
    fclose(mf);

    fprintf(stderr, "storage corpus written to %s\n", outdir);
    return 0;
}

// Reverse mode: run the extracted C++ readers over every file in a directory
// and report per-file accept/stop/reject + recovered record counts. This is how
// "C++ reads (Rust-written) files" works without Windows or the full engine; in
// CI it re-reads the C++ generator's own output as a sanity check.
int VerifyStorage(const char* dir)
{
    DIR* d = opendir(dir);
    if (!d) { fprintf(stderr, "cannot open dir %s\n", dir); return 1; }

    std::vector<std::string> names;
    for (struct dirent* e = readdir(d); e; e = readdir(d))
    {
        std::string n = e->d_name;
        if (n == "." || n == ".." || n == "MANIFEST.json") { continue; }
        names.push_back(n);
    }
    closedir(d);
    std::sort(names.begin(), names.end());

    auto ends_with = [](const std::string& s, const char* suf) {
        size_t n = strlen(suf);
        return s.size() >= n && s.compare(s.size() - n, n, suf) == 0;
    };

    int rc = 0;
    for (const std::string& n : names)
    {
        std::vector<char> bytes;
        if (!ReadBinaryFile(std::string(dir) + "/" + n, bytes))
        {
            printf("%s: ERROR could not read\n", n.c_str());
            rc = 1;
            continue;
        }
        if (ends_with(n, ".log"))
        {
            rsl_storage::LogScanResult s = rsl_storage::ScanLog(bytes.data(), bytes.size());
            printf("%s: %s records=%zu stopOffset=%llu (%s)\n", n.c_str(),
                   OutcomeName(s.outcome), s.records.size(),
                   (unsigned long long)s.stopOffset, s.detail.c_str());
        }
        else if (ends_with(n, ".codex"))
        {
            rsl_storage::CheckpointVerifyResult v =
                rsl_storage::VerifyCheckpointFile(bytes.data(), bytes.size());
            printf("%s: %s version=%u userData=%llu (%s)\n", n.c_str(),
                   OutcomeName(v.outcome), v.version,
                   (unsigned long long)v.userDataSize, v.detail.c_str());
        }
        else if (ends_with(n, ".txt"))
        {
            UInt32 value = 0;
            bool ok = rsl_storage::DecodeDefunct(bytes.data(), bytes.size(), &value);
            printf("%s: %s value=%u\n", n.c_str(), ok ? "accept" : "reject", value);
        }
        else
        {
            printf("%s: skipped (unknown extension)\n", n.c_str());
        }
    }
    return rc;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc >= 3 && strcmp(argv[1], "--storage") == 0)
    {
        return GenerateStorage(argv[2]);
    }
    if (argc >= 3 && strcmp(argv[1], "--verify-storage") == 0)
    {
        return VerifyStorage(argv[2]);
    }
    // Phase 4a: live C++ TCP peer, the interop oracle for the Rust net tests.
    // Not part of corpus regeneration; spawned on demand.
    if (argc >= 3 && strcmp(argv[1], "--packet-peer") == 0)
    {
        const char* mode = "echo";
        if (argc >= 5 && strcmp(argv[3], "--mode") == 0) { mode = argv[4]; }
        return rsl_packet::RunPeer(atoi(argv[2]), mode);
    }
    // Phase 4d: the same peer over TLS 1.2, via OpenSSL. A *proxy* oracle --
    // the real C++ uses SChannel, which does not run here. See tls_peer.cpp.
    //
    //   --tls-peer   <port> --cert <pem> --key <pem> --ca <pem> [--mode echo|log]
    //   --tls-client <host> <port> --cert <pem> --key <pem> --ca <pem>
    //                [--payload <str>] [--count <n>]
    if (argc >= 3 &&
        (strcmp(argv[1], "--tls-peer") == 0 || strcmp(argv[1], "--tls-client") == 0))
    {
#ifndef RSL_GOLDEN_TLS
        fprintf(stderr,
                "%s needs OpenSSL: install libssl-dev and re-run cmake\n", argv[1]);
        return 3;
#else
        const char* cert = NULL;
        const char* key = NULL;
        const char* ca = NULL;
        const char* mode = "echo";
        const char* payload = "tls interop";
        int count = 1;
        for (int i = 2; i + 1 < argc; ++i)
        {
            if (strcmp(argv[i], "--cert") == 0) { cert = argv[i + 1]; }
            else if (strcmp(argv[i], "--key") == 0) { key = argv[i + 1]; }
            else if (strcmp(argv[i], "--ca") == 0) { ca = argv[i + 1]; }
            else if (strcmp(argv[i], "--mode") == 0) { mode = argv[i + 1]; }
            else if (strcmp(argv[i], "--payload") == 0) { payload = argv[i + 1]; }
            else if (strcmp(argv[i], "--count") == 0) { count = atoi(argv[i + 1]); }
        }
        if (cert == NULL || key == NULL || ca == NULL)
        {
            fprintf(stderr, "%s needs --cert <pem> --key <pem> --ca <pem>\n", argv[1]);
            return 2;
        }
        if (strcmp(argv[1], "--tls-peer") == 0)
        {
            return rsl_tls::RunServer(atoi(argv[2]), cert, key, ca, mode);
        }
        if (argc < 4)
        {
            fprintf(stderr, "--tls-client needs <host> <port>\n");
            return 2;
        }
        return rsl_tls::RunClient(argv[2], atoi(argv[3]), cert, key, ca, payload, count);
#endif
    }
    // Phase 4c: the live C++ learn port, both directions. Also spawned on
    // demand by the Rust tests, not part of corpus regeneration.
    //
    //   --learn-server <port> --dir <data-dir> [--connections <n>]
    //   --learn-client <host> <port> --mode <status|votes|checkpoint>
    //                  [--decree <n>] [--size <n>] [--out <file>]
    if (argc >= 3 && strcmp(argv[1], "--learn-server") == 0)
    {
        const char* dir = NULL;
        int connections = 1;
        for (int i = 3; i + 1 < argc; i += 2)
        {
            if (strcmp(argv[i], "--dir") == 0) { dir = argv[i + 1]; }
            else if (strcmp(argv[i], "--connections") == 0) { connections = atoi(argv[i + 1]); }
        }
        if (dir == NULL)
        {
            fprintf(stderr, "--learn-server needs --dir <data-dir>\n");
            return 2;
        }
        return rsl_learn::RunServer(atoi(argv[2]), dir, connections);
    }
    if (argc >= 4 && strcmp(argv[1], "--learn-client") == 0)
    {
        const char* mode = "status";
        const char* out = "checkpoint.out";
        unsigned long long decree = 0;
        unsigned long long size = 0;
        for (int i = 4; i + 1 < argc; i += 2)
        {
            if (strcmp(argv[i], "--mode") == 0) { mode = argv[i + 1]; }
            else if (strcmp(argv[i], "--decree") == 0) { decree = strtoull(argv[i + 1], NULL, 10); }
            else if (strcmp(argv[i], "--size") == 0) { size = strtoull(argv[i + 1], NULL, 10); }
            else if (strcmp(argv[i], "--out") == 0) { out = argv[i + 1]; }
        }
        return rsl_learn::RunClient(argv[2], atoi(argv[3]), mode, decree, size, out);
    }

    printf("# RSL Phase-1 golden vectors (generated by tools/golden-gen)\n");
    printf("# magic=0x%08x checksumOffset=%u\n\n",
           (unsigned)s_MessageMagic, (unsigned)s_ChecksumOffset);

    GenerateFingerprints();
    GenerateBaseMessages();
    GenerateVotes();
    GenerateJoinMessages();
    GeneratePrepareMessages();
    GeneratePrepareAccepted();
    GenerateStatusResponse();
    GenerateBootstrap();
    // New record kinds go last so existing RECORD/FPRINT bytes never move.
    GenerateContainers();
    GeneratePackets();
    GenerateLearn();

    fprintf(stderr, "self-check: %d passed, %d failed\n",
            g_selfCheckPassed, g_selfCheckFailed);
    return g_selfCheckFailed == 0 ? 0 : 1;
}
