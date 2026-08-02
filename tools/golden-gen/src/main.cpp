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

#include "message.h"
#include "msg_engine_compat.h"
#include "utils.h"
#include "fingerprint.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

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

void EmitRecord(const char* type, const char* desc, int version, Message& msg,
                const std::string& fields)
{
    UInt64 checksum = 0;
    std::vector<char> buf = MarshalWithChecksum(msg, &checksum);
    SelfCheck(desc, buf);

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

} // namespace

int main()
{
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

    fprintf(stderr, "self-check: %d passed, %d failed\n",
            g_selfCheckPassed, g_selfCheckFailed);
    return g_selfCheckFailed == 0 ? 0 : 1;
}
