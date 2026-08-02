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

void EmitRecord(const char* type, const char* desc, int version, Message& msg)
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
            EmitRecord("Message", desc, (int)v, msg);
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
            EmitRecord("Vote", desc, (int)v, vote);
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
            EmitRecord("Vote", "Vote with 2 requests", (int)v, vote);
        }

        // Vote with a non-empty primary cookie (v>=2 marshals the cookie).
        if (v >= RSLProtocolVersion_2)
        {
            const char cookieData[] = "primary-cookie-bytes";
            PrimaryCookie cookie((void*)cookieData, (UInt32)sizeof(cookieData) - 1, true);
            Vote vote(v, Member("101"), 0x1000ULL, 7, Ballot(44, "202"), &cookie);
            const char req[] = "req-with-cookie";
            vote.AddRequest((char*)req, (UInt32)sizeof(req) - 1, NULL);
            EmitRecord("Vote", "Vote with primary cookie + 1 request", (int)v, vote);
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
            EmitRecord("Vote", "Reconfiguration vote (2 members)", (int)v, vote);
        }

        // Relinquish-primary vote (v>=5).
        if (v >= RSLProtocolVersion_5)
        {
            PrimaryCookie cookie;
            Vote vote(v, Member("101"), 0x2000ULL, 7, Ballot(45, "202"),
                      &cookie, /*relinquishPrimary*/ true);
            EmitRecord("Vote", "Vote relinquishPrimary=true", (int)v, vote);
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
        EmitRecord("JoinMessage", "Join with log/checkpoint fields", (int)v, msg);
    }
}

void GeneratePrepareMessages()
{
    for (RSLProtocolVersion v : kVersions)
    {
        const char cookieData[] = "prep-cookie";
        PrimaryCookie cookie((void*)cookieData, (UInt32)sizeof(cookieData) - 1, true);
        PrepareMsg msg(v, Member("101"), 0xdeadbeefULL, 4, Ballot(7, "202"), &cookie);
        EmitRecord("PrepareMsg", "Prepare with cookie", (int)v, msg);
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
        EmitRecord("PrepareAccepted", "PrepareAccepted wrapping a vote", (int)v, msg);
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
        EmitRecord("StatusResponse", "StatusResponse full", (int)v, msg);
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
        EmitRecord("BootstrapMsg", "Bootstrap (3 members)", (int)v, msg);
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
