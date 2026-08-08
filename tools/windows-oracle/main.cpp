#include "fingerprint.h"
#include "interop_test_facade.h"
#include "legislator.h"
#include "learn_oracle.h"
#include "message.h"
#include "network_oracle.h"
#include "rsl.h"
#include "SSLImpl.h"
#include "utils.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <io.h>
#include <string>
#include <utility>
#include <vector>

using namespace RSLib;
using namespace RSLibImpl;

namespace
{
void OracleLogEntry(
    const char *,
    const char *,
    int,
    int,
    CallBackLogLevel,
    const char *title,
    const char *format,
    va_list arguments)
{
    fprintf(stderr, "RSL_LOG %s: ", title == NULL ? "" : title);
    vfprintf(stderr, format, arguments);
    fputc('\n', stderr);
}

const int kSchemaVersion = 1;
const char *kGeneratorIdentity = "rsl-windows-production-oracle";
size_t g_recordCount;
size_t g_fingerprintCount;
size_t g_containerCount;
std::string g_vectorMetadata;

const RSLProtocolVersion kVersions[] = {
    RSLProtocolVersion_1,
    RSLProtocolVersion_2,
    RSLProtocolVersion_3,
    RSLProtocolVersion_4,
    RSLProtocolVersion_5,
    RSLProtocolVersion_6,
};

std::string JsonString(const std::string &value)
{
    std::string result("\"");
    for (size_t i = 0; i < value.size(); ++i)
    {
        unsigned char c = static_cast<unsigned char>(value[i]);
        switch (c)
        {
        case '\\': result += "\\\\"; break;
        case '"': result += "\\\""; break;
        case '\r': result += "\\r"; break;
        case '\n': result += "\\n"; break;
        case '\t': result += "\\t"; break;
        default:
            if (c < 0x20)
            {
                char escaped[8];
                sprintf_s(escaped, "\\u%04x", c);
                result += escaped;
            }
            else
            {
                result += static_cast<char>(c);
            }
        }
    }
    result += '"';
    return result;
}

std::string Hex(const void *data, size_t length)
{
    static const char digits[] = "0123456789abcdef";
    const unsigned char *bytes = static_cast<const unsigned char *>(data);
    std::string result;
    result.reserve(length * 2);
    for (size_t i = 0; i < length; ++i)
    {
        result += digits[bytes[i] >> 4];
        result += digits[bytes[i] & 0xf];
    }
    return result;
}

std::string Hex64(UInt64 value)
{
    char text[32];
    sprintf_s(text, "%016I64x", value);
    return text;
}

void AddVectorMetadata(const std::string &metadata)
{
    if (!g_vectorMetadata.empty())
    {
        g_vectorMetadata += ",\n";
    }
    g_vectorMetadata += "    " + metadata;
}

const char *Architecture()
{
#if defined(_M_X64)
    return "x86_64";
#elif defined(_M_ARM64)
    return "arm64";
#else
    return "unknown";
#endif
}

const char *Configuration()
{
#if defined(_DEBUG)
    return "Debug";
#else
    return "Release";
#endif
}

std::string RunGit(const char *arguments)
{
    std::string command = "git ";
    command += arguments;
    command += " 2>NUL";
    FILE *pipe = _popen(command.c_str(), "r");
    if (pipe == NULL)
    {
        return "unknown";
    }

    char buffer[256];
    std::string result;
    while (fgets(buffer, sizeof(buffer), pipe) != NULL)
    {
        result += buffer;
    }
    _pclose(pipe);
    while (!result.empty() && (result.back() == '\r' || result.back() == '\n'))
    {
        result.pop_back();
    }
    return result.empty() ? "unknown" : result;
}

bool GitIsDirty()
{
    FILE *pipe = _popen("git status --porcelain --untracked-files=no 2>NUL", "r");
    if (pipe == NULL)
    {
        return false;
    }
    int first = fgetc(pipe);
    _pclose(pipe);
    return first != EOF;
}

MemberId Member(const char *value)
{
    return MemberId(value);
}

BallotNumber Ballot(UInt32 id, const char *member)
{
    return BallotNumber(id, Member(member));
}

RSLNode MakeNode(
    const char *id,
    unsigned int ip,
    unsigned short port,
    unsigned short learnPort,
    const char *host)
{
    RSLNode node;
    strcpy_s(node.m_memberIdString, id);
    strcpy_s(node.m_hostName, host);
    node.m_ip = ip;
    node.m_rslPort = port;
    node.m_rslLearnPort = learnPort;
    node.m_appPort = static_cast<unsigned short>(port + 2);
    return node;
}

std::vector<char> MarshalWithChecksum(Message &message, UInt64 *checksum)
{
    UInt32 length = message.GetMarshalLen();
    std::vector<char> bytes(length);
    FixedMarshalMemoryManager manager(bytes.data(), length);
    MarshalData marshal(&manager);
    message.Marshal(&marshal);
    bytes.resize(marshal.GetMarshaledLength());

    UInt32 dataOffset = s_ChecksumOffset + sizeof(UInt64);
    UInt64 calculated = Utils::CalculateChecksum(
        bytes.data() + dataOffset,
        static_cast<UInt32>(bytes.size()) - dataOffset);
    memcpy(bytes.data() + s_ChecksumOffset, &calculated, sizeof(calculated));
    if (checksum != NULL)
    {
        *checksum = calculated;
    }
    return bytes;
}

bool EmitRecord(FILE *output, const char *type, const char *description, Message &message)
{
    UInt64 checksum;
    std::vector<char> bytes = MarshalWithChecksum(message, &checksum);
    Message check;
    if (!check.UnMarshalBuf(bytes.data(), static_cast<UInt32>(bytes.size())) ||
        !check.VerifyChecksum(bytes.data(), static_cast<UInt32>(bytes.size())))
    {
        return false;
    }

    fprintf(output, "RECORD\n");
    fprintf(output, "TYPE %s\n", type);
    fprintf(output, "DESC %s\n", description);
    fprintf(output, "VERSION %u\n", static_cast<unsigned int>(message.m_version));
    fprintf(output, "LEN %Iu\n", bytes.size());
    fprintf(output, "CHECKSUM %s\n", Hex64(checksum).c_str());
    fprintf(output, "BYTES %s\n\n", Hex(bytes.data(), bytes.size()).c_str());

    char metadata[160];
    sprintf_s(
        metadata,
        "\"version\":%u,\"length\":%Iu",
        static_cast<unsigned int>(message.m_version),
        bytes.size());
    AddVectorMetadata(
        "{\"kind\":\"record\",\"type\":" + JsonString(type) +
        ",\"description\":" + JsonString(description) + "," + metadata + "}");
    ++g_recordCount;
    return true;
}

void EmitFingerprint(FILE *output, const char *description, const void *data, size_t length)
{
    UInt64 fingerprint = FingerPrint64::GetInstance()->GetFingerPrint(data, length);
    fprintf(output, "FPRINT\n");
    fprintf(output, "DESC %s\n", description);
    fprintf(output, "LEN %Iu\n", length);
    if (length == 0)
    {
        fprintf(output, "INPUT\n");
    }
    else
    {
        fprintf(output, "INPUT %s\n", Hex(data, length).c_str());
    }
    fprintf(output, "CHECKSUM %s\n\n", Hex64(fingerprint).c_str());
    AddVectorMetadata(
        "{\"kind\":\"fingerprint\",\"description\":" + JsonString(description) +
        ",\"length\":" + std::to_string(length) +
        ",\"checksum\":" + JsonString(Hex64(fingerprint)) + "}");
    ++g_fingerprintCount;
}

void EmitContainer(FILE *output, const char *description, MarshalData &marshal)
{
    fprintf(output, "CONTAINER\n");
    fprintf(output, "DESC %s\n", description);
    fprintf(output, "LEN %u\n", marshal.GetMarshaledLength());
    fprintf(
        output,
        "BYTES %s\n\n",
        Hex(marshal.GetMarshaled(), marshal.GetMarshaledLength()).c_str());
    AddVectorMetadata(
        "{\"kind\":\"container\",\"description\":" + JsonString(description) +
        ",\"length\":" + std::to_string(marshal.GetMarshaledLength()) + "}");
    ++g_containerCount;
}

bool GenerateWire(const char *fileName)
{
    g_recordCount = 0;
    g_fingerprintCount = 0;
    g_containerCount = 0;
    g_vectorMetadata.clear();

    FILE *output = NULL;
    if (fopen_s(&output, fileName, "wb") != 0 || output == NULL)
    {
        fprintf(stderr, "cannot write %s\n", fileName);
        return false;
    }

    fprintf(output, "# schemaVersion=%d\n", kSchemaVersion);
    fprintf(output, "# generator=%s\n", kGeneratorIdentity);
    fprintf(output, "# sourceRevision=%s\n", RunGit("rev-parse HEAD").c_str());
    fprintf(output, "# sourceDirty=%s\n", GitIsDirty() ? "true" : "false");
    fprintf(output, "# architecture=%s\n", Architecture());
    fprintf(output, "# configuration=%s\n\n", Configuration());

    EmitFingerprint(output, "empty", "", 0);
    const char *strings[] = {
        "a",
        "abc",
        "message digest",
        "The quick brown fox jumps over the lazy dog",
        "\x00\x01\x02\x03\x04\x05\x06\x07",
    };
    const size_t lengths[] = { 1, 3, 14, 43, 8 };
    for (size_t i = 0; i < _countof(strings); ++i)
    {
        char description[32];
        sprintf_s(description, "string#%Iu", i);
        EmitFingerprint(output, description, strings[i], lengths[i]);
    }
    unsigned char ramp[256];
    for (size_t i = 0; i < _countof(ramp); ++i)
    {
        ramp[i] = static_cast<unsigned char>(i);
    }
    EmitFingerprint(output, "ramp-256", ramp, sizeof(ramp));

    struct BaseMessage
    {
        UInt16 id;
        const char *name;
    };
    const BaseMessage baseMessages[] = {
        { Message_None, "None" },
        { Message_VoteAccepted, "VoteAccepted" },
        { Message_Prepare, "Prepare_base" },
        { Message_PrepareAccepted, "PrepareAccepted_base" },
        { Message_NotAccepted, "NotAccepted" },
        { Message_StatusQuery, "StatusQuery" },
        { Message_StatusResponse, "StatusResponse_base" },
        { Message_FetchVotes, "FetchVotes" },
        { Message_FetchCheckpoint, "FetchCheckpoint" },
        { Message_ReconfigurationDecision, "ReconfigurationDecision" },
        { Message_DefunctConfiguration, "DefunctConfiguration" },
        { Message_JoinRequest, "JoinRequest" },
    };

    bool success = true;
    for (size_t i = 0; i < _countof(baseMessages); ++i)
    {
        for (size_t v = 0; v < _countof(kVersions); ++v)
        {
            Message message(
                kVersions[v],
                baseMessages[i].id,
                Member("101"),
                0x1122334455667788ULL,
                0x0a0b0c0d,
                Ballot(0x00c0ffee, "202"),
                0xf0e1d2c3b4a59687ULL);
            success = EmitRecord(output, "Message", baseMessages[i].name, message) && success;
        }
    }

    for (size_t v = 0; v < _countof(kVersions); ++v)
    {
        PrimaryCookie cookie;
        Vote vote(kVersions[v], Member("101"), 0xabcdefULL, 7, Ballot(42, "202"), &cookie);
        const char first[] = "hello-decree";
        const char second[] = "second-request-payload";
        vote.AddRequest(const_cast<char *>(first), sizeof(first) - 1, NULL);
        vote.AddRequest(const_cast<char *>(second), sizeof(second) - 1, NULL);
        success = EmitRecord(output, "Vote", "Vote with 2 requests", vote) && success;

        JoinMessage join(kVersions[v], Member("101"), 0x5566778899aabbccULL, 3);
        join.m_learnPort = 0xbeef;
        join.m_minDecreeInLog = 0x1000;
        join.m_checkpointedDecree = 0x0fff;
        join.m_checkpointSize = 0x123456789aULL;
        success = EmitRecord(output, "JoinMessage", "Join with checkpoint fields", join) && success;

        PrepareMsg prepare(
            kVersions[v],
            Member("101"),
            0xdeadbeefULL,
            4,
            Ballot(7, "202"),
            &cookie);
        success = EmitRecord(output, "PrepareMsg", "Prepare", prepare) && success;

        Vote *acceptedVote = new Vote(
            kVersions[v],
            Member("101"),
            0xcafeULL,
            4,
            Ballot(7, "202"),
            &cookie);
        PrepareAccepted accepted(
            kVersions[v],
            Member("101"),
            0xcafeULL,
            4,
            Ballot(8, "202"),
            acceptedVote);
        success = EmitRecord(output, "PrepareAccepted", "PrepareAccepted", accepted) && success;

        StatusResponse status(kVersions[v], Member("101"), 0x11ULL, 5, Ballot(9, "202"));
        status.m_queryDecree = 0x22;
        status.m_queryBallot = Ballot(10, "303");
        status.m_lastReceivedAgo = 0x33;
        status.m_minDecreeInLog = 0x44;
        status.m_checkpointedDecree = 0x55;
        status.m_checkpointSize = 0x66;
        status.m_maxBallot = Ballot(11, "404");
        status.m_state = 0x77;
        success = EmitRecord(output, "StatusResponse", "StatusResponse full", status) && success;

        if (kVersions[v] >= RSLProtocolVersion_4)
        {
            RSLNodeCollection members;
            members.Append(MakeNode("101", 0x0100007f, 8080, 8081, "host-a"));
            members.Append(MakeNode("202", 0x0100017f, 9090, 9091, "host-b"));
            const char configCookie[] = "bootstrap-cfg";
            MemberSet memberSet(
                members,
                const_cast<char *>(configCookie),
                sizeof(configCookie) - 1);
            BootstrapMsg bootstrap(kVersions[v], Member("101"), memberSet);
            success = EmitRecord(output, "BootstrapMsg", "Bootstrap", bootstrap) && success;
        }
    }

    {
        MarshalData marshal;
        MarshalStartPlaceHolder *placeholder = marshal.StartContainer(true);
        marshal.WriteData(5, const_cast<char *>("hello"));
        marshal.CloseContainer(placeholder);
        EmitContainer(output, "short-hello", marshal);
    }
    {
        MarshalData marshal;
        MarshalStartPlaceHolder *placeholder = marshal.StartContainer(false);
        marshal.WriteData(5, const_cast<char *>("hello"));
        marshal.CloseContainer(placeholder);
        EmitContainer(output, "long-hello", marshal);
    }
    {
        MarshalData marshal;
        MarshalStartPlaceHolder *outer = marshal.StartContainer(false);
        marshal.WriteUInt32(0xdeadbeef);
        MarshalStartPlaceHolder *inner = marshal.StartContainer(true);
        marshal.WriteData(3, const_cast<char *>("abc"));
        marshal.CloseContainer(inner);
        marshal.WriteUInt16(0xbeef);
        marshal.CloseContainer(outer);
        EmitContainer(output, "nested-long-short", marshal);
    }

    __int64 outputLength = _ftelli64(output);
    fflush(output);
    if (outputLength <= 0 || _chsize_s(_fileno(output), outputLength - 1) != 0)
    {
        fclose(output);
        return false;
    }
    fclose(output);
    if (!success)
    {
        return false;
    }

    std::string manifestPath = std::string(fileName) + ".manifest.json";
    FILE *manifest = NULL;
    if (fopen_s(&manifest, manifestPath.c_str(), "wb") != 0 || manifest == NULL)
    {
        return false;
    }
    fprintf(manifest, "{\n");
    fprintf(manifest, "  \"schemaVersion\": %d,\n", kSchemaVersion);
    fprintf(manifest, "  \"generator\": {\n");
    fprintf(manifest, "    \"identity\": %s,\n", JsonString(kGeneratorIdentity).c_str());
    fprintf(manifest, "    \"sourceRevision\": %s,\n", JsonString(RunGit("rev-parse HEAD")).c_str());
    fprintf(manifest, "    \"sourceDirty\": %s,\n", GitIsDirty() ? "true" : "false");
    fprintf(manifest, "    \"architecture\": %s,\n", JsonString(Architecture()).c_str());
    fprintf(manifest, "    \"configuration\": %s\n", JsonString(Configuration()).c_str());
    fprintf(manifest, "  },\n");
    fprintf(manifest, "  \"artifactPolicy\": {\n");
    fprintf(manifest, "    \"literalWindowsFile\": true,\n");
    fprintf(manifest, "    \"byteStable\": false,\n");
    fprintf(
        manifest,
        "    \"canonicalMetadata\": "
        "\"vector kinds, descriptions, versions, lengths, and stable checksums\"\n");
    fprintf(manifest, "  },\n");
    fprintf(manifest, "  \"records\": %Iu,\n", g_recordCount);
    fprintf(manifest, "  \"fingerprints\": %Iu,\n", g_fingerprintCount);
    fprintf(manifest, "  \"containers\": %Iu,\n", g_containerCount);
    fprintf(manifest, "  \"vectors\": [\n%s\n  ]\n", g_vectorMetadata.c_str());
    fprintf(manifest, "}\n");
    fclose(manifest);
    return true;
}

CheckpointHeader *MakeCheckpointHeader(RSLProtocolVersion version, UInt64 decree)
{
    PrimaryCookie cookie;
    Vote *nextVote = new Vote(
        version,
        Member("101"),
        decree + 1,
        7,
        Ballot(5, "202"),
        &cookie);
    nextVote->CalculateChecksum();

    CheckpointHeader *header = new CheckpointHeader();
    header->m_version = version;
    header->m_memberId = Member("101");
    header->m_lastExecutedDecree = decree;
    header->m_maxBallot = Ballot(9, "202");
    header->m_nextVote = nextVote;
    header->m_stateSaved = true;
    header->m_checksumBlockSize =
        version >= RSLProtocolVersion_4 ? s_ChecksumBlockSize : 0;

    RSLNodeCollection members;
    members.Append(MakeNode("101", 0x0100007f, 8080, 8081, "host-a"));
    members.Append(MakeNode("202", 0x0100017f, 9090, 9091, "host-b"));
    const char configCookie[] = "cfg";
    MemberSet *memberSet = new MemberSet(
        members,
        const_cast<char *>(configCookie),
        sizeof(configCookie) - 1);
    header->m_stateConfiguration = new ConfigurationInfo(
        0x0a0b0c0d,
        decree + 1,
        memberSet);
    return header;
}

std::string Join(const std::string &directory, const std::string &name)
{
    std::string result = directory;
    if (!result.empty() && result.back() != '\\')
    {
        result += '\\';
    }
    result += name;
    return result;
}

std::string LogDirectory(const std::string &directory)
{
    std::string result = directory;
    if (!result.empty() && result.back() != '\\')
    {
        result += '\\';
    }
    return result;
}

bool MutateByte(const std::string &path, UInt64 offset)
{
    HANDLE file = CreateFileA(
        path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    LARGE_INTEGER position;
    position.QuadPart = offset;
    bool success = SetFilePointerEx(file, position, NULL, FILE_BEGIN) != FALSE;
    unsigned char value;
    DWORD transferred;
    success = success && ReadFile(file, &value, 1, &transferred, NULL) != FALSE && transferred == 1;
    value ^= 0xff;
    success = success && SetFilePointerEx(file, position, NULL, FILE_BEGIN) != FALSE;
    success = success && WriteFile(file, &value, 1, &transferred, NULL) != FALSE && transferred == 1;
    CloseHandle(file);
    return success;
}

UInt64 FileLength(const std::string &path)
{
    WIN32_FILE_ATTRIBUTE_DATA data;
    if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &data))
    {
        return 0;
    }
    ULARGE_INTEGER size;
    size.LowPart = data.nFileSizeLow;
    size.HighPart = data.nFileSizeHigh;
    return size.QuadPart;
}

bool TruncateFile(const std::string &path, UInt64 length)
{
    HANDLE file = CreateFileA(
        path.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    LARGE_INTEGER position;
    position.QuadPart = length;
    bool success =
        SetFilePointerEx(file, position, NULL, FILE_BEGIN) != FALSE &&
        SetEndOfFile(file) != FALSE;
    CloseHandle(file);
    return success;
}

const char *OutcomeName(InteropStorageOutcome outcome)
{
    switch (outcome)
    {
    case InteropStorageAccept: return "accept";
    case InteropStorageStop: return "stop-at-offset";
    case InteropStorageReject: return "reject";
    default: return "unknown";
    }
}

std::string LogJson(const std::string &name, const InteropLogVerdict &verdict)
{
    char numbers[256];
    sprintf_s(
        numbers,
        "\"size\":%I64u,\"outcome\":\"%s\",\"stopOffset\":%I64u,\"recordCount\":%Iu",
        verdict.fileSize,
        OutcomeName(verdict.outcome),
        verdict.stopOffset,
        verdict.records.size());
    return
        "{\"file\":" + JsonString(name) +
        ",\"kind\":\"log\"," + numbers +
        ",\"detail\":" + JsonString(verdict.detail) + "}";
}

std::string CheckpointJson(
    const std::string &name,
    const InteropCheckpointVerdict &verdict)
{
    char numbers[320];
    sprintf_s(
        numbers,
        "\"size\":%I64u,\"outcome\":\"%s\",\"version\":%u,"
        "\"headerLen\":%u,\"userDataSize\":%I64u,\"checksumBlockSize\":%u,"
        "\"stateSaved\":%s",
        verdict.fileSize,
        OutcomeName(verdict.outcome),
        verdict.version,
        verdict.headerLen,
        verdict.userDataSize,
        verdict.checksumBlockSize,
        verdict.stateSaved ? "true" : "false");
    return
        "{\"file\":" + JsonString(name) +
        ",\"kind\":\"checkpoint\"," + numbers +
        ",\"detail\":" + JsonString(verdict.detail) + "}";
}

bool EndsWith(const std::string &value, const char *suffix)
{
    size_t suffixLength = strlen(suffix);
    return
        value.size() >= suffixLength &&
        value.compare(value.size() - suffixLength, suffixLength, suffix) == 0;
}

bool VerifyOne(const std::string &directory, const std::string &name, std::string *json)
{
    std::string path = Join(directory, name);
    if (EndsWith(name, ".log"))
    {
        InteropLogVerdict verdict;
        if (!RSLInteropTestFacade::ScanLog(path.c_str(), &verdict))
        {
            return false;
        }
        *json = LogJson(name, verdict);
        return verdict.outcome != InteropStorageReject;
    }

    InteropCheckpointVerdict verdict;
    if (!RSLInteropTestFacade::VerifyCheckpoint(path.c_str(), &verdict))
    {
        return false;
    }
    *json = CheckpointJson(name, verdict);
    return verdict.outcome != InteropStorageReject;
}

std::vector<std::string> StorageFiles(const std::string &directory)
{
    std::vector<std::string> names;
    WIN32_FIND_DATAA data;
    HANDLE find = FindFirstFileA(Join(directory, "*").c_str(), &data);
    if (find == INVALID_HANDLE_VALUE)
    {
        return names;
    }
    do
    {
        std::string name = data.cFileName;
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 &&
            (EndsWith(name, ".log") || EndsWith(name, ".codex")))
        {
            names.push_back(name);
        }
    } while (FindNextFileA(find, &data));
    FindClose(find);
    std::sort(names.begin(), names.end());
    return names;
}

int VerifyStorage(const std::string &directory)
{
    std::vector<std::string> names = StorageFiles(directory);
    if (names.empty())
    {
        fprintf(stderr, "no .log or .codex files in %s\n", directory.c_str());
        return 2;
    }

    bool rejected = false;
    for (size_t i = 0; i < names.size(); ++i)
    {
        std::string json;
        bool accepted = VerifyOne(directory, names[i], &json);
        if (json.empty())
        {
            fprintf(stderr, "failed to inspect %s (error=%lu)\n", names[i].c_str(), GetLastError());
            return 2;
        }
        printf("%s\n", json.c_str());
        rejected = !accepted || rejected;
    }
    return rejected ? 3 : 0;
}

bool GenerateStorage(const std::string &directory, bool includeLarge)
{
    if (!CreateDirectoryA(directory.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
    {
        fprintf(stderr, "cannot create %s (error=%lu)\n", directory.c_str(), GetLastError());
        return false;
    }

    std::string logDirectory = LogDirectory(directory);
    PrimaryCookie cookie;
    Vote validVote(
        RSLProtocolVersion_6,
        Member("101"),
        100,
        7,
        Ballot(3, "202"),
        &cookie);
    Message *validMessages[] = { &validVote };
    if (RSLInteropTestFacade::WriteLog(
            logDirectory.c_str(),
            100,
            validMessages,
            _countof(validMessages)) != NO_ERROR)
    {
        return false;
    }

    Vote corruptFirst(
        RSLProtocolVersion_6,
        Member("101"),
        300,
        7,
        Ballot(3, "202"),
        &cookie);
    Vote corruptSecond(
        RSLProtocolVersion_6,
        Member("101"),
        301,
        7,
        Ballot(3, "202"),
        &cookie);
    Message *corruptMessages[] = { &corruptFirst, &corruptSecond };
    if (RSLInteropTestFacade::WriteLog(
            logDirectory.c_str(),
            300,
            corruptMessages,
            _countof(corruptMessages)) != NO_ERROR ||
        !MutateByte(Join(directory, "300.log"), 20))
    {
        return false;
    }

    Vote tornFirst(
        RSLProtocolVersion_6,
        Member("101"),
        200,
        7,
        Ballot(3, "202"),
        &cookie);
    Vote tornSecond(
        RSLProtocolVersion_6,
        Member("101"),
        201,
        7,
        Ballot(3, "202"),
        &cookie);
    std::vector<char> request(600, 'x');
    tornSecond.AddRequest(request.data(), static_cast<UInt32>(request.size()), NULL);
    Message *tornMessages[] = { &tornFirst, &tornSecond };
    std::string tornPath = Join(directory, "200.log");
    if (RSLInteropTestFacade::WriteLog(
            logDirectory.c_str(),
            200,
            tornMessages,
            _countof(tornMessages)) != NO_ERROR ||
        !TruncateFile(tornPath, FileLength(tornPath) - 100))
    {
        return false;
    }

    std::vector<char> state(4096);
    for (size_t i = 0; i < state.size(); ++i)
    {
        state[i] = static_cast<char>(i & 0xff);
    }
    CheckpointHeader *header = MakeCheckpointHeader(RSLProtocolVersion_6, 500);
    std::string checkpointPath = Join(directory, "500.codex");
    if (RSLInteropTestFacade::WriteCheckpoint(
            checkpointPath.c_str(),
            header,
            state.data(),
            state.size()) != NO_ERROR)
    {
        return false;
    }
    std::string corruptCheckpointPath = Join(directory, "501-corrupt.codex");
    if (!CopyFileA(checkpointPath.c_str(), corruptCheckpointPath.c_str(), FALSE) ||
        !MutateByte(corruptCheckpointPath, header->GetMarshalLen() + 17))
    {
        return false;
    }

    std::vector<std::pair<std::string, std::string> > expected;
    expected.push_back(std::make_pair("100.log", "accept"));
    expected.push_back(std::make_pair("200.log", "stop-at-offset"));
    expected.push_back(std::make_pair("300.log", "reject"));
    expected.push_back(std::make_pair("500.codex", "accept"));
    expected.push_back(std::make_pair("501-corrupt.codex", "reject"));

    if (includeLarge)
    {
        const size_t dataOnlyBlock = s_ChecksumBlockSize - sizeof(UInt64);
        const size_t stateLengths[] = {
            dataOnlyBlock,
            dataOnlyBlock + 1,
            dataOnlyBlock * 2 + 50,
        };
        const UInt64 decrees[] = { 600, 601, 602 };
        for (size_t i = 0; i < _countof(stateLengths); ++i)
        {
            std::vector<char> largeState(stateLengths[i]);
            for (size_t j = 0; j < largeState.size(); ++j)
            {
                largeState[j] = static_cast<char>(j & 0xff);
            }
            CheckpointHeader *largeHeader =
                MakeCheckpointHeader(RSLProtocolVersion_6, decrees[i]);
            char name[64];
            sprintf_s(name, "%I64u.codex", decrees[i]);
            if (RSLInteropTestFacade::WriteCheckpoint(
                    Join(directory, name).c_str(),
                    largeHeader,
                    largeState.data(),
                    largeState.size()) != NO_ERROR)
            {
                return false;
            }
            expected.push_back(std::make_pair(name, "accept"));
        }
    }

    std::string entries;
    for (size_t i = 0; i < expected.size(); ++i)
    {
        std::string json;
        VerifyOne(directory, expected[i].first, &json);
        if (json.find(
                std::string("\"outcome\":\"") +
                expected[i].second +
                "\"") == std::string::npos)
        {
            fprintf(
                stderr,
                "unexpected production verdict for %s: %s\n",
                expected[i].first.c_str(),
                json.c_str());
            return false;
        }
        if (!entries.empty())
        {
            entries += ",\n";
        }
        entries += "    " + json;
    }

    std::string manifestPath = Join(directory, "MANIFEST.json");
    FILE *manifest = NULL;
    if (fopen_s(&manifest, manifestPath.c_str(), "wb") != 0 || manifest == NULL)
    {
        return false;
    }
    fprintf(manifest, "{\n");
    fprintf(manifest, "  \"schemaVersion\": %d,\n", kSchemaVersion);
    fprintf(manifest, "  \"generator\": {\n");
    fprintf(manifest, "    \"identity\": %s,\n", JsonString(kGeneratorIdentity).c_str());
    fprintf(manifest, "    \"sourceRevision\": %s,\n", JsonString(RunGit("rev-parse HEAD")).c_str());
    fprintf(manifest, "    \"sourceDirty\": %s,\n", GitIsDirty() ? "true" : "false");
    fprintf(manifest, "    \"architecture\": %s,\n", JsonString(Architecture()).c_str());
    fprintf(manifest, "    \"configuration\": %s\n", JsonString(Configuration()).c_str());
    fprintf(manifest, "  },\n");
    fprintf(manifest, "  \"artifactPolicy\": {\n");
    fprintf(manifest, "    \"literalWindowsFiles\": true,\n");
    fprintf(manifest, "    \"byteStable\": false,\n");
    fprintf(manifest, "    \"canonicalMetadata\": \"production reader verdicts and recovered fields\"\n");
    fprintf(manifest, "  },\n");
    fprintf(manifest, "  \"files\": [\n%s\n  ]\n", entries.c_str());
    fprintf(manifest, "}\n");
    fclose(manifest);
    return true;
}

void PrintIdentity()
{
    printf(
        "{\"schemaVersion\":%d,\"identity\":%s,\"sourceRevision\":%s,"
        "\"sourceDirty\":%s,\"architecture\":%s,\"configuration\":%s}\n",
        kSchemaVersion,
        JsonString(kGeneratorIdentity).c_str(),
        JsonString(RunGit("rev-parse HEAD")).c_str(),
        GitIsDirty() ? "true" : "false",
        JsonString(Architecture()).c_str(),
        JsonString(Configuration()).c_str());
}

int SelfTest()
{
    char tempPath[MAX_PATH];
    if (GetTempPathA(_countof(tempPath), tempPath) == 0)
    {
        return 1;
    }
    char directory[MAX_PATH];
    sprintf_s(directory, "%sRSLWindowsOracle-%lu", tempPath, GetCurrentProcessId());
    if (!GenerateStorage(directory, false))
    {
        return 1;
    }

    std::string wire = Join(directory, "wire.txt");
    if (!GenerateWire(wire.c_str()))
    {
        return 1;
    }

    const char *files[] = {
        "100.log",
        "200.log",
        "300.log",
        "500.codex",
        "501-corrupt.codex",
        "MANIFEST.json",
        "wire.txt",
        "wire.txt.manifest.json",
    };
    for (size_t i = 0; i < _countof(files); ++i)
    {
        DeleteFileA(Join(directory, files[i]).c_str());
    }
    RemoveDirectoryA(directory);
    printf("self-test: production wire and storage paths passed\n");
    return 0;
}

bool EnvironmentFlag(const char *name, bool defaultValue, bool *valid)
{
    char value[16];
    DWORD length = GetEnvironmentVariableA(name, value, _countof(value));
    if (length == 0)
    {
        return defaultValue;
    }
    if (length >= _countof(value))
    {
        *valid = false;
        return defaultValue;
    }
    if (_stricmp(value, "yes") == 0 || strcmp(value, "1") == 0 ||
        _stricmp(value, "true") == 0)
    {
        return true;
    }
    if (_stricmp(value, "no") == 0 || strcmp(value, "0") == 0 ||
        _stricmp(value, "false") == 0)
    {
        return false;
    }
    *valid = false;
    return defaultValue;
}

std::string EnvironmentValue(const char *name)
{
    DWORD length = GetEnvironmentVariableA(name, NULL, 0);
    if (length == 0)
    {
        return std::string();
    }
    std::vector<char> value(length);
    GetEnvironmentVariableA(name, value.data(), length);
    return std::string(value.data());
}

bool ConfigureTls()
{
    std::string thumbprintA = EnvironmentValue("RSL_TLS_THUMBPRINT_A");
    std::string thumbprintB = EnvironmentValue("RSL_TLS_THUMBPRINT_B");
    if (thumbprintA.empty() && thumbprintB.empty())
    {
        return true;
    }

    bool valid = true;
    bool validateChain = EnvironmentFlag("RSL_TLS_VALIDATE_CHAIN", true, &valid);
    bool checkRevocation = EnvironmentFlag("RSL_TLS_CHECK_REVOCATION", false, &valid);
    bool whitelist = EnvironmentFlag("RSL_TLS_WHITELIST", true, &valid);
    if (!valid)
    {
        fprintf(stderr, "TLS_CONFIG outcome=reject detail=invalid-boolean\n");
        return false;
    }

    std::string storeScope = EnvironmentValue("RSL_TLS_STORE_SCOPE");
    if (_stricmp(storeScope.c_str(), "CurrentUser") == 0)
    {
        SSLAuth::SetCertificateStoreLocation(CERT_SYSTEM_STORE_CURRENT_USER);
    }
    else if (!storeScope.empty() &&
             _stricmp(storeScope.c_str(), "LocalMachine") != 0)
    {
        fprintf(stderr, "TLS_CONFIG outcome=reject detail=invalid-store-scope\n");
        return false;
    }

    if (SSLAuth::SetSSLThumbprints(
            "MY",
            thumbprintA.empty() ? NULL : thumbprintA.c_str(),
            thumbprintB.empty() ? NULL : thumbprintB.c_str(),
            validateChain,
            checkRevocation) != ERROR_SUCCESS)
    {
        fprintf(stderr, "TLS_CONFIG outcome=reject detail=credential-or-thumbprint\n");
        return false;
    }

    std::string subjectA = EnvironmentValue("RSL_TLS_SUBJECT_A");
    std::string parentA = EnvironmentValue("RSL_TLS_PARENT_A");
    std::string subjectB = EnvironmentValue("RSL_TLS_SUBJECT_B");
    std::string parentB = EnvironmentValue("RSL_TLS_PARENT_B");
    if ((subjectA.empty() != parentA.empty()) ||
        (subjectB.empty() != parentB.empty()))
    {
        fprintf(stderr, "TLS_CONFIG outcome=reject detail=incomplete-subject-rule\n");
        return false;
    }
    if (!subjectA.empty() || !subjectB.empty())
    {
        if (SSLAuth::SetSSLSubjectNames(
                subjectA.empty() ? NULL : subjectA.c_str(),
                parentA.empty() ? NULL : parentA.c_str(),
                subjectB.empty() ? NULL : subjectB.c_str(),
                parentB.empty() ? NULL : parentB.c_str(),
                whitelist) != ERROR_SUCCESS)
        {
            fprintf(stderr, "TLS_CONFIG outcome=reject detail=subject-rule\n");
            return false;
        }
    }

    fprintf(
        stderr,
        "TLS_CONFIG outcome=accept store=%s slotA=%s slotB=%s "
        "chain=%s revocation=%s subjects=%s\n",
        _stricmp(storeScope.c_str(), "CurrentUser") == 0 ? "CurrentUser" : "LocalMachine",
        thumbprintA.empty() ? "no" : "yes",
        thumbprintB.empty() ? "no" : "yes",
        validateChain ? "enforce" : "log-only",
        checkRevocation ? "check" : "skip",
        subjectA.empty() && subjectB.empty() ? "no" : "yes");
    return true;
}
}

int main(int argc, char **argv)
{
    bool tlsRequested =
        GetEnvironmentVariableA("RSL_TLS_THUMBPRINT_A", NULL, 0) != 0 ||
        GetEnvironmentVariableA("RSL_TLS_THUMBPRINT_B", NULL, 0) != 0;
    if (!RSLInit(
            NULL,
            false,
            NULL,
            tlsRequested ? &OracleLogEntry : NULL))
    {
        fprintf(stderr, "RSLInit failed\n");
        return 1;
    }
    if (!ConfigureTls())
    {
        RSLUnload();
        return 4;
    }

    int result = 2;
    if (argc == 2 && strcmp(argv[1], "--identity") == 0)
    {
        PrintIdentity();
        result = 0;
    }
    else if (argc == 2 && strcmp(argv[1], "--self-test") == 0)
    {
        result = SelfTest();
    }
    else if (argc == 3 && strcmp(argv[1], "--wire") == 0)
    {
        result = GenerateWire(argv[2]) ? 0 : 1;
    }
    else if (argc == 3 && strcmp(argv[1], "--storage") == 0)
    {
        result = GenerateStorage(argv[2], false) ? 0 : 1;
    }
    else if (argc == 3 && strcmp(argv[1], "--storage-full") == 0)
    {
        result = GenerateStorage(argv[2], true) ? 0 : 1;
    }
    else if (argc == 3 && strcmp(argv[1], "--verify-storage") == 0)
    {
        result = VerifyStorage(argv[2]);
    }
    else if (argc >= 3 && strcmp(argv[1], "--net-server") == 0)
    {
        const char *mode = "echo";
        int count = 1;
        bool waitForDisconnect = false;
        for (int i = 3; i + 1 < argc; i += 2)
        {
            if (strcmp(argv[i], "--mode") == 0) { mode = argv[i + 1]; }
            else if (strcmp(argv[i], "--count") == 0) { count = atoi(argv[i + 1]); }
            else if (strcmp(argv[i], "--wait-disconnect") == 0)
            {
                waitForDisconnect = strcmp(argv[i + 1], "yes") == 0;
            }
        }
        std::string rotateA = EnvironmentValue("RSL_TLS_ROTATE_THUMBPRINT_A");
        std::string rotateB = EnvironmentValue("RSL_TLS_ROTATE_THUMBPRINT_B");
        bool valid = true;
        bool validateChain = EnvironmentFlag("RSL_TLS_VALIDATE_CHAIN", true, &valid);
        bool checkRevocation = EnvironmentFlag("RSL_TLS_CHECK_REVOCATION", false, &valid);
        result = valid ?
            rsl_oracle::RunNetworkServer(
                atoi(argv[2]),
                mode,
                count,
                waitForDisconnect,
                rotateA.empty() ? NULL : rotateA.c_str(),
                rotateB.empty() ? NULL : rotateB.c_str(),
                validateChain,
                checkRevocation) :
            2;
    }
    else if (argc >= 4 && strcmp(argv[1], "--net-client") == 0)
    {
        const char *payload = "";
        const char *expect = "echo";
        int count = 1;
        bool reconnectEach = false;
        for (int i = 4; i + 1 < argc; i += 2)
        {
            if (strcmp(argv[i], "--payload") == 0) { payload = argv[i + 1]; }
            else if (strcmp(argv[i], "--count") == 0) { count = atoi(argv[i + 1]); }
            else if (strcmp(argv[i], "--expect") == 0) { expect = argv[i + 1]; }
            else if (strcmp(argv[i], "--reconnect-each") == 0)
            {
                reconnectEach = strcmp(argv[i + 1], "yes") == 0;
            }
        }
        result = rsl_oracle::RunNetworkClient(
            argv[2],
            atoi(argv[3]),
            payload,
            count,
            expect,
            reconnectEach);
    }
    else if (argc >= 3 && strcmp(argv[1], "--learn-server") == 0)
    {
        const char *directory = NULL;
        int connections = 1;
        int version = 6;
        for (int i = 3; i + 1 < argc; i += 2)
        {
            if (strcmp(argv[i], "--dir") == 0) { directory = argv[i + 1]; }
            else if (strcmp(argv[i], "--connections") == 0) { connections = atoi(argv[i + 1]); }
            else if (strcmp(argv[i], "--version") == 0) { version = atoi(argv[i + 1]); }
        }
        if (directory == NULL)
        {
            fprintf(stderr, "--learn-server needs --dir\n");
            result = 2;
        }
        else
        {
            result = rsl_oracle::RunLearnServer(
                atoi(argv[2]),
                directory,
                connections,
                version);
        }
    }
    else if (argc >= 4 && strcmp(argv[1], "--learn-client") == 0)
    {
        const char *mode = "status";
        const char *outputFile = "";
        int version = 6;
        unsigned long long decree = 0;
        unsigned long long size = 0;
        unsigned int maxBallot = 99;
        for (int i = 4; i + 1 < argc; i += 2)
        {
            if (strcmp(argv[i], "--mode") == 0) { mode = argv[i + 1]; }
            else if (strcmp(argv[i], "--version") == 0) { version = atoi(argv[i + 1]); }
            else if (strcmp(argv[i], "--decree") == 0) { decree = _strtoui64(argv[i + 1], NULL, 10); }
            else if (strcmp(argv[i], "--size") == 0) { size = _strtoui64(argv[i + 1], NULL, 10); }
            else if (strcmp(argv[i], "--out") == 0) { outputFile = argv[i + 1]; }
            else if (strcmp(argv[i], "--max-ballot") == 0)
            {
                maxBallot = static_cast<unsigned int>(strtoul(argv[i + 1], NULL, 10));
            }
        }
        result = rsl_oracle::RunLearnClient(
            argv[2],
            atoi(argv[3]),
            mode,
            version,
            decree,
            size,
            outputFile,
            maxBallot);
    }
    else
    {
        fprintf(
            stderr,
            "usage: RSLWindowsOracle "
            "--identity | --self-test | --wire <file> | "
            "--storage <directory> | --storage-full <directory> | "
            "--verify-storage <directory> | "
            "--net-server <port> [--mode echo|log] [--count n] "
            "[--wait-disconnect yes|no] | "
            "--net-client <ip> <port> [--payload hex] [--count n] "
            "[--expect echo|disconnect] [--reconnect-each yes|no] | "
            "--learn-server <port> --dir <directory> [--connections n] "
            "[--version 1..6] | "
            "--learn-client <ip> <port> --mode status|votes|checkpoint "
            "[--version 1..6] [--decree n] [--size n] [--out file] "
            "[--max-ballot n]\n");
    }

    RSLUnload();
    return result;
}
