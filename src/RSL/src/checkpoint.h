#pragma once

// checkpoint.h -- declarations of the checkpoint (.codex) format types shared
// by the Windows RSL engine and the Linux golden-vector tool.
//
// ConfigurationInfo and CheckpointHeader define the byte layout of the .codex
// checkpoint file, so their data members and marshaling methods must stay
// identical between the engine and tools/golden-gen (which generates and
// verifies golden .log/.codex corpora on Linux for the Rust port). They used to
// be declared inline in legislator.h and copied by hand into the tool's compat
// header; having ONE declaration removes that drift risk.
//
// This header is NOT standalone-includable: it assumes MemberSet, MemberId,
// BallotNumber, Vote, MarshalData, Ptr<>/RefCount and RSLProtocolVersion are
// already declared. Both includers satisfy that:
//   - Windows: legislator.h includes it right after its MemberSet declaration.
//   - Linux:   tools/golden-gen/compat/storage_compat.h includes it after
//              msg_engine_compat.h (which supplies MemberSet + page helpers).
//
// Everything here is shared verbatim EXCEPT the Windows-only file/stream entry
// points on CheckpointHeader, which are guarded by _WIN32 because they take
// types that only exist in the engine build (StreamReader,
// RSLCheckpointStreamWriter, DynString -- the latter's header needs MSVC-only
// CRT functions). Those methods perform I/O; they carry no format information
// of their own, so guarding them does not split the byte layout.

namespace RSLibImpl
{
    // Checkpoint user state is written in blocks of this size, each block
    // ending in an 8-byte Rabin-64 checksum of its data.
    static const UInt32 s_ChecksumBlockSize = 4 * 1024 * 1024; // 4 megabytes

    class ConfigurationInfo : public RefCount
    {
    public:
        ConfigurationInfo() : m_configurationNumber(0), m_initialDecree(0) { }
        ConfigurationInfo(UInt32 configurationNumber, UInt64 initialDecree, MemberSet *memberSet) :
            m_configurationNumber(configurationNumber), m_initialDecree(initialDecree), m_memberSet(memberSet)
        { }

        void Marshal(MarshalData *marshal, RSLProtocolVersion version);
        bool UnMarshal(MarshalData *marshal, RSLProtocolVersion version);
        UInt32 GetMarshalLen(RSLProtocolVersion version);

        UInt32 GetConfigurationNumber() const { return m_configurationNumber; }
        UInt64 GetInitialDecree() const { return m_initialDecree; }
        MemberSet *GetMemberSet() { return m_memberSet; }
        size_t GetNumMembers() { return m_memberSet->GetNumMembers(); }
        const RSLNodeCollection& GetMemberCollection() { return m_memberSet->GetMemberCollection(); }
        const RSLNode *GetMemberInfo(UInt16 whichMember) { return m_memberSet->GetMemberInfo(whichMember); }
        bool IncludesMember(MemberId memberId) { return m_memberSet->IncludesMember(memberId); }

        void UpdateMemberSet(MemberSet *memberset)
        {
            m_memberSet = memberset;
        }

    private:
        UInt32 m_configurationNumber;
        UInt64 m_initialDecree;
        Ptr<MemberSet> m_memberSet;
    };

    class CheckpointHeader
    {
    public:
        CheckpointHeader() :
            m_version(RSLProtocolVersion_1), m_unMarshalLen(0), m_checksum(0),
            m_memberId(), m_lastExecutedDecree(0), m_stateSaved(true), m_size(0),
            m_checksumBlockSize(0)
        {}

        // The _WIN32 guards below fence off the Windows-only I/O entry points
        // (implemented in legislator.cpp). They read/write the marshaled bytes
        // produced by the unguarded methods; the Linux tool drives those
        // directly over in-memory buffers instead. Declaration order is kept
        // exactly as it was in legislator.h so this stays a provable pure move.
        UInt32 GetMarshalLen();
#ifdef _WIN32
        void Marshal(const char* file);
#endif
        void Marshal(MarshalData *marshal);
#ifdef _WIN32
        bool UnMarshal(const char* file);
#endif
        bool UnMarshal(MarshalData *marshal);
#ifdef _WIN32
        bool UnMarshal(StreamReader *reader);
        void SetBytesIssued(RSLCheckpointStreamWriter * writer);

        static void GetCheckpointFileName(DynString &file, UInt64 decree);
#endif

        RSLProtocolVersion m_version;
        UInt32 m_unMarshalLen;
        UInt64 m_checksum;
        MemberId m_memberId; // member that produced this checkpoint
        UInt64 m_lastExecutedDecree;  // decree executed at this checkpoint
        BallotNumber m_maxBallot;
        Ptr<ConfigurationInfo> m_stateConfiguration;
        Ptr<Vote> m_nextVote;
        bool m_stateSaved;                // Indicates whether user data was saved too
        unsigned long long m_size;        // The whole chekcpoint file size
        unsigned int m_checksumBlockSize; // The size of each block (user data + checksum token)
    };
}
