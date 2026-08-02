// Linux compat stand-in for the parts of legislator.h that message.cpp needs.
//
// message.cpp includes legislator.h but, for the golden-gen slice, only three
// things from it are actually referenced: the page-rounding helpers used by
// Vote's buffer management, and the MemberSet class (used by reconfiguration
// Votes and BootstrapMsg). Pulling in the full legislator.h would drag in the
// whole engine (net, disk, config), so we reproduce just those declarations
// here. The MemberSet declaration is kept identical to legislator.h so this
// header and engine_min.cpp agree on its layout.
#pragma once

#include "rsl.h"        // RSLNodeCollection, RSLNodeArray, RSLNode, RSLMemberSet
#include "marshal.h"    // MarshalData
#include "RefCount.h"   // RefCount, Ptr
#include "message.h"    // MemberId, BallotNumber (already included by message.cpp)

// message.cpp uses the bare max()/min() macros (Vote::AddMemory). MSVC's
// windows.h defines these; libstdc++ does not, so re-establish them here, after
// all STL headers have been pulled in by message.h.
#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif
#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

namespace RSLibImpl
{
    // --- from legislator.h ---------------------------------------------------
    static const UInt32 s_PageSize = 512;
    static const UInt32 s_SystemPageSize = 4096;

    inline UInt32 RoundUpToPage(UInt32 x)
    {
        return ((x + (s_PageSize - 1)) & ~(s_PageSize - 1));
    }

    inline UInt32 RoundUpToSystemPage(UInt32 x)
    {
        return ((x + (s_SystemPageSize - 1)) & ~(s_SystemPageSize - 1));
    }

    // Declaration copied verbatim from RSL/src/legislator.h so that message.cpp
    // and engine_min.cpp share one definition. Implemented in engine_min.cpp
    // (extracted verbatim from RSL/src/rsl.cpp).
    class MemberSet : public RefCount
    {
    public:

        MemberSet();
        MemberSet(const MemberSet& memberset);
        MemberSet(const RSLNodeCollection &members, void *cookie, UInt32 cookieLength);
        ~MemberSet();

        void Copy(const MemberSet *memberset);

        void Marshal(MarshalData *marshal, RSLProtocolVersion version);
        bool UnMarshal(MarshalData *marshal, RSLProtocolVersion version);
        UInt32 GetMarshalLen(RSLProtocolVersion version);

        size_t GetNumMembers() const;
        RSLNode *GetMemberInfo(UInt16 whichMember);
        const RSLNodeCollection& GetMemberCollection() const;
        RSLNodeArray *GetMemberArray_Deprecated();

        bool IncludesMember(MemberId memberId) const;
        void SetConfigurationCookie(void *cookie, UInt32 cookieLength);

        void *GetConfigurationCookie(UInt32 *length) const;

        bool Verify(RSLProtocolVersion version) const;

    private:
        RSLNodeArray m_members_Deprecated;
        RSLNodeCollection m_members;

        void *m_cookie;
        UInt32 m_cookieLength;

        MemberSet& operator=(const MemberSet &copy);

        void FreeCookie();
    };
}
