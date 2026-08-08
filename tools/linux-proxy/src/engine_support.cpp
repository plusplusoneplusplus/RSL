// engine_support.cpp -- the minimum slice of RSL/src/rsl.cpp needed to link the
// rsl-linux-proxy tool: RSLNode member-id helpers, RSLNodeCollection, and MemberSet.
//
// Every function below is copied VERBATIM from RSL/src/rsl.cpp (as of the
// current tree) so the marshaled bytes are byte-identical to the original
// engine. The only thing that differs is the set of #includes: instead of
// pulling in legislator.h / apdiskio.h / SSLImpl.h (the whole engine), we use
// the message.h + msg_engine_compat.h subset. See
// notes: tools/linux-proxy/README.md.
#include "message.h"
#include "msg_engine_compat.h"
#include "utils.h"
#include <strsafe.h>
#include <stdlib.h>

using namespace RSLib;
using namespace RSLibImpl;

// ---------------------------------------------------------------------------
// RSLNode member-id helpers (rsl.cpp)
// ---------------------------------------------------------------------------
void
RSLNode::SetMemberIdAsUInt64(unsigned long long memberId)
{
    HRESULT hresult = StringCbPrintfA(m_memberIdString, sizeof(m_memberIdString), "%I64u", memberId);
    LogAssert(SUCCEEDED(hresult));
}

UInt64
RSLNode::GetMemberIdAsUInt64()
{
    return RSLNode::ParseMemberIdAsUInt64(m_memberIdString);
}

unsigned long long
RSLNode::ParseMemberIdAsUInt64(const char* memberId)
{
    if (*memberId == NULL)
    {
        return 0;
    }
    char * endPtr = NULL;
    UInt64 value = _strtoui64(memberId, &endPtr, 0);
    LogAssert(*endPtr == NULL);
    return value;
}

// ---------------------------------------------------------------------------
// MemberSet (rsl.cpp)
// ---------------------------------------------------------------------------
MemberSet::MemberSet() : m_cookie(NULL), m_cookieLength(0)
{
}

MemberSet::MemberSet(const MemberSet &memberset) :
    m_members(memberset.m_members), m_cookie(NULL), m_cookieLength(0)
{
    SetConfigurationCookie(memberset.m_cookie, memberset.m_cookieLength);
}

MemberSet::MemberSet(const RSLNodeCollection &members, void *cookie, UInt32 cookieLength)
    : m_members(members), m_cookie(NULL), m_cookieLength(0)
{
    SetConfigurationCookie(cookie, cookieLength);
}

MemberSet::~MemberSet()
{
    FreeCookie();
}

void
MemberSet::Copy(const MemberSet *memberset)
{
    m_members = memberset->m_members;
    SetConfigurationCookie(memberset->m_cookie, memberset->m_cookieLength);
}

void
MemberSet::Marshal(MarshalData *marshal, RSLProtocolVersion version)
{
    UInt16 numMembers = (UInt16)GetNumMembers();
    marshal->WriteUInt16(numMembers);

    for (UInt16 whichMember = 0; whichMember < numMembers; ++whichMember)
    {
        const RSLNode *node = GetMemberInfo(whichMember);

        MemberId id(node->m_memberIdString);
        id.Marshal(marshal, version);
        marshal->WriteUInt32(node->m_ip);
        marshal->WriteUInt16(node->m_rslPort);
        if (version > RSLProtocolVersion_3)
        {
            marshal->WriteUInt16(node->m_rslLearnPort);
        }
        else
        {
            marshal->WriteUInt16(node->m_appPort);
        }

        size_t hostNameLength;
        LogAssert(SUCCEEDED(StringCchLengthA(node->m_hostName, sizeof(node->m_hostName), &hostNameLength)));
        marshal->WriteUInt16((UInt16)hostNameLength);
        marshal->WriteData((UInt32)hostNameLength, (void *)node->m_hostName);
    }

    marshal->WriteUInt32(m_cookieLength);
    marshal->WriteData(m_cookieLength, m_cookie);
}

bool
MemberSet::UnMarshal(MarshalData *marshal, RSLProtocolVersion version)
{
    FreeCookie();

    UInt16 numMembers;
    if (!marshal->ReadUInt16(&numMembers))
    {
        return false;
    }

    RSLNodeCollection members;
    for (UInt16 whichMember = 0; whichMember < numMembers; ++whichMember)
    {
        RSLNode node;

        MemberId id;
        if (!id.UnMarshal(marshal, version))
        {
            return false;
        }

        HRESULT success = StringCbCopyA(node.m_memberIdString, sizeof(node.m_memberIdString), id.GetValue());

        if (!SUCCEEDED(success))
        {
            return false;
        }

        if (!marshal->ReadUInt32(&node.m_ip))
        {
            return false;
        }
        if (!marshal->ReadUInt16(&node.m_rslPort))
        {
            return false;
        }

        if (version > RSLProtocolVersion_3)
        {
            if (!marshal->ReadUInt16(&node.m_rslLearnPort))
            {
                return false;
            }
        }
        else
        {
            if (!marshal->ReadUInt16(&node.m_appPort))
            {
                return false;
            }
        }

        UInt16 hostNameLength;
        if (!marshal->ReadUInt16(&hostNameLength))
        {
            return false;
        }
        LogAssert(hostNameLength < sizeof(node.m_hostName));
        if (!marshal->ReadData(hostNameLength, (void *)node.m_hostName))
        {
            return false;
        }
        node.m_hostName[hostNameLength] = '\0';

        members.Append(node);
    }

    m_members = members;

    if (!marshal->ReadUInt32(&m_cookieLength))
    {
        return false;
    }
    if (m_cookieLength > RSLMemberSet::s_MaxMemberSetCookieLength)
    {
        RSLInfo("Cookie in member set too long", LogTag_UInt1, m_cookieLength);
        return false;
    }

    if (m_cookieLength != 0)
    {
        m_cookie = malloc(m_cookieLength);
        LogAssert(m_cookie);

        if (!marshal->ReadData(m_cookieLength, m_cookie))
        {
            return false;
        }
    }

    return true;
}

UInt32
MemberSet::GetMarshalLen(RSLProtocolVersion version)
{
    size_t numMembers = GetNumMembers();
    UInt32 nodeMarshalLen =
        MemberId::GetBaseSize(version) + // memberid
        4 + // ip
        2 + // rslport
        2 + // rsllearnpport
        2; // hostname length
    size_t marshalLen = nodeMarshalLen * numMembers + 6 + m_cookieLength;
    for (size_t whichMember = 0; whichMember < numMembers; ++whichMember)
    {
        RSLNode * node = &m_members[whichMember];
        size_t hostNameLength;
        LogAssert(SUCCEEDED(StringCchLengthA(node->m_hostName, sizeof(node->m_hostName), &hostNameLength)));
        marshalLen += hostNameLength;
    }

    return (UInt32)marshalLen;
}

size_t
MemberSet::GetNumMembers() const
{
    return m_members.Count();
}

RSLNode *
MemberSet::GetMemberInfo(UInt16 whichMember)
{
    return &m_members[whichMember];
}

const RSLNodeCollection&
MemberSet::GetMemberCollection() const
{
    return m_members;
}

RSLNodeArray *
MemberSet::GetMemberArray_Deprecated()
{
    m_members_Deprecated.clear();
    for (size_t i = 0; i < m_members.Count(); i++)
    {
        m_members_Deprecated.push_back(m_members[i]);
    }

    return &m_members_Deprecated;
}

bool
MemberSet::IncludesMember(MemberId memberId) const
{
    size_t numMembers = GetNumMembers();
    for (size_t whichMember = 0; whichMember < numMembers; ++whichMember)
    {
        if (memberId.Compare(m_members[whichMember].m_memberIdString) == 0)
        {
            return true;
        }
    }

    return false;
}

bool
MemberSet::Verify(RSLProtocolVersion version) const
{
    if (m_members.Count() == 0)
    {
        RSLError("Replica Set cannot be empty");
        return false;
    }

    for (size_t i = 0; i < m_members.Count(); i++)
    {
        for (size_t j = i + 1; j < m_members.Count(); j++)
        {
            // Same member Id
            if (MemberId::Compare(m_members[i].m_memberIdString, m_members[j].m_memberIdString) == 0)
            {
                RSLError(
                    "Replica Set contains a duplicated entry",
                    LogTag_RSLMemberId, m_members[i].m_memberIdString);
                return false;
            }
        }

        if (m_members[i].m_rslPort == 0)
        {
            RSLError("Replica port cannot be zero");
            return false;
        }

        if (m_members[i].m_memberIdString == NULL)
        {
            RSLError("Empty memberId invalid");
            return false;
        }

        if (version < RSLProtocolVersion_4)
        {
            char * endPtr = NULL;
            UInt64 value = _strtoui64(m_members[i].m_memberIdString, &endPtr, 0);
            if (*endPtr != NULL)
            {
                RSLError(
                    "MemberId must be a 64 bit number",
                    LogTag_RSLMemberId, m_members[i].m_memberIdString);
                return false;
            }
            (void)value;
        }
    }
    return true;
}

void
MemberSet::SetConfigurationCookie(void *cookie, UInt32 cookieLength)
{
    FreeCookie();

    m_cookieLength = cookieLength;
    if (m_cookieLength != 0)
    {
        m_cookie = malloc(m_cookieLength);
        LogAssert(m_cookie);
        memcpy(m_cookie, cookie, cookieLength);
    }
}

void *
MemberSet::GetConfigurationCookie(UInt32 *length) const
{
    if (length)
    {
        *length = m_cookieLength;
    }
    return m_cookie;
}

void
MemberSet::FreeCookie()
{
    if (m_cookie != NULL)
    {
        free(m_cookie);
        m_cookie = NULL;
        m_cookieLength = 0;
    }
}

// ---------------------------------------------------------------------------
// RSLNodeCollection (rsl.cpp)
// ---------------------------------------------------------------------------
RSLNodeCollection::RSLNodeCollection() :
    m_size(0),
    m_count(0),
    m_array(nullptr)
{
    m_size = s_Increment;
    m_array = new RSLNode[m_size];
    LogAssert(m_array != nullptr);
}

RSLNodeCollection::RSLNodeCollection(const RSLNodeCollection& other) :
    m_size(0),
    m_count(0),
    m_array(nullptr)
{
    CopyFrom(other);
}

RSLNodeCollection::~RSLNodeCollection()
{
    delete[] m_array;
    m_array = nullptr;
}

RSLNodeCollection& RSLNodeCollection::operator=(RSLNodeCollection const& other)
{
    CopyFrom(other);

    return *this;
}

size_t RSLNodeCollection::Count() const
{
    return m_count;
}

void RSLNodeCollection::Append(const RSLNode& node)
{
    EnsureSize();
    LogAssert(m_count < m_size);

    m_array[m_count] = node;
    m_count++;
}

void RSLNodeCollection::Remove(size_t index)
{
    LogAssert(index < m_count);
    LogAssert(m_count > 0);

    m_count--;
    if (m_count == 0)
    {
        return;
    }

    for (size_t i = index; i < m_count; i++)
    {
        m_array[i] = m_array[i + 1];
    }
}

RSLNode& RSLNodeCollection::operator[](size_t index) const
{
    LogAssert(index < m_size);

    return m_array[index];
}

void RSLNodeCollection::Clear()
{
    m_count = 0;
}

void RSLNodeCollection::EnsureSize()
{
    if (m_size > m_count)
    {
        return;
    }

    LogAssert(m_size == m_count);

    RSLNode* pOldArray = m_array;
    const size_t newSize = m_size + s_Increment;
    RSLNode* pNewArray = new RSLNode[newSize];
    for (size_t i = 0; i < m_size; i++)
    {
        pNewArray[i] = m_array[i];
    }
    delete[] pOldArray;

    m_size = newSize;
    m_array = pNewArray;
}

void RSLNodeCollection::CopyFrom(const RSLNodeCollection& other)
{
    Clear();

    for (size_t i = 0; i < other.Count(); i++)
    {
        Append(other[i]);
    }
}
