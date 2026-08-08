#include "network_oracle.h"

#include "NetPacket.h"
#include "NetPacketSvc.h"
#include "SSLImpl.h"

#include <winsock2.h>

#include <cstdio>
#include <cstring>
#include <deque>
#include <string>
#include <utility>
#include <vector>

using namespace RSLibImpl;

namespace rsl_oracle
{
namespace
{
    const DWORD CallbackTimeoutMs = 30000;
    const UInt32 MaxPacketSize = 100 * 1024 * 1024;

    bool DecodeHex(const char *text, std::vector<unsigned char> *bytes)
    {
        size_t length = strlen(text);
        if ((length & 1) != 0)
        {
            return false;
        }

        bytes->clear();
        bytes->reserve(length / 2);
        for (size_t i = 0; i < length; i += 2)
        {
            unsigned int value;
            if (sscanf_s(text + i, "%2x", &value) != 1)
            {
                return false;
            }
            bytes->push_back(static_cast<unsigned char>(value));
        }
        return true;
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

    int ReserveLoopbackPort()
    {
        SOCKET socketHandle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (socketHandle == INVALID_SOCKET)
        {
            return 0;
        }

        sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = inet_addr("127.0.0.1");
        address.sin_port = 0;

        int port = 0;
        if (bind(socketHandle, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0)
        {
            int length = sizeof(address);
            if (getsockname(
                    socketHandle,
                    reinterpret_cast<sockaddr *>(&address),
                    &length) == 0)
            {
                port = ntohs(address.sin_port);
            }
        }
        closesocket(socketHandle);
        return port;
    }

    class NetworkHandler : public SendHandler, public ReceiveHandler, public ConnectHandler
    {
    public:
        NetworkHandler(
            PacketFactory *factory,
            bool echo,
            int expected,
            bool waitForDisconnect,
            bool destroySentPackets) :
            m_factory(factory),
            m_service(NULL),
            m_echo(echo),
            m_expected(expected),
            m_waitForDisconnect(waitForDisconnect),
            m_destroySentPackets(destroySentPackets),
            m_received(0),
            m_sent(0),
            m_successfulSent(0),
            m_connected(false),
            m_disconnected(false),
            m_failed(false),
            m_done(CreateEvent(NULL, TRUE, FALSE, NULL)),
            m_sendEvent(CreateEvent(NULL, FALSE, FALSE, NULL)),
            m_receiveEvent(CreateEvent(NULL, FALSE, FALSE, NULL)),
            m_connectEvent(CreateEvent(NULL, FALSE, FALSE, NULL))
        {
            InitializeCriticalSection(&m_lock);
        }

        ~NetworkHandler()
        {
            CloseHandle(m_done);
            CloseHandle(m_sendEvent);
            CloseHandle(m_receiveEvent);
            CloseHandle(m_connectEvent);
            DeleteCriticalSection(&m_lock);
        }

        void SetService(NetPacketSvc *service)
        {
            m_service = service;
        }

        void ProcessSend(Packet *packet, TxRxStatus status)
        {
            EnterCriticalSection(&m_lock);
            ++m_sent;
            if (status == TxSuccess)
            {
                ++m_successfulSent;
                if (m_received >= m_expected && m_successfulSent >= m_expected)
                {
                    m_failed = false;
                }
            }
            if (status == TxNoConnection || status == TxAbort)
            {
                if (m_successfulSent < m_expected)
                {
                    m_failed = true;
                    fprintf(stderr, "NETWORK_FAILURE callback=send status=%d\n", status);
                }
            }
            if (!m_destroySentPackets)
            {
                m_sendResults.push_back(std::make_pair(packet, status));
            }
            LeaveCriticalSection(&m_lock);

            if (m_destroySentPackets)
            {
                m_factory->DestroyPacket(packet);
            }
            SetEvent(m_sendEvent);
            CompleteIfReady();
        }

        void ProcessReceive(Packet *packet)
        {
            UInt32 length = packet->m_MemoryManager.GetValidLength();
            const void *buffer = packet->m_MemoryManager.GetBuffer();

            EnterCriticalSection(&m_lock);
            std::string payload = Hex(buffer, length);
            m_payloads.push_back(payload);
            m_receiveResults.push_back(payload);
            ++m_received;
            LeaveCriticalSection(&m_lock);

            if (m_echo)
            {
                TxRxStatus status = m_service->Send(packet, CallbackTimeoutMs);
                if (status != TxSuccess)
                {
                    m_factory->DestroyPacket(packet);
                    EnterCriticalSection(&m_lock);
                    m_failed = true;
                    fprintf(stderr, "NETWORK_FAILURE callback=echo-send status=%d\n", status);
                    LeaveCriticalSection(&m_lock);
                    SetEvent(m_done);
                }
            }
            else
            {
                m_factory->DestroyPacket(packet);
            }

            SetEvent(m_receiveEvent);
            CompleteIfReady();
        }

        void ProcessConnect(UInt32, UInt16, ConnectState state)
        {
            EnterCriticalSection(&m_lock);
            if (state == Connected)
            {
                m_connected = true;
                m_disconnected = false;
            }
            else if (state == DisConnected || state == ConnectFailed)
            {
                m_disconnected = true;
                if (state == ConnectFailed || m_received < m_expected)
                {
                    m_failed = true;
                    fprintf(
                        stderr,
                        "NETWORK_FAILURE callback=connect state=%d received=%d expected=%d\n",
                        state,
                        m_received,
                        m_expected);
                }
            }
            LeaveCriticalSection(&m_lock);

            SetEvent(m_connectEvent);
            CompleteIfReady();
        }

        bool WaitDone()
        {
            return WaitForSingleObject(m_done, CallbackTimeoutMs) == WAIT_OBJECT_0;
        }

        bool WaitSend(Packet **packet, TxRxStatus *status)
        {
            if (WaitForSingleObject(m_sendEvent, CallbackTimeoutMs) != WAIT_OBJECT_0)
            {
                return false;
            }
            EnterCriticalSection(&m_lock);
            if (m_sendResults.empty())
            {
                LeaveCriticalSection(&m_lock);
                return false;
            }
            *packet = m_sendResults.front().first;
            *status = m_sendResults.front().second;
            m_sendResults.pop_front();
            LeaveCriticalSection(&m_lock);
            return true;
        }

        bool WaitReceive(std::string *payload)
        {
            if (WaitForSingleObject(m_receiveEvent, CallbackTimeoutMs) != WAIT_OBJECT_0)
            {
                return false;
            }
            EnterCriticalSection(&m_lock);
            if (m_receiveResults.empty())
            {
                LeaveCriticalSection(&m_lock);
                return false;
            }
            *payload = m_receiveResults.front();
            m_receiveResults.pop_front();
            LeaveCriticalSection(&m_lock);
            return true;
        }

        bool WaitForDisconnected()
        {
            ULONGLONG deadline = GetTickCount64() + CallbackTimeoutMs;
            for (;;)
            {
                EnterCriticalSection(&m_lock);
                bool disconnected = m_disconnected;
                LeaveCriticalSection(&m_lock);
                if (disconnected)
                {
                    return true;
                }
                ULONGLONG now = GetTickCount64();
                if (now >= deadline ||
                    WaitForSingleObject(m_connectEvent, static_cast<DWORD>(deadline - now)) != WAIT_OBJECT_0)
                {
                    return false;
                }
            }
        }

        int Received()
        {
            EnterCriticalSection(&m_lock);
            int received = m_received;
            LeaveCriticalSection(&m_lock);
            return received;
        }

        int Sent()
        {
            EnterCriticalSection(&m_lock);
            int sent = m_sent;
            LeaveCriticalSection(&m_lock);
            return sent;
        }

        bool Failed()
        {
            EnterCriticalSection(&m_lock);
            bool failed = m_failed;
            LeaveCriticalSection(&m_lock);
            return failed;
        }

        std::vector<std::string> Payloads()
        {
            EnterCriticalSection(&m_lock);
            std::vector<std::string> payloads = m_payloads;
            LeaveCriticalSection(&m_lock);
            return payloads;
        }

    private:
        void CompleteIfReady()
        {
            EnterCriticalSection(&m_lock);
            bool completed =
                m_received >= m_expected &&
                (!m_echo || m_successfulSent >= m_received) &&
                (!m_waitForDisconnect || m_disconnected);
            LeaveCriticalSection(&m_lock);
            if (completed)
            {
                SetEvent(m_done);
            }
        }

        PacketFactory *m_factory;
        NetPacketSvc *m_service;
        bool m_echo;
        int m_expected;
        bool m_waitForDisconnect;
        bool m_destroySentPackets;
        int m_received;
        int m_sent;
        int m_successfulSent;
        bool m_connected;
        bool m_disconnected;
        bool m_failed;
        HANDLE m_done;
        HANDLE m_sendEvent;
        HANDLE m_receiveEvent;
        HANDLE m_connectEvent;
        CRITICAL_SECTION m_lock;
        std::deque<std::pair<Packet *, TxRxStatus> > m_sendResults;
        std::deque<std::string> m_receiveResults;
        std::vector<std::string> m_payloads;
    };

    Packet *CreatePacket(
        PacketFactory *factory,
        const std::vector<unsigned char> &payload,
        UInt32 serverIp,
        UInt16 serverPort)
    {
        Packet *packet = factory->CreatePacket();
        packet->m_MemoryManager.ResizeBuffer(static_cast<UInt32>(payload.size()));
        if (!payload.empty())
        {
            memcpy(packet->m_MemoryManager.GetBuffer(), payload.data(), payload.size());
        }
        packet->m_MemoryManager.SetValidLength(static_cast<UInt32>(payload.size()));
        packet->SetServerAddr(serverIp, serverPort);
        return packet;
    }
}

int RunNetworkServer(
    int port,
    const char *mode,
    int count,
    bool waitForDisconnect,
    const char *rotateThumbprintA,
    const char *rotateThumbprintB,
    bool validateChain,
    bool checkRevocation)
{
    if (count < 0 || (strcmp(mode, "echo") != 0 && strcmp(mode, "log") != 0))
    {
        fprintf(stderr, "invalid network server arguments\n");
        return 2;
    }
    if (port == 0)
    {
        port = ReserveLoopbackPort();
    }
    if (port <= 0 || port > 65535)
    {
        fprintf(stderr, "failed to choose a loopback port\n");
        return 2;
    }

    PacketFactory factory(MaxPacketSize, MaxPacketSize);
    NetworkHandler handler(
        &factory,
        strcmp(mode, "echo") == 0,
        count,
        waitForDisconnect,
        true);
    NetPacketSvc service(64 * 1024);
    handler.SetService(&service);
    int error = service.StartAsServer(
        static_cast<UInt16>(port),
        &handler,
        &handler,
        &handler,
        &factory,
        inet_addr("127.0.0.1"));
    if (error != 0)
    {
        fprintf(stderr, "NetPacketSvc::StartAsServer failed: %d\n", error);
        return 1;
    }

    printf("PORT %d\n", port);
    fflush(stdout);

    bool rotated = true;
    if (rotateThumbprintA != NULL)
    {
        std::string firstPayload;
        rotated =
            handler.WaitReceive(&firstPayload) &&
            SSLAuth::SetSSLThumbprints(
                "MY",
                rotateThumbprintA,
                rotateThumbprintB,
                validateChain,
                checkRevocation) == ERROR_SUCCESS;
        fprintf(
            stderr,
            "TLS_ROTATE outcome=%s slotA=yes slotB=%s\n",
            rotated ? "accept" : "reject",
            rotateThumbprintB == NULL ? "no" : "yes");
    }
    bool completed = handler.WaitDone();
    Sleep(100);
    bool failed = handler.Failed();
    service.Stop();

    std::vector<std::string> payloads = handler.Payloads();
    for (size_t i = 0; i < payloads.size(); ++i)
    {
        printf("PAYLOAD %s\n", payloads[i].c_str());
    }
    printf(
        "RESULT received=%d sent=%d disconnected=%s\n",
        handler.Received(),
        handler.Sent(),
        waitForDisconnect ? "yes" : "not-required");
    return completed && rotated && !failed ? 0 : 1;
}

int RunNetworkClient(
    const char *host,
    int port,
    const char *payloadHex,
    int count,
    const char *expect,
    bool reconnectEach)
{
    if (port <= 0 || port > 65535 || count <= 0 ||
        (strcmp(expect, "echo") != 0 && strcmp(expect, "disconnect") != 0))
    {
        fprintf(stderr, "invalid network client arguments\n");
        return 2;
    }

    std::vector<unsigned char> payload;
    if (!DecodeHex(payloadHex, &payload))
    {
        fprintf(stderr, "invalid payload hex\n");
        return 2;
    }

    UInt32 serverIp = inet_addr(host);
    if (serverIp == INADDR_NONE)
    {
        fprintf(stderr, "network client requires an IPv4 address\n");
        return 2;
    }

    PacketFactory factory(MaxPacketSize, MaxPacketSize);
    NetworkHandler handler(&factory, false, count, false, false);
    NetPacketSvc service(64 * 1024);
    service.SetFailPacketsOnDisconnect(strcmp(expect, "disconnect") == 0);
    handler.SetService(&service);
    int error = service.StartAsClient(
        &handler,
        &handler,
        &handler,
        &factory,
        inet_addr("127.0.0.1"));
    if (error != 0)
    {
        fprintf(stderr, "NetPacketSvc::StartAsClient failed: %d\n", error);
        return 1;
    }

    bool success = true;
    if (!reconnectEach)
    {
        for (int i = 0; i < count && success; ++i)
        {
            Packet *packet = CreatePacket(
                &factory,
                payload,
                serverIp,
                static_cast<UInt16>(port));
            if (service.Send(packet, CallbackTimeoutMs) != TxSuccess)
            {
                factory.DestroyPacket(packet);
                success = false;
            }
        }
        for (int i = 0; i < count && success; ++i)
        {
            Packet *sentPacket = NULL;
            TxRxStatus sendStatus = TxAbort;
            success = handler.WaitSend(&sentPacket, &sendStatus);
            if (sentPacket != NULL)
            {
                factory.DestroyPacket(sentPacket);
            }
            success = success && sendStatus == TxSuccess;
        }
        if (strcmp(expect, "echo") == 0)
        {
            for (int i = 0; i < count && success; ++i)
            {
                std::string received;
                success = handler.WaitReceive(&received) && received == payloadHex;
            }
        }
    }
    else
    {
        for (int i = 0; i < count && success; ++i)
        {
            Packet *packet = CreatePacket(
                &factory,
                payload,
                serverIp,
                static_cast<UInt16>(port));
            if (service.Send(packet, CallbackTimeoutMs) != TxSuccess)
            {
                factory.DestroyPacket(packet);
                success = false;
                break;
            }
            Packet *sentPacket = NULL;
            TxRxStatus sendStatus = TxAbort;
            success = handler.WaitSend(&sentPacket, &sendStatus);
            if (success && sentPacket != NULL)
            {
                factory.DestroyPacket(sentPacket);
            }
            success = success && sendStatus == TxSuccess;

            if (success && strcmp(expect, "echo") == 0)
            {
                std::string received;
                success = handler.WaitReceive(&received) && received == payloadHex;
            }
            if (success && i + 1 < count)
            {
                service.CloseConnection(serverIp, static_cast<UInt16>(port));
                success = handler.WaitForDisconnected();
            }
        }
    }

    if (success && strcmp(expect, "disconnect") == 0)
    {
        success = handler.WaitForDisconnected() && handler.Received() == 0;
    }

    service.Stop();
    printf(
        "RESULT sent=%d received=%d expectation=%s outcome=%s\n",
        handler.Sent(),
        handler.Received(),
        expect,
        success ? "accept" : "reject");
    return success ? 0 : 1;
}
}
