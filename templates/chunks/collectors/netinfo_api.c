// chunk: collectors/netinfo_api
// depends: core/emit_buffer
// provides: collect_netinfo
// headers: iphlpapi.h
// libs: iphlpapi
// note: API-only network info — GetAdaptersInfo + GetExtendedTcpTable, no LOLBins

#ifndef CHUNK_NETINFO_API
#define CHUNK_NETINFO_API

#include <iphlpapi.h>

static void collect_netinfo(void) {
    emitf("=== NETWORK INFO ===\r\n");

    ULONG buf_sz = 16384;
    IP_ADAPTER_INFO *info = (IP_ADAPTER_INFO *)malloc(buf_sz);
    if (!info) return;

    if (GetAdaptersInfo(info, &buf_sz) == ERROR_BUFFER_OVERFLOW) {
        IP_ADAPTER_INFO *re = (IP_ADAPTER_INFO *)realloc(info, buf_sz);
        if (!re) { free(info); return; }
        info = re;
    }

    if (GetAdaptersInfo(info, &buf_sz) == NO_ERROR) {
        IP_ADAPTER_INFO *a = info;
        while (a) {
            emitf("  Adapter: %s\r\n", a->Description);
            emitf("    MAC: %02X-%02X-%02X-%02X-%02X-%02X\r\n",
                   a->Address[0], a->Address[1], a->Address[2],
                   a->Address[3], a->Address[4], a->Address[5]);
            emitf("    IP: %s\r\n", a->IpAddressList.IpAddress.String);
            emitf("    Mask: %s\r\n", a->IpAddressList.IpMask.String);
            emitf("    GW: %s\r\n", a->GatewayList.IpAddress.String);
            if (a->DhcpEnabled)
                emitf("    DHCP: %s\r\n", a->DhcpServer.IpAddress.String);
            a = a->Next;
        }
    }
    free(info);

    DWORD tcp_sz = 0;
    GetExtendedTcpTable(NULL, &tcp_sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (tcp_sz > 0) {
        MIB_TCPTABLE_OWNER_PID *tcp = (MIB_TCPTABLE_OWNER_PID *)malloc(tcp_sz);
        if (tcp && GetExtendedTcpTable(tcp, &tcp_sz, FALSE, AF_INET,
                                        TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            emitf("  Active TCP:\r\n");
            int shown = 0;
            for (DWORD i = 0; i < tcp->dwNumEntries && shown < 50; i++) {
                MIB_TCPROW_OWNER_PID *r = &tcp->table[i];
                if (r->dwState != MIB_TCP_STATE_ESTAB) continue;
                struct in_addr la, ra;
                la.S_un.S_addr = r->dwLocalAddr;
                ra.S_un.S_addr = r->dwRemoteAddr;
                emitf("    %s:%d -> %s:%d  PID=%lu\r\n",
                       inet_ntoa(la), ntohs((u_short)r->dwLocalPort),
                       inet_ntoa(ra), ntohs((u_short)r->dwRemotePort),
                       r->dwOwningPid);
                shown++;
            }
        }
        free(tcp);
    }

    emitf("\r\n");
}

#endif
