// chunk: commands/cmd_netinfo
// depends: (none)
// provides: cmd_netinfo
// headers: iphlpapi.h
// libs: iphlpapi
// note: network adapters + TCP table via API — zero child processes

#ifndef CHUNK_CMD_NETINFO
#define CHUNK_CMD_NETINFO

#include <iphlpapi.h>

static int cmd_netinfo(const char *args, DWORD args_len, char *out, DWORD *out_len) {
    (void)args; (void)args_len;
    DWORD cap = *out_len;
    int pos = 0;

    pos += snprintf(out + pos, cap - pos, "=== ADAPTERS ===\r\n");

    ULONG buf_sz = 16384;
    IP_ADAPTER_INFO *info = (IP_ADAPTER_INFO *)malloc(buf_sz);
    if (info && GetAdaptersInfo(info, &buf_sz) == ERROR_SUCCESS) {
        IP_ADAPTER_INFO *a = info;
        while (a && (DWORD)pos < cap - 512) {
            pos += snprintf(out + pos, cap - pos, "%s\r\n", a->Description);
            pos += snprintf(out + pos, cap - pos, "  IP: %s\r\n", a->IpAddressList.IpAddress.String);
            pos += snprintf(out + pos, cap - pos, "  GW: %s\r\n", a->GatewayList.IpAddress.String);
            pos += snprintf(out + pos, cap - pos, "  MAC: %02X-%02X-%02X-%02X-%02X-%02X\r\n",
                            a->Address[0], a->Address[1], a->Address[2],
                            a->Address[3], a->Address[4], a->Address[5]);
            a = a->Next;
        }
    }
    if (info) free(info);

    pos += snprintf(out + pos, cap - pos, "\r\n=== TCP CONNECTIONS ===\r\n");

    DWORD tcp_sz = 0;
    GetExtendedTcpTable(NULL, &tcp_sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (tcp_sz > 0) {
        MIB_TCPTABLE_OWNER_PID *tcp = (MIB_TCPTABLE_OWNER_PID *)malloc(tcp_sz);
        if (tcp && GetExtendedTcpTable(tcp, &tcp_sz, FALSE, AF_INET,
                                        TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < tcp->dwNumEntries && (DWORD)pos < cap - 256; i++) {
                MIB_TCPROW_OWNER_PID *r = &tcp->table[i];
                if (r->dwState != MIB_TCP_STATE_ESTAB && r->dwState != MIB_TCP_STATE_LISTEN)
                    continue;
                struct in_addr la, ra;
                la.s_addr = r->dwLocalAddr;
                ra.s_addr = r->dwRemoteAddr;
                char local_ip[16], remote_ip[16];
                strncpy(local_ip, inet_ntoa(la), sizeof(local_ip) - 1);
                strncpy(remote_ip, inet_ntoa(ra), sizeof(remote_ip) - 1);
                pos += snprintf(out + pos, cap - pos, "  %s:%d -> %s:%d [PID %lu] %s\r\n",
                                local_ip, ntohs((u_short)r->dwLocalPort),
                                remote_ip, ntohs((u_short)r->dwRemotePort),
                                r->dwOwningPid,
                                r->dwState == MIB_TCP_STATE_LISTEN ? "LISTEN" : "ESTAB");
            }
        }
        if (tcp) free(tcp);
    }

    *out_len = (DWORD)pos;
    return 0;
}

#endif
