// chunk: evasion/string_encrypt
// depends: (none)
// provides: XOR_KEY, XSTR, xor_decode
// note: compile-time XOR encryption for string literals — prevents static string scanning

#ifndef CHUNK_STRING_ENCRYPT_H
#define CHUNK_STRING_ENCRYPT_H

#define XOR_KEY 0x5A

static void xor_decode(char *buf, const unsigned char *enc, int len) {
    for (int i = 0; i < len; i++)
        buf[i] = (char)(enc[i] ^ XOR_KEY);
    buf[len] = '\0';
}

#define XSTR_1(c) ((unsigned char)((c) ^ XOR_KEY))

#define XDEC2(s, v) do { \
    static const unsigned char _e[] = { XSTR_1(s[0]), XSTR_1(s[1]) }; \
    xor_decode(v, _e, 2); \
} while(0)

#endif
