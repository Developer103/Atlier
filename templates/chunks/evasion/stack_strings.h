// chunk: evasion/stack_strings
// depends: (none)
// provides: STACK_STR macros
// note: Build strings char-by-char on stack — nothing in .rdata section

#ifndef CHUNK_STACK_STRINGS
#define CHUNK_STACK_STRINGS

#define SS2(buf, a, b) \
    do { char buf[3]; buf[0]=a; buf[1]=b; buf[2]=0;

#define SS3(buf, a, b, c) \
    do { char buf[4]; buf[0]=a; buf[1]=b; buf[2]=c; buf[3]=0;

#define SS4(buf, a, b, c, d) \
    do { char buf[5]; buf[0]=a; buf[1]=b; buf[2]=c; buf[3]=d; buf[4]=0;

#define SS_END } while(0)

static void ss_build(char *out, int max, const unsigned char *encoded, int len) {
    for (int i = 0; i < len && i < max - 1; i++)
        out[i] = (char)(encoded[i] ^ 0x55);
    out[(len < max - 1) ? len : max - 1] = '\0';
}

#define SS_XOR55(buf, sz, ...) \
    do { \
        static const unsigned char _enc[] = { __VA_ARGS__ }; \
        char buf[sz]; \
        ss_build(buf, sz, _enc, sizeof(_enc)); \

#define SS_USE(buf) buf
#define SS_DONE } while(0)

#endif
