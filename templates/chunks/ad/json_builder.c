// chunk: ad/json_builder
// depends: (none)
// provides: jb_init, jb_finalize, jb_obj_open, jb_obj_close, jb_arr_open, jb_arr_close, jb_key_str, jb_key_int, jb_key_bool, jb_key_null, jb_key_arr_str, jb_key_obj_open, jb_key_obj_close, jb_raw
// headers: (none)
// libs: (none)

typedef enum {
    JB_USERS, JB_GROUPS, JB_COMPUTERS, JB_DOMAINS,
    JB_GPOS, JB_OUS, JB_CONTAINERS, JB_COUNT
} jb_type_t;

static const char *jb_type_names[] = {
    "users", "groups", "computers", "domains", "gpos", "ous", "containers"
};

typedef struct {
    char *buf;
    DWORD pos;
    DWORD cap;
    int count;
    int depth;
    int needs_comma[16];
} jb_buffer_t;

static jb_buffer_t g_jb[JB_COUNT];

static void jb_grow(jb_buffer_t *b, DWORD need) {
    if (b->pos + need >= b->cap) {
        DWORD newcap = b->cap * 2;
        if (newcap < b->pos + need + 4096) newcap = b->pos + need + 4096;
        char *nb = (char *)HeapAlloc(GetProcessHeap(), 0, newcap);
        if (!nb) return;
        if (b->buf) {
            CopyMemory(nb, b->buf, b->pos);
            HeapFree(GetProcessHeap(), 0, b->buf);
        }
        b->buf = nb;
        b->cap = newcap;
    }
}

static void jb_write(jb_buffer_t *b, const char *s, int len) {
    if (len < 0) len = lstrlenA(s);
    jb_grow(b, (DWORD)len);
    CopyMemory(b->buf + b->pos, s, len);
    b->pos += len;
}

static void jb_comma(jb_buffer_t *b) {
    if (b->depth >= 0 && b->depth < 16 && b->needs_comma[b->depth]) {
        jb_write(b, ",", 1);
    }
    if (b->depth >= 0 && b->depth < 16) b->needs_comma[b->depth] = 1;
}

static void jb_escape_str(jb_buffer_t *b, const char *s) {
    jb_write(b, "\"", 1);
    if (s) {
        for (; *s; s++) {
            switch (*s) {
                case '"':  jb_write(b, "\\\"", 2); break;
                case '\\': jb_write(b, "\\\\", 2); break;
                case '\n': jb_write(b, "\\n", 2); break;
                case '\r': jb_write(b, "\\r", 2); break;
                case '\t': jb_write(b, "\\t", 2); break;
                default:
                    if ((unsigned char)*s < 0x20) {
                        char esc[8];
                        wsprintfA(esc, "\\u%04x", (unsigned char)*s);
                        jb_write(b, esc, 6);
                    } else {
                        jb_write(b, s, 1);
                    }
            }
        }
    }
    jb_write(b, "\"", 1);
}

static void jb_init(void) {
    for (int i = 0; i < JB_COUNT; i++) {
        ZeroMemory(&g_jb[i], sizeof(jb_buffer_t));
        g_jb[i].cap = 65536;
        g_jb[i].buf = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, g_jb[i].cap);
        jb_write(&g_jb[i], "{\"data\":[", 9);
        g_jb[i].depth = 0;
        g_jb[i].needs_comma[0] = 0;
    }
}

static int jb_finalize(jb_type_t t, char **out, DWORD *out_len) {
    jb_buffer_t *b = &g_jb[t];
    char meta[256];
    wsprintfA(meta, "],\"meta\":{\"methods\":0,\"type\":\"%s\",\"count\":%d,\"version\":6}}",
              jb_type_names[t], b->count);
    jb_write(b, meta, -1);
    *out = b->buf;
    *out_len = b->pos;
    return b->count;
}

static void jb_obj_open(jb_type_t t) {
    jb_buffer_t *b = &g_jb[t];
    jb_comma(b);
    jb_write(b, "{", 1);
    b->depth++;
    if (b->depth < 16) b->needs_comma[b->depth] = 0;
    b->count++;
}

static void jb_obj_close(jb_type_t t) {
    jb_buffer_t *b = &g_jb[t];
    jb_write(b, "}", 1);
    if (b->depth > 0) b->depth--;
}

static void jb_arr_open(jb_type_t t, const char *key) {
    jb_buffer_t *b = &g_jb[t];
    jb_comma(b);
    jb_escape_str(b, key);
    jb_write(b, ":[", 2);
    b->depth++;
    if (b->depth < 16) b->needs_comma[b->depth] = 0;
}

static void jb_arr_close(jb_type_t t) {
    jb_buffer_t *b = &g_jb[t];
    jb_write(b, "]", 1);
    if (b->depth > 0) b->depth--;
}

static void jb_key_str(jb_type_t t, const char *key, const char *val) {
    jb_buffer_t *b = &g_jb[t];
    jb_comma(b);
    jb_escape_str(b, key);
    jb_write(b, ":", 1);
    jb_escape_str(b, val);
}

static void jb_key_int(jb_type_t t, const char *key, long long val) {
    jb_buffer_t *b = &g_jb[t];
    jb_comma(b);
    jb_escape_str(b, key);
    char num[32];
    wsprintfA(num, ":%I64d", val);
    jb_write(b, num, -1);
}

static void jb_key_bool(jb_type_t t, const char *key, int val) {
    jb_buffer_t *b = &g_jb[t];
    jb_comma(b);
    jb_escape_str(b, key);
    jb_write(b, val ? ":true" : ":false", val ? 5 : 6);
}

static void jb_key_null(jb_type_t t, const char *key) {
    jb_buffer_t *b = &g_jb[t];
    jb_comma(b);
    jb_escape_str(b, key);
    jb_write(b, ":null", 5);
}

static void jb_key_arr_str(jb_type_t t, const char *key, const char **vals, int count) {
    jb_arr_open(t, key);
    jb_buffer_t *b = &g_jb[t];
    for (int i = 0; i < count; i++) {
        jb_comma(b);
        jb_escape_str(b, vals[i]);
    }
    jb_arr_close(t);
}

static void jb_key_obj_open(jb_type_t t, const char *key) {
    jb_buffer_t *b = &g_jb[t];
    jb_comma(b);
    jb_escape_str(b, key);
    jb_write(b, ":{", 2);
    b->depth++;
    if (b->depth < 16) b->needs_comma[b->depth] = 0;
}

static void jb_key_obj_close(jb_type_t t) {
    jb_buffer_t *b = &g_jb[t];
    jb_write(b, "}", 1);
    if (b->depth > 0) b->depth--;
}

static void jb_raw(jb_type_t t, const char *raw, int len) {
    jb_write(&g_jb[t], raw, len);
}

static void jb_cleanup(void) {
    for (int i = 0; i < JB_COUNT; i++) {
        if (g_jb[i].buf) {
            HeapFree(GetProcessHeap(), 0, g_jb[i].buf);
            g_jb[i].buf = NULL;
        }
    }
}
