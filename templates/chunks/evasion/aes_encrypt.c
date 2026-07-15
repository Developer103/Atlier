// chunk: evasion/aes_encrypt
// depends: (none)
// provides: aes_decrypt_str
// headers: windows.h,wincrypt.h
// libs: crypt32
// risk: none
// note: AES-128 CBC string decryption using CryptoAPI — strings encrypted at build time

#ifndef CHUNK_AES_ENCRYPT
#define CHUNK_AES_ENCRYPT

#include <windows.h>
#include <wincrypt.h>

static int aes_decrypt_str(const BYTE *cipher, DWORD cipher_len,
                           const BYTE key[16], const BYTE iv[16],
                           char *out, DWORD out_sz) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    int ret = 0;

    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return 0;

    struct {
        BLOBHEADER hdr;
        DWORD keySize;
        BYTE keyData[16];
    } keyBlob;
    keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
    keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
    keyBlob.hdr.reserved = 0;
    keyBlob.hdr.aiKeyAlg = CALG_AES_128;
    keyBlob.keySize = 16;
    memcpy(keyBlob.keyData, key, 16);

    if (!CryptImportKey(hProv, (BYTE *)&keyBlob, sizeof(keyBlob), 0, 0, &hKey))
        goto cleanup;

    DWORD mode = CRYPT_MODE_CBC;
    CryptSetKeyParam(hKey, KP_MODE, (BYTE *)&mode, 0);
    CryptSetKeyParam(hKey, KP_IV, (BYTE *)iv, 0);

    DWORD len = cipher_len;
    if (len > out_sz - 1) len = out_sz - 1;
    memcpy(out, cipher, len);

    if (CryptDecrypt(hKey, 0, TRUE, 0, (BYTE *)out, &len)) {
        out[len] = '\0';
        ret = 1;
    }

cleanup:
    if (hKey) CryptDestroyKey(hKey);
    if (hProv) CryptReleaseContext(hProv, 0);
    return ret;
}

#endif
