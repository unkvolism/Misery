#include <windows.h>
#include <stdio.h>

#include "Common.h"

int FindFirstSyscall(char* pMem, DWORD size) {

    // gets the first byte of first syscall
    DWORD i = 0;
    DWORD offset = 0;
    BYTE pattern1[] = "\x0f\x05\xc3";  // syscall ; ret
    BYTE pattern2[] = "\xcc\xcc\xcc";  // int3 * 3

    // find first occurance of syscall+ret instructions
    for (i = 0; i < size - 3; i++) {
        if (!memcmp(pMem + i, pattern1, 3)) {
            offset = i;
            break;
        }
    }

    // now find the beginning of the syscall
    for (i = 3; i < 50; i++) {
        if (!memcmp(pMem + offset - i, pattern2, 3)) {
            offset = offset - i + 3;
            printf("\n[!] First syscall found at : 0x%p\n", pMem + offset);
            break;
        }
    }

    return offset;
}


int FindLastSysCall(char* pMem, DWORD size) {

    // returns the last byte of the last syscall
    DWORD i;
    DWORD offset = 0;
    BYTE pattern[] = "\x0f\x05\xc3\xcd\x2e\xc3\xcc\xcc\xcc";  // syscall ; ret ; int 2e ; ret ; int3 * 3

    // backwards lookup
    for (i = size - 9; i > 0; i--) {
        if (!memcmp(pMem + i, pattern, 9)) {
            offset = i + 6;
            printf("[!] Last syscall byte found at : 0x%p\n", pMem + offset);
            break;
        }
    }

    return offset;
}