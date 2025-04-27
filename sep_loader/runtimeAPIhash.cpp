#include "runtimeAPIhash.h"
#include <winternl.h>
#include <stdio.h>

FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {
    if (!hModule) {
        ////printf("[DEBUG] Invalid module handle\n"); // Debug
        return NULL;
    }

    PBYTE pBase = (PBYTE)hModule;
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        ////printf("[DEBUG] Invalid DOS header\n"); // Debug
        return NULL;
    }

    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        // //printf("[DEBUG] Invalid NT header\n"); // Debug
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase +
        pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pImgExportDir->NumberOfNames; i++) {
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
        PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

        ////printf("[DEBUG] Checking API: %s -> Hash: 0x%08X\n", pFunctionName, HashStringFnv1a(pFunctionName)); // Debug

        if (dwApiNameHash == HashStringFnv1a(pFunctionName)) {
            // //printf("[DEBUG] Found API: %s at address: 0x%p\n", pFunctionName, pFunctionAddress); // Debug
            return (FARPROC)pFunctionAddress;
        }
    }

    // //printf("[DEBUG] API with hash 0x%08X not found!\n", dwApiNameHash); // Debug
    return NULL;
}
