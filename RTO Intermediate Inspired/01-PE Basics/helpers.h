/*
Based on RTO Course from Sektor 7 Institute.


 
*/

#pragma once

#include <windows.h>
#include <malloc.h>

HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName);
FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char * sProcName);
