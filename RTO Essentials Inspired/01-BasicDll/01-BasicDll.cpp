/*
Based on RTO Course from Sektor 7 Institute

https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain
https://stackoverflow.com/questions/2081409/what-does-apientry-do
https://docs.microsoft.com/en-us/cpp/preprocessor/comment-c-cpp?view=msvc-160
https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa

@ECHO OFF

cl.exe /D_USRDLL /D_WINDLL implantDLL.cpp /MT /link /DLL /OUT:implant.dll


*/

#include <Windows.h>
#pragma comment(lib, "User32" )




BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved )  // reserved
{
    // Perform actions based on the reason for calling.
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
         // Initialize once for each new process.
         // Return FALSE to fail DLL load.
            break;

        case DLL_THREAD_ATTACH:
         // Do thread-specific initialization.
            break;

        case DLL_THREAD_DETACH:
         // Do thread-specific cleanup.
            break;

        case DLL_PROCESS_DETACH:
         // Perform any necessary cleanup.
            break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}

extern "C" {
__declspec(dllexport) BOOL WINAPI TestExport(void) {

    LPCSTR lpText = "InnerContent";
    LPCSTR lpCaption = "TitleBar";

    int messagebox = MessageBoxA(NULL, lpText, lpCaption, MB_OK);

    return TRUE;

};
};