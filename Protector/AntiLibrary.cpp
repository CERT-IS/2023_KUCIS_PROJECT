#include <Windows.h>

#pragma comment(linker, "/INCLUDE:_tls_used") //Use TLS

void NTAPI TlsCallback(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        //Check if debugger is present
        if (IsDebuggerPresent())
            ExitProcess(0);
    }
}
#pragma data_seg(".CRT$XLX")
PIMAGE_TLS_CALLBACK p_thread_callback[] = { TlsCallback, 0 };
#pragma data_seg()

//TODO: PEB LDR -> Sign