#include <Windows.h>
#include "AntiLibrary.hpp"
inline bool BasicDebugTriggered()
{
    if (IsDebuggerPresent())
    {
        printf("DETECTED/DEBUG/IsDebuggerPresent\n");
        return true;
    }
    //get peb
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    auto NtGlobalFlag = peb->NtGlobalFlag;
    if (NtGlobalFlag & 0x70)
    {
        printf("DETECTED/DEBUG/NtGlobalFlag:%p\n", NtGlobalFlag);
        return true;
    }
    return false;
}
inline bool HWBPDebugTriggered()
{
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);

    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
    {
        printf("DETECTED/DEBUG/HWBP/Dr0:%p, Dr1:%p, Dr2:%p, Dr3:%p\n", ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3);
        return true;
    }
    return false;
}
inline bool HypervisorDebugTriggered()
{
    __try
    {
        __asm
        {
            //pushf
            __emit 0x9C
            //or dword ptr [esp], 0x100
            __emit 0x81
            __emit 0x0C
            __emit 0x24
            __emit 0x00
            __emit 0x01
            __emit 0x00
            __emit 0x00
            //popf
            __emit 0x9D
            //cpuid
            __emit 0x0F
            __emit 0xA2
            __emit 0x90
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
    //if detected, it will crash
}

inline DWORD AntiDebugTriggered()
{
    if (BasicDebugTriggered())
       return 1;

    if (HWBPDebugTriggered())
        return 2;

   if (HypervisorDebugTriggered())
        return 3;

    return 0;
}