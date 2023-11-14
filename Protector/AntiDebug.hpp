#include <Windows.h>
#include "AntiLibrary.hpp"
inline bool BasicDebugTriggered()
{
    if (IsDebuggerPresent())
        return true;
    //get peb
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
    #else
    PPEB peb = (PPEB)__readfsdword(0x30);
    #endif
    auto NtGlobalFlag = peb->NtGlobalFlag;
    if (NtGlobalFlag & 0x70)
        return true;

    return false;
}
inline bool HWBPDebugTriggered()
{
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);

    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
        return true;

    return false;
}
inline bool HypervisorDebugTriggered()
{
    __try
    {
        __asm
        {
            __emit 0xf3;
            __emit 0x90;
            __emit 0x00;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return true;
    }

    return false;
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