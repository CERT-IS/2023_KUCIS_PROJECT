#include <Windows.h>

inline bool BasicDebugTriggered()
{
    if (IsDebuggerPresent())
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

inline bool AntiDebugTriggered()
{
    if (BasicDebugTriggered())
        return true;

    if (HWBPDebugTriggered())
        return true;

    if (HypervisorDebugTriggered())
        return true;

    return false;
}