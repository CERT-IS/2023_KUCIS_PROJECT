#include "AntiProcess.hpp"
#include "CodeIntegrity.hpp"
#include "AntiLibrary.hpp"
#include "AntiDebug.hpp"

DWORD64 lastDebugCheckTime = 0;
DWORD64 lastLibraryCheckTime = 0;
DWORD64 lastProcessCheckTime = 0;
DWORD64 lastCodeIntegrityCheckTime = 0;

DWORD WINAPI AntiDebugThread(LPVOID lpParam)
{
    while (true)
    {
        Sleep(5000);
        if (DWORD triggered = AntiDebugTriggered())
        {
            //TODO: Send log to server.
        }
        lastDebugCheckTime = GetTickCount64();
    }
}

DWORD WINAPI AntiLibraryThread(LPVOID lpParam)
{
    while (true)
    {
        Sleep(5000);
        CheckLibrary();
        lastLibraryCheckTime = GetTickCount64();
    }
}

DWORD WINAPI AntiProcessThread(LPVOID lpParam)
{
    while (true)
    {
        Sleep(5000);
        CheckProcess();
        lastProcessCheckTime = GetTickCount64();
    }
}

DWORD WINAPI AntiCodeIntegrityThread(LPVOID lpParam)
{
    CodeIntegrityVerifier* verifier = new CodeIntegrityVerifier((DWORD_PTR)GetModuleHandleW(nullptr));
    while (true)
    {
        Sleep(5000);
        if (!verifier->Verify())
        {
            printf("DETECTED/CODE_INTEGRITY/CodeIntegrity check failed\n");
        }
        lastCodeIntegrityCheckTime = GetTickCount64();
    }
}

__forceinline void CheckThreadWorking(void)
{
    DWORD64 currentTime = GetTickCount64();
    if (currentTime - lastDebugCheckTime > 10000 && lastDebugCheckTime != 0)
    {
        printf("DETECTED/SUSPEND_THREAD/AntiDebugThread\n");
        __debugbreak(); //force make exception to crash
    }
    if (currentTime - lastLibraryCheckTime > 10000 && lastLibraryCheckTime != 0)
    {
        printf("DETECTED/SUSPEND_THREAD/AntiLibraryThread\n");
        __debugbreak(); //force make exception to crash
    }
    if (currentTime - lastProcessCheckTime > 10000 && lastProcessCheckTime != 0)
    {
        printf("DETECTED/SUSPEND_THREAD/AntiProcessThread\n");
        __debugbreak(); //force make exception to crash
    }
    if (currentTime - lastCodeIntegrityCheckTime > 10000 && lastCodeIntegrityCheckTime != 0)
    {
        printf("DETECTED/SUSPEND_THREAD/AntiCodeIntegrityThread\n");
        __debugbreak(); //force make exception to crash
    }
}

int main(void)
{
    //Initialize thread
    CreateThread(nullptr, 0, AntiDebugThread, nullptr, 0, nullptr);
    CreateThread(nullptr, 0, AntiLibraryThread, nullptr, 0, nullptr);
    CreateThread(nullptr, 0, AntiProcessThread, nullptr, 0, nullptr);
    CreateThread(nullptr, 0, AntiCodeIntegrityThread, nullptr, 0, nullptr);

    //Main loop
    while (true)
    {
        CheckThreadWorking();
        Sleep(1000);
    }

}