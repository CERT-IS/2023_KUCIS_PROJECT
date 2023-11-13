#include "AntiProcess.hpp"
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include "Utils.hpp"
typedef NTSTATUS(NTAPI* t_NtQuerySystemInformation)(_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_opt_ PVOID SystemInformation, _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength);
typedef NTSTATUS(NTAPI* t_NtQueryObject)(_In_opt_ HANDLE Handle, _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass, _Out_opt_ PVOID ObjectInformation, _In_ ULONG ObjectInformationLength, _Out_opt_ PULONG ReturnLength);
typedef NTSTATUS(NTAPI* t_NtQueryInformationProcess)(_In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ PVOID ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_opt_ PULONG ReturnLength);
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

t_NtQuerySystemInformation NtQuerySystemInformation = (t_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
t_NtQueryObject NtQueryObject = (t_NtQueryObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject");

const wchar_t* BlacklistedWindowName[] = {
    L"OllyDbg",
    L"IDA Pro",
    L"Cheat Engine",
    L"Process Hacker",
    L"Process Explorer",
    L"Process Monitor"
};
const wchar_t* BlacklistedProcessName[] = {
    L"ollydbg.exe",
    L"idaq.exe",
    L"idaq64.exe",
    L"ida.exe",
    L"ida64.exe",
    L"Cheat Engine.exe",
    L"cheatengine-x86_64.exe",
    L"cheatengine-i386.exe",
    L"Process Hacker.exe",
    L"ProcessHacker.exe",
    L"procdump.exe",
    L"procmon.exe"
};

BOOL EnumWindowsCallback(HWND hWnd, LPARAM lParam)
{
    wchar_t WindowName[256] = { 0 };
    GetWindowTextW(hWnd, WindowName, 256);
    for (int i = 0; i < sizeof(BlacklistedWindowName) / sizeof(wchar_t*); i++)
    {
        if (wcsstr(WindowName, BlacklistedWindowName[i]))
        {
            GetWindowThreadProcessId(hWnd, (LPDWORD)lParam);
            return FALSE;
        }
    }
    return TRUE;
}
__forceinline void CheckProcessHasMyHandle(void)
{
    ULONG returnLength = 0;
    NTSTATUS status = NtQuerySystemInformation(SystemExtendedHandleInformation, nullptr, 0, &returnLength);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
        return;

    ULONG bufferSize = returnLength;
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(bufferSize);
    if (!handleInfo)
        return;

    status = NtQuerySystemInformation(SystemExtendedHandleInformation, handleInfo, bufferSize, &returnLength);
    if (status)
    {
        free(handleInfo);
        return;
    }

    //loop handles
    for (int i = 0; i < handleInfo->NumberOfHandles; i++)
    {
        const auto& handle = handleInfo->Handles[i];

        if (handle.ObjectTypeIndex == 7 && handle.UniqueProcessId != GetCurrentProcessId()) //Process
        {
            HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, handle.UniqueProcessId);
            if (!hProcess)
                continue;
            HANDLE hDupHandle = nullptr;
            DuplicateHandle(hProcess, (HANDLE)handle.HandleValue, GetCurrentProcess(), &hDupHandle, 0, FALSE, 0);
            if (!hDupHandle)
            {
                CloseHandle(hProcess);
                continue;
            }

            //check handle access has PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION
            if ((handle.GrantedAccess & PROCESS_QUERY_INFORMATION) == 0 && (handle.GrantedAccess & PROCESS_QUERY_LIMITED_INFORMATION) == 0)
            {
                CloseHandle(hProcess);
                CloseHandle(hDupHandle);
                continue;
            }

            if (GetProcessId(hDupHandle) != GetCurrentProcessId())
            {
                CloseHandle(hProcess);
                CloseHandle(hDupHandle);
                continue;
            }
            //조사 드가자.

            wchar_t path[MAX_PATH] = { 0 };
            GetModuleFileNameExW(hProcess, nullptr, path, MAX_PATH);

            std::string signType;
            std::wstring catalogFile;
            std::list<SIGN_NODE_INFO> SignChain;
            if (!CheckFileDigitalSignature(path, nullptr, catalogFile, signType, SignChain))
            {
                //TODO: Send log to server.

            }

            CloseHandle(hProcess);
            CloseHandle(hDupHandle);
        }
    }
}
__forceinline void CheckProcess(void)
{
    CheckProcessHasMyHandle();
    DWORD detectedProcessId = 0;
    EnumWindows(EnumWindowsCallback, (LPARAM)&detectedProcessId);

    if (detectedProcessId)
    {
        //TODO: Send log to server.
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, detectedProcessId);
        if (hProcess)
        {
            TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
        }
    }
    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return;

    BOOL bRet = Process32First(hSnapshot, &pe32);
    while (bRet)
    {
        for (int i = 0; i < sizeof(BlacklistedProcessName) / sizeof(wchar_t*); i++)
        {
            if (wcsstr(pe32.szExeFile, BlacklistedProcessName[i]))
            {
                //TODO: Send log to server.
            }
        }
        bRet = Process32Next(hSnapshot, &pe32);
    }
    CloseHandle(hSnapshot);
}