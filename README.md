
# [2023] KUCIS 윈도우 기반 C/C++ 프로그램 프로텍터: Secure Guardian



## 목차
* 프로젝트 개요
* 기능
* 사용방법
* 동작과정
  


## 프로젝트 개요

본 프로젝트는 윈도우 환경에서 C/C++로 개발된 프로그램들의 보안을 강화하기 위해 구현된 프로텍터, Secure Guardian에 대한 설명입니다. 
Secure Guardian는 시스템 해킹이 발생했다고 판단하는 방법들에 대해 감지, 차단을 목적으로 개발되었습니다.



## 기능
Secure Guardian는 4개의 탐지 스레드를 포함하고 있습니다.

* AntiDebugThread  동적 분석을 막기 위해 프로세스 확인, 스레드 레지스터 확인, 하이퍼바이저 탐지 등의 방법을 사용하여 디버그를 탐지합니다.
* AntiLibraryThread  DLL injection을 막기 위해 DLL이 로드될 때마다 호출되어 라이브러리를 검사하면서 이상 DLL을 탐지합니다.
* AntiProcessThread  윈도우 API를 이용하여 핸들과 현재 열려있는 창을 검사하며, 외부 도구의 사용으로 발생하는 동적 및 정적 분석 행동을 감지하고, 이를 감시 대상 명단과 비교하여 탐지합니다.
* AntiCodeIntegrityThread  코드 세션의 해시를 계산하여 저장된 해시와 현재 해시를 비교하여 코드의 무결성을 탐지하여 코드 변조를 막습니다.



## 사용방법

1.  core.cpp 파일을 C++ 프로젝트에 업로드
(AntiDebugThread, AntiLibraryThread, AntiProcessThread, AntiCodeIntegrityThread와 관련된 헤더 파일과 라이브러리도 함께 링크)
2. C++ 컴파일러를 사용하여 프로젝트를 컴파일
3. 생성된 실행 파일을 실행



## 동작과정

### AntiDebugThread
https://github.com/CERT-IS/2023_KUCIS_PROJECT/blob/%231/feature/newProject/Protector/AntiDebug.hpp
현재 실행 중인 프로그램이 디버그 중인지 아닌지를 검사하는 스레드

    
##### BasicDebugTriggered 함수, IsDebuggerPresent 함수
Windows API의 일부로, IsDebuggerPresent라는 함수를 사용하여 디버거가 현재 프로세스에 연결되어 있는지 확인
프로세스 환경 블록(PEB)의 NtGlobalFlag를 확인하여 기본적인 디버그를 감지


```
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
```


##### HWBPDebugTriggered 함수
하드웨어 브레이크포인트가 설정되었는지 확인


```
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
```


##### HypervisorDebugTriggered 함수
가상화 기반 보안(VBS) 또는 하이퍼바이저를 사용한 디버깅을 감지 
__asm 블록 내에서 예외를 발생시키는 특정 명령어를 실행하고, 이것이 예외를 발생시키면 하이퍼바이저에 의해 디버깅 중인 것으로 판단

```
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
```


##### AntiDebugTriggered 함수
위의 세 가지 디버그 감지 함수를 호출, 감지된 디버그 유형에 따라 다른 값을 반환

```
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
```


### AntiLibraryThread
https://github.com/CERT-IS/2023_KUCIS_PROJECT/blob/%231/feature/newProject/Protector/AntiLibrary.hpp
로드된 라이브러리들을 검사하고 디지털 서명을 확인하는 작업을 수행

##### CheckLibrary 함수
프로세스 환경 블록(PEB)을 통해 로드된 모듈의 목록을 가져와 각 모듈의 디지털 서명을 검사
디지털 서명이 없는 모듈이 발견되면 해당 모듈의 경로를 출력
-> 악성 코드나 무단으로 수정된 라이브러리를 탐지


```
__forceinline void CheckLibrary()
{
    //get peb
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    //get ldr
    PPEB_LDR_DATA ldr = peb->Ldr;

    //loop through modules
    auto head = &ldr->InLoadOrderModuleList;
    for (auto curr = head->Flink; curr != head; curr = curr->Flink)
    {
        //get module
        auto mod = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (mod->DllBase == GetModuleHandle(NULL))
        {
            continue;
        }
        //get module name
        auto path = malloc(mod->FullDllName.Length + sizeof(wchar_t));
        memcpy(path, mod->FullDllName.Buffer, mod->FullDllName.Length);
        ((wchar_t*)path)[mod->FullDllName.Length / sizeof(wchar_t)] = 0;

        std::wstring catalogFile;
        std::string signType;
        std::list<SIGN_NODE_INFO> SignChain;
        if (!CheckFileDigitalSignature((LPCWSTR)path, NULL, catalogFile, signType, SignChain))
        {
            printf("DETECTED/LDR/CheckLibrary: %ws\n", path);
            continue;
        }
        //printf("file: %ws\n", path);
        //PrintSignatureInfo(signType, catalogFile, SignChain);
    }
}
```


##### TlsCallback 함수
스레드 로컬 스토리지(TLS) 콜백을 이용하여 DLL이 로드되거나 언로드될 때마다 해당 함수를 호출해 라이브러리의 로드 상태를 지속적으로 모니터링


```
void NTAPI TlsCallback(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{
    //TODO: CreateThread detection
}
#pragma data_seg(".CRT$XLX")
PIMAGE_TLS_CALLBACK p_thread_callback[] = { TlsCallback, 0 };
#pragma data_seg()
```


### AntiProcessThread
https://github.com/CERT-IS/2023_KUCIS_PROJECT/blob/%231/feature/newProject/Protector/AntiProcess.hpp
특정 프로세스와 윈도우를 찾아내는 역할을 수행, 검출된 프로세스와 윈도우에 대한 정보를 출력하는 기능

##### EnumWindowsCallback 함수
시스템에서 실행 중인 모든 윈도우를 열거하고, 각 윈도우의 이름을 검사하여 블랙리스트에 있는지 확인
블랙리스트에 있는 윈도우가 발견되면, 해당 윈도우의 이름을 출력하고 열거를 중지

```
BOOL WINAPI EnumWindowsCallback(HWND hWnd, LPARAM lParam)
{
    wchar_t WindowName[256] = { 0 };
    GetWindowTextW(hWnd, WindowName, 256);
    for (int i = 0; i < sizeof(BlacklistedWindowName) / sizeof(wchar_t*); i++)
    {
        if (wcsstr(WindowName, BlacklistedWindowName[i]))
        {
            //GetWindowThreadProcessId(hWnd, (LPDWORD)lParam);
			std::wstring* detectedWindowName = (std::wstring*)lParam;
			*detectedWindowName = WindowName;
            return FALSE;
        }
    }
    return TRUE;
}
```

##### CheckProcessHasMyHandle 함수
시스템의 모든 핸들을 열거하고, 각 핸들이 현재 프로세스의 핸들에 연결되어 있는지 확인
연결되어 있으면, 해당 핸들을 소유한 프로세스의 실행 파일 경로를 검사하여 디지털 서명이 있는지 확인
디지털 서명이 없으면, 해당 프로세스가 우리의 핸들을 가지고 있음을 로그로 출력

```
__forceinline void CheckProcessHasMyHandle(void)
{
    ULONG returnLength = 0;
	PSYSTEM_HANDLE_INFORMATION_EX handleInfo = nullptr;
	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
	do
	{
		if (returnLength)
		{
			if (handleInfo)
			{
				handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)realloc(handleInfo, returnLength);
			}
			else
			{
				handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(returnLength);
			}
		}
		status = NtQuerySystemInformation(SystemExtendedHandleInformation, handleInfo, returnLength, &returnLength);
	}
	while (status == STATUS_INFO_LENGTH_MISMATCH);

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
            DuplicateHandle(hProcess, (HANDLE)handle.HandleValue, GetCurrentProcess(), &hDupHandle, PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0);
            if (!hDupHandle)
            {
                CloseHandle(hProcess);
                continue;
            }

            //check handle access has PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION
            /*if ((handle.GrantedAccess & PROCESS_QUERY_INFORMATION) == 0 && (handle.GrantedAccess & PROCESS_QUERY_LIMITED_INFORMATION) == 0)
            {
                CloseHandle(hProcess);
                CloseHandle(hDupHandle);
                continue;
            }*/
            if (GetProcessId(hDupHandle) != GetCurrentProcessId())
            {
                CloseHandle(hProcess);
                CloseHandle(hDupHandle);
                continue;
            }
            //Á¶»ç µå°¡ÀÚ.

            wchar_t path[MAX_PATH] = { 0 };
            GetModuleFileNameExW(hProcess, nullptr, path, MAX_PATH);

            std::string signType;
            std::wstring catalogFile;
            std::list<SIGN_NODE_INFO> SignChain;
            if (!CheckFileDigitalSignature(path, nullptr, catalogFile, signType, SignChain))
            {
                //TODO: Send log to server.
				printf("DETECTED/HANDLE/Unknown process has our handle. path: %ws\n", path);
            }

            CloseHandle(hProcess);
            CloseHandle(hDupHandle);
        }
    }
}
```

##### CheckProcess 함수
CheckProcessHasMyHandle 함수를 호출하여 핸들 검사를 수행한 후, 시스템에서 실행 중인 모든 프로세스를 열거하고 각 프로세스의 이름을 검사하여 블랙리스트에 있는 프로세스가 발견되면, 해당 프로세스의 이름을 출력

```
__forceinline void CheckProcess(void)
{
    CheckProcessHasMyHandle();
	
    std::wstring detectedWindowName;
    EnumWindows(EnumWindowsCallback, (LPARAM)&detectedWindowName);
	
    if (!detectedWindowName.empty())
    {
        //TODO: Send log to server.
		printf("DETECTED/WINDOW/Blacklisted windows has been found. name: %ws\n", detectedWindowName.c_str());
        /*HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, detectedProcessId);
        if (hProcess)
        {
            TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
        }*/
    }
	return;
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
				printf("DETECTED/WINDOW/Blacklisted process has been found. name: %ws\n", pe32.szExeFile);
            }
        }
        bRet = Process32Next(hSnapshot, &pe32);
    }
    CloseHandle(hSnapshot);
}
```


### AntiCodeIntegrityThread
https://github.com/CERT-IS/2023_KUCIS_PROJECT/blob/%231/feature/newProject/Protector/CodeIntegrity.hpp
프로그램의 코드 무결성을 검증

##### CodeIntegrityVerifier 클래스
".text" 섹션에 대한 해시를 계산하여 이를 저장하고, 'Verify' 메서드를 호출하면, 현재 '.text' 섹션의 해시를 다시 계산하고 저장된 해시와 비교합니다. 두 해시가 같으면 'true'를 반환하며, 그렇지 않으면 'false'를 반환합니다.
-> 프로그램의 실행 도중 '.text' 섹션의 코드가 변경되면 'Verify' 메서드는 'false'를 반환하여 코드 무결성이 손상되었음을 알림

```
class CodeIntegrityVerifier
{
private:
    DWORD_PTR m_moduleBase;
    DWORD_PTR m_moduleSize;
    DWORD m_sectionHash;
public:
    CodeIntegrityVerifier(DWORD_PTR moduleBase, DWORD_PTR moduleSize = 0)
    {
        m_moduleBase = moduleBase;
        m_moduleSize = moduleSize;
        if (!m_moduleSize)
        {
            IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)m_moduleBase;
            if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
                return;
            IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)(m_moduleBase + pDosHeader->e_lfanew);
            if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
                return;
            m_moduleSize = pNtHeaders->OptionalHeader.SizeOfImage;
        }
        GetSectionHash(moduleBase, ".text", &m_sectionHash);
    }
    __forceinline bool Verify()
    {
        DWORD hash;
        if (!GetSectionHash(m_moduleBase, ".text", &hash))
            return false;
        return hash == m_sectionHash;
    }
};
```
