
# [2023] KUCIS 윈도우 기반 C/C++ 프로그램 프로텍터: Secure Guardian



## 목차
* 프로젝트 개요
* 기능
* 사용방법
  


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
core.cpp 파일에서 AntiDebugThread, AntiLibraryThread, AntiProcessThread, AntiCodeIntegrityThread 4개의 탐지 스레드를 생성하며 
각 모듈에서 프로그램 훼손 여부가 탐지되면 서버에 로그를 보내고 사용자에게 알려준 뒤 프로그램이 종료되는 프로텍터


#### AntiDebugThread
https://github.com/CERT-IS/2023_KUCIS_PROJECT/blob/%231/feature/newProject/Protector/AntiDebug.hpp
현재 실행 중인 프로그램이 디버그 중인지 아닌지를 검사하는 스레드
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
    
##### BasicDebugTriggered 함수, IsDebuggerPresent 함수
프로세스 환경 블록(PEB)의 NtGlobalFlag를 확인하여 기본적인 디버그를 감지

##### HWBPDebugTriggered 함수
하드웨어 브레이크포인트를 감지하기 위해 디버거 레지스터를 확인

##### HypervisorDebugTriggered 함수
하이퍼바이저 기반 디버거를 감지
cpuid 명령어를 사용하여 처리되지 않은 예외를 유발하여 디버거를 감지

##### AntiDebugTriggered 함수
위의 세 가지 디버그 감지 함수를 호출, 감지된 디버그 유형에 따라 다른 값을 반환


#### AntiLibraryThread
https://github.com/CERT-IS/2023_KUCIS_PROJECT/blob/%231/feature/newProject/Protector/AntiLibrary.hpp


#### AntiProcessThread
https://github.com/CERT-IS/2023_KUCIS_PROJECT/blob/%231/feature/newProject/Protector/AntiProcess.hpp

#### AntiCodeIntegrityThread
https://github.com/CERT-IS/2023_KUCIS_PROJECT/blob/%231/feature/newProject/Protector/CodeIntegrity.hpp




