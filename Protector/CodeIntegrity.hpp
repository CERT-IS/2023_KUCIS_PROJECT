#include <Windows.h>
#include <string>
#include <intrin.h>
inline bool GetSectionHash(DWORD_PTR moduleBase, const std::string& sectionName, LPDWORD pHash)
{
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)moduleBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)(moduleBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return false;
    IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
    {
        if (strcmp((char*)pSectionHeader->Name, sectionName.c_str()) == 0)
        {
            *pHash = 0xDEADBEEF;
            for (int i = 0; i < pSectionHeader->SizeOfRawData; i += 4)
            {
                *pHash = _mm_crc32_u32(*pHash, *(DWORD*)(moduleBase + pSectionHeader->VirtualAddress + i));
            }
            return true;
        }
        pSectionHeader++;
    }
    return false;
}
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