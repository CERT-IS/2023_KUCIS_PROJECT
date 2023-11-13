#include <Windows.h>

#include <list>
#include <string>
typedef struct _SIGN_COUNTER_SIGN {
    std::string SignerName;
    std::string MailAddress;
    std::string TimeStamp;
} SIGN_COUNTER_SIGN, * PSIGN_COUNTER_SIGN;
typedef struct _CERT_NODE_INFO {
    std::string SubjectName;
    std::string IssuerName;
    std::string Version;
    std::string Serial;
    std::string Thumbprint;
    std::string NotBefore;
    std::string NotAfter;
    std::string SignAlgorithm;
    std::wstring CRLpoint;
} CERT_NODE_INFO, * PCERT_NODE_INFO;
typedef struct _SIGN_NODE_INFO {
    std::string DigestAlgorithm;
    std::string Version;
    SIGN_COUNTER_SIGN CounterSign;
    std::list<CERT_NODE_INFO> CertChain;
} SIGN_NODE_INFO, * PSIGN_NODE_INFO;

BOOL CheckFileDigitalSignature(
    LPCWSTR FilePath,
    LPCWSTR CataPath,
    std::wstring& CataFile,
    std::string& SignType,
    std::list<SIGN_NODE_INFO>& SignChain);
void PrintSignatureInfo(std::string& SignType, std::wstring& CataFile, std::list<SIGN_NODE_INFO>& SignChain);