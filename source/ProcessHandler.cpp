#include "IOProcessor.h"
#include "ProcessHandler.h"
#include <stdint.h>
#include <Windows.h>
#include <TlHelp32.h> // Must come after windows.


// Static definitions
void* ProcessHandler::INVALID_HANDLE = INVALID_HANDLE_VALUE;

/*
/ Function: DisplayActiveProcs
/ Notes: None
*/
void ProcessHandler::DisplayActiveProcs(const char* query)
{
  // This buffer will serve as the standard format for 
  // the output process list.
  const size_t strMax = 64;
  std::string strProcList(strMax, ' ');
  memcpy(reinterpret_cast<void*>(&strProcList[0]), "Process.Id", 10);
  memcpy(reinterpret_cast<void*>(&strProcList[16]), "Process.Name", 12);

  // Print feed back
  IOProcessor::Print("> Enumerating active process list");

  // Retrieve active process list
  std::vector<PROCENTRY> procs;
  ProcessHandler pHandler;
  
  pHandler.EnumProcs(procs);
  if (0 == procs.size())
  {
    IOProcessor::Print("- Unable to retrieve active process list");
    return;
  }

  // Print list banner
  IOProcessor::Print();
  IOProcessor::Print(strProcList.c_str());
  memset(reinterpret_cast<void*>(&strProcList[0]), '-', strMax);
  IOProcessor::Print(strProcList.c_str());

  // Iterate through process list and output.
  for (size_t i = 0; i < procs.size(); ++i)
  {
    // Skip this entry if there is a mismatch in query..
    if (nullptr != query)
    {
      std::string strProcName = procs[i].ProcessName;
      if (std::string::npos == strProcName.find(query))
      {
        continue;
      }
    }

    // Output process information
    char strPid[10] = { ' ' };
    sprintf_s(strPid, "%08X", procs[i].ProcessId);
    memset(reinterpret_cast<void*>(&strProcList[0]), ' ', strMax);
    memcpy(reinterpret_cast<void*>(&strProcList[0]), strPid, strlen(strPid));
    memcpy(reinterpret_cast<void*>(&strProcList[16]),
           procs[i].ProcessName,
           sizeof(procs[i].ProcessName));
    IOProcessor::Print(strProcList.c_str());
  }

  IOProcessor::Print();
}

/*
/ Function: AttachToProcess
/ Notes: None
*/
bool ProcessHandler::AttachToProcess(const char* processName)
{
  // Cleanup previous process handle if valid.
  if (INVALID_HANDLE_VALUE != ProcessHandle)
  {
    ProcessName.clear();
    ProcessId = 0;
    CloseHandle(ProcessHandle);
  }

  // Retrieve active process list
  std::vector<PROCENTRY> procs;
  EnumProcs(procs);
  if (0 == procs.size())
  {
    IOProcessor::Print("- Unable to retrieve active process list");
    return false;
  }

  // Iterate through process list and search for our target.
  for (size_t i = 0; i < procs.size(); ++i)
  {
    std::string strProcName = procs[i].ProcessName;
    if (std::string::npos != strProcName.find(processName))
    {
      ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procs[i].ProcessId);
      ProcessName = strProcName;
      ProcessId = procs[i].ProcessId;
      break;
    }
  }

  return (INVALID_HANDLE_VALUE != ProcessHandle);
}

/*
/ Function: AttachToProcess
/ Notes: None
*/
bool ProcessHandler::AttachToProcess(unsigned long processId)
{
  // We don't have to find a matching process id to attach in this
  // case, but we still want the process name, therefore perform
  // a seach on currently active processes.
  // Cleanup previous process handle if valid.
  if (INVALID_HANDLE_VALUE != ProcessHandle)
  {
    CloseHandle(ProcessHandle);
    ProcessHandle = INVALID_HANDLE_VALUE;
  }

  // Retrieve active process list
  std::vector<PROCENTRY> procs;
  EnumProcs(procs);
  if (0 == procs.size())
  {
    IOProcessor::Print("- Unable to retrieve active process list");
    return false;
  }

  // Iterate through process list and search for our target.
  for (size_t i = 0; i < procs.size(); ++i)
  {
    if (processId == procs[i].ProcessId)
    {
      ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procs[i].ProcessId);
      ProcessName = procs[i].ProcessName;
      ProcessId = procs[i].ProcessId;
      break;
    }
  }

  return (INVALID_HANDLE_VALUE != ProcessHandle);
}

/*
/ Function: GetProcessHandle
/ Notes: None
*/
void* ProcessHandler::GetProcessHandle() const
{
  return ProcessHandle;
}

/*
/ Function: GetProcessName
/ Notes: None
*/
const char* ProcessHandler::GetProcessName() const
{
  return ProcessName.c_str();
}

/*
/ Function: GetProcessId
/ Notes: None
*/
uint32_t ProcessHandler::GetProcessId() const
{
  return ProcessId;
}

/*
/ Function: ResetHandle
/ Notes: None
*/
void ProcessHandler::ResetHandle()
{
  CloseHandle(ProcessHandle);
  ProcessHandle = INVALID_HANDLE;
  ProcessName.clear();
  ProcessId = 0;
}

/*
/ Function: ProcessHandler
/ Notes: None
*/
ProcessHandler::ProcessHandler() :
  ProcessHandle(INVALID_HANDLE_VALUE),
  ProcessName(""),
  ProcessId(0)
{
  static bool privEnabled = false;
  if (false == privEnabled)
  {
    privEnabled = EnableDbgPriv();
  }
}

/*
/ Function: ~ProcessHandler
/ Notes: None
*/
ProcessHandler::~ProcessHandler()
{
  if (INVALID_HANDLE_VALUE != ProcessHandle)
  {
    CloseHandle(ProcessHandle);
  }
}

/*
/ Function: EnableDbgPriv
/ Notes: None
*/
bool ProcessHandler::EnableDbgPriv()
{
  TOKEN_PRIVILEGES tokenPrivs;
  TOKEN_PRIVILEGES prevTokenPrivs;
  unsigned long tokenSize = sizeof(TOKEN_PRIVILEGES);

  // Open a handle to this thread to adjust token privileges
  HANDLE tokenHandle = INVALID_HANDLE_VALUE;
  if (FALSE == OpenThreadToken(GetCurrentThread(), 
                               TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                               FALSE,
                               &tokenHandle))
  {
    if (ERROR_NO_TOKEN == GetLastError())
    {
      if (FALSE == ImpersonateSelf(SecurityImpersonation))
      {
        return false;
      }

      if (FALSE == OpenThreadToken(GetCurrentThread(),
                                   TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, 
                                   FALSE,
                                   &tokenHandle))
      {
        return false;
      }
    }
  }

  // Retrieve value of SE_DEBUG_NAME privilege
  LUID luid;
  if (FALSE == LookupPrivilegeValue(0, SE_DEBUG_NAME, &luid))
  {
    return false;
  }

  // AdjustTokenPrivileges with default values in order to retrieve
  // current attribnute values.
  bool success = false;
  tokenPrivs.PrivilegeCount = 1;
  tokenPrivs.Privileges[0].Luid = luid;
  tokenPrivs.Privileges[0].Attributes = 0;
  AdjustTokenPrivileges(tokenHandle, FALSE,
                        &tokenPrivs, sizeof(TOKEN_PRIVILEGES),
                        &prevTokenPrivs, &tokenSize);

  // Enable the privilege, then apply.
  if (ERROR_SUCCESS == GetLastError())
  {
    prevTokenPrivs.PrivilegeCount = 1;
    prevTokenPrivs.Privileges[0].Luid = luid;
    prevTokenPrivs.Privileges[0].Attributes |= SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(tokenHandle, FALSE, &prevTokenPrivs, tokenSize, 0, 0);
    success = ERROR_SUCCESS == GetLastError();
  }

  CloseHandle(tokenHandle);
  return success;
}

/*
/ Function: EnumProcs
/ Notes: None
*/
void ProcessHandler::EnumProcs(std::vector<PROCENTRY>& pList)
{
  // Clear list
  pList.clear();

  // Retrieve snapshot of running processe
  HANDLE snapHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (INVALID_HANDLE_VALUE == snapHandle)
  {
    IOProcessor::Print("> Failed creating process snapshot");
    return;
  }

  // Iterate through all snapped processes
  PROCESSENTRY32 pe32;
  pe32.dwSize = sizeof(PROCESSENTRY32);

  BOOL pe32Itr = Process32First(snapHandle, &pe32);
  while (FALSE != pe32Itr)
  {
    // Extract process id and name. Format string and print.
    PROCENTRY pEntry;
    pEntry.ProcessId = pe32.th32ProcessID;
    memset(pEntry.ProcessName, 0, sizeof(pEntry.ProcessName));

    size_t pNameLen = lstrlen(pe32.szExeFile);
    size_t maxLen = sizeof(pEntry.ProcessName) > pNameLen ?
      sizeof(pEntry.ProcessName) : pNameLen;

    // WCHAR occupies 2-bytes, therefore we need to skip every other byte
    for (size_t i = 0; i < pNameLen; ++i)
    {
      if (i >= maxLen)
      {
        break;
      }

      pEntry.ProcessName[i] = reinterpret_cast<char*>(pe32.szExeFile)[i * 2];
    }

    pList.push_back(pEntry);

    pe32Itr = Process32Next(snapHandle, &pe32);
  }

  // Close snapshot handle
  CloseHandle(snapHandle);
}