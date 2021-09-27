#pragma once
#include <stdint.h>
#include <vector>


/*
/ This class provides utilities for finding, executing, and
/ attaching to processes.
*/
class ProcessHandler
{
public:
  static void DisplayActiveProcs(const char* query = nullptr);
  bool AttachToProcess(const char* processName);
  bool AttachToProcess(unsigned long processId);
  void* GetProcessHandle() const;
  const char* GetProcessName() const;
  uint32_t GetProcessId() const;
  void ResetHandle();
  ProcessHandler();
  ~ProcessHandler();

  static void* INVALID_HANDLE;

private:
  struct PROCENTRY
  {
    char ProcessName[64];
    uint32_t ProcessId;
  };

  bool EnableDbgPriv();
  void EnumProcs(std::vector<PROCENTRY>& pList);


  void* ProcessHandle;
  std::string ProcessName;
  uint32_t ProcessId;
};