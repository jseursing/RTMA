#pragma once
#include "RTMAManager.h"


// Forward declarations
class ProcessHandler;


/*
/ This instance of RTMA Manager is to be used by the server.
*/
class RTMA_SVRManager : public RTMAManager
{
public:
  static RTMA_SVRManager* Instance();
  static void TaskMain();
  static void MainLoop();

  ProcessHandler* Attach(uint32_t pid);
  ProcessHandler* Attach(const char* pName);
  bool ExecuteInjectDMA(const char* path);
  void InjectLibrary(char* libraryPath);
  bool InjectDMAModule();
  bool UnloadDMAModule();
  virtual bool PEScan(MsgHeader* message = nullptr);
  virtual bool MemRegionScan(MsgHeader* message = nullptr);
  virtual void ProcessDMA(MsgHeader* message);
  bool DisplayScanResults();
  bool Scan(char* value, size_t size);
  bool NextScan(char* value, size_t size);
  bool Read(uintptr_t address, size_t size);
  bool Write(uintptr_t address, char* value, size_t size);

private:
  
  RTMA_SVRManager();
  ~RTMA_SVRManager();
  

  ProcessHandler* Procs;
  uint32_t RemoteScanCount;
  uint32_t DisplayScanCount;
};