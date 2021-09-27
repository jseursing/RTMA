#include "AckMsg.h"
#include "CodeInjection.h"
#include "DMAMsg.h"
#include "IOProcessor.h"
#include "MemScanMsg.h"
#include "MemScanner.h"
#include "OSInterface.h"
#include "ProcessHandler.h"
#include "UDPSocket.h"
#include "RTMA_SVRManager.h"


/*
/ Function: TaskMain
/ Notes: None
*/
void RTMA_SVRManager::TaskMain()
{
  SetConsoleTitleA("Remote Terminal Memory Access");

  const char appBanner[] =
    "/*                                        */\n"
    "/      Remote Terminal Memory Access       /\n"
    "/*                                        */\n";

  // Print the banner
  IOProcessor::Print(appBanner);

  // Initialize server RTMAManager
  RTMA_SVRManager* instance = RTMA_SVRManager::Instance();
  instance->ReadLock = OSInterface::SemCreate("RTMASEM", 0, 1);

  // Initialize I/O Sockets
  instance->RTMAServer = UDPSocket::Create(69); // Bind Server
  instance->RTMAClient = UDPSocket::Create();   // Send to client

  // Launch MainLoop
  unsigned long threadId;
  void* pTask = OSInterface::TaskCreate(MainLoop, 
                                        nullptr, 
                                        1024 * 32, 
                                        threadId, 
                                        1);
  OSInterface::ActivateTask(pTask);

  while (true)
  {
    switch (instance->CurrentMode)
    {
    case REMOTE:
      IOProcessor::PrintNoEOL("REM> ");
      break;
    case DMA:
      IOProcessor::PrintNoEOL("DMA> ");
      break;
    }

    std::string input = IOProcessor::GetInput();
    if (0 < input.length())
    {
      std::vector<std::string> params = IOProcessor::Parameterize(input);
      if (false == IOProcessor::ProcessParameters(params)) // FALSE means we wait..
      {
        // Lock to halt..
        OSInterface::SemTake(instance->ReadLock, -1);
      }
    }
  }
}

/*
/ Function: MainLoop
/ Notes: None
*/
void RTMA_SVRManager::MainLoop()
{
  RTMA_SVRManager* instance = RTMA_SVRManager::Instance();

  char buf[1024 * 32] = { 0 }; // 32K allocated for message receiving
  while (true)
  {
    if (StatusTypes::STATUS_OK ==
        instance->RTMAServer->RecvMsg(buf, sizeof(buf), -1))
    {
      MsgHeader* msgHeader = reinterpret_cast<MsgHeader*>(buf);
      switch (msgHeader->GetType())
      {
      case MsgHeader::INIT:
        if (MsgHeader::RESPONSE == msgHeader->GetSubtype())
        {
          instance->CurrentMode = DMA;
          OSInterface::SemGive(instance->ReadLock);
        }
        break;

      case MsgHeader::ACKNOWLEDGE:
        {
          AckMsg* ack = reinterpret_cast<AckMsg*>(msgHeader);
          if (MsgHeader::ACCEPTED == ack->GetSubtype())
          {
            switch (ack->GetQueryType())
            {
            case MsgHeader::PESCAN:
              IOProcessor::Print("Scanning PE structure");
              break;
            case MsgHeader::MEMSCAN:
              IOProcessor::Print("Scanning memory region");
              break;
            case MsgHeader::RELEASE:
              instance->CurrentMode = REMOTE;

              // Unlock user input access
              OSInterface::SemGive(instance->ReadLock);
            default: break;
            }
          }
          else
          {
            IOProcessor::Print("Request was rejected\n");
          }
        }
        break;

      case MsgHeader::PESCAN:
        instance->PEScan(msgHeader);
        break;

      case MsgHeader::MEMSCAN:
        instance->MemRegionScan(msgHeader);
        break;

      case MsgHeader::DMA:
        instance->ProcessDMA(msgHeader);
        break;
      }
    }
  }
}

/*
/ Function: Instance
/ Notes: none
*/
RTMA_SVRManager* RTMA_SVRManager::Instance()
{
  static RTMA_SVRManager instance;
  if (nullptr == ThisInstance)
  {
    ThisInstance = &instance;
  }

  return &instance;
}

/*
/ Function: Attach
/ Notes: none
*/
ProcessHandler* RTMA_SVRManager::Attach(uint32_t pid)
{
  ProcessHandler* pHandle = nullptr;

  // First look for an existing handler
  for (size_t i = 0; i < MAX_HANDLES; ++i)
  {
    if (pid == Procs[i].GetProcessId())
    {
      pHandle = &Procs[i];
      break;
    }
  }

  // Create a new instance if we didn't find an existing one
  if (nullptr == pHandle)
  {
    for (size_t i = 0; i < MAX_HANDLES; ++i)
    {
      // Look for an unused handler
      if (0 == Procs[i].GetProcessId())
      {
        Procs[i].AttachToProcess(pid);
        pHandle = &Procs[i];
        break;
      }
    }
  }

  // Output status
  if (nullptr != pHandle)
  {
    if (ProcessHandler::INVALID_HANDLE == pHandle->GetProcessHandle())
    {
      IOProcessor::Print("- Failed attaching to process");
    }
    else
    {
      char strStatus[256] = { 0 };

#if _WIN32 || _WIN64
#if _WIN64
      sprintf_s(strStatus,
                "Remote Terminal Memory Access - "
                "%s | PID: %08X | HANDLE: %llX",
                pHandle->GetProcessName(),
                pHandle->GetProcessId(),
                reinterpret_cast<uintptr_t>(pHandle->GetProcessHandle()));
#else
      sprintf_s(strStatus,
                "Remote Terminal Memory Access - "
                "%s | PID: %08X | HANDLE: %08X",
                pHandle->GetProcessName(),
                pHandle->GetProcessId(),
                reinterpret_cast<uintptr_t>(pHandle->GetProcessHandle()));
#endif
#endif
      SetConsoleTitleA(strStatus);
    }
  }

  CurrentHandler = pHandle;

  return pHandle;
}

/*
/ Function: Attach
/ Notes: none
*/
ProcessHandler* RTMA_SVRManager::Attach(const char* pName)
{
  ProcessHandler* pHandle = nullptr;

  // First look for an existing handler
  for (size_t i = 0; i < MAX_HANDLES; ++i)
  {
    if (std::string::npos !=
        std::string(Procs[i].GetProcessName()).find(pName))
    {
      pHandle = &Procs[i];
      break;
    }
  }

  // If we have an existing connection, validate PID via OpenProcess.
  if (nullptr != pHandle)
  {
    if (false == pHandle->AttachToProcess(pHandle->GetProcessId()))
    {
      pHandle->ResetHandle();
      pHandle = nullptr;
    }
  }

  // Create a new instance if we didn't find an existing one
  if (nullptr == pHandle)
  {
    for (size_t i = 0; i < MAX_HANDLES; ++i)
    {
      // Look for an unused handler
      if (0 == Procs[i].GetProcessId())
      {
        Procs[i].AttachToProcess(pName);
        pHandle = &Procs[i];
      }
    }
  }

  // Output status
  if (nullptr != pHandle)
  {
    if (ProcessHandler::INVALID_HANDLE == pHandle->GetProcessHandle())
    {
      IOProcessor::Print("- Failed attaching to process");
    }
    else
    {
      char strStatus[256] = { 0 };

#if _WIN32 || _WIN64
#if _WIN64
      sprintf_s(strStatus,
                "Remote Terminal Memory Access - "
                "%s | PID: %08X | HANDLE: %llX",
                pHandle->GetProcessName(),
                pHandle->GetProcessId(),
                reinterpret_cast<uintptr_t>(pHandle->GetProcessHandle()));
#else
      sprintf_s(strStatus,
                "Remote Terminal Memory Access - "
                "%s | PID: %08X | HANDLE: %08X",
                pHandle->GetProcessName(),
                pHandle->GetProcessId(),
                reinterpret_cast<uintptr_t>(pHandle->GetProcessHandle()));
#endif
#endif
      SetConsoleTitleA(strStatus);
    }
  }

  CurrentHandler = pHandle;

  return pHandle;
}

/*
/ Function: ExecuteInjectDMA
/ Notes: none
*/
bool RTMA_SVRManager::ExecuteInjectDMA(const char* path)
{
  void* pHandle = nullptr;
  void* tHandle = nullptr;
  if (INVALID_HANDLE_VALUE ==
      OSInterface::ProcessSpawn(const_cast<char*>(path), true, pHandle, tHandle))
  {
    IOProcessor::Print("- Failed launching process");
    return true;
  }

  bool shouldWait = InjectDMAModule();
  OSInterface::ActivateTask(tHandle);

  return shouldWait;
}

/*
/ Function: InjectLibrary
/ Notes: none
*/
void RTMA_SVRManager::InjectLibrary(char* libraryPath)
{
  if (nullptr == CurrentHandler)
  {
    IOProcessor::Print("- Code Injection requires process attachment");
    return;
  }

  bool success = CodeInjection::InjectLibrary(CurrentHandler->GetProcessHandle(),
                                              libraryPath);
  IOProcessor::Print(true == success ?
                     "+ Successfully injected library" :
                     "- Failed injecting library");
}

/*
/ Function: InjectDMAModule
/ Notes: none
*/
bool RTMA_SVRManager::InjectDMAModule()
{
  if (REMOTE != CurrentMode)
  {
    IOProcessor::Print("- DMA mode already active");
    return true;
  }

  if (nullptr == CurrentHandler)
  {
    IOProcessor::Print("- Code Injection requires process attachment");
    return true;
  }

  char libPath[512] = { 0 };
  GetCurrentDirectoryA(512, libPath);

#if _WIN32 || _WIN64
#if _WIN64
  strcat_s(libPath, "\\RTMALIB64.dll");
#else
  strcat_s(libPath, "\\RTMALIB32.dll");
#endif
#endif

  bool success = CodeInjection::InjectLibrary(CurrentHandler->GetProcessHandle(),
                                              libPath);
  if (false == success)
  {
    IOProcessor::Print("- Failed injecting DMA module");
    return true;
  }

  return false;
}

/*
/ Function: UnloadDMAModule
/ Notes: none
*/
bool RTMA_SVRManager::UnloadDMAModule()
{
  if (REMOTE == CurrentMode)
  {
    IOProcessor::Print("- REMOTE mode already active");
    return true;
  }

  // Send Release query message
  MsgHeader releaseMsg = MsgHeader(MsgHeader::RELEASE,
                                   MsgHeader::QUERY,
                                   sizeof(MsgHeader));
  RTMAServer->SendMsg(LOCALIP,
                      CLIENT_PORT,
                      reinterpret_cast<char*>(&releaseMsg),
                      releaseMsg.GetLength());
  return false;
}

/*
/ Function: PEScan
/ Notes: none
*/
bool RTMA_SVRManager::PEScan(MsgHeader* message)
{
  if (nullptr != message)
  {
    if (MsgHeader::RESPONSE == message->GetSubtype())
    {
      char statusMsg[512] = { 0 };

      MemScanMsg* scanResult = reinterpret_cast<MemScanMsg*>(message);
      uint32_t sectionCnt = (scanResult->GetLength() - sizeof(MsgHeader) - 8) / 24;

      uintptr_t rawPtr = reinterpret_cast<uintptr_t>(scanResult->GetDataPointer());
#if _WIN32 || _WIN64
#if _WIN64
      sprintf_s(statusMsg, "\nImage Base: %llX", *reinterpret_cast<uintptr_t*>(rawPtr));
#else
      sprintf_s(statusMsg, "\nImage Base: %08X", *reinterpret_cast<uintptr_t*>(rawPtr));
#endif
#endif
      IOProcessor::Print(statusMsg);

      // Print PE banner and border
      std::string sectionStr(45, ' ');
      memcpy(&sectionStr[0], "Name", 4);
      memcpy(&sectionStr[12], "Address", 7);
      memcpy(&sectionStr[32], "Size", 4);
      IOProcessor::Print(sectionStr.c_str());
      memset(&sectionStr[0], '-', 45);
      IOProcessor::Print(sectionStr.c_str());
      memset(&sectionStr[0], ' ', 45);

      for (size_t i = 0; i < sectionCnt; ++i)
      {
        rawPtr += 8;
        memset(statusMsg, 0, sizeof(statusMsg));

        char sectionName[8] = { 0 };
        memcpy(sectionName, reinterpret_cast<void*>(rawPtr), 8);
        memcpy(&sectionStr[0], sectionName, strlen(sectionName));

#if _WIN32 || _WIN64
#if _WIN64
        rawPtr += 8;
        char sectionAddr[16] = { ' ' };
        sprintf_s(sectionAddr, "%llX", *reinterpret_cast<uintptr_t*>(rawPtr));
        memcpy(&sectionStr[12], sectionAddr, strlen(sectionAddr));

        rawPtr += 8;
        char sectionSize[16] = { ' ' };
        sprintf_s(sectionSize, "%llX", *reinterpret_cast<uintptr_t*>(rawPtr));
        memcpy(&sectionStr[32], sectionSize, strlen(sectionSize));
#else
        rawPtr += 8;
        char sectionAddr[8] = { ' ' };
        sprintf_s(sectionAddr, "%08X", *reinterpret_cast<uintptr_t*>(rawPtr));
        memcpy(&sectionStr[12], sectionAddr, strlen(sectionAddr));

        rawPtr += 8;
        char sectionSize[8] = { ' ' };
        sprintf_s(sectionSize, "%08X", *reinterpret_cast<uintptr_t*>(rawPtr));
        memcpy(&sectionStr[32], sectionSize, strlen(sectionSize));
#endif
#endif  
        IOProcessor::Print(sectionStr.c_str());
        memset(&sectionStr[0], ' ', sectionStr.size());
      }

      // Unlock user input access
      OSInterface::SemGive(ReadLock);
    }

    IOProcessor::Print(); // Spacing

    return true;
  }

  if (REMOTE == CurrentMode)
  {
    if (nullptr == CurrentHandler)
    {
      IOProcessor::Print("- PEScan requires process attachment");
      return true;
    }

    MemScanner scanner(CurrentHandler->GetProcessHandle());
    if (false == scanner.ScanPESections())
    {
      IOProcessor::Print("- PEScan failed");
      return true;
    }

    // Begin outputting status
    char buf[128] = { 0 };

#if _WIN32 || _WIN64
#if _WIN64
    sprintf_s(buf, "Image Base: %llX", scanner.GetImageBase());
#else
    sprintf_s(buf, "Image Base: %08X", scanner.GetImageBase());
#endif
#endif
    IOProcessor::Print(buf);

    // Print PE banner and border
    std::string sectionStr(45, ' ');
    memcpy(&sectionStr[0], "Name", 4);
    memcpy(&sectionStr[12], "Address", 7);
    memcpy(&sectionStr[32], "Size", 4);
    IOProcessor::Print(sectionStr.c_str());
    memset(&sectionStr[0], '-', sectionStr.size());
    IOProcessor::Print(sectionStr.c_str());
    memset(&sectionStr[0], ' ', sectionStr.size());

    std::vector<MemScanner::SectionEntry>& sections = scanner.GetSections();
    for (size_t i = 0; i < sections.size(); ++i)
    {
      memcpy(&sectionStr[0], sections[i].Name, strlen(sections[i].Name));

#if _WIN32 || _WIN64
#if _WIN64
      char sectionAddr[16] = { ' ' };
      sprintf_s(sectionAddr, "%llX", sections[i].Address);
      memcpy(&sectionStr[12], sectionAddr, strlen(sectionAddr));

      char sectionSize[16] = { ' ' };
      sprintf_s(sectionSize, "%llX", sections[i].Size);
      memcpy(&sectionStr[32], sectionSize, strlen(sectionSize));
#else
      rawPtr += 8;
      char sectionAddr[8] = { ' ' };
      sprintf_s(sectionAddr, "%08X", sections[i].Address);
      memcpy(&sectionStr[12], sectionAddr, strlen(sectionAddr));

      rawPtr += 8;
      char sectionSize[8] = { ' ' };
      sprintf_s(sectionSize, "%08X", sections[i].Size);
      memcpy(&sectionStr[32], sectionSize, strlen(sectionSize));
#endif
#endif  
      IOProcessor::Print(sectionStr.c_str());
      memset(&sectionStr[0], ' ', 45);
    }

    IOProcessor::Print(); // Spacing
  }
  else
  {
    // Send a PEScan request to the client.
    MemScanMsg scanMsg;
    RTMAServer->SendMsg(LOCALIP,
                        CLIENT_PORT,
                        reinterpret_cast<char*>(&scanMsg),
                        scanMsg.GetLength());

    return false; // Wait for response
  }

  return true;
}

/*
/ Function: MemRegionScan
/ Notes: none
*/
bool RTMA_SVRManager::MemRegionScan(MsgHeader* message)
{
  if (nullptr != message)
  {
    if (MsgHeader::RESPONSE == message->GetSubtype())
    {
      char statusMsg[512] = { 0 };

      MemScanMsg* scanResult = reinterpret_cast<MemScanMsg*>(message);
      uint32_t regionCnt = (scanResult->GetLength() - sizeof(MsgHeader) - 8) / 32;

      uintptr_t rawPtr = reinterpret_cast<uintptr_t>(scanResult->GetDataPointer());

      // If the first 8-bytes denote -1, this is a memory region scan.
      if (MemScanMsg::REGION_SCAN == scanResult->GetScanType())
      {
        // Print Memory Region banner and border
        std::string sectionStr(100, ' ');
        memcpy(&sectionStr[0], "Address", 7);
        memcpy(&sectionStr[20], "Size", 4);
        memcpy(&sectionStr[40], "State", 5);
        memcpy(&sectionStr[60], "Protection", 10);
        IOProcessor::Print(sectionStr.c_str());
        memset(&sectionStr[0], '-', sectionStr.size());
        IOProcessor::Print(sectionStr.c_str());
        memset(&sectionStr[0], ' ', sectionStr.size());

        for (size_t i = 0; i < regionCnt; ++i)
        {
#if _WIN32 || _WIN64
#if _WIN64
          rawPtr += 8;
          char regionAddr[16] = { ' ' };
          sprintf_s(regionAddr, "%llX", *reinterpret_cast<uintptr_t*>(rawPtr));
          memcpy(&sectionStr[0], regionAddr, strlen(regionAddr));

          rawPtr += 8;
          char regionSize[16] = { ' ' };
          sprintf_s(regionSize, "%llX", *reinterpret_cast<uintptr_t*>(rawPtr));
          memcpy(&sectionStr[20], regionSize, strlen(regionSize));
#else
          rawPtr += 8;
          char sectionAddr[8] = { ' ' };
          sprintf_s(sectionAddr, "%08X", *reinterpret_cast<uintptr_t*>(rawPtr));
          memcpy(&sectionStr[12], sectionAddr, strlen(sectionAddr));

          rawPtr += 8;
          char sectionSize[8] = { ' ' };
          sprintf_s(sectionSize, "%08X", *reinterpret_cast<uintptr_t*>(rawPtr));
          memcpy(&sectionStr[32], sectionSize, strlen(sectionSize));
#endif
#endif  

          rawPtr += 8;
          uintptr_t uState = *reinterpret_cast<uintptr_t*>(rawPtr);

          rawPtr += 8;
          uintptr_t uProtection = *reinterpret_cast<uintptr_t*>(rawPtr);

          std::string state;
          std::string protection;
          MemScanner::MemRegionEntry region{ 0, 0,
                                            static_cast<uint32_t>(uState),
                                            static_cast<uint32_t>(uProtection) };
          MemScanner::TranslateMemAttr(&region, state, protection);

          memcpy(&sectionStr[40], state.c_str(), state.length());
          memcpy(&sectionStr[60], protection.c_str(), protection.length());
          IOProcessor::Print(sectionStr.c_str());
          memset(&sectionStr[0], ' ', sectionStr.size());
        }

        IOProcessor::Print(); // Spacing
      }
      else if ((MemScanMsg::FIRST_SCAN == scanResult->GetScanType()) ||
               (MemScanMsg::NEXT_SCAN == scanResult->GetScanType()))
      {
        uintptr_t rawPtr = reinterpret_cast<uintptr_t>
                           (scanResult->GetDataPointer()) + 8;

        RemoteScanCount = *reinterpret_cast<uint32_t*>(rawPtr);

        char status[64] = { 0 };
        sprintf_s(status, "Scanner found %d results", RemoteScanCount);
        IOProcessor::Print(status);

        // Unlock user input access
        OSInterface::SemGive(ReadLock);
      }
    }

    return true;
  }

  if (REMOTE == CurrentMode)
  {
    if (nullptr == CurrentHandler)
    {
      IOProcessor::Print("- Memory Scan requires process attachment");
      return true;
    }

    MemScanner scanner(CurrentHandler->GetProcessHandle());
    if (false == scanner.ScanMemRegions())
    {
      IOProcessor::Print("- Memory Scan failed");
      return true;
    }

    // Begin outputting status
    char buf[128] = { 0 };

    // Print Memory Region banner and border
    std::string sectionStr(100, ' ');
    memcpy(&sectionStr[0], "Address", 7);
    memcpy(&sectionStr[20], "Size", 4);
    memcpy(&sectionStr[40], "State", 5);
    memcpy(&sectionStr[60], "Protection", 10);
    IOProcessor::Print(sectionStr.c_str());
    memset(&sectionStr[0], '-', sectionStr.size());
    IOProcessor::Print(sectionStr.c_str());
    memset(&sectionStr[0], ' ', sectionStr.size());

    std::vector<MemScanner::MemRegionEntry>& regions = scanner.GetMemRegions();
    for (size_t i = 0; i < regions.size(); ++i)
    {
      std::string state;
      std::string protection;
      scanner.TranslateMemAttr(&regions[i], state, protection);

#if _WIN32 || _WIN64
#if _WIN64
      char sectionAddr[16] = { ' ' };
      sprintf_s(sectionAddr, "%llX", regions[i].Address);
      memcpy(&sectionStr[0], sectionAddr, strlen(sectionAddr));

      char sectionSize[16] = { ' ' };
      sprintf_s(sectionSize, "%llX", regions[i].Size);
      memcpy(&sectionStr[20], sectionSize, strlen(sectionSize));
#else
      rawPtr += 8;
      char sectionAddr[8] = { ' ' };
      sprintf_s(sectionAddr, "%08X", sections[i].Address);
      memcpy(&sectionStr[0], sectionAddr, strlen(sectionAddr));

      rawPtr += 8;
      char sectionSize[8] = { ' ' };
      sprintf_s(sectionSize, "%08X", sections[i].Size);
      memcpy(&sectionStr[20], sectionSize, strlen(sectionSize));
#endif
#endif  

      memcpy(&sectionStr[40], state.c_str(), state.length());
      memcpy(&sectionStr[60], protection.c_str(), protection.length());
      IOProcessor::Print(sectionStr.c_str());
      memset(&sectionStr[0], ' ', sectionStr.size());
    }

    IOProcessor::Print(); // Spacing
  }
  else
  {
    // Send a MemScan request to the client.
    MemScanMsg scanMsg(nullptr, 0);
    scanMsg.SetScanType(MemScanMsg::REGION_SCAN);
    RTMAServer->SendMsg(LOCALIP,
                        CLIENT_PORT,
                        reinterpret_cast<char*>(&scanMsg),
                        scanMsg.GetLength());

    return false; // Wait for response
  }

  return true;
}


/*
/ Function: ProcessDMA
/ Notes: none
*/
void RTMA_SVRManager::ProcessDMA(MsgHeader* message)
{
  if (MsgHeader::RESPONSE == message->GetSubtype())
  {
    DMAMsg* dmaResponse = reinterpret_cast<DMAMsg*>(message);

    char status[256] = { 0 };
#if _WIN32 || _WIN64
#if _WIN64
    sprintf_s(status,
              "%llX -> ",
              reinterpret_cast<uintptr_t>(dmaResponse->GetAddress()));
#else
    sprintf_s(status,
              "%08X -> ",
              reinterpret_cast<uintptr_t>(dmaResponse->GetAddress()));
#endif
#endif

    size_t size = dmaResponse->GetSize();
    switch (size)
    {
    case 8:
      sprintf_s(status,
                "%s%lld (%llX)",
                status,
                *reinterpret_cast<uintptr_t*>(dmaResponse->GetValuePtr()),
                *reinterpret_cast<uintptr_t*>(dmaResponse->GetValuePtr()));
      break;
    case 4:
      sprintf_s(status,
                "%s%d (%08X)",
                status,
                *reinterpret_cast<uint32_t*>(dmaResponse->GetValuePtr()),
                *reinterpret_cast<uint32_t*>(dmaResponse->GetValuePtr()));
      break;
    case 2:
      sprintf_s(status,
                "%s%d (%04X)",
                status,
                *reinterpret_cast<uint16_t*>(dmaResponse->GetValuePtr()),
                *reinterpret_cast<uint16_t*>(dmaResponse->GetValuePtr()));
      break;
    case 1:
      sprintf_s(status,
                "%s%d (%02X)",
                status,
                *reinterpret_cast<uint8_t*>(dmaResponse->GetValuePtr()),
                *reinterpret_cast<uint8_t*>(dmaResponse->GetValuePtr()));
      break;
    default:
      sprintf_s(status, "%s'%s' ", status, reinterpret_cast<char*>(dmaResponse->GetValuePtr()));
      for (size_t i = 0; i < size; ++i)
      {
        sprintf_s(status,
                  "%s%02X ",
                  status,
                  reinterpret_cast<uint8_t*>(dmaResponse->GetValuePtr())[i]);
      }
    }

    IOProcessor::Print(status);

    // Unlock user input access 
    --DisplayScanCount; 
    if (0 == DisplayScanCount)
    {
      OSInterface::SemGive(ReadLock);
    }
  }
}

/*
/ Function: DisplayScanResults
/ Notes: none
*/
bool RTMA_SVRManager::DisplayScanResults()
{
  if (REMOTE == CurrentMode)
  {
    if (nullptr == CurrentHandler)
    {
      IOProcessor::Print("- Memory Scan requires process attachment");
      return true;
    }

    if (nullptr == ScanInstance)
    {
      IOProcessor::Print("- You must first perform a scan");
      return true;
    }

    std::vector<uintptr_t> results;
    ScanInstance->GetScanResults(results);

    char status[64] = {0};
    sprintf_s(status, "Displaying %d results", static_cast<uint32_t>(results.size()));
    for (size_t i = 0; i < results.size(); ++i)
    {
      Read(results[i], ScanInstance->GetValueSize());
    }
  }
  else
  {
    if (0 == RemoteScanCount)
    {
      IOProcessor::Print("- There are not recent scan results");
      return true;
    }

    char status[64] = { 0 };
    sprintf_s(status, "Displaying %d results", RemoteScanCount);
    DisplayScanCount = RemoteScanCount;
    IOProcessor::Print(status);

    // Send a DisplayScan message
    MsgHeader queryMsg(MsgHeader::DISPLAYSCAN, MsgHeader::QUERY, sizeof(MsgHeader));
    RTMAServer->SendMsg(LOCALIP,
                        CLIENT_PORT,
                        reinterpret_cast<char*>(&queryMsg),
                        queryMsg.GetLength());

    return false; // Wait for response(s)
  }

  return true; // Never reached..
}

/*
/ Function: Scan
/ Notes: none
*/
bool RTMA_SVRManager::Scan(char* value, size_t size)
{
  if (REMOTE == CurrentMode)
  {
    if (nullptr == CurrentHandler)
    {
      IOProcessor::Print("- Memory Scan requires process attachment");
      return true;
    }

    if (nullptr != ScanInstance)
    {
      delete ScanInstance;
    }

    ScanInstance = new MemScanner(CurrentHandler->GetProcessHandle());

    IOProcessor::Print("Performing scan");
    RemoteScanCount = static_cast<uint32_t>(ScanInstance->PerformNewScan(value, size));

    char status[64] = { 0 };
    sprintf_s(status, "Found %d results", RemoteScanCount);
    IOProcessor::Print(status);
  }
  else
  {
    // Send a MemScan request to the client.
    MemScanMsg scanMsg(reinterpret_cast<void*>(value), size);
    scanMsg.SetScanType(MemScanMsg::FIRST_SCAN);
    RTMAServer->SendMsg(LOCALIP,
                        CLIENT_PORT,
                        reinterpret_cast<char*>(&scanMsg),
                        scanMsg.GetLength());

    return false; // Wait for response
  }

  return true;
}

/*
/ Function: NextScan
/ Notes: none
*/
bool RTMA_SVRManager::NextScan(char* value, size_t size)
{
  if (REMOTE == CurrentMode)
  {
    if (nullptr == CurrentHandler)
    {
      IOProcessor::Print("- Memory Scan requires process attachment");
      return true;
    }

    if (nullptr == ScanInstance)
    {
      IOProcessor::Print("- Initial scan must first be performed");
      return true;
    }

    RemoteScanCount = static_cast<uint32_t>(ScanInstance->PerformNextScan(value, size));

    char status[64] = { 0 };
    sprintf_s(status, "Found %d results", RemoteScanCount);
    IOProcessor::Print(status);
  }
  else
  {
    // Send a MemScan request to the client.
    MemScanMsg scanMsg(reinterpret_cast<void*>(&value), 0);
    scanMsg.SetScanType(MemScanMsg::NEXT_SCAN);
    RTMAServer->SendMsg(LOCALIP,
                        CLIENT_PORT,
                        reinterpret_cast<char*>(&scanMsg),
                        scanMsg.GetLength());

    return false; // Wait for response
  }

  return true;
}

/*
/ Function: ReadInteger
/ Notes: none
*/
bool RTMA_SVRManager::Read(uintptr_t address, size_t size)
{
  if (REMOTE == CurrentMode)
  {
    if (nullptr == CurrentHandler)
    {
      IOProcessor::Print("- Memory Access requires process attachment");
      return true;
    }

    char buffer[64] = { 0 }; // Read Limit
    CodeInjection::RemoteRead(CurrentHandler->GetProcessHandle(),
                              reinterpret_cast<void*>(address),
                              buffer,
                              size);

    char status[256] = { 0 };
#if _WIN32 || _WIN64
#if _WIN64
    sprintf_s(status, "%llX -> ", address);
#else
    sprintf_s(status, "%08X -> ", address);
#endif
#endif

    switch (size)
    {
    case 8:
      sprintf_s(status, 
                "%s%llX (%I64u)", 
                status,
                *reinterpret_cast<uintptr_t*>(buffer),
                *reinterpret_cast<uintptr_t*>(buffer));
      break;
    case 4:
      sprintf_s(status,
                "%s%08X (%d)",
                status,
                *reinterpret_cast<uint32_t*>(buffer),
                *reinterpret_cast<uint32_t*>(buffer));
      break;
    case 2:
      sprintf_s(status,
                "%s%04X (%d)",
                status,
                *reinterpret_cast<uint16_t*>(buffer),
                *reinterpret_cast<uint16_t*>(buffer));
      break;
    case 1:
      sprintf_s(status,
                "%s%02X (%d)",
                status,
                *reinterpret_cast<uint8_t*>(buffer),
                *reinterpret_cast<uint8_t*>(buffer));
      break;
    default:
      sprintf_s(status, "%s'%s' ", status, buffer);
      for (size_t i = 0; i < size; ++i) 
      {
        sprintf_s(status, "%s%02X ", status, reinterpret_cast<uint8_t*>(buffer)[i]);
      }
    }

    IOProcessor::Print(status);
  }
  else
  {
    // Send a Mem Read request to the client.
    DMAMsg dmaMsg(address, size, MsgHeader::QUERY);
    RTMAServer->SendMsg(LOCALIP,
                        CLIENT_PORT,
                        reinterpret_cast<char*>(&dmaMsg),
                        dmaMsg.GetLength());

    return false; // Wait for response
  }

  return true;
}

/*
/ Function: Write
/ Notes: none
*/
bool RTMA_SVRManager::Write(uintptr_t address, char* value, size_t size)
{
  if (REMOTE == CurrentMode)
  {
    if (nullptr == CurrentHandler)
    {
      IOProcessor::Print("- Memory Access requires process attachment");
      return true;
    }

    if (0 != address)
    {
      CodeInjection::RemoteWrite(CurrentHandler->GetProcessHandle(),
                                 reinterpret_cast<void*>(address),
                                 value,
                                 size);
      Read(address, size);
    }
    else
    {
      if (nullptr == ScanInstance)
      {
        IOProcessor::Print("- Write to scan results requires existing scan");
        return true;
      }

      // NULL address denotes all scan results..
      std::vector<uintptr_t> scanAddresses;
      ScanInstance->GetScanResults(scanAddresses);
      for (size_t i = 0; i < scanAddresses.size(); ++i)
      {
        CodeInjection::RemoteWrite(CurrentHandler->GetProcessHandle(),
                                   reinterpret_cast<void*>(scanAddresses[i]),
                                   value,
                                   size);
        Read(scanAddresses[i], size);
      }
    }
  }
  else
  {
    if (0 == RemoteScanCount)
    {
      IOProcessor::Print("- There are no remote scan results");
      return true;
    }

    // Send a Mem Read request to the client.
    DMAMsg dmaMsg(address, value, size, MsgHeader::QUERY);
    RTMAServer->SendMsg(LOCALIP,
                        CLIENT_PORT,
                        reinterpret_cast<char*>(&dmaMsg),
                        dmaMsg.GetLength());

    return false;
  }

  return true;
}

/*
/ Function: RTMA_SVRManager
/ Notes: none
*/
RTMA_SVRManager::RTMA_SVRManager() :
  RTMAManager(),
  Procs(nullptr),
  RemoteScanCount(0),
  DisplayScanCount(0)
{
  Procs = new ProcessHandler[MAX_HANDLES];
}

/*
/ Function: ~RTMA_SVRManager
/ Notes: none
*/
RTMA_SVRManager::~RTMA_SVRManager()
{
  delete[] Procs;
}