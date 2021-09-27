#include "AckMsg.h"
#include "CodeInjection.h"
#include "DMAMsg.h"
#include "MemScanMsg.h"
#include "MemScanner.h"
#include "OSInterface.h"
#include "ProcessHandler.h"
#include "UDPSocket.h"
#include "RTMA_CLTManager.h"


/*
/ Function: TaskMain
/ Notes: None
*/
void RTMA_CLTManager::TaskMain()
{
  /*
    FILE* InHandle = nullptr;
    FILE* OutHandle = nullptr;

    // Allocate a console and redirect I/O
    AllocConsole();
    freopen_s(&InHandle, "CONIN$", "r", stdin);
    freopen_s(&OutHandle, "CONOUT$", "w", stdout);
  */

  // Launch the task
  unsigned long threadId;
  void* pTask = OSInterface::TaskCreate(MainLoop, 
                                        nullptr, 
                                        1024 * 32, 
                                        threadId, 
                                        1);
  OSInterface::ActivateTask(pTask);
}

/*
/ Function: MainLoop
/ Notes: None
*/
void RTMA_CLTManager::MainLoop()
{
  // Initialize client RTMAManager
  bool unload = false;
  RTMA_CLTManager* instance = RTMA_CLTManager::Instance();

  // Initialize I/O Sockets
  instance->RTMAServer = UDPSocket::Create();            // Send to Server
  instance->RTMAClient = UDPSocket::Create(CLIENT_PORT); // Bind client

  // Send Init response message
  MsgHeader initMsg = MsgHeader(MsgHeader::INIT,
                                MsgHeader::RESPONSE,
                                sizeof(MsgHeader));
  instance->RTMAClient->SendMsg(LOCALIP,
                                SERVER_PORT,
                                reinterpret_cast<char*>(&initMsg),
                                initMsg.GetLength());

  char buf[1024] = { 0 };
  while (false == unload)
  {
    if (StatusTypes::STATUS_OK ==
        instance->RTMAClient->RecvMsg(buf, sizeof(buf), -1))
    {
      MsgHeader* msgHeader = reinterpret_cast<MsgHeader*>(buf);
      switch (msgHeader->GetType())
      {
      case MsgHeader::RELEASE:
        {
          // Send a response..
          AckMsg ackMsg(MsgHeader::RELEASE, true);
          instance->RTMAClient->SendMsg(LOCALIP,
                                        SERVER_PORT,
                                        reinterpret_cast<char*>(&ackMsg),
                                        ackMsg.GetLength());

          unload = true; // Unload library
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

        case MsgHeader::DISPLAYSCAN:
          instance->ProcessDisplayScan();
        break;

        default:
        {
          // Send a rejection response..
          AckMsg ackMsg(msgHeader->GetType(), false);
          instance->RTMAClient->SendMsg(LOCALIP,
                                        SERVER_PORT,
                                        reinterpret_cast<char*>(&ackMsg),
                                        ackMsg.GetLength());
        }
      }
    }

    memset(buf, 0, sizeof(buf));
  }

#if _WIN64
  FreeLibrary(GetModuleHandleA("RTMALIB64.dll"));
#else
  FreeLibrary(GetModuleHandleA("RTMALIB32.dll"));
#endif
}

/*
/ Function: Instance
/ Notes: none
*/
RTMA_CLTManager* RTMA_CLTManager::Instance()
{
  static RTMA_CLTManager instance;
  if (nullptr == ThisInstance)
  {
    ThisInstance = &instance;
  }

  return &instance;
}

/*
/ Function: PEScan
/ Notes: none
*/
bool RTMA_CLTManager::PEScan(MsgHeader* message)
{
  if (MsgHeader::QUERY == message->GetSubtype())
  {
    // Acknowledge scan request
    AckMsg ackMsg(MsgHeader::PESCAN, true);
    RTMAClient->SendMsg(LOCALIP,
                        SERVER_PORT,
                        reinterpret_cast<char*>(&ackMsg),
                        ackMsg.GetLength());

    // Perform the memory scan...
    MemScanner scanner;
    scanner.ScanPESections();

    std::vector<MemScanner::SectionEntry> sections = scanner.GetSections();

    // Allocate a Scan response msg
    MemScanMsg* scanMsg = MemScanMsg::CreatePEScanResponse
                          (static_cast<uint32_t>(sections.size()));

    // The first 8-bytes encompasses the Image Base
    uintptr_t rawPtr = reinterpret_cast<uintptr_t>(scanMsg->GetDataPointer());
    *reinterpret_cast<uintptr_t*>(rawPtr) = scanner.GetImageBase();

    // Each section takes up 24-bytes, 8 for name, addr, and size (32-64-bit proof)
    for (size_t i = 0; i < sections.size(); ++i)
    {
      rawPtr += 8;
      memcpy(reinterpret_cast<void*>(rawPtr),
             sections[i].Name,
             strlen(sections[i].Name));

      rawPtr += 8;
      *reinterpret_cast<uintptr_t*>(rawPtr) = sections[i].Address;

      rawPtr += 8;
      *reinterpret_cast<uintptr_t*>(rawPtr) = sections[i].Size;
    }

    // Send the response
    RTMAClient->SendMsg(LOCALIP,
                        SERVER_PORT,
                        reinterpret_cast<char*>(scanMsg),
                        scanMsg->GetLength());
    MemScanMsg::Destroy(scanMsg);
  }

  return true;
}

/*
/ Function: MemRegionScan
/ Notes: none
*/
bool RTMA_CLTManager::MemRegionScan(MsgHeader* message)
{
  if (MsgHeader::QUERY == message->GetSubtype())
  {
    MemScanMsg* inScanMsg = reinterpret_cast<MemScanMsg*>(message);
    uintptr_t rawPtr = reinterpret_cast<uintptr_t>(inScanMsg->GetDataPointer());

    switch (inScanMsg->GetScanType())
    {
      case MemScanMsg::REGION_SCAN:
      {
        // Acknowledge scan request
        AckMsg ackMsg(MsgHeader::MEMSCAN, true);
        RTMAClient->SendMsg(LOCALIP,
                            SERVER_PORT,
                            reinterpret_cast<char*>(&ackMsg),
                            ackMsg.GetLength());

        // Perform the memory scan...
        MemScanner scanner;
        scanner.ScanMemRegions();

        std::vector<MemScanner::MemRegionEntry>& regions = scanner.GetMemRegions();

        // Allocate a Scan response msg
        MemScanMsg* scanMsg = MemScanMsg::CreateMemScanResponse
                              (static_cast<uint32_t>(regions.size()));
        scanMsg->SetScanType(MemScanMsg::REGION_SCAN);

        // The first 8-bytes encompasses the Image Base
        uintptr_t rawPtr = reinterpret_cast<uintptr_t>(scanMsg->GetDataPointer());

        // Each region takes up 32-bytes, 8 for address, size, state, and protection
        for (size_t i = 0; i < regions.size(); ++i)
        {
          rawPtr += 8;
          *reinterpret_cast<uintptr_t*>(rawPtr) = regions[i].Address;
          rawPtr += 8;
          *reinterpret_cast<uintptr_t*>(rawPtr) = regions[i].Size;
          rawPtr += 8;
          *reinterpret_cast<uintptr_t*>(rawPtr) = regions[i].State;
          rawPtr += 8;
          *reinterpret_cast<uintptr_t*>(rawPtr) = regions[i].Protection;
        }

        // Send the response
        RTMAClient->SendMsg(LOCALIP,
                            SERVER_PORT,
                            reinterpret_cast<char*>(scanMsg),
                            scanMsg->GetLength());
        MemScanMsg::Destroy(scanMsg);
      }
      break;

      case MemScanMsg::FIRST_SCAN:
      {
        // Acknowledge scan request
        AckMsg ackMsg(MsgHeader::MEMSCAN, true);
        RTMAClient->SendMsg(LOCALIP,
                            SERVER_PORT,
                            reinterpret_cast<char*>(&ackMsg),
                            ackMsg.GetLength());

        if (nullptr != ScanInstance)
        {
          delete ScanInstance;
        }

        ScanInstance = new MemScanner();

        uintptr_t rawPtr = reinterpret_cast<uintptr_t>(inScanMsg->GetDataPointer());
        uintptr_t size = *reinterpret_cast<uintptr_t*>(rawPtr + 8);

        char value[64] = {0};
        memcpy(value, reinterpret_cast<void*>(rawPtr + 16), size);

        uintptr_t resultsCnt = ScanInstance->PerformNewScan(value, size);

        MemScanMsg* scanMsg = MemScanMsg::CreateMemScanResultsResponse
                              (static_cast<uint32_t>(resultsCnt));
        scanMsg->SetScanType(MemScanMsg::FIRST_SCAN);
        RTMAClient->SendMsg(LOCALIP,
                            SERVER_PORT,
                            reinterpret_cast<char*>(scanMsg),
                            scanMsg->GetLength());
        MemScanMsg::Destroy(scanMsg);
        
      }
      break;

      case MemScanMsg::NEXT_SCAN:
      {
        MemScanMsg* scanMsg = nullptr;
        if (nullptr == ScanInstance)
        {
          AckMsg ackMsg(MsgHeader::MEMSCAN, false);
          RTMAClient->SendMsg(LOCALIP,
                              SERVER_PORT,
                              reinterpret_cast<char*>(&ackMsg),
                              ackMsg.GetLength());
          break;
        }

        // Acknowledge scan request
        AckMsg ackMsg(MsgHeader::MEMSCAN, true);
        RTMAClient->SendMsg(LOCALIP,
                            SERVER_PORT,
                            reinterpret_cast<char*>(&ackMsg),
                            ackMsg.GetLength());

        uintptr_t rawPtr = reinterpret_cast<uintptr_t>(inScanMsg->GetDataPointer());
        uintptr_t size = *reinterpret_cast<uintptr_t*>(rawPtr + 8);

        char value[64] = { 0 };
        memcpy(value, reinterpret_cast<void*>(rawPtr + 16), size);

        uintptr_t resultsCnt = ScanInstance->PerformNextScan(value, size);

        // Allocate a Scan response msg
        scanMsg = MemScanMsg::CreateMemScanResultsResponse
                  (static_cast<uint32_t>(resultsCnt));
        scanMsg->SetScanType(MemScanMsg::NEXT_SCAN);
        RTMAClient->SendMsg(LOCALIP,
                            SERVER_PORT,
                            reinterpret_cast<char*>(scanMsg),
                            scanMsg->GetLength());
        MemScanMsg::Destroy(scanMsg);
      }
      break;
    }
  }

  return true;
}

/*
/ Function: ProcessDMA
/ Notes: none
*/
void RTMA_CLTManager::ProcessDMA(MsgHeader* message)
{
  DMAMsg* dmaMsg = reinterpret_cast<DMAMsg*>(message);
  if (MsgHeader::QUERY == dmaMsg->GetSubtype())
  {
    switch (dmaMsg->GetDMAType())
    {
      case DMAMsg::READ:
      {
        // Read Memory
        char readBuf[64] = { 0 };
        CodeInjection::DMARead(dmaMsg->GetAddress(), readBuf, dmaMsg->GetSize());

        // Send DMA response
        DMAMsg dmaResponse(reinterpret_cast<uintptr_t>(dmaMsg->GetAddress()),
                           readBuf,
                           dmaMsg->GetSize(),
                           MsgHeader::RESPONSE);

        RTMAClient->SendMsg(LOCALIP,
                            SERVER_PORT,
                            reinterpret_cast<char*>(&dmaResponse),
                            dmaResponse.GetLength());
      }
      break;

      case DMAMsg::WRITE:
      {
        uintptr_t address = reinterpret_cast<uintptr_t>(dmaMsg->GetAddress());
        if (0 != address)
        {
          // Write Memory
          CodeInjection::DMAWrite(dmaMsg->GetAddress(),
                                  dmaMsg->GetValuePtr(),
                                  dmaMsg->GetSize());

          // Read Memory
          char readBuf[64] = { 0 };
          CodeInjection::DMARead(dmaMsg->GetAddress(), readBuf, dmaMsg->GetSize());

          // Send DMA response
          DMAMsg dmaResponse(reinterpret_cast<uintptr_t>(dmaMsg->GetAddress()),
                              readBuf,
                              dmaMsg->GetSize(),
                              MsgHeader::RESPONSE);

          RTMAClient->SendMsg(LOCALIP,
                              SERVER_PORT,
                              reinterpret_cast<char*>(&dmaResponse),
                              dmaResponse.GetLength());
        }
        else
        {
          // NULL address denotes write to scan results
          std::vector<uintptr_t> scanAddresses;
          ScanInstance->GetScanResults(scanAddresses);
          for (size_t i = 0; i < scanAddresses.size(); ++i)
          {
            // Write Memory
            CodeInjection::DMAWrite(reinterpret_cast<void*>(scanAddresses[i]),
                                    dmaMsg->GetValuePtr(),
                                    dmaMsg->GetSize());

            // Read Memory
            char readBuf[64] = { 0 };
            CodeInjection::DMARead(reinterpret_cast<void*>(scanAddresses[i]), 
                                   readBuf, 
                                   dmaMsg->GetSize());

            // Send DMA response
            DMAMsg dmaResponse(reinterpret_cast<uintptr_t>(dmaMsg->GetAddress()),
                               readBuf,
                               dmaMsg->GetSize(),
                               MsgHeader::RESPONSE);

            RTMAClient->SendMsg(LOCALIP,
                                SERVER_PORT,
                                reinterpret_cast<char*>(&dmaResponse),
                                dmaResponse.GetLength());
          }
        }
      }
      break;
    }
  }
}

/*
/ Function: ProcessDisplayScan
/ Notes: none
*/
void RTMA_CLTManager::ProcessDisplayScan()
{
  // Do not check for scan results. The Server shouldn't
  // have allowed this request to arrive if there weren't any.

  std::vector<uintptr_t> results;
  ScanInstance->GetScanResults(results);

  // Read Memory
  for (size_t i = 0; i < results.size(); ++i)
  {
    char readBuf[64] = { 0 };
    CodeInjection::DMARead(reinterpret_cast<void*>(results[i]), 
                           readBuf, 
                           ScanInstance->GetValueSize());

    // Send DMA response
    DMAMsg dmaResponse(results[i], 
                       readBuf,
                       ScanInstance->GetValueSize(),
                       MsgHeader::RESPONSE);

    RTMAClient->SendMsg(LOCALIP,
                        SERVER_PORT,
                        reinterpret_cast<char*>(&dmaResponse),
                        dmaResponse.GetLength());
  }
}

/*
/ Function: RTMA_CLTManager
/ Notes: none
*/
RTMA_CLTManager::RTMA_CLTManager() :
  RTMAManager()
{
}

/*
/ Function: ~RTMA_CLTManager
/ Notes: none
*/
RTMA_CLTManager::~RTMA_CLTManager()
{
}