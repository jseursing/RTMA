#pragma once
#include <mutex>
#include <stdint.h>
#include <string>

// Forward declarations
class MemScanner;
class MsgHeader;
class ProcessHandler;
class UDPSocket;

/*
/ This class encompasses all process/thread handling.
*/
class RTMAManager
{
public:
  static RTMAManager* Instance();

  virtual bool PEScan(MsgHeader* message = nullptr) = 0;
  virtual bool MemRegionScan(MsgHeader* message = nullptr) = 0;
  virtual void ProcessDMA(MsgHeader* message) = 0;

protected:

  RTMAManager();
  ~RTMAManager();

  static const uint32_t MAX_HANDLES = 10; // Arbitrary number
  static const uint32_t SERVER_PORT = 69;
  static const uint32_t CLIENT_PORT = 70;
  static char LOCALIP[];

  static RTMAManager* ThisInstance;
  ProcessHandler* CurrentHandler;
  MemScanner* ScanInstance;
  UDPSocket* RTMAServer;
  UDPSocket* RTMAClient;
  void* ReadLock;

  // Flag indicating DMA mode
  enum Mode
  {
    REMOTE,
    DMA
  };

  Mode CurrentMode;
};