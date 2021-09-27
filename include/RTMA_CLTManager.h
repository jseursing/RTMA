#pragma once
#include "RTMAManager.h"

/*
/ This instance of RTMA Manager is to be used by the server.
*/
class RTMA_CLTManager : public RTMAManager
{
public:
  static RTMA_CLTManager* Instance();
  static void TaskMain();
  static void MainLoop();

  virtual bool PEScan(MsgHeader* message);
  virtual bool MemRegionScan(MsgHeader* message);
  virtual void ProcessDMA(MsgHeader* message);
  void ProcessDisplayScan();

private:

  RTMA_CLTManager();
  ~RTMA_CLTManager();
};