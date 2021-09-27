#include "AckMsg.h"
#include "CodeInjection.h"
#include "DMAMsg.h"
#include "IOProcessor.h"
#include "MemScanMsg.h"
#include "MemScanner.h"
#include "OSInterface.h"
#include "ProcessHandler.h"
#include "RTMAManager.h"
#include "UDPSocket.h"
#include <new>
#include <string>
#include <Windows.h>


// Static definition
RTMAManager* RTMAManager::ThisInstance = nullptr;
char RTMAManager::LOCALIP[] = {"127.0.0.1"};

/*
/ Function: Instance
/ Notes: none
*/
RTMAManager* RTMAManager::Instance()
{
  return ThisInstance;
}

/*
/ Function: RTMAManager
/ Notes: none
*/
RTMAManager::RTMAManager() :
  CurrentHandler(nullptr),
  RTMAServer(nullptr),
  RTMAClient(nullptr),
  ScanInstance(nullptr),
  CurrentMode(REMOTE)
{
}

/*
/ Function: ~RTMAManager
/ Notes: none
*/
RTMAManager::~RTMAManager()
{
}