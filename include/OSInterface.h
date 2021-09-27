#pragma once
#include "StatusTypes.h"
#include <stdint.h>

/*
* This class provides an interface to operating system 
* specific functions.
*/
class OSInterface
{
public:
  ////////////////////////////////////////////////////////////////////////
  //
  // Process Functions
  //
  static void* ProcessSpawn(char* cmdLine, 
                            bool suspend,
                            void*& pHandle, 
                            void*& tHandle);

  ////////////////////////////////////////////////////////////////////////
  //
  // Task Functions
  //
  static void* TaskCreate(void* entrypoint, 
                          void* param, 
                          uint32_t stackSize, 
                          unsigned long& threadId,
                          int32_t priority);
  static void ActivateTask(void* pTask);
  static void SuspendTask(void* pTask);
  static void TaskKill(void* pTask);
  static unsigned long GetTaskId();

  ////////////////////////////////////////////////////////////////////////
  //
  // Socket Functions
  //  
  static uintptr_t UDPCreate(StatusTypes::StatusEnum& status, 
                             uint16_t port = 0,
                             bool bindPort = false);
  static void UDPClose(uintptr_t sock);
  static StatusTypes::StatusEnum UDPSend(uintptr_t sock,
                                         char* addr, 
                                         uint16_t port, 
                                         char* buf, 
                                         uint32_t len);
  static StatusTypes::StatusEnum UDPRecv(uintptr_t sock,
                                         char* buf,
                                         uint32_t maxLen,
                                         uint32_t timeoutMs,
                                         char* addr = nullptr,
                                         uint32_t addrMaxLen = 0,
                                         uint16_t* port = nullptr);

  ////////////////////////////////////////////////////////////////////////
  //
  // Synchronization Functions
  //
  static void* SemCreate(const char* name, int32_t iVal, int32_t mVal);
  static void* GetSem(const char* name);
  static StatusTypes::StatusEnum SemTake(void* sem, uint32_t timeout);
  static StatusTypes::StatusEnum SemGive(void* sem);

  static const void* INVALID_TASK;
};