#pragma once
#include "MsgHeader.h"

/*
/ This class provides a message interface to read/write memory.
*/
class DMAMsg : public MsgHeader
{
public:
  enum DMATypeEnum
  {
    READ,
    WRITE
  };

  void SetAsResponse();
  DMATypeEnum GetDMAType() const;
  void* GetAddress() const;
  void* GetValuePtr() const;
  size_t GetSize() const;
  DMAMsg(uintptr_t address, size_t len, SubtypeEnum subtype);
  DMAMsg(uintptr_t address, char* value, size_t len, SubtypeEnum subtype);
  ~DMAMsg();

private:
  
  DMATypeEnum DMAType;
  void* Address;
  bool LockValue;
  char Value[64];
  size_t Length;
};