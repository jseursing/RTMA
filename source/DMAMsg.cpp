#include "DMAMsg.h"
#include <cstring>


/*
/  Function: GetDMAType
/  Notes: None
*/
DMAMsg::DMATypeEnum DMAMsg::GetDMAType() const
{
  return DMAType;
}

/*
/  Function: GetAddress
/  Notes: None
*/
void* DMAMsg::GetAddress() const
{
  return Address;
}

/*
/  Function: GetValuePtr
/  Notes: None
*/
void* DMAMsg::GetValuePtr() const
{
  return reinterpret_cast<void*>(const_cast<char*>(Value));
}

/*
/  Function: GetSize
/  Notes: None
*/
size_t DMAMsg::GetSize() const
{
  return Length;
}


/*
/  Function: DMAMsg
/  Notes: None
*/
DMAMsg::DMAMsg(uintptr_t address, size_t len, SubtypeEnum subtype) :
  MsgHeader(MsgHeader::DMA, subtype, sizeof(DMAMsg))
{
  DMAType = READ;
  Address = reinterpret_cast<void*>(address);
  memset(Value, 0, sizeof(Value));
  Length = len;
}

/*
/  Function: DMAMsg
/  Notes: None
*/
DMAMsg::DMAMsg(uintptr_t address, char* value, size_t len, SubtypeEnum subtype) :
  MsgHeader(MsgHeader::DMA, subtype, sizeof(DMAMsg))
{
  DMAType = WRITE;
  Address = reinterpret_cast<void*>(address);
  memcpy(Value, value, len);
  Length = len;
}

/*
/  Function: ~DMAMsg
/  Notes: None
*/
DMAMsg::~DMAMsg()
{

}