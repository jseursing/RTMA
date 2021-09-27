#include "MemScanMsg.h"
#include <cstring>
#include <new>


/*
/  Function: CreatePEScanResponse
/  Notes: None
*/
MemScanMsg* MemScanMsg::CreatePEScanResponse(uint32_t sectionCnt)
{
  uint32_t len = sizeof(MsgHeader) + 8 + (sectionCnt * 24); // name, addr, size

  MemScanMsg* scanMsg = new (malloc(len)) MemScanMsg(PESCAN, len);
  memset(scanMsg->RawData, 0, len - sizeof(MsgHeader));

  return scanMsg;
}

/*
/  Function: CreateMemScanResponse
/  Notes: None
*/
MemScanMsg* MemScanMsg::CreateMemScanResponse(uint32_t regionCnt)
{
  uint32_t len = sizeof(MsgHeader) + 8 + (32 * regionCnt); // addr, size, state, protect

  MemScanMsg* scanMsg = new (malloc(len)) MemScanMsg(MEMSCAN, len);
  memset(scanMsg->RawData, 0, len - sizeof(MsgHeader));

  return scanMsg;
}

/*
/  Function: CreateMemScanResponse
/  Notes: None
*/
MemScanMsg* MemScanMsg::CreateMemScanResultsResponse(uint32_t results)
{
  uint32_t len = sizeof(MsgHeader) + 16;

  MemScanMsg* scanMsg = new (malloc(len)) MemScanMsg(MEMSCAN, len);
  memset(scanMsg->RawData, 0, len - sizeof(MsgHeader));
  *reinterpret_cast<uintptr_t*>(&(scanMsg->RawData[8])) = results;

  return scanMsg;
}

/*
/  Function: Destroy
/  Notes: None
*/
void MemScanMsg::Destroy(MemScanMsg*& scanMsg)
{
  scanMsg->~MemScanMsg();
  free(scanMsg);
}

/*
/  Function: SetScanType
/  Notes: None
*/
void MemScanMsg::SetScanType(ScanTypeEnum type)
{
  ScanType = type;
}

/*
/  Function: GetScanType
/  Notes: None
*/
MemScanMsg::ScanTypeEnum MemScanMsg::GetScanType() const
{
  return ScanType;
}

/*
/  Function: GetDataPointer
/  Notes: None
*/
char* MemScanMsg::GetDataPointer()
{
  return RawData;
}

/*
/  Function: MemScanMsg
/  Notes: This is a memory scan constructor.
*/
MemScanMsg::MemScanMsg(void* value, size_t len) :
  MsgHeader(MsgHeader::MEMSCAN, MsgHeader::QUERY, sizeof(MemScanMsg))
{
  *reinterpret_cast<uintptr_t*>(&RawData[8]) = len;
  memcpy(&RawData[16], value, len);
}

/*
/  Function: MemScanMsg
/  Notes: This is a pe scan constructor.
*/
MemScanMsg::MemScanMsg() :
  MsgHeader(MsgHeader::PESCAN, MsgHeader::QUERY, sizeof(MemScanMsg) - 1)
{
  
}

/*
/  Function:~MemScanMsg
/  Notes: None
*/
MemScanMsg::~MemScanMsg()
{

}

/*
/  Function: MemScanMsg
/  Notes: None
*/
MemScanMsg::MemScanMsg(TypeEnum type, uint32_t length) :
  MsgHeader(type, MsgHeader::RESPONSE, length)
{
}
