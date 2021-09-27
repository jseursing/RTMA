#pragma once
#include "MsgHeader.h"

/*
/ This class represents a message which requests
/ and provides information on a process's Portable
/ Executable structure. A response for this type of
/ message should exercise the ::Create() and ::Destroy()
/ functions.
*/
class MemScanMsg : public MsgHeader
{
public:
  enum ScanTypeEnum
  {
    FIRST_SCAN  = 0,
    NEXT_SCAN   = 1,
    REGION_SCAN = -1
  };

  static MemScanMsg* CreatePEScanResponse(uint32_t sectionCnt);
  static MemScanMsg* CreateMemScanResponse(uint32_t regionCnt);
  static MemScanMsg* CreateMemScanResultsResponse(uint32_t results);
  static void Destroy(MemScanMsg*& scanMsg);
  void SetScanType(ScanTypeEnum type);
  ScanTypeEnum GetScanType() const;
  char* GetDataPointer();
  MemScanMsg(void* value, size_t len);
  MemScanMsg();
  ~MemScanMsg();

private:

  MemScanMsg(TypeEnum type, uint32_t length);

  // This isn't the actual length of the data. The response
  // version of this message should allocate enough memory
  // to cover all sections.
  union
  {
    ScanTypeEnum ScanType;
    char RawData[64 + 8];
  };
};