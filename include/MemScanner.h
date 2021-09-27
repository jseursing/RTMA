#pragma once
#include <string>
#include <vector>
#include <Windows.h>
#include <winternl.h>


// Define NT API here to be used
typedef NTSTATUS(NTAPI* defNtQueryInformationProcess)(HANDLE ProcHandle,
                                                      PROCESSINFOCLASS ProcInfoClass,
                                                      PVOID ProcInfo,
                                                      ULONG ProcInfoLen,
                                                      PULONG returnLen OPTIONAL);
static defNtQueryInformationProcess _NtQueryInformationProcess;

/*
/ This class is responsible for retrieving process memory regions
/ and memory scans.
*/
class MemScanner
{
public:

  struct SectionEntry
  {
    char Name[8];
    uintptr_t Address;
    uintptr_t Size;
  };

  struct MemRegionEntry
  {
    uintptr_t Address;
    uintptr_t Size;
    uint32_t State;
    uint32_t Protection;
  };
  
  std::vector<SectionEntry>& GetSections();
  bool ScanPESections();
  std::vector<MemRegionEntry>& GetMemRegions();
  bool ScanMemRegions();
  static void TranslateMemAttr(MemRegionEntry* entry, 
                               std::string& state, 
                               std::string& protection);

  uintptr_t PerformNewScan(void* buf, size_t size);
  uintptr_t PerformNextScan(void* buf, size_t size);
  void GetScanResults(std::vector<uintptr_t>& results);
  uint32_t GetScanResultCount() const;
  uintptr_t GetImageBase() const;
  uint32_t GetValueSize() const;
  MemScanner(void* pHandle = nullptr);
  ~MemScanner();

private:
  
  struct ScanParams
  {
    MemScanner* ScanInstance;
    size_t VectorIndex;
    bool* CompletionFlag;
  };
  static void ScanService(void* scanParams);

  void* ProcessHandle;
  void* ImageBase;
  char ScanValue[64]; // Max Size for searches..
  uint32_t ValueSize;


  std::vector<SectionEntry> Sections;
  std::vector<MemRegionEntry> MemRegions;
  std::vector<std::vector<uintptr_t>> ScanResults;
};