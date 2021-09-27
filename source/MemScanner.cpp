#include "CodeInjection.h"
#include "MemScanner.h"
#include "OSInterface.h"
#include <Windows.h>

/*
/  Function: GetSections
/  Notes: None
*/
std::vector<MemScanner::SectionEntry>& MemScanner::GetSections()
{
  return Sections;
}

/*
/  Function: GetImageBase
/  Notes: None
*/
uintptr_t MemScanner::GetImageBase() const
{
  return reinterpret_cast<uintptr_t>(ImageBase);
}

/*
/  Function: GetValueSize
/  Notes: None
*/
uint32_t MemScanner::GetValueSize() const
{
  return ValueSize;
}

/*
/  Function: ScanPESections
/  Notes: None
*/
bool MemScanner::ScanPESections()
{
  if (nullptr == ImageBase)
  {
    return false;
  }

  // Read the DOS header
  SIZE_T read = 0;
  unsigned char temp_buf[1024] = { 0 };
  if (false == CodeInjection::RemoteRead(ProcessHandle, 
                                         ImageBase,
                                         temp_buf, 
                                         sizeof(IMAGE_DOS_HEADER)))
  {
    return false;
  }

  // Read the FILE header
  uintptr_t bufferSize = sizeof(IMAGE_DOS_HEADER) +
                         reinterpret_cast<IMAGE_DOS_HEADER*>(temp_buf)->e_lfanew;

  uintptr_t addr = reinterpret_cast<uintptr_t>(ImageBase) +
                   reinterpret_cast<IMAGE_DOS_HEADER*>(temp_buf)->e_lfanew;
  if (false == CodeInjection::RemoteRead(ProcessHandle, 
                                         reinterpret_cast<void*>(addr),
                                         temp_buf, 
                                         sizeof(IMAGE_NT_HEADERS)))
  {
    return false;
  }

  // Calculate the entire buffer size needed to retrieve our PE Headers,
  // then read the contents into the buffer.
  IMAGE_NT_HEADERS* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(temp_buf);
  bufferSize += sizeof(ntHeader->Signature) +
                sizeof(IMAGE_FILE_HEADER) +
                ntHeader->FileHeader.SizeOfOptionalHeader +
                (ntHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

  char* buffer = new char[bufferSize];
  if (false == CodeInjection::RemoteRead(ProcessHandle, ImageBase, buffer, bufferSize))
  {
    delete[] buffer;
    return false;
  }

  // Retrieve all PE File sections needed to retrieve .text, .*data, etc
  IMAGE_DOS_HEADER* dosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer);
  IMAGE_NT_HEADERS* ntHdrs = reinterpret_cast<IMAGE_NT_HEADERS*>
                             (reinterpret_cast<uintptr_t>(buffer) + dosHdr->e_lfanew);
  if (nullptr == ntHdrs)
  {
    delete[] buffer;
    return false;
  }

  // Validate magic and signature before proceeding.
  if ((IMAGE_DOS_SIGNATURE != dosHdr->e_magic) &&
      (IMAGE_NT_SIGNATURE != ntHdrs->Signature))
  {
    delete[] buffer;
    return false;
  }

  // Get the first section and begin populating section data.
  IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHdrs);
  
  Sections.clear();
  for (unsigned int i = 0; i < ntHdrs->FileHeader.NumberOfSections; ++i)
  {
    SectionEntry entry;
    memcpy(entry.Name, section[i].Name, 8);
    entry.Address = reinterpret_cast<uintptr_t>(ImageBase) +
                    section[i].VirtualAddress;
    entry.Size = section[i].Misc.VirtualSize;
    Sections.push_back(entry);
  }

  delete[] buffer;

  return true;
}

/*
/  Function: GetMemRegions
/  Notes: None
*/
std::vector<MemScanner::MemRegionEntry>& MemScanner::GetMemRegions()
{
  return MemRegions;
}

/*
/  Function: ScanMemRegions
/  Notes: None
*/
bool MemScanner::ScanMemRegions()
{
  MemRegions.clear();

  char* currAddress = nullptr;
  MEMORY_BASIC_INFORMATION mbi;
  while (0 != VirtualQueryEx(ProcessHandle, currAddress, &mbi, sizeof(mbi)))
  {
    // Filter out the following protections.
    unsigned long exclude_filter = PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE;
    unsigned long include_filter = PAGE_EXECUTE_WRITECOPY |
                                   PAGE_EXECUTE_READWRITE | 
                                   PAGE_READWRITE |
                                   PAGE_WRITECOPY;

    if (!(mbi.Protect & exclude_filter))
    {
      // We are only tracking MEM_COMMIT state and protection which allows READ/WRITE.
      if ((MEM_COMMIT & mbi.State) &&
          (include_filter & mbi.Protect))
      {
        MemRegionEntry memRegion;
        memRegion.Address = reinterpret_cast<uintptr_t>(currAddress);
        memRegion.Size = mbi.RegionSize;
        memRegion.State = mbi.State;
        memRegion.Protection = mbi.Protect;
        MemRegions.push_back(memRegion);
      }
    }

    currAddress += mbi.RegionSize;
  }

  return 0 != MemRegions.size();
}

/*
/  Function: TranslateMemAttr
/  Notes: None
*/
void MemScanner::TranslateMemAttr(MemRegionEntry* entry, 
                                  std::string& state, 
                                  std::string& protection)
{
  state = "";
  protection = "";

  switch (entry->State)
  {
  case MEM_COMMIT:
    state = "COMMIT";
    break;
  case MEM_FREE:
    state = "FREE";
    break;
  case MEM_RESERVE:
    state = "RESERVED";
    break;
  }

  if (MEM_COMMIT == entry->State)
  {
    switch (entry->Protection & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE))
    {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
      protection = "EXECUTE";
      break;
    case PAGE_EXECUTE_READWRITE:
      protection = "EXECUTE_READ_WRITE";
      break;
    case PAGE_EXECUTE_WRITECOPY:
      protection = "EXECUTE_COPY_ONWRITE";
      break;
    case PAGE_NOACCESS:
      protection = "NO_ACCESS";
      break;
    case PAGE_READONLY:
      protection = "READ_ONLY";
      break;
    case PAGE_READWRITE:
      protection = "READ_WRITE";
      break;
    case PAGE_WRITECOPY:
      protection = "READ_COPY_ONWRITE";
      break;
    }

    if (entry->Protection & PAGE_GUARD)
    {
      protection += " | GUARD";
    }
  }
}

/*
/  Function: PerformNewScan
/  Notes: None
*/
uintptr_t MemScanner::PerformNewScan(void* buf, size_t size)
{
  if (false == ScanMemRegions()) // Retrieve all memory regions
  {
    return 0;
  }

  // Free all existing scan results and setup for new scan
  ScanResults.clear();
  for (size_t i = 0; i < MemRegions.size(); ++i)
  {
    ScanResults.emplace_back(std::vector<uintptr_t>());
  }

  // Completion flags..
  bool* completionFlags = new bool[MemRegions.size()];
  for (size_t i = 0; i < MemRegions.size(); ++i)
  {
    completionFlags[i] = false;
  }

  // Setup target scan value and size
  ValueSize = static_cast<uint32_t>(size);
  memset(ScanValue, 0, sizeof(ScanValue));
  memcpy(ScanValue, buf, size);

  // Create a scan task for each memory region...
  for (size_t i = 0; i < MemRegions.size(); ++i)
  {
    ScanParams* params = new ScanParams();
    params->CompletionFlag = &completionFlags[i];
    params->ScanInstance = this;
    params->VectorIndex = i;

    unsigned long tid = 0;
    void* pTask = OSInterface::TaskCreate(ScanService, params, 1024 * 10, tid, 1);
    OSInterface::ActivateTask(pTask);
  }

  // Do not continue until all completion flags are set.
  uintptr_t results = 0;
  for (bool done = false; done == false;)
  {
    for (size_t i = 0; i < MemRegions.size(); ++i)
    {
      if (false == completionFlags[i])
      {
        results = 0;
        break;
      }
      else 
      {
        results += ScanResults[i].size();
        if (i == (MemRegions.size() - 1))
        {
          done = true;
        }
      }
    }
  }

  // Free completion flags
  delete[] completionFlags;

  return results;
}

/*
/  Function: PerformNextScan
/  Notes: None
*/
uintptr_t MemScanner::PerformNextScan(void* buf, size_t size)
{
  // We will not be starting new tasks for next scans...
  // (might bite me in the ass, who knows)
  ValueSize = static_cast<uint32_t>(size);
  memset(ScanValue, 0, sizeof(ScanValue));
  memcpy(ScanValue, buf, size);

  for (size_t i = 0; i < ScanResults.size(); ++i)
  {
    if (0 < ScanResults[i].size())
    {
      for (int j = static_cast<int>(ScanResults[i].size() - 1); j >= 0; --j)
      {
        char value[64] = {0};
        CodeInjection::RemoteRead(ProcessHandle,
                                  reinterpret_cast<void*>(ScanResults[i][j]), 
                                  value, 
                                  ValueSize);
        switch (ValueSize)
        {
        case 8:
          if (*reinterpret_cast<uintptr_t*>(ScanValue) != 
              *reinterpret_cast<uintptr_t*>(value))
          {
            ScanResults[i].erase(ScanResults[i].begin() + j);
          }
          break;
        case 4:
          if (*reinterpret_cast<uint32_t*>(ScanValue) !=
              *reinterpret_cast<uint32_t*>(value))
          {
            ScanResults[i].erase(ScanResults[i].begin() + j);
          }
          break;
        case 2:
          if (*reinterpret_cast<uint16_t*>(ScanValue) !=
              *reinterpret_cast<uint16_t*>(value))
          {
            ScanResults[i].erase(ScanResults[i].begin() + j);
          }
          break;
        case 1:
          if (*reinterpret_cast<uint8_t*>(ScanValue) !=
              *reinterpret_cast<uint8_t*>(value))
          {
            ScanResults[i].erase(ScanResults[i].begin() + j);
          }
          break;
        default:
          if (0 != memcmp(ScanValue, value, ValueSize))
          {
            ScanResults[i].erase(ScanResults[i].begin() + j);
          }
        }
      }
    }
  }

  uintptr_t results = 0;
  for (size_t i = 0; i < ScanResults.size(); ++i)
  {
    results += ScanResults[i].size();
  }

  return results;
}

/*
/  Function: GetScanResults
/  Notes: None
*/
void MemScanner::GetScanResults(std::vector<uintptr_t>& results)
{
  results.clear();

  for (size_t i = 0; i < ScanResults.size(); ++i)
  {
    for (size_t j = 0; j < ScanResults[i].size(); ++j)
    {
      results.push_back(ScanResults[i][j]);
    }
  }
}

/*
/  Function: GetScanResultCount
/  Notes: None
*/
uint32_t MemScanner::GetScanResultCount() const
{
  uint32_t resultCount = 0;
  for (size_t i = 0; i < ScanResults.size(); ++i)
  {
    resultCount += static_cast<uint32_t>(ScanResults[i].size());
  }

  return resultCount;
}

/*
/  Function: ScanService
/  Notes: None
*/
void MemScanner::ScanService(void* scanParams)
{
  // Retrieve all parameters
  ScanParams* params = reinterpret_cast<ScanParams*>(scanParams);
  MemScanner* instance = params->ScanInstance;
  size_t vectorIndex = params->VectorIndex;
  bool* completionFlag = params->CompletionFlag;

  // Retrieve start address and size
  uintptr_t address = instance->MemRegions[vectorIndex].Address;
  uintptr_t size = instance->MemRegions[vectorIndex].Size;

  // Read the memory into local buffer
  char* buffer = new char[size];
  if (true == CodeInjection::RemoteRead(instance->ProcessHandle,
                                        reinterpret_cast<void*>(address),
                                        buffer,
                                        size))
  {
    switch (instance->ValueSize)
    {
    case 8:
      {
        uintptr_t value = *reinterpret_cast<uintptr_t*>(instance->ScanValue);
        
        // We are assuming a 64-bit system/double-point precision search. This
        // should be word-aligned (maybe??)
        for (size_t offset = 0; offset < size; offset += instance->ValueSize)
        {
          if (value == *reinterpret_cast<uintptr_t*>(&buffer[offset]))
          {
            instance->ScanResults[vectorIndex].push_back(address + offset);
          }
        }
      }
    break;
    
    case 4:
      {
        uint32_t value = *reinterpret_cast<uint32_t*>(instance->ScanValue);

        // We assume values are word aligned..
        for (size_t offset = 0; offset < size; offset += instance->ValueSize)
        {
          if (value == *reinterpret_cast<uint32_t*>(&buffer[offset]))
          {
            instance->ScanResults[vectorIndex].push_back(address + offset);
          }
        }
      }
    break;

    case 2:
      {
        uint16_t value = *reinterpret_cast<uint16_t*>(instance->ScanValue);

        // Values can sit at relative offset 0, 1, or 2..
        for (size_t offset = 0; offset < size; ++offset)
        {
          if (3 != (offset % 4))
          {
            if (value == *reinterpret_cast<uint16_t*>(&buffer[offset]))
            {
              instance->ScanResults[vectorIndex].push_back(address + offset);
            }
          }
        }
      }
    break;
  
    case 1:
      {
        uint8_t value = *reinterpret_cast<uint8_t*>(instance->ScanValue);

        // Values can sit at relative offset 0, 1, or 2..
        for (size_t offset = 0; offset < size; ++offset)
        {
          if (value == *reinterpret_cast<uint8_t*>(&buffer[offset]))
          {
            instance->ScanResults[vectorIndex].push_back(address + offset);
          }
        }
      }
    break;  

    default:
      {
        // Values can sit at relative offset 0, 1, or 2..
        for (size_t offset = 0; offset < size; ++offset)
        {
          if (0 == memcmp(&buffer[offset], instance->ScanValue, instance->ValueSize))
          {
            instance->ScanResults[vectorIndex].push_back(address + offset);
          }
        }
      }
    }
  }

  delete[] buffer; // Free mem
  delete params; // Free parameters

  *completionFlag = true;
}

/*
/  Function: MemScanner
/  Notes: None
*/
MemScanner::MemScanner(void* pHandle) :
  ProcessHandle(nullptr == pHandle ? GetCurrentProcess() : pHandle),
  ImageBase(nullptr)
{
  // Initialize NTAPI function and retrieve Image Base address.
  if (0 == _NtQueryInformationProcess)
  {
    _NtQueryInformationProcess = 
      reinterpret_cast<defNtQueryInformationProcess>
      (GetProcAddress(GetModuleHandleA("ntdll.dll"), 
                      "NtQueryInformationProcess"));
  }

  // Retrieve external process information
  PROCESS_BASIC_INFORMATION pbi;
  NTSTATUS status = _NtQueryInformationProcess(ProcessHandle,
                                               ProcessBasicInformation,
                                               &pbi, 
                                               sizeof(pbi), 
                                               0);
  if (true == NT_SUCCESS(status))
  {
    pbi.PebBaseAddress;

    PEB peb;
    SIZE_T read = 0;
    if (false == CodeInjection::RemoteRead(ProcessHandle, 
                                           pbi.PebBaseAddress, 
                                           &peb, 
                                           sizeof(PEB)))
    {
      return;
    }

    ImageBase = peb.Reserved3[1];
  }
}

/*
/  Function: ~MemScanner
/  Notes: None
*/
MemScanner::~MemScanner()
{

}