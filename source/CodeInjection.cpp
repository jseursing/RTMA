#include "CodeInjection.h"
#include <stdint.h>
#include <Windows.h>
#include <TlHelp32.h> // Must come after windows.


/*
/ Function: InjectThisExe
/ Notes: None
*/
bool CodeInjection::InjectThisExe(void* pHandle, void* entrypoint)
{
  // Retrieve this image base and size
  void* selfBaseAddr = GetModuleHandle(nullptr);
  IMAGE_DOS_HEADER* dosHdr = 
    reinterpret_cast<IMAGE_DOS_HEADER*>(selfBaseAddr);
  IMAGE_NT_HEADERS* ntHdrs = 
    reinterpret_cast<IMAGE_NT_HEADERS*>
    (reinterpret_cast<uintptr_t>(selfBaseAddr) + dosHdr->e_lfanew);
  uintptr_t selfSize = ntHdrs->OptionalHeader.SizeOfImage;

  // Copy this image's code into a buffer. No error-checking here
  // because we expect heap allocation to succeed.
  char* imageBuf = new char[selfSize];
  memcpy(imageBuf, selfBaseAddr, selfSize);

  // Allocate space in the target process for this image
  void* targetBaseAddr = nullptr;
  if (false == RemoteAlloc(pHandle, true, selfSize, targetBaseAddr))
  {
    delete[] imageBuf;
    return false;
  }

    // Calculate written <-> base image offset
  uintptr_t imageOffset = reinterpret_cast<uintptr_t>(targetBaseAddr) -
                          reinterpret_cast<uintptr_t>(selfBaseAddr);

  // Relocate the copy of this image's code so that relative virtual addresses
  // are resolved correctly in the target process upon execution. 
  uintptr_t baseRelocVAddr = 
    ntHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
  IMAGE_BASE_RELOCATION* relocTbl =
    reinterpret_cast<IMAGE_BASE_RELOCATION*>
    (reinterpret_cast<uintptr_t>(selfBaseAddr) + baseRelocVAddr);
  while (0 < relocTbl->SizeOfBlock)
  {
    uint32_t entryCount = (relocTbl->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 
                          sizeof(unsigned short);

    // Retrieve Offset which follows immediately after the DataDirectory[] struct
    // 12-MSB.
    uint16_t* offset = reinterpret_cast<uint16_t*>(relocTbl + 1);

    for (size_t i = 0; i < entryCount; ++i)
    {
      if (0 != offset)
      {
        uintptr_t* relocPtr = reinterpret_cast<uintptr_t*>(
                              reinterpret_cast<uintptr_t>(imageBuf) +
                              relocTbl->VirtualAddress +
                              (offset[i] & 0xFFF));
        *relocPtr += imageOffset;
      }
    }

    // Go to next relocation table
    relocTbl = reinterpret_cast<IMAGE_BASE_RELOCATION*>
                (reinterpret_cast<uintptr_t>(relocTbl) + relocTbl->SizeOfBlock);
  }

  // Write our image to the target allocation space
  if (false == RemoteWrite(pHandle, targetBaseAddr, imageBuf, selfSize))
  {
    delete[] imageBuf;
    return false;
  }

  // Free image buf
  delete[] imageBuf;

  // Everything has been setup, execute the remote code
  void* pFunc = reinterpret_cast<void*>
                (reinterpret_cast<uintptr_t>(entrypoint) + imageOffset);

  return RemoteExecute(pHandle, pFunc, nullptr);
}

/*
/ Function: InjectLibrary
/ Notes: None
*/
bool CodeInjection::InjectLibrary(void* pHandle, char* libPath)
{
  size_t pathLen = strlen(libPath);

  // Allocate space in the target process for the library path
  void* libPathAddr = nullptr;
  if (false == RemoteAlloc(pHandle, false, pathLen, libPathAddr))
  {
    return false;
  }

  // Write the library path to the buffer
  if (false == RemoteWrite(pHandle, libPathAddr, libPath, pathLen))
  {
    return false;
  }

  // Execute LoadLibrary remotely.
  void* hModule = GetModuleHandleA("Kernel32.dll");
  if (nullptr == hModule)
  {
    return false;
  }

  void* apiAddr = GetProcAddress(reinterpret_cast<HMODULE>(hModule), "LoadLibraryA");
  if (nullptr == apiAddr)
  {
    return false;
  }

  return RemoteExecute(pHandle, apiAddr, libPathAddr);
}

/*
/ Function: RemoteWrite
/ Notes: None
*/
bool CodeInjection::RemoteWrite(void* pHandle, void* addr, void* buf, size_t len)
{
  SIZE_T bytesWritten = 0;

  unsigned long oldProtect = 0;
  if (VirtualProtectEx(pHandle, addr, len, PAGE_READWRITE, &oldProtect))
  {
    WriteProcessMemory(pHandle, addr, buf, len, &bytesWritten);
    VirtualProtectEx(pHandle, addr, len, oldProtect, &oldProtect);
  }

  return (bytesWritten == len);
}

/*
/ Function: RemoteRead
/ Notes: None
*/
bool CodeInjection::RemoteRead(void* pHandle, void* addr, void* buf, size_t maxLen)
{
  SIZE_T bytesRead = 0;

  unsigned long oldProtect = 0;
  if (VirtualProtectEx(pHandle, addr, maxLen, PAGE_READWRITE, &oldProtect))
  {
    ReadProcessMemory(pHandle, addr, buf, maxLen, &bytesRead);
    VirtualProtectEx(pHandle, addr, maxLen, oldProtect, &oldProtect);
  }

  return (bytesRead == maxLen);
}

/*
/ Function: RemoteAlloc
/ Notes: None
*/
bool CodeInjection::RemoteAlloc(void* pHandle, bool executable, size_t len, void*& addr)
{
  void* targetAddress = addr;
  unsigned long protection = true == executable ? PAGE_EXECUTE_READWRITE : 
                                                  PAGE_READWRITE;
  addr = VirtualAllocEx(pHandle, targetAddress, len, MEM_COMMIT, protection);

  return (nullptr != addr);
}

/*
/ Function: RemoteExecute
/ Notes: None
*/
bool CodeInjection::RemoteExecute(void* pHandle, void* addr, void* param)
{
  LPTHREAD_START_ROUTINE pFunc = reinterpret_cast<LPTHREAD_START_ROUTINE>(addr);

  return (INVALID_HANDLE_VALUE !=
          CreateRemoteThread(pHandle, 0, 0, pFunc, param, 0, 0));
}

/*
/ Function: DMAWrite
/ Notes: None
*/
void CodeInjection::DMAWrite(void* addr, void* buf, size_t len)
{
  unsigned long oldProtect = 0;
  if (VirtualProtect(addr, len, PAGE_READWRITE, &oldProtect))
  {
    memcpy(addr, buf, len);
    VirtualProtect(addr, len, oldProtect, &oldProtect);
  }
}

/*
/ Function: DMARead
/ Notes: None
*/
void CodeInjection::DMARead(void* addr, void* buf, size_t len)
{
  unsigned long oldProtect = 0;
  if (VirtualProtect(addr, len, PAGE_READWRITE, &oldProtect))
  {
    memcpy(buf, addr, len);
    VirtualProtect(addr, len, oldProtect, &oldProtect);
  }
}