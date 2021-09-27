#pragma once
#include <stdint.h>
#include <vector>

/*
/ This class provides utilities to inject code into a target
/ process and execute it if specified.
*/
class CodeInjection
{
public:
  static bool InjectThisExe(void* pHandle, void* entrypoint);
  static bool InjectLibrary(void* pHandle, char* libPath);
  static bool RemoteWrite(void* pHandle, void* addr, void* buf, size_t len);
  static bool RemoteRead(void* pHandle, void* addr, void* buf, size_t maxLen);
  static bool RemoteAlloc(void* pHandle, bool executable, size_t len, void*& addr);
  static bool RemoteExecute(void* pHandle, void* addr, void* param);
  static void DMAWrite(void* addr, void* buf, size_t len);
  static void DMARead(void* addr, void* buf, size_t len);

private:
};