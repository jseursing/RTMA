#include "CodeInjection.h"
#include "IOProcessor.h"
#include "ProcessHandler.h"
#include "RTMA_SVRManager.h"
#include <iostream>

// Static definitions
IOProcessor::StrCmdMap IOProcessor::CommandMap[] =
{
  {"process",     IOProcessor::Process_Command},
  {"attach",      IOProcessor::Attach_Command},
  {"inject",      IOProcessor::Inject_Command},
  {"pescan",      IOProcessor::PEScan_Command},
  {"scan64",      IOProcessor::Scan64_Command},
  {"scan32",      IOProcessor::Scan32_Command},
  {"scan16",      IOProcessor::Scan16_Command},
  {"scan8",       IOProcessor::Scan8_Command},
  {"scanstr",     IOProcessor::ScanStr_Command},
  {"scan",        IOProcessor::Scan_Command},
  {"nextscan64",  IOProcessor::NextScan64_Command},
  {"nextscan32",  IOProcessor::NextScan32_Command},
  {"nextscan16",  IOProcessor::NextScan16_Command},
  {"nextscan8",   IOProcessor::NextScan8_Command},
  {"nextscanstr", IOProcessor::NextScanStr_Command},
  {"nextscan",    IOProcessor::NextScan_Command},
  {"displayscan", IOProcessor::DisplayScanResults},
  {"mode" ,       IOProcessor::Mode_Command},
  {"read64",      IOProcessor::Read64_Command},
  {"read32",      IOProcessor::Read32_Command},
  {"read16",      IOProcessor::Read16_Command},
  {"read8",       IOProcessor::Read8_Command},
  {"readstr",     IOProcessor::ReadStr_Command},
  {"read",        IOProcessor::Read_Command},
  {"write64",     IOProcessor::Write64_Command},
  {"write32",     IOProcessor::Write32_Command},
  {"write16",     IOProcessor::Write16_Command},
  {"write8",      IOProcessor::Write8_Command},
  {"writestr",    IOProcessor::WriteStr_Command},
  {"write",       IOProcessor::Write_Command},
  {"help",        IOProcessor::Command_Help},
  {"",            nullptr} // Must be last entry
};

/*
/  Function: Print
/  Notes: None
*/
void IOProcessor::Print(const char* str)
{
  std::cout << str << std::endl;
}

/*
/  Function: PrintNoEOL
/  Notes: Prints without new line.
*/
void IOProcessor::PrintNoEOL(const char* str)
{
  std::cout << str;
}

/*
/  Function: GetInput
/  Notes: None
*/
std::string IOProcessor::GetInput()
{
  std::string input;
  std::getline(std::cin, input);
  
  return input;
}

/*
/  Function: Parameterize
/  Notes: None.
*/
std::vector<std::string> IOProcessor::Parameterize(std::string& input)
{
  std::vector<std::string> parameters;

  size_t currPos = 0;
  size_t nextPos = input.find(" ");
  
  // Check to see if this is a single parameter command..
  if (std::string::npos == nextPos)
  {
    parameters.push_back(input);
  }

  // This is a multi parameter command
  else
  {
    while (std::string::npos != nextPos)
    {
      std::string token = input.substr(currPos, nextPos - currPos);
      
      // Break down each field by spaces, with quotations taking precedence.
      if (std::string::npos != token.find("\""))
      {
        nextPos = input.find("\"", currPos + 1);
        if (std::string::npos == nextPos)
        {
          token = input.substr(currPos, input.length() - currPos);
        }
        else
        {
          ++nextPos;
          token = input.substr(currPos, nextPos - currPos);
        }
      }

      // strip quotes
      if (std::string::npos != token.find("\""))
      {
        token = token.substr(1, token.length() - 2);
      }

      parameters.push_back(token);

      currPos = nextPos + 1;
      nextPos = input.find(" ", currPos);
    }

    // If nextPos isn't equal to currPos, add the final token
    if (nextPos != currPos)
    {
      // Guard against ill-terminated quotes.
      if (static_cast<size_t>(currPos) < input.length())
      {
        std::string token = input.substr(currPos);

        // strip quotes
        if (std::string::npos != token.find("\""))
        {
          token = token.substr(1, token.length() - 2);
        }

        parameters.push_back(token);
      }
    }
  }

  return parameters;
}

/*
/  Function: ProcessParameters
/  Notes: None.
*/
bool IOProcessor::ProcessParameters(std::vector<std::string>& params)
{
  // Check for no parameters or "help" command
  if (0 == params.size())
  {
    return Command_Help(params);
  }

  // Iterate through our command map until we reach the end, 
  // or we find a mapped function.
  StrCmdMap* pMap = CommandMap;
  while (nullptr != pMap->cmdRoutine)
  {
    if (0 == _strcmpi(pMap->command, params[0].c_str()))
    {
      return reinterpret_cast<bool(*)(std::vector<std::string>&)>
                             (pMap->cmdRoutine)(params);
    }

    ++pMap;
  }

  return Unrecognized_Command();
}

/*
/  Function: Process_Command
/  Notes: handles 'process' command
*/
bool IOProcessor::Process_Command(std::vector<std::string>& params)
{
  if (params.size() < 2)
  {
    IOProcessor::Print("- Invalid parameters");
    return true;
  }

  // List parameter
  if (0 == _strcmpi(params[1].data(), "-l"))
  {
    ProcessHandler::DisplayActiveProcs(nullptr);
    return true;
  }

  // Find process
  if (0 == _strcmpi(params[1].data(), "-f"))
  {
    if (3 > params.size())
    {
      IOProcessor::Print("- Invalid parameters");
      return true;
    }

    ProcessHandler::DisplayActiveProcs(params[2].c_str());
    return true;
  }


  // Unrecognized parameter
  std::string errStr = "- Invalid parameter '" + params[1] + "'";
  IOProcessor::Print(errStr.c_str());

  return true;
}

/*
/  Function: Attach_Command
/  Notes: Handles 'attach' command
*/
bool IOProcessor::Attach_Command(std::vector<std::string>& params)
{
  if (3 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");

    return true;
  }

  if (0 == _strcmpi(params[1].data(), "-p"))
  {
    uint32_t pid = strtoul(params[2].data(),
                           nullptr,
                           std::string::npos != params[3].find("x") ? 16 : 10);
    RTMA_SVRManager::Instance()->Attach(pid);

    return true;
  }

  if (0 == _strcmpi(params[1].data(), "-n"))
  {
    RTMA_SVRManager::Instance()->Attach(params[2].data());

    return true;
  }

  if (0 == _strcmpi(params[1].data(), "-f"))
  {
    return RTMA_SVRManager::Instance()->ExecuteInjectDMA(params[2].c_str());
  }

  // Unrecognized parameter
  std::string errStr = "- Invalid parameter '" + params[1] + "'";
  IOProcessor::Print(errStr.c_str());

  return true;
}

/*
/  Function: Inject_Command
/  Notes: Handles 'inject' command
*/
bool IOProcessor::Inject_Command(std::vector<std::string>& params)
{
  if (params.size() < 2)
  {
    IOProcessor::Print("- Invalid parameters");
    return true;
  }

  // Inject library parameter
  if (2 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true;
  }

  RTMA_SVRManager::Instance()->InjectLibrary(const_cast<char*>(params[1].c_str()));
  return true;
}

/*
/  Function: PEScan_Command
/  Notes: None.
*/
bool IOProcessor::PEScan_Command(std::vector<std::string>& params)
{
  return RTMAManager::Instance()->PEScan();
}

/*
/  Function: Scan64_Command
/  Notes: None.
*/
bool IOProcessor::Scan64_Command(std::vector<std::string>& params)
{
  if (2 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  char valueBuf[64] = { 0 };

  uintptr_t value = strtoull(params[1].data(),
                             0,
                             std::string::npos != params[1].find("x") ? 16 : 10);
  memcpy(valueBuf, &value, sizeof(value));

  return RTMA_SVRManager::Instance()->Scan(valueBuf, sizeof(value));
}

/*
/  Function: Scan32_Command
/  Notes: None.
*/
bool IOProcessor::Scan32_Command(std::vector<std::string>& params)
{
  if (2 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  char valueBuf[64] = { 0 };

  uint32_t value = strtoul(params[1].data(),
                           0,
                           std::string::npos != params[1].find("x") ? 16 : 10);
  memcpy(valueBuf, &value, sizeof(value));

  return RTMA_SVRManager::Instance()->Scan(valueBuf, sizeof(value));
}

/*
/  Function: Scan16_Command
/  Notes: None.
*/
bool IOProcessor::Scan16_Command(std::vector<std::string>& params)
{
  if (2 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  char valueBuf[64] = { 0 };

  uint16_t value = static_cast<uint16_t>
                   (strtoul(params[1].data(),
                            0,
                            std::string::npos != params[1].find("x") ? 16 : 10));
  memcpy(valueBuf, &value, sizeof(value));

  return RTMA_SVRManager::Instance()->Scan(valueBuf, sizeof(value));
}

/*
/  Function: Scan8_Command
/  Notes: None.
*/
bool IOProcessor::Scan8_Command(std::vector<std::string>& params)
{
  if (2 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  char valueBuf[64] = { 0 };

  uint8_t value = static_cast<uint8_t>
                  (strtoul(params[1].data(),
                           0,
                           std::string::npos != params[1].find("x") ? 16 : 10));
  memcpy(valueBuf, &value, sizeof(value));

  return RTMA_SVRManager::Instance()->Scan(valueBuf, sizeof(value));
}

/*
/  Function: ScanStr_Command
/  Notes: None.
*/
bool IOProcessor::ScanStr_Command(std::vector<std::string>& params)
{
  if (2 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  char valueBuf[64] = { 0 };
  memcpy(valueBuf, params[1].data(), params[1].length());

  return RTMA_SVRManager::Instance()->Scan(valueBuf, params[1].length());
}

/*
/  Function: Scan_Command
/  Notes: None.
*/
bool IOProcessor::Scan_Command(std::vector<std::string>& params)
{
  if (1 == params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  // Memory Region scan parameter
  if (0 == _strcmpi(params[1].data(), "-l"))
  {
    return RTMAManager::Instance()->MemRegionScan();
  }

  // We assume this is a memory scan, therefore we need 3 parameters minimum
  if (3 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  uintptr_t size = strtoul(params[1].c_str(), 0, 10);

  char valueBuf[64] = { 0 };
  switch (size)
  {
    case 8:
    {
      uintptr_t value = strtoull(params[2].data(),
                                 0,
                                 std::string::npos != params[2].find("x") ? 16 : 10);
      memcpy(valueBuf, &value, sizeof(value));
    }
    break;

    case 4:
    {
      uint32_t value = strtoul(params[2].data(),
                               0,
                               std::string::npos != params[2].find("x") ? 16 : 10);
      memcpy(valueBuf, &value, sizeof(value));
    }
    break;

    case 2:
    {
      uint16_t value = static_cast<uint16_t>
                       (strtoul(params[2].data(),
                                0,
                                std::string::npos != params[2].find("x") ? 16 : 10));
      memcpy(valueBuf, &value, sizeof(value));
    }
    break;

    case 1:
    {
      uint8_t value = static_cast<uint8_t>
                      (strtoul(params[2].data(),
                               0,
                               std::string::npos != params[2].find("x") ? 16 : 10));
      memcpy(valueBuf, &value, sizeof(value));
    }
    break;

    default:
    {
      // Verify we have enough parameters..
      if (size != (params.size() - 2))
      {
        Print("Scan request length does not match value provided (byte array)");
        return true;
      }

      for (size_t i = 0; i < size; ++i)
      {
        valueBuf[i] = static_cast<uint8_t>(strtoul(params[2 + i].data(), 0, 16));
      }
    }
  }

  return RTMA_SVRManager::Instance()->Scan(valueBuf, size);
}

/*
/  Function: NextScan64_Command
/  Notes: None.
*/
bool IOProcessor::NextScan64_Command(std::vector<std::string>& params)
{
  if (2 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  char valueBuf[64] = { 0 };

  uintptr_t value = strtoull(params[1].data(),
                             0,
                             std::string::npos != params[1].find("x") ? 16 : 10);
  memcpy(valueBuf, &value, sizeof(value));
 
  return RTMA_SVRManager::Instance()->NextScan(valueBuf, sizeof(value));
}

/*
/  Function: NextScan32_Command
/  Notes: None.
*/
bool IOProcessor::NextScan32_Command(std::vector<std::string>& params)
{
  if (2 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  char valueBuf[64] = { 0 };

  uint32_t value = strtoul(params[1].data(),
                           0,
                           std::string::npos != params[1].find("x") ? 16 : 10);
  memcpy(valueBuf, &value, sizeof(value));

  return RTMA_SVRManager::Instance()->NextScan(valueBuf, sizeof(value));
}

/*
/  Function: NextScan16_Command
/  Notes: None.
*/
bool IOProcessor::NextScan16_Command(std::vector<std::string>& params)
{
  if (2 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  char valueBuf[64] = { 0 };

  uint16_t value = static_cast<uint16_t>
                   (strtoul(params[1].data(),
                            0,
                            std::string::npos != params[1].find("x") ? 16 : 10));
  memcpy(valueBuf, &value, sizeof(value));

  return RTMA_SVRManager::Instance()->NextScan(valueBuf, sizeof(value));
}

/*
/  Function: NextScan16_Command
/  Notes: None.
*/
bool IOProcessor::NextScan8_Command(std::vector<std::string>& params)
{
  if (2 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  char valueBuf[64] = { 0 };

  uint8_t value = static_cast<uint8_t>
                  (strtoul(params[1].data(),
                           0,
                           std::string::npos != params[1].find("x") ? 16 : 10));
  memcpy(valueBuf, &value, sizeof(value));

  return RTMA_SVRManager::Instance()->NextScan(valueBuf, sizeof(value));
}

/*
/  Function: NextScanStr_Command
/  Notes: None.
*/
bool IOProcessor::NextScanStr_Command(std::vector<std::string>& params)
{
  if (2 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  char valueBuf[64] = { 0 };
  memcpy(valueBuf, params[1].data(), params[1].length());

  return RTMA_SVRManager::Instance()->NextScan(valueBuf, params[1].length());
}

/*
/  Function: NextScan_Command
/  Notes: None.
*/
bool IOProcessor::NextScan_Command(std::vector<std::string>& params)
{
  if (1 == params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  uintptr_t size = strtoul(params[1].c_str(), 0, 10);

  char valueBuf[64] = { 0 };
  switch (size)
  {
    case 8:
    {
      uintptr_t value = strtoull(params[2].data(),
                                 0,
                                 std::string::npos != params[2].find("x") ? 16 : 10);
      memcpy(valueBuf, &value, sizeof(value));
    }
    break;

    case 4:
    {
      uint32_t value = strtoul(params[2].data(),
                               0,
                               std::string::npos != params[2].find("x") ? 16 : 10);
      memcpy(valueBuf, &value, sizeof(value));
    }
    break;

    case 2:
    {
      uint16_t value = static_cast<uint16_t>
                       (strtoul(params[2].data(),
                                0,
                                std::string::npos != params[2].find("x") ? 16 : 10));
      memcpy(valueBuf, &value, sizeof(value));
    }
    break;

    case 1:
    {
      uint8_t value = static_cast<uint8_t>
                      (strtoul(params[2].data(),
                               0,
                               std::string::npos != params[2].find("x") ? 16 : 10));
      memcpy(valueBuf, &value, sizeof(value));
    }
    break;

    default:
    {
      // Verify we have enough parameters..
      if (size != (params.size() - 2))
      {
        Print("Scan request length does not match value provided (byte array)");
        return true;
      }

      for (size_t i = 0; i < size; ++i)
      {
        valueBuf[i] = static_cast<uint8_t>(strtoul(params[2 + i].data(), 0, 16));
      }
    }
  }

  return RTMA_SVRManager::Instance()->NextScan(valueBuf, size);
}

/*
/  Function: DisplayScanResults
/  Notes: None.
*/
bool IOProcessor::DisplayScanResults(std::vector<std::string>& params)
{
  return RTMA_SVRManager::Instance()->DisplayScanResults();
}

/*
/  Function: Read64_Command
/  Notes: None.
*/
bool IOProcessor::Read64_Command(std::vector<std::string>& params)
{
  if (2 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  uintptr_t address =
#if _WIN32 || _WIN64
#if _WIN64
    strtoull(params[1].c_str(), 0, 16);
#else
    strtoul(params[1].c_str(), 0, 16);
#endif
#endif

  return RTMA_SVRManager::Instance()->Read(address, 8);
}

/*
/  Function: Read32_Command
/  Notes: None.
*/
bool IOProcessor::Read32_Command(std::vector<std::string>& params)
{
  if (2 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  uintptr_t address =
#if _WIN32 || _WIN64
#if _WIN64
    strtoull(params[1].c_str(), 0, 16);
#else
    strtoul(params[1].c_str(), 0, 16);
#endif
#endif

  return RTMA_SVRManager::Instance()->Read(address, 4);
}

/*
/  Function: Read16_Command
/  Notes: None.
*/
bool IOProcessor::Read16_Command(std::vector<std::string>& params)
{
  if (2 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  uintptr_t address =
#if _WIN32 || _WIN64
#if _WIN64
    strtoull(params[1].c_str(), 0, 16);
#else
    strtoul(params[1].c_str(), 0, 16);
#endif
#endif

  return RTMA_SVRManager::Instance()->Read(address, 2);
}

/*
/  Function: Read64_Command
/  Notes: None.
*/
bool IOProcessor::Read8_Command(std::vector<std::string>& params)
{
  if (2 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  uintptr_t address =
#if _WIN32 || _WIN64
#if _WIN64
    strtoull(params[1].c_str(), 0, 16);
#else
    strtoul(params[1].c_str(), 0, 16);
#endif
#endif

  return RTMA_SVRManager::Instance()->Read(address, 1);
}

/*
/  Function: ReadStr_Command
/  Notes: None.
*/
bool IOProcessor::ReadStr_Command(std::vector<std::string>& params)
{
  if (2 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  uintptr_t address =
#if _WIN32 || _WIN64
#if _WIN64
    strtoull(params[1].c_str(), 0, 16);
#else
    strtoul(params[1].c_str(), 0, 16);
#endif
#endif

  return RTMA_SVRManager::Instance()->Read(address, strtoul(params[2].c_str(), 0, 10));
}

/*
/  Function: Read_Command
/  Notes: None.
*/
bool IOProcessor::Read_Command(std::vector<std::string>& params)
{
  if (3 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  uintptr_t address =
#if _WIN32 || _WIN64
#if _WIN64
    strtoull(params[1].c_str(), 0, 16);
#else
    strtoul(params[1].c_str(), 0, 16);
#endif
#endif

  uint32_t size = strtoul(params[2].c_str(), 
                          0, 
                          std::string::npos != params[2].find("x") ? 16 : 10);

  return RTMA_SVRManager::Instance()->Read(address, size);
}

/*
/  Function: Write64_Command
/  Notes: None.
*/
bool IOProcessor::Write64_Command(std::vector<std::string>& params)
{
  if (3 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  uintptr_t address = 0;
  if (0 != _strcmpi(params[1].c_str(), "scanresults"))
  {
#if _WIN32 || _WIN64
#if _WIN64
    strtoull(params[1].c_str(), 0, 16);
#else
    strtoul(params[1].c_str(), 0, 16);
#endif
#endif
  }

  char valueBuf[8] = {0};
  uintptr_t value = strtoull(params[2].data(),
                              0,
                              std::string::npos != params[2].find("x") ? 16 : 10);
  memcpy(valueBuf, &value, sizeof(value));

  return RTMA_SVRManager::Instance()->Write(address, valueBuf, sizeof(valueBuf));
}

/*
/  Function: Write32_Command
/  Notes: None.
*/
bool IOProcessor::Write32_Command(std::vector<std::string>& params)
{
  if (3 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  uintptr_t address = 0;
  if (0 != _strcmpi(params[1].c_str(), "scanresults"))
  {
#if _WIN32 || _WIN64
#if _WIN64
    strtoull(params[1].c_str(), 0, 16);
#else
    strtoul(params[1].c_str(), 0, 16);
#endif
#endif
  }

  char valueBuf[4] = { 0 };
  uint32_t value = strtoul(params[2].data(),
                           0,
                           std::string::npos != params[2].find("x") ? 16 : 10);
  memcpy(valueBuf, &value, sizeof(value));

  return RTMA_SVRManager::Instance()->Write(address, valueBuf, sizeof(valueBuf));
}

/*
/  Function: Write16_Command
/  Notes: None.
*/
bool IOProcessor::Write16_Command(std::vector<std::string>& params)
{
  if (3 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  uintptr_t address = 0;
  if (0 != _strcmpi(params[1].c_str(), "scanresults"))
  {
#if _WIN32 || _WIN64
#if _WIN64
    strtoull(params[1].c_str(), 0, 16);
#else
    strtoul(params[1].c_str(), 0, 16);
#endif
#endif
  }

  char valueBuf[2] = { 0 };
  uint16_t value = static_cast<uint16_t>
                   (strtoul(params[2].data(),
                            0,
                            std::string::npos != params[2].find("x") ? 16 : 10));
  memcpy(valueBuf, &value, sizeof(value));

  return RTMA_SVRManager::Instance()->Write(address, valueBuf, sizeof(valueBuf));
}

/*
/  Function: Write8_Command
/  Notes: None.
*/
bool IOProcessor::Write8_Command(std::vector<std::string>& params)
{
  if (3 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  uintptr_t address = 0;
  if (0 != _strcmpi(params[1].c_str(), "scanresults"))
  {
#if _WIN32 || _WIN64
#if _WIN64
    strtoull(params[1].c_str(), 0, 16);
#else
    strtoul(params[1].c_str(), 0, 16);
#endif
#endif
  }

  char valueBuf[1] = { 0 };
  uint16_t value = static_cast<uint8_t>
                   (strtoul(params[2].data(),
                            0,
                            std::string::npos != params[2].find("x") ? 16 : 10));
  memcpy(valueBuf, &value, sizeof(value));

  return RTMA_SVRManager::Instance()->Write(address, valueBuf, sizeof(valueBuf));
}

/*
/  Function: ReadStr_Command
/  Notes: None.
*/
bool IOProcessor::WriteStr_Command(std::vector<std::string>& params)
{
  if (2 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  uintptr_t address =
#if _WIN32 || _WIN64
#if _WIN64
    strtoull(params[1].c_str(), 0, 16);
#else
    strtoul(params[1].c_str(), 0, 16);
#endif
#endif

  return RTMA_SVRManager::Instance()->Write(address, 
                                            const_cast<char*>(params[2].data()), 
                                            params[2].length());
}

/*
/  Function: Write_Command
/  Notes: None.
*/
bool IOProcessor::Write_Command(std::vector<std::string>& params)
{
  if (4 > params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  uintptr_t address = 0;
  if (0 != _strcmpi(params[1].c_str(), "scanresults"))
  {
#if _WIN32 || _WIN64
#if _WIN64
    strtoull(params[1].c_str(), 0, 16);
#else
    strtoul(params[1].c_str(), 0, 16);
#endif
#endif
  }

  uintptr_t size = strtoul(params[2].c_str(), 0, 10);

  char* valueBuf = new char[size];

  // Verify we have enough parameters..
  if (size != (params.size() - 3))
  {
    Print("Write request length does not match value provided (byte array)");
    return true;
  }

  for (size_t i = 0; i < size; ++i)
  {
    valueBuf[i] = static_cast<uint8_t>(strtoul(params[3 + i].data(), 0, 16));
  }

  bool wait = RTMA_SVRManager::Instance()->Write(address, valueBuf, size);
  delete[] valueBuf;
    
  return wait;
}

/*
/  Function: Mode_Command
/  Notes: None.
*/
bool IOProcessor::Mode_Command(std::vector<std::string>& params)
{
  if (1 == params.size())
  {
    IOProcessor::Print("- Invalid parameters");
    return true; // Do not have to wait..
  }

  // Inject DMA module
  if (0 == _strcmpi(params[1].data(), "dma"))
  {
    return RTMA_SVRManager::Instance()->InjectDMAModule();
  }

  // Unload DMA module
  if (0 == _strcmpi(params[1].data(), "remote"))
  {
    return RTMA_SVRManager::Instance()->UnloadDMAModule();
  }

  IOProcessor::Print("- Invalid parameters");
  return true;
}

/*
/  Function: ProcessParameters
/  Notes: None.
*/
bool IOProcessor::Command_Help(std::vector<std::string>& params)
{
  char help_prompt[] =
    "Command    Parameters\n"
    "-------    ----------------------------------------------------------\n"
    "help       \n"
    "process    <-l/-f>                [-l: nil] [-f: $query]\n"
    "           -1                     List all active processes\n"
    "           -f                     Filter by process name containing $query\n"
    "attach     <-p/-n/-f>             [-p: <pid>] [-n: <name>]\n"
    "           -p                     [-p: $Process Id]\n"
    "           -n                     [-n: Process Name]\n"
    "           -f                     [-f: \"Executable path\"]\n"
    "inject     <libpath>              Inject dynamically-linked library\n"
    "                                  -libPath Full library path\n"
    "pescan                            Retrieves PE Information\n"
    "scan64     <val>                  Initial 64-bit value scan\n"
    "scan32     <val>                  Initial 32-bit value scan\n"
    "scan16     <val>                  Initial 16-bit value scan\n"
    "scan8      <val>                  Initial 8-bit value scan\n"
    "scanstr    <\"str\">              Initial string value scan\n"
    "scan       <-l/# <val>>           -l Lists all memory regions\n"
    "                                  -# number of bytes followed by value\n"
    "                                  * Value must be in hex array, space delimited\n"
    "nextscan64  <val>                 Next 64-bit value scan\n"
    "nextscan32  <val>                 Next 32-bit value scan\n"
    "nextscan16  <val>                 Next 16-bit value scan\n"
    "nextscan8   <val>                 Next 8-bit value scan\n"
    "nextscanstr <\"str\">             Next string value scan\n"
    "nextscan    <# val>               Performs a scan on existing results\n"
    "                                  -# number of bytes followed by value\n"
    "                                  * If # is not 1, 2, 4, or 8, must be in hex array space delimited\n"
    "displayscan                       Displays results of most recent scan\n"
    "read64     <addr>                 Reads 64-bit value at specified address\n"
    "read32     <addr>                 Reads 32-bit value at specified address\n"
    "read16     <addr>                 Reads 16-bit value at specified address\n"
    "read8      <addr>                 Reads 8-bit value at specified address\n"
    "read       <addr> <#>             Reads memory at the specified address\n"
    "                                  -# number of bytes to read\n"
    "write64    <-l> <addr> <val>      Writes 64-bit value at specified address\n"
    "                                  -l Lock value in place\n"
    "write32    <-l> <addr> <val>      Writes 32-bit value at specified address\n"
    "                                  -l Lock value in place\n"
    "write16    <-l> <addr> <val>      Writes 16-bit value at specified address\n"
    "                                  -l Lock value in place\n"
    "write8     <-l> <addr> <val>      Writes 8-bit value at specified address\n"
    "                                  -l Lock value in place\n"
    "write      <-l> <addr> <#> <val>  Writes memory at the specified address\n"
    "                                  -l Lock value in place\n"
    "                                  -# number of bytes to write\n"
    "                                  -val Value to write\n"
    "mode       <dma/remote>           Switches between DMA or REMOTE\n"
    "                                  -DMA will inject DMA library into target\n";
  IOProcessor::Print(help_prompt);

  return true; // Continue processing
}

/*
/  Function: Unrecognized_Command
/  Notes: None.
*/
bool IOProcessor::Unrecognized_Command()
{
  Print("Unrecognized command");
  return true; // Continue processing
}