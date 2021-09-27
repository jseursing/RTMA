#pragma once
#include <string>
#include <vector>

/*
/ This class handles terminal input and output.
*/
class IOProcessor
{
public:
  static void Print(const char* str = "");
  static void PrintNoEOL(const char* str);
  static std::string GetInput();
  static std::vector<std::string> Parameterize(std::string& input);
  static bool ProcessParameters(std::vector<std::string>& params);

private:

  static bool Process_Command(std::vector<std::string>& params);
  static bool Attach_Command(std::vector<std::string>& params);
  static bool Inject_Command(std::vector<std::string>& params);
  static bool PEScan_Command(std::vector<std::string>& params);
  static bool Scan64_Command(std::vector<std::string>& params);
  static bool Scan32_Command(std::vector<std::string>& params);
  static bool Scan16_Command(std::vector<std::string>& params);
  static bool Scan8_Command(std::vector<std::string>& params);
  static bool ScanStr_Command(std::vector<std::string>& params);
  static bool Scan_Command(std::vector<std::string>& params);
  static bool NextScan64_Command(std::vector<std::string>& params);
  static bool NextScan32_Command(std::vector<std::string>& params);
  static bool NextScan16_Command(std::vector<std::string>& params);
  static bool NextScan8_Command(std::vector<std::string>& params);
  static bool NextScanStr_Command(std::vector<std::string>& params);
  static bool NextScan_Command(std::vector<std::string>& params);
  static bool DisplayScanResults(std::vector<std::string>& params);
  static bool Read64_Command(std::vector<std::string>& params);
  static bool Read32_Command(std::vector<std::string>& params);
  static bool Read16_Command(std::vector<std::string>& params);
  static bool Read8_Command(std::vector<std::string>& params);
  static bool ReadStr_Command(std::vector<std::string>& params);
  static bool Read_Command(std::vector<std::string>& params);
  static bool Write64_Command(std::vector<std::string>& params);
  static bool Write32_Command(std::vector<std::string>& params);
  static bool Write16_Command(std::vector<std::string>& params);
  static bool Write8_Command(std::vector<std::string>& params);
  static bool WriteStr_Command(std::vector<std::string>& params);
  static bool Write_Command(std::vector<std::string>& params);
  static bool Mode_Command(std::vector<std::string>& params);
  static bool Command_Help(std::vector<std::string>& params);
  static bool Unrecognized_Command();

  // Below is a structure defining a string command
  // mapped to a function. The function must accept
  // std::vector<std::string>& as a parameter.
  struct StrCmdMap
  {
    const char command[32];
    void* cmdRoutine;
  };
  static StrCmdMap CommandMap[];
};