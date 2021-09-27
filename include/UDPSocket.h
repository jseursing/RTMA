#pragma once
#include "StatusTypes.h"
#include <stdint.h>

class UDPSocket
{
public:
  
  static UDPSocket* Create(uint16_t port = 0);
  static void Destroy(UDPSocket* socket);
  StatusTypes::StatusEnum SendMsg(char* addr, 
                                  uint16_t port, 
                                  char* msg, 
                                  uint32_t len);
  StatusTypes::StatusEnum RecvMsg(char* buf, 
                                  uint32_t maxLen, 
                                  uint32_t timeoutMs, 
                                  char* srcAddr = nullptr,
                                  uint16_t* srcPort = nullptr);

private:

  UDPSocket(uint16_t port);   // Server constructor
  UDPSocket();                // Client constructor
  ~UDPSocket();
  
  uintptr_t Socket;

  // Test Friend declarations
  friend class UDPSocketTest;
};