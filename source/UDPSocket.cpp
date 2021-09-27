#include "OSInterface.h"
#include "UDPSocket.h"
#include <cstring>


/////////////////////////////////////////////////////////////////////////////////////////
//
// Function: Create
// Notes:    None
//
/////////////////////////////////////////////////////////////////////////////////////////
UDPSocket* UDPSocket::Create(uint16_t port)
{
  UDPSocket* udpSocket = nullptr;
  switch (port)
  {
  case 0:
    udpSocket = new UDPSocket();
    break;
  default:
    udpSocket = new UDPSocket(port);
  }

  return udpSocket;
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function: Destroy
// Notes:    None
//
/////////////////////////////////////////////////////////////////////////////////////////
void UDPSocket::Destroy(UDPSocket* socket)
{
  if (nullptr != socket)
  {
    OSInterface::UDPClose(socket->Socket);
    delete socket;
  }
}


/////////////////////////////////////////////////////////////////////////////////////////
//
// Function: SendMsg
// Notes:    None
//
/////////////////////////////////////////////////////////////////////////////////////////
StatusTypes::StatusEnum 
UDPSocket::SendMsg(char* addr, uint16_t port, char* msg, uint32_t len)
{
  return OSInterface::UDPSend(Socket, addr, port, msg, len);
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function: RecvMsg
// Notes:    None
//
/////////////////////////////////////////////////////////////////////////////////////////
StatusTypes::StatusEnum UDPSocket::RecvMsg(char* buf, 
                                           uint32_t maxLen, 
                                           uint32_t timeoutMs, 
                                           char* filterAddr, 
                                           uint16_t* filterPort)
{
  char src_addr[32] = {0};
  uint16_t port = 0;

  StatusTypes::StatusEnum status = OSInterface::UDPRecv(Socket, 
                                                        buf, 
                                                        maxLen, 
                                                        timeoutMs, 
                                                        src_addr, 
                                                        sizeof(src_addr), 
                                                        &port);
  if (StatusTypes::STATUS_OK == status)
  {
    // If a filter address was specified, handle the buffer...
    if ((nullptr != filterAddr) &&
        (nullptr != filterPort))
    {
      memcpy(filterAddr, src_addr, strlen(src_addr));
      *filterPort = port;
    }
  }

  return status;
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function: UDPSocket
// Notes:    None
//
/////////////////////////////////////////////////////////////////////////////////////////
UDPSocket::UDPSocket(uint16_t port)
{
  StatusTypes::StatusEnum status;
  Socket = OSInterface::UDPCreate(status, port, true);
  if (StatusTypes::STATUS_OK != status)
  {
    // TODO
  }
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function: UDPSocket
// Notes:    None
//
/////////////////////////////////////////////////////////////////////////////////////////
UDPSocket::UDPSocket()
{
  StatusTypes::StatusEnum status;
  Socket = OSInterface::UDPCreate(status);
  if (StatusTypes::STATUS_OK != status)
  {
    // TODO
  }
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function: ~UDPSocket
// Notes:    None
//
/////////////////////////////////////////////////////////////////////////////////////////
UDPSocket::~UDPSocket()
{

}