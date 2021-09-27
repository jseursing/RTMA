#pragma once

// Disable enum class warnings
#pragma warning(push)
#pragma warning(disable : 26812)

// Class definition
class StatusTypes
{
public:

  // The source of the error
  enum ErrorSrcEnum
  {
    INVALID_SRC,
    SEM_MGR    = 5,
    UDP_MGR    = 6,
    MAX_SRC
  };

  // The category of the error
  enum ErrorTypeEnum
  {
    INVALID_CATEGORY,
    NO_RESOURCES  = 1,
    INIT_FAILED   = 2,
    INVALID_ID    = 3,
    TIMEOUT       = 4,
    INVALID_OBJ   = 5,
    NOT_OWNER     = 6,
    OS_ERROR      = 7,
    STATE_ERROR   = 8,
    INVALID_COUNT = 9,
    MAX_CATEGORY
  };

  // The type of the error
  enum ErrorTypeEnum
  {
    INVALID_TYPE,
    SOURCE         = 1,
    DESTINATION    = 2,
    ALLOCATED      = 3,
    RELEASED       = 4,
    MEM_ERROR      = 5,
    MAX_TYPE
  };

  #define ERR_STATUS(src,cat,code) ((src << 24) | (cat << 16) | code)
  enum StatusEnum
  {
    STATUS_OK            = 0,
    STATUS_ERROR_TIMEOUT = 1,

    // UDP Manager
    UDP_ALREADY_INIT     = ERR_STATUS(UDP_MGR,    INIT_FAILED,    ALLOCATED),
    UDP_INVALID_ID       = ERR_STATUS(UDP_MGR,    INVALID_ID,             0),
    UDP_INVALID_SCKT     = ERR_STATUS(UDP_MGR,    INVALID_ID,             1),
    UDP_INIT_LIB_ERROR   = ERR_STATUS(UDP_MGR,    OS_ERROR,               0),
    UDP_SCKT_INIT_ERROR  = ERR_STATUS(UDP_MGR,    OS_ERROR,               1),
    UDP_SCKT_BIND_ERROR  = ERR_STATUS(UDP_MGR,    OS_ERROR,               2),
    UDP_SCKT_SEND_ERROR  = ERR_STATUS(UDP_MGR,    OS_ERROR,               3),
    UDP_SCKT_RECV_ERROR  = ERR_STATUS(UDP_MGR,    OS_ERROR,               4),
    UDP_SCKT_SELECT_ERR  = ERR_STATUS(UDP_MGR,    OS_ERROR,               5),
    UDP_SCKT_NO_DATA     = ERR_STATUS(UDP_MGR,    TIMEOUT,                0),

    // Semaphore Manager
    SEMMGR_ALREADY_INIT  = ERR_STATUS(SEM_MGR, INIT_FAILED,      ALLOCATED),
    SEMMGR_INVALID_ID    = ERR_STATUS(SEM_MGR, NO_RESOURCES,             0),
    SEMMGR_GIVE_ERROR    = ERR_STATUS(SEM_MGR, OS_ERROR,                 0),
    SEMMGR_TAKE_ERROR    = ERR_STATUS(SEM_MGR, OS_ERROR,                 1)
  };
};