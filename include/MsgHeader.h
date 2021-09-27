#pragma once
#include <stdint.h>


/*
/ This class should precede all messages.
*/
class MsgHeader
{
public:
  
  // Header type enum
  enum TypeEnum
  {
    INIT,
    RELEASE,
    ACKNOWLEDGE,
    MEMSCAN,
    PESCAN,
    DMA,
    DISPLAYSCAN
  };

  // Header subtype enum
  enum SubtypeEnum
  {
    QUERY,
    RESPONSE,
    ACCEPTED,
    REJECTED
  };

  TypeEnum GetType() const;
  SubtypeEnum GetSubtype() const;
  uint32_t GetLength() const;
  MsgHeader(TypeEnum type, SubtypeEnum subtype, uint32_t len);
  ~MsgHeader();

private:
  
  TypeEnum Type       : 4;
  SubtypeEnum Subtype : 4;
  uint32_t Length     : 24;
};