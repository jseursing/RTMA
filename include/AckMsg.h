#pragma once
#include "MsgHeader.h"


/*
/ This message class is a response to a query.
*/
class AckMsg : public MsgHeader
{
public:
  
  TypeEnum GetQueryType() const;
  AckMsg(TypeEnum queryType, bool accept);
  ~AckMsg();

private:

  TypeEnum QueryType;
};