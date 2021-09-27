#include "AckMsg.h"


/*
/ Function: GetQueryType
/ Notes: None
*/
AckMsg::TypeEnum AckMsg::GetQueryType() const
{
  return QueryType;
}

/*
/ Function: AckMsg
/ Notes: None
*/
AckMsg::AckMsg(TypeEnum queryType, bool accept) :
  MsgHeader(TypeEnum::ACKNOWLEDGE, 
            true == accept ? SubtypeEnum::ACCEPTED : SubtypeEnum::REJECTED, 
            sizeof(AckMsg)),
  QueryType(queryType)
{
  
}

/*
/ Function: ~AckMsg
/ Notes: None
*/
AckMsg::~AckMsg()
{

}