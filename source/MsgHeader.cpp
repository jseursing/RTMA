#include "MsgHeader.h"


/*
/ Function: GetType
/ Notes: None
*/
MsgHeader::TypeEnum MsgHeader::GetType() const
{
  return Type;
}

/*
/ Function: GetSubtype
/ Notes: None
*/
MsgHeader::SubtypeEnum MsgHeader::GetSubtype() const
{
  return Subtype;
}

/*
/ Function: GetLength
/ Notes: None
*/
uint32_t MsgHeader::GetLength() const
{
  return Length;
}

/*
/ Function: MsgHeader
/ Notes: None
*/
MsgHeader::MsgHeader(TypeEnum type, SubtypeEnum subtype, uint32_t len) :
  Type(type),
  Subtype(subtype),
  Length(len)
{

}

/*
/ Function: ~MsgHeader
/ Notes: None
*/
MsgHeader::~MsgHeader()
{

}