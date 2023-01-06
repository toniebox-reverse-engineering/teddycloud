/**
 * @file lldp_tlv.c
 * @brief TLV parsing and formatting
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneTCP Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL LLDP_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "lldp/lldp.h"
#include "lldp/lldp_tlv.h"
#include "lldp/lldp_debug.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (LLDP_SUPPORT == ENABLED)


/**
 * @brief Add or replace a TLV
 * @param[in] lldpdu Pointer to the LLDP data unit
 * @param[in] type TLV type
 * @param[in] index TLV occurrence index
 * @param[in] value TLV information string
 * @param[in] length Length of the information string, in bytes
 * @param[in] replace Replace the existing TLV if a match is found
 * @return Error code
 **/

error_t lldpSetTlv(LldpDataUnit *lldpdu, uint8_t type, uint_t index,
   const uint8_t *value, size_t length, bool_t replace)
{
   error_t error;
   uint_t k;
   size_t oldLen;
   size_t newLen;
   LldpTlv tlv;
   LldpTlvHeader *header;

   //Initialize occurrence index
   k = 0;

   //Extract the first TLV
   error = lldpGetFirstTlv(lldpdu, &tlv);

   //Parse the LLDP data unit
   while(!error)
   {
      //Check TLV type
      if(tlv.type == type)
      {
         //Matching occurrence found?
         if(k++ == index)
         {
            //Insert a new TLV or replace the existing TLV
            break;
         }
      }
      else if(tlv.type > type)
      {
         //Insert a new TLV
         replace = FALSE;
         break;
      }
      else
      {
         //Just for sanity
      }

      //Extract the next TLV
      error = lldpGetNextTlv(lldpdu, &tlv);
   }

   //The End Of LLDPDU TLV marks the end of the LLDPDU
   if(error == ERROR_END_OF_STREAM)
   {
      //Insert a new TLV
      replace = FALSE;
      //Continue processing
      error = NO_ERROR;
   }

   //Check status code
   if(!error)
   {
      //Check whether the current TLV should be replaced
      if(replace)
      {
         //Calculate the length of the existing TLV
         oldLen = sizeof(LldpTlvHeader) + tlv.length;
         //Calculate the length of the new TLV
         newLen = sizeof(LldpTlvHeader) + length;

         //Ensure that the TLVs do not exceed the maximum length allowed for
         //the LLDPDU
         if((lldpdu->length - oldLen + newLen) <= LLDP_MAX_LLDPDU_SIZE)
         {
            //Make room for the new TLV
            if(newLen != oldLen)
            {
               osMemmove(lldpdu->data + tlv.pos + newLen, lldpdu->data + tlv.pos + oldLen,
                  lldpdu->length - tlv.pos - oldLen);
            }

            //Adjust the length of the LLDPDU
            lldpdu->length -= oldLen;
         }
         else
         {
            //Report an error
            error = ERROR_BUFFER_OVERFLOW;
         }
      }
      else
      {
         //Calculate the length of the new TLV
         newLen = sizeof(LldpTlvHeader) + length;

         //Ensure that the TLVs do not exceed the maximum length allowed for
         //the LLDPDU
         if((lldpdu->length + newLen) <= LLDP_MAX_LLDPDU_SIZE)
         {
            //Make room for the new TLV
            if(tlv.pos < lldpdu->length)
            {
               osMemmove(lldpdu->data + tlv.pos + newLen, lldpdu->data + tlv.pos,
                  lldpdu->length - tlv.pos);
            }
         }
         else
         {
            //Report an error
            error = ERROR_BUFFER_OVERFLOW;
         }
      }
   }

   //Check status code
   if(!error)
   {
      //Point to the buffer where to format the new TLV
      header = (LldpTlvHeader *) (lldpdu->data + tlv.pos);

      //Format TLV header
      header->type = type;
      header->lengthH = (length >> 8) & 0x01;
      header->lengthL = length & 0xFF;

      //Copy the TLV information string
      if(length > 0)
      {
         osMemcpy(header->value, value, length);
      }

      //Adjust the length of the LLDPDU
      lldpdu->length += sizeof(LldpTlvHeader) + length;
   }

   //Return status code
   return error;
}


/**
 * @brief Search a LLDPDU for a given TLV
 * @param[in] lldpdu Pointer to the LLDP data unit
 * @param[in] type TLV type
 * @param[in] index TLV occurrence index
 * @param[out] value TLV information string
 * @param[out] length Length of the information string, in bytes
 * @return Error code
 **/

error_t lldpGetTlv(LldpDataUnit *lldpdu, uint8_t type, uint_t index,
   const uint8_t **value, size_t *length)
{
   error_t error;
   uint_t k;
   LldpTlv tlv;

   //Initialize occurrence index
   k = 0;

   //Extract the first TLV
   error = lldpGetFirstTlv(lldpdu, &tlv);

   //Parse the LLDP data unit
   while(!error)
   {
      //Check TLV type
      if(tlv.type == type)
      {
         //Matching occurrence found?
         if(k++ == index)
         {
            //The specified TLV has been found
            *value = tlv.value;
            *length = tlv.length;

            //We are done
            break;
         }
      }

      //Extract the next TLV
      error = lldpGetNextTlv(lldpdu, &tlv);
   }

   //Return status code
   return error ? ERROR_NOT_FOUND : NO_ERROR;
}


/**
 * @brief Extract the first TLV from an LLDPDU
 * @param[in] lldpdu Pointer to the LLDP data unit
 * @param[out] tlv Next TLV
 * @return Error code
 **/

error_t lldpGetFirstTlv(LldpDataUnit *lldpdu, LldpTlv *tlv)
{
   //Rewind to the beginning of the LLDPDU
   lldpdu->pos = 0;

   //Extract the first TLV
   return lldpGetNextTlv(lldpdu, tlv);
}


/**
 * @brief Extract the next TLV from an LLDPDU
 * @param[in] lldpdu Pointer to the LLDP data unit
 * @param[out] tlv Next TLV
 * @return Error code
 **/

error_t lldpGetNextTlv(LldpDataUnit *lldpdu, LldpTlv *tlv)
{
   size_t n;
   LldpTlvHeader *header;

   //Initialize TLV
   tlv->pos = lldpdu->pos;
   tlv->type = 0;
   tlv->value = 0;
   tlv->length = 0;

   //End of LLDPDU detected?
   if(lldpdu->pos >= lldpdu->length)
      return ERROR_END_OF_STREAM;

   //Check whether the TLV extends past the physical end of the frame
   if((lldpdu->pos + sizeof(LldpTlvHeader)) > lldpdu->length)
      return ERROR_INVALID_SYNTAX;

   //Point to the current TLV
   header = (LldpTlvHeader *) (lldpdu->data + lldpdu->pos);

   //The least significant bit in the first octet of the TLV format is the
   //most significant bit of the TLV information string length field
   n = (header->lengthH << 8) | header->lengthL;

   //Check TLV length
   if((lldpdu->pos + sizeof(LldpTlvHeader) + n) > lldpdu->length)
      return ERROR_INVALID_SYNTAX;

   //The End Of LLDPDU TLV marks the end of the LLDPDU
   if(header->type == LLDP_TLV_TYPE_END_OF_LLDPDU)
      return ERROR_END_OF_STREAM;

   //Extract TLV parameters
   tlv->pos = lldpdu->pos;
   tlv->type = header->type;
   tlv->value = header->value;
   tlv->length = n;

   //Save the position of the next TLV
   lldpdu->pos += sizeof(LldpTlvHeader) + n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Remove a TLV from a LLDPDU
 * @param[in] lldpdu Pointer to the LLDP data unit
 * @param[in] type TLV type
 * @param[in] index TLV occurrence index
 * @return Error code
 **/

error_t lldpDeleteTlv(LldpDataUnit *lldpdu, uint8_t type, uint_t index)
{
   error_t error;
   uint_t k;
   LldpTlv tlv;

   //Initialize occurrence index
   k = 0;

   //Extract the first TLV
   error = lldpGetFirstTlv(lldpdu, &tlv);

   //Parse the LLDP data unit
   while(!error)
   {
      //Check TLV type
      if(tlv.type == type)
      {
         //Matching occurrence found?
         if(k++ == index)
         {
            //Remove the current TLV
            osMemmove(lldpdu->data + tlv.pos, lldpdu->data + lldpdu->pos,
               lldpdu->length - lldpdu->pos);

            //Adjust the length of the LLDPDU
            lldpdu->length -= tlv.length;

            //The specified TLV has been deleted
            error = NO_ERROR;

            //We are done
            break;
         }
      }

      //Extract the next TLV
      error = lldpGetNextTlv(lldpdu, &tlv);
   }

   //The End Of LLDPDU TLV marks the end of the LLDPDU
   if(error == ERROR_END_OF_STREAM)
   {
      error = ERROR_NOT_FOUND;
   }

   //Return status code
   return error;
}


/**
 * @brief Decode the contents of a Management Address TLV
 * @param[in] value Pointer to the TLV value to decode
 * @param[in] length Length of the TLV value, in bytes
 * @param[out] mgmtAddr1 First part of the Management Address TLV
 * @param[out] mgmtAddr2 Second part of the Management Address TLV
 * @return Error code
 **/

error_t lldpDecodeMgmtAddrTlv(const uint8_t *value, size_t length,
   const LldpMgmtAddrTlv1 **mgmtAddr1, const LldpMgmtAddrTlv2 **mgmtAddr2)
{
   LldpMgmtAddrTlv1 *part1;
   LldpMgmtAddrTlv2 *part2;

   //Malformed TLV?
   if(length < sizeof(LldpMgmtAddrTlv1))
      return ERROR_INVALID_SYNTAX;

   //Point to the first part of the Management Address TLV
   part1 = (LldpMgmtAddrTlv1 *) value;

   //Check the length of the management address
   if(part1->mgmtAddrLen < LLDP_MIN_MGMT_ADDR_LEN ||
      part1->mgmtAddrLen > LLDP_MAX_MGMT_ADDR_LEN)
   {
      return ERROR_INVALID_SYNTAX;
   }

   //Malformed TLV?
   if((sizeof(LldpMgmtAddrTlv1) + sizeof(LldpMgmtAddrTlv2) +
      part1->mgmtAddrLen - 1) > length)
   {
      return ERROR_INVALID_SYNTAX;
   }

   //Point to the second part of the Management Address TLV
   part2 = (LldpMgmtAddrTlv2 *) (part1->mgmtAddr + part1->mgmtAddrLen - 1);

   //Check the length of the OID
   if(part2->oidLen > LLDP_MAX_OID_LEN)
   {
      return ERROR_INVALID_SYNTAX;
   }

   //Malformed TLV?
   if((sizeof(LldpMgmtAddrTlv1) + sizeof(LldpMgmtAddrTlv2) +
      part1->mgmtAddrLen - 1 + part2->oidLen) > length)
   {
      return ERROR_INVALID_SYNTAX;
   }

   //Return a pointer to the first part of the Management Address TLV
   if(mgmtAddr1 != NULL)
   {
      *mgmtAddr1 = part1;
   }

   //Return a pointer to the second part of the Management Address TLV
   if(mgmtAddr2 != NULL)
   {
      *mgmtAddr2 = part2;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Add or replace an organizationally specific TLV
 * @param[in] lldpdu Pointer to the LLDP data unit
 * @param[in] oui Organizationally unique identifier
 * @param[in] subtype Organizationally defined subtype
 * @param[in] index TLV occurrence index
 * @param[in] value Organizationally defined information string
 * @param[in] length Length of the information string, in bytes
 * @param[in] replace Replace the existing TLV if a match is found
 * @return Error code
 **/

error_t lldpSetOrgDefTlv(LldpDataUnit *lldpdu, uint32_t oui, uint8_t subtype,
   uint_t index, const uint8_t *value, size_t length, bool_t replace)
{
   error_t error;
   size_t k;
   size_t n;
   size_t oldLen;
   size_t newLen;
   LldpTlv tlv;
   LldpTlvHeader *header;
   LldpOrgDefTlv *orgDefTlv;

   //Initialize occurrence index
   k = 0;

   //Extract the first TLV
   error = lldpGetFirstTlv(lldpdu, &tlv);

   //Parse the LLDP data unit
   while(!error)
   {
      //Check TLV type
      if(tlv.type == LLDP_TLV_TYPE_ORG_DEFINED)
      {
         //Malformed organizationally specific TLV?
         if(tlv.length < sizeof(LldpOrgDefTlv))
         {
            error = ERROR_INVALID_SYNTAX;
            break;
         }

         //Point to the organizationally specific tag
         orgDefTlv = (LldpOrgDefTlv *) tlv.value;

         //Check organizationally unique identifier
         if(LOAD24BE(orgDefTlv->oui) == oui)
         {
            //Check TLV subtype
            if(orgDefTlv->subtype == subtype)
            {
               //Matching occurrence found?
               if(k++ == index)
               {
                  //Insert a new TLV or replace the existing TLV
                  break;
               }
            }
            else if(orgDefTlv->subtype > subtype)
            {
               //Insert a new TLV
               replace = FALSE;
               break;
            }
            else
            {
               //Just for sanity
            }
         }
         else if(LOAD24BE(orgDefTlv->oui) > oui)
         {
            //Insert a new TLV
            replace = FALSE;
            break;
         }
         else
         {
            //Just for sanity
         }
      }
      else if(tlv.type > LLDP_TLV_TYPE_ORG_DEFINED)
      {
         //Insert a new TLV
         replace = FALSE;
         break;
      }
      else
      {
         //Just for sanity
      }

      //Extract the next TLV
      error = lldpGetNextTlv(lldpdu, &tlv);
   }

   //The End Of LLDPDU TLV marks the end of the LLDPDU
   if(error == ERROR_END_OF_STREAM)
   {
      //Insert a new TLV
      replace = FALSE;
      //Continue processing
      error = NO_ERROR;
   }

   //Check status code
   if(!error)
   {
      //Check whether the current TLV should be replaced
      if(replace)
      {
         //Calculate the length of the existing TLV
         oldLen = sizeof(LldpTlvHeader) + tlv.length;
         //Calculate the length of the new TLV
         newLen = sizeof(LldpTlvHeader) + sizeof(LldpOrgDefTlv) + length;

         //Ensure that the TLVs do not exceed the maximum length allowed for
         //the LLDPDU
         if((lldpdu->length - oldLen + newLen) <= LLDP_MAX_LLDPDU_SIZE)
         {
            //Make room for the new TLV
            if(newLen != oldLen)
            {
               osMemmove(lldpdu->data + tlv.pos + newLen, lldpdu->data + tlv.pos + oldLen,
                  lldpdu->length - tlv.pos - oldLen);
            }

            //Adjust the length of the LLDPDU
            lldpdu->length -= oldLen;
         }
         else
         {
            //Report an error
            error = ERROR_BUFFER_OVERFLOW;
         }
      }
      else
      {
         //Calculate the length of the new TLV
         newLen = sizeof(LldpTlvHeader) + sizeof(LldpOrgDefTlv) + length;

         //Ensure that the TLVs do not exceed the maximum length allowed for
         //the LLDPDU
         if((lldpdu->length + newLen) <= LLDP_MAX_LLDPDU_SIZE)
         {
            //Make room for the new TLV
            if(tlv.pos < lldpdu->length)
            {
               osMemmove(lldpdu->data + tlv.pos + newLen, lldpdu->data + tlv.pos,
                  lldpdu->length - tlv.pos);
            }
         }
         else
         {
            //Report an error
            error = ERROR_BUFFER_OVERFLOW;
         }
      }
   }

   //Check status code
   if(!error)
   {
      //Calculate the length of the TLV value field
      n = sizeof(LldpOrgDefTlv) + length;

      //Point to the buffer where to format the new TLV
      header = (LldpTlvHeader *) (lldpdu->data + tlv.pos);

      //Format TLV header
      header->type = LLDP_TLV_TYPE_ORG_DEFINED;
      header->lengthH = (n >> 8) & 0x01;
      header->lengthL = n & 0xFF;

      //Point to the organizationally specific TLV header
      orgDefTlv = (LldpOrgDefTlv *) header->value;

      //The organizationally unique identifier field shall contain the
      //organization's OUI
      STORE24BE(oui, orgDefTlv->oui);

      //The organizationally defined subtype field shall contain a unique
      //subtype value assigned by the defining organization
      orgDefTlv->subtype = subtype;

      //Copy the organizationally defined information string
      if(length > 0)
      {
         osMemcpy(orgDefTlv->value, value, length);
      }

      //Adjust the length of the LLDPDU
      lldpdu->length += sizeof(LldpTlvHeader) + n;
   }

   //Return status code
   return error;
}


/**
 * @brief Search an LLDPDU for an organizationally specific TLV
 * @param[in] lldpdu Pointer to the LLDP data unit
 * @param[in] oui Organizationally unique identifier
 * @param[in] subtype Organizationally defined subtype
 * @param[in] index TLV occurrence index
 * @param[out] value Organizationally defined information string
 * @param[out] length Length of the information string, in bytes
 * @return Error code
 **/

error_t lldpGetOrgDefTlv(LldpDataUnit *lldpdu, uint32_t oui, uint8_t subtype,
   uint_t index, const uint8_t **value, size_t *length)
{
   error_t error;
   uint_t k;
   LldpTlv tlv;
   const LldpOrgDefTlv *orgDefTlv;

   //Initialize occurrence index
   k = 0;

   //Extract the first TLV
   error = lldpGetFirstTlv(lldpdu, &tlv);

   //Parse the LLDP data unit
   while(!error)
   {
      //Check TLV type
      if(tlv.type == LLDP_TLV_TYPE_ORG_DEFINED)
      {
         //Malformed TLV?
         if(tlv.length < sizeof(LldpOrgDefTlv))
         {
            error = ERROR_INVALID_SYNTAX;
            break;
         }

         //Point to the organizationally specific information
         orgDefTlv = (const LldpOrgDefTlv *) tlv.value;

         //Check organizationally unique identifier
         if(LOAD24BE(orgDefTlv->oui) == oui)
         {
            //Check TLV subtype
            if(orgDefTlv->subtype == subtype)
            {
               //Matching occurrence found?
               if(k++ == index)
               {
                  //The specified TLV has been found
                  *value = tlv.value + sizeof(LldpOrgDefTlv);
                  *length = tlv.length - sizeof(LldpOrgDefTlv);

                  //We are done
                  break;
               }
            }
         }
      }

      //Extract the next TLV
      error = lldpGetNextTlv(lldpdu, &tlv);
   }

   //Return status code
   return error ? ERROR_NOT_FOUND : NO_ERROR;
}


/**
 * @brief Remove an organizationally specific TLV from a LLDPDU
 * @param[in] lldpdu Pointer to the LLDP data unit
 * @param[in] oui Organizationally unique identifier
 * @param[in] subtype Organizationally defined subtype
 * @param[in] index TLV occurrence index
 * @return Error code
 **/

error_t lldpDeleteOrgDefTlv(LldpDataUnit *lldpdu, uint32_t oui, uint8_t subtype,
   uint_t index)
{
   error_t error;
   uint_t k;
   LldpTlv tlv;
   const LldpOrgDefTlv *orgDefTlv;

   //Initialize occurrence index
   k = 0;

   //Extract the first TLV
   error = lldpGetFirstTlv(lldpdu, &tlv);

   //Parse the LLDP data unit
   while(!error)
   {
      //Check TLV type
      if(tlv.type == LLDP_TLV_TYPE_ORG_DEFINED)
      {
         //Malformed TLV?
         if(tlv.length < sizeof(LldpOrgDefTlv))
         {
            error = ERROR_INVALID_SYNTAX;
            break;
         }

         //Point to the organizationally specific tag
         orgDefTlv = (LldpOrgDefTlv *) tlv.value;

         //Check organizationally unique identifier
         if(LOAD24BE(orgDefTlv->oui) == oui)
         {
            //Check TLV subtype
            if(orgDefTlv->subtype == subtype)
            {
               //Matching occurrence found?
               if(k++ == index)
               {
                  //Remove the current TLV
                  osMemmove(lldpdu->data + tlv.pos, lldpdu->data + lldpdu->pos,
                     lldpdu->length - lldpdu->pos);

                  //Adjust the length of the LLDPDU
                  lldpdu->length -= tlv.length;

                  //We are done
                  break;
               }
            }
         }
      }

      //Extract the next TLV
      error = lldpGetNextTlv(lldpdu, &tlv);
   }

   //The End Of LLDPDU TLV marks the end of the LLDPDU
   if(error == ERROR_END_OF_STREAM)
   {
      error = ERROR_NOT_FOUND;
   }

   //Return status code
   return error;
}

#endif
