/**
 * @file lldp_mib_impl_remote.c
 * @brief LLDP MIB module implementation (lldpRemoteSystemsData subtree)
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
#define TRACE_LEVEL SNMP_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "mibs/mib_common.h"
#include "mibs/lldp_mib_module.h"
#include "mibs/lldp_mib_impl.h"
#include "mibs/lldp_mib_impl_remote.h"
#include "core/crypto.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "lldp/lldp_mgmt.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (LLDP_MIB_SUPPORT == ENABLED && LLDP_RX_MODE_SUPPORT == ENABLED)


/**
 * @brief Get lldpRemEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpRemEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   size_t n;
   uint_t lldpRemTimeMark;
   uint_t lldpRemLocalPortNum;
   uint_t lldpRemIndex;
   LldpNeighborEntry *entry;

   //Point to the instance identifier
   n = object->oidLen;

   //lldpRemTimeMark is used as 1st instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &lldpRemTimeMark);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemLocalPortNum is used as 2nd instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &lldpRemLocalPortNum);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemIndex is used as 3rd instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &lldpRemIndex);
   //Invalid instance identifier?
   if(error)
      return error;

   //Sanity check
   if(n != oidLen)
      return ERROR_INSTANCE_NOT_FOUND;

   //Search the remote systems MIB for a matching row
   entry = lldpMgmtFindRemoteTableEntry(lldpMibBase.lldpAgentContext,
      lldpRemTimeMark, lldpRemLocalPortNum, lldpRemIndex);
   //No matching row found?
   if(entry == NULL)
      return ERROR_INSTANCE_NOT_FOUND;

   //lldpRemChassisIdSubtype object?
   if(!strcmp(object->name, "lldpRemChassisIdSubtype"))
   {
      LldpChassisIdSubtype chassisIdSubtype;
      const uint8_t *chassisId;
      size_t chassisIdLen;

      //This object indicates the type of encoding used to identify the
      //chassis associated with the remote system
      error = lldpMgmtGetRemoteChassisId(entry, &chassisIdSubtype, &chassisId,
         &chassisIdLen);

      //Check status code
      if(!error)
      {
         //Return object value
         value->integer = (int32_t) chassisIdSubtype;
      }
   }
   //lldpRemChassisId object?
   else if(!strcmp(object->name, "lldpRemChassisId"))
   {
      LldpChassisIdSubtype chassisIdSubtype;
      const uint8_t *chassisId;
      size_t chassisIdLen;

      //This object identifies the chassis component associated with the
      //remote system
      error = lldpMgmtGetRemoteChassisId(entry, &chassisIdSubtype, &chassisId,
         &chassisIdLen);

      //Check status code
      if(!error)
      {
         //Make sure the buffer is large enough to hold the entire object
         if(*valueLen >= chassisIdLen)
         {
            //Copy object value
            osMemcpy(value->octetString, chassisId, chassisIdLen);
            //Return object length
            *valueLen = chassisIdLen;
         }
         else
         {
            //Report an error
            error = ERROR_BUFFER_OVERFLOW;
         }
      }
   }
   //lldpRemPortIdSubtype object?
   else if(!strcmp(object->name, "lldpRemPortIdSubtype"))
   {
      LldpPortIdSubtype portIdSubtype;
      const uint8_t *portId;
      size_t portIdLen;

      //This object indicates the type of port identifier encoding used in
      //the associated lldpRemPortId object
      error = lldpMgmtGetRemotePortId(entry, &portIdSubtype, &portId,
         &portIdLen);

      //Check status code
      if(!error)
      {
         //Return object value
         value->integer = (int32_t) portIdSubtype;
      }
   }
   //lldpRemPortId object?
   else if(!strcmp(object->name, "lldpRemPortId"))
   {
      LldpPortIdSubtype portIdSubtype;
      const uint8_t *portId;
      size_t portIdLen;

      //This object identifies the port component associated with a given port
      //in the remote system
      error = lldpMgmtGetRemotePortId(entry, &portIdSubtype, &portId,
         &portIdLen);

      //Check status code
      if(!error)
      {
         //Make sure the buffer is large enough to hold the entire object
         if(*valueLen >= portIdLen)
         {
            //Copy object value
            osMemcpy(value->octetString, portId, portIdLen);
            //Return object length
            *valueLen = portIdLen;
         }
         else
         {
            //Report an error
            error = ERROR_BUFFER_OVERFLOW;
         }
      }
   }
   //lldpRemPortDesc object?
   else if(!strcmp(object->name, "lldpRemPortDesc"))
   {
      const char_t *portDesc;
      size_t portDescLen;

      //This object identifies the description associated of the given port
      //associated with the remote system
      error = lldpMgmtGetRemotePortDesc(entry, &portDesc, &portDescLen);

      //Check status code
      if(!error)
      {
         //Make sure the buffer is large enough to hold the entire object
         if(*valueLen >= portDescLen)
         {
            //Copy object value
            osMemcpy(value->octetString, portDesc, portDescLen);
            //Return object length
            *valueLen = portDescLen;
         }
         else
         {
            //Report an error
            error = ERROR_BUFFER_OVERFLOW;
         }
      }
   }
   //lldpRemSysName object?
   else if(!strcmp(object->name, "lldpRemSysName"))
   {
      const char_t *sysName;
      size_t sysNameLen;

      //This object identifies the system name of the remote system
      error = lldpMgmtGetRemoteSysName(entry, &sysName, &sysNameLen);

      //Check status code
      if(!error)
      {
         //Make sure the buffer is large enough to hold the entire object
         if(*valueLen >= sysNameLen)
         {
            //Copy object value
            osMemcpy(value->octetString, sysName, sysNameLen);
            //Return object length
            *valueLen = sysNameLen;
         }
         else
         {
            //Report an error
            error = ERROR_BUFFER_OVERFLOW;
         }
      }
   }
   //lldpRemSysDesc object?
   else if(!strcmp(object->name, "lldpRemSysDesc"))
   {
      const char_t *sysDesc;
      size_t sysDescLen;

      //This object identifies the system description of the remote system
      error = lldpMgmtGetRemoteSysDesc(entry, &sysDesc, &sysDescLen);

      //Check status code
      if(!error)
      {
         //Make sure the buffer is large enough to hold the entire object
         if(*valueLen >= sysDescLen)
         {
            //Copy object value
            osMemcpy(value->octetString, sysDesc, sysDescLen);
            //Return object length
            *valueLen = sysDescLen;
         }
         else
         {
            //Report an error
            error = ERROR_BUFFER_OVERFLOW;
         }
      }
   }
   //lldpRemSysCapSupported object?
   else if(!strcmp(object->name, "lldpRemSysCapSupported"))
   {
      error_t error;
      uint16_t supportedCap;
      uint16_t enabledCap;

      //This object identifies which system capabilities are supported on the
      //remote system
      error = lldpMgmtGetRemoteSysCap(entry, &supportedCap, &enabledCap);

      //Check status code
      if(!error)
      {
         //Each bit in the bitmap corresponds to a given capability
         if(supportedCap != 0)
         {
            //Make sure the buffer is large enough to hold the entire object
            if(*valueLen >= sizeof(uint8_t))
            {
               //Copy object value
               value->octetString[0] = reverseInt8((uint8_t) supportedCap);
               //Return object length
               *valueLen = sizeof(uint8_t);
            }
            else
            {
               //Report an error
               error = ERROR_BUFFER_OVERFLOW;
            }
         }
         else
         {
            //An empty set means that no enumerated values are set
            *valueLen = 0;
         }
      }
   }
   //lldpRemSysCapEnabled object?
   else if(!strcmp(object->name, "lldpRemSysCapEnabled"))
   {
      error_t error;
      uint16_t supportedCap;
      uint16_t enabledCap;

      //This object identifies which system capabilities are enabled on the
      //remote system
      error = lldpMgmtGetRemoteSysCap(entry, &supportedCap, &enabledCap);

      //Check status code
      if(!error)
      {
         //Each bit in the bitmap corresponds to a given capability
         if(supportedCap != 0)
         {
            //Make sure the buffer is large enough to hold the entire object
            if(*valueLen >= sizeof(uint8_t))
            {
               //Copy object value
               value->octetString[0] = reverseInt8((uint8_t) enabledCap);
               //Return object length
               *valueLen = sizeof(uint8_t);
            }
            else
            {
               //Report an error
               error = ERROR_BUFFER_OVERFLOW;
            }
         }
         else
         {
            //An empty set means that no enumerated values are set
            *valueLen = 0;
         }
      }
   }
   //Unknown object?
   else
   {
      //The specified object does not exist
      error = ERROR_OBJECT_NOT_FOUND;
   }

   //Return status code
   return error;
}


/**
 * @brief Get next lldpRemEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t lldpMibGetNextLldpRemEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, uint8_t *nextOid, size_t *nextOidLen)
{
   error_t error;
   uint_t i;
   size_t n;
   bool_t acceptable;
   LldpAgentContext *context;
   LldpNeighborEntry *entry;
   LldpNeighborEntry *nextEntry;

   //Initialize variables
   nextEntry = NULL;

   //Point to the LLDP agent context
   context = lldpMibBase.lldpAgentContext;
   //Make sure the context is valid
   if(context == NULL)
      return ERROR_OBJECT_NOT_FOUND;

   //Make sure the buffer is large enough to hold the OID prefix
   if(*nextOidLen < object->oidLen)
      return ERROR_BUFFER_OVERFLOW;

   //Copy OID prefix
   osMemcpy(nextOid, object->oid, object->oidLen);

   //Loop through the remote systems MIB
   for(i = 0; i < context->numNeighbors; i++)
   {
      //Point to the current entry
      entry = &context->neighbors[i];

      //Check whether the entry is valid
      if(entry->rxInfo.length > 0)
      {
         //Append the instance identifier to the OID prefix
         n = object->oidLen;

         //lldpRemTimeMark is used as 1st instance identifier
         error = mibEncodeIndex(nextOid, *nextOidLen, &n, entry->timeMark);
         //Invalid instance identifier?
         if(error)
            return error;

         //lldpRemLocalPortNum is used as 2nd instance identifier
         error = mibEncodeIndex(nextOid, *nextOidLen, &n, entry->portIndex);
         //Invalid instance identifier?
         if(error)
            return error;

         //lldpRemIndex is used as 3rd instance identifier
         error = mibEncodeIndex(nextOid, *nextOidLen, &n, entry->index);
         //Invalid instance identifier?
         if(error)
            return error;

         //Check whether the resulting object identifier lexicographically
         //follows the specified OID
         if(oidComp(nextOid, n, oid, oidLen) > 0)
         {
            //Perform lexicographic comparison
            if(nextEntry == NULL)
            {
               acceptable = TRUE;
            }
            else if(entry->timeMark < nextEntry->timeMark)
            {
               acceptable = TRUE;
            }
            else if(entry->timeMark > nextEntry->timeMark)
            {
               acceptable = FALSE;
            }
            else if(entry->portIndex < nextEntry->portIndex)
            {
               acceptable = TRUE;
            }
            else if(entry->portIndex > nextEntry->portIndex)
            {
               acceptable = FALSE;
            }
            else if(entry->index < nextEntry->index)
            {
               acceptable = TRUE;
            }
            else
            {
               acceptable = FALSE;
            }

            //Save the closest object identifier that follows the specified
            //OID in lexicographic order
            if(acceptable)
            {
               nextEntry = entry;
            }
         }
      }
   }

   //The specified OID does not lexicographically precede the name
   //of some object?
   if(nextEntry == NULL)
      return ERROR_OBJECT_NOT_FOUND;

   //Append the instance identifier to the OID prefix
   n = object->oidLen;

   //lldpRemTimeMark is used as 1st instance identifier
   error = mibEncodeIndex(nextOid, *nextOidLen, &n, nextEntry->timeMark);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemLocalPortNum is used as 2nd instance identifier
   error = mibEncodeIndex(nextOid, *nextOidLen, &n, nextEntry->portIndex);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemIndex is used as 3rd instance identifier
   error = mibEncodeIndex(nextOid, *nextOidLen, &n, nextEntry->index);
   //Invalid instance identifier?
   if(error)
      return error;

   //Save the length of the resulting object identifier
   *nextOidLen = n;
   //Next object found
   return NO_ERROR;
}


/**
 * @brief Get lldpRemManAddrEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpRemManAddrEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   size_t n;
   int_t index;
   uint_t lldpRemTimeMark;
   uint_t lldpRemLocalPortNum;
   uint_t lldpRemIndex;
   uint_t lldpRemManAddrSubtype;
   uint8_t lldpRemManAddr[LLDP_MAX_MGMT_ADDR_LEN];
   size_t lldpRemManAddrLen;
   LldpNeighborEntry *entry;
   LldpIfNumSubtype ifNumSubtype;
   uint32_t ifNum;
   const uint8_t *addrOid;
   size_t addrOidLen;

   //Point to the instance identifier
   n = object->oidLen;

   //lldpRemTimeMark is used as 1st instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &lldpRemTimeMark);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemLocalPortNum is used as 2nd instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &lldpRemLocalPortNum);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemIndex is used as 3rd instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &lldpRemIndex);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemManAddrSubtype is used as 4th instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &lldpRemManAddrSubtype);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemManAddr is used as 5th instance identifier
   error = mibDecodeOctetString(oid, oidLen, &n, lldpRemManAddr,
      LLDP_MAX_MGMT_ADDR_LEN, &lldpRemManAddrLen, FALSE);
   //Invalid instance identifier?
   if(error)
      return error;

   //Sanity check
   if(n != oidLen)
      return ERROR_INSTANCE_NOT_FOUND;

   //Search the remote systems MIB for a matching row
   entry = lldpMgmtFindRemoteTableEntry(lldpMibBase.lldpAgentContext,
      lldpRemTimeMark, lldpRemLocalPortNum, lldpRemIndex);
   //No matching row found?
   if(entry == NULL)
      return ERROR_INSTANCE_NOT_FOUND;

   //Search the remote systems MIB for a matching address
   index = lldpMgmtFindRemoteMgmtAddr(entry, lldpRemManAddrSubtype,
      lldpRemManAddr, lldpRemManAddrLen);
   //No matching address found?
   if(index < 0)
      return ERROR_INSTANCE_NOT_FOUND;

   //Extract the management address from the remote systems MIB
   error = lldpMgmtGetRemoteMgmtAddr(entry, index, NULL, NULL, NULL,
      &ifNumSubtype, &ifNum, &addrOid, &addrOidLen);
   //No matching address found?
   if(error)
      return ERROR_INSTANCE_NOT_FOUND;

   //lldpRemManAddrIfSubtype object?
   if(!strcmp(object->name, "lldpRemManAddrIfSubtype"))
   {
      //This object identifies the interface numbering method used for defining
      //the interface number, associated with the remote system
      if(ifNumSubtype == LLDP_IF_NUM_SUBTYPE_IF_INDEX)
      {
         //interface identifier based on the ifIndex MIB object
         value->integer = LLDP_MIB_MAN_ADDR_IF_SUBTYPE_IF_INDEX;
      }
      else if(ifNumSubtype == LLDP_IF_NUM_SUBTYPE_SYS_PORT_NUM)
      {
         //interface identifier based on the system port numbering convention
         value->integer = LLDP_MIB_MAN_ADDR_IF_SUBTYPE_SYS_PORT_NUM;
      }
      else
      {
         //The interface is not known
         value->integer = LLDP_MIB_MAN_ADDR_IF_SUBTYPE_UNKNOWN;
      }
   }
   //lldpRemManAddrIfId object?
   else if(!strcmp(object->name, "lldpRemManAddrIfId"))
   {
      //This object identifies the interface number regarding the management
      //address component associated with the remote system
      value->integer = ifNum;
   }
   //lldpRemManAddrOID object?
   else if(!strcmp(object->name, "lldpRemManAddrOID"))
   {
      //Make sure the buffer is large enough to hold the entire object
      if(*valueLen >= addrOidLen)
      {
         //Copy object value
         osMemcpy(value->octetString, addrOid, addrOidLen);
         //Return object length
         *valueLen = addrOidLen;
      }
      else
      {
         //Report an error
         error = ERROR_BUFFER_OVERFLOW;
      }
   }
   //Unknown object?
   else
   {
      //The specified object does not exist
      error = ERROR_OBJECT_NOT_FOUND;
   }

   //Return status code
   return error;
}


/**
 * @brief Get next lldpRemManAddrEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t lldpMibGetNextLldpRemManAddrEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, uint8_t *nextOid, size_t *nextOidLen)
{
   error_t error;
   uint_t i;
   size_t n;
   bool_t acceptable;
   LldpTlv tlv;
   LldpAgentContext *context;
   LldpNeighborEntry *entry;
   LldpNeighborEntry *nextEntry;
   const LldpMgmtAddrTlv1 *addr;
   const LldpMgmtAddrTlv1 *nextAddr;

   //Initialize variables
   nextEntry = NULL;
   nextAddr = NULL;

   //Point to the LLDP agent context
   context = lldpMibBase.lldpAgentContext;
   //Make sure the context is valid
   if(context == NULL)
      return ERROR_OBJECT_NOT_FOUND;

   //Make sure the buffer is large enough to hold the OID prefix
   if(*nextOidLen < object->oidLen)
      return ERROR_BUFFER_OVERFLOW;

   //Copy OID prefix
   osMemcpy(nextOid, object->oid, object->oidLen);

   //Loop through the remote systems MIB
   for(i = 0; i < context->numNeighbors; i++)
   {
      //Point to the current entry
      entry = &context->neighbors[i];

      //Check whether the entry is valid
      if(entry->rxInfo.length > 0)
      {
         //Extract the first TLV
         error = lldpGetFirstTlv(&entry->rxInfo, &tlv);

         //Loop through the TLVs
         while(!error)
         {
            //Check TLV type
            if(tlv.type == LLDP_TLV_TYPE_MGMT_ADDR)
            {
               //Decode the contents of the Management Address TLV
               error = lldpDecodeMgmtAddrTlv(tlv.value, tlv.length, &addr, NULL);
               //Malformed TLV?
               if(error)
               {
                  break;
               }

               //Append the instance identifier to the OID prefix
               n = object->oidLen;

               //lldpRemTimeMark is used as 1st instance identifier
               error = mibEncodeIndex(nextOid, *nextOidLen, &n, entry->timeMark);
               //Invalid instance identifier?
               if(error)
                  return error;

               //lldpRemLocalPortNum is used as 2nd instance identifier
               error = mibEncodeIndex(nextOid, *nextOidLen, &n, entry->portIndex);
               //Invalid instance identifier?
               if(error)
                  return error;

               //lldpRemIndex is used as 3rd instance identifier
               error = mibEncodeIndex(nextOid, *nextOidLen, &n, entry->index);
               //Invalid instance identifier?
               if(error)
                  return error;

               //lldpRemManAddrSubtype is used as 4th instance identifier
               error = mibEncodeIndex(nextOid, *nextOidLen, &n,
                  addr->mgmtAddrSubtype);
               //Invalid instance identifier?
               if(error)
                  return error;

               //lldpRemManAddr is used as 5th instance identifier
               error = mibEncodeOctetString(nextOid, *nextOidLen, &n,
                  addr->mgmtAddr, addr->mgmtAddrLen - 1, FALSE);
               //Invalid instance identifier?
               if(error)
                  return error;

               //Check whether the resulting object identifier lexicographically
               //follows the specified OID
               if(oidComp(nextOid, n, oid, oidLen) > 0)
               {
                  //Perform lexicographic comparison
                  if(nextEntry == NULL || nextAddr == NULL)
                  {
                     acceptable = TRUE;
                  }
                  else if(entry->timeMark < nextEntry->timeMark)
                  {
                     acceptable = TRUE;
                  }
                  else if(entry->timeMark > nextEntry->timeMark)
                  {
                     acceptable = FALSE;
                  }
                  else if(entry->portIndex < nextEntry->portIndex)
                  {
                     acceptable = TRUE;
                  }
                  else if(entry->portIndex > nextEntry->portIndex)
                  {
                     acceptable = FALSE;
                  }
                  else if(entry->index < nextEntry->index)
                  {
                     acceptable = TRUE;
                  }
                  else if(entry->index > nextEntry->index)
                  {
                     acceptable = FALSE;
                  }
                  else if(addr->mgmtAddrSubtype < nextAddr->mgmtAddrSubtype)
                  {
                     acceptable = TRUE;
                  }
                  else if(addr->mgmtAddrSubtype > nextAddr->mgmtAddrSubtype)
                  {
                     acceptable = FALSE;
                  }
                  else if(addr->mgmtAddrLen < nextAddr->mgmtAddrLen)
                  {
                     acceptable = TRUE;
                  }
                  else if(addr->mgmtAddrLen > nextAddr->mgmtAddrLen)
                  {
                     acceptable = FALSE;
                  }
                  else if(osMemcmp(addr->mgmtAddr, nextAddr->mgmtAddr,
                     nextAddr->mgmtAddrLen) < 0)
                  {
                     acceptable = TRUE;
                  }
                  else
                  {
                     acceptable = FALSE;
                  }

                  //Save the closest object identifier that follows the specified
                  //OID in lexicographic order
                  if(acceptable)
                  {
                     nextEntry = entry;
                     nextAddr = addr;
                  }
               }
            }

            //Extract the next TLV
            error = lldpGetNextTlv(&entry->rxInfo, &tlv);
         }
      }
   }

   //The specified OID does not lexicographically precede the name
   //of some object?
   if(nextEntry == NULL || nextAddr == NULL)
      return ERROR_OBJECT_NOT_FOUND;

   //Append the instance identifier to the OID prefix
   n = object->oidLen;

   //lldpRemTimeMark is used as 1st instance identifier
   error = mibEncodeIndex(nextOid, *nextOidLen, &n, nextEntry->timeMark);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemLocalPortNum is used as 2nd instance identifier
   error = mibEncodeIndex(nextOid, *nextOidLen, &n, nextEntry->portIndex);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemIndex is used as 3rd instance identifier
   error = mibEncodeIndex(nextOid, *nextOidLen, &n, nextEntry->index);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemManAddrSubtype is used as 4th instance identifier
   error = mibEncodeIndex(nextOid, *nextOidLen, &n, nextAddr->mgmtAddrSubtype);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemManAddr is used as 5th instance identifier
   error = mibEncodeOctetString(nextOid, *nextOidLen, &n, nextAddr->mgmtAddr,
      nextAddr->mgmtAddrLen - 1, FALSE);
   //Invalid instance identifier?
   if(error)
      return error;

   //Save the length of the resulting object identifier
   *nextOidLen = n;
   //Next object found
   return NO_ERROR;
}


/**
 * @brief Get lldpRemUnknownTLVEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpRemUnknownTLVEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   size_t n;
   uint_t lldpRemTimeMark;
   uint_t lldpRemLocalPortNum;
   uint_t lldpRemIndex;
   uint_t lldpRemUnknownTLVType;
   LldpNeighborEntry *entry;
   const uint8_t *info;
   size_t infoLen;

   //Point to the instance identifier
   n = object->oidLen;

   //lldpRemTimeMark is used as 1st instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &lldpRemTimeMark);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemLocalPortNum is used as 2nd instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &lldpRemLocalPortNum);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemIndex is used as 3rd instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &lldpRemIndex);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemUnknownTLVType is used as 4th instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &lldpRemUnknownTLVType);
   //Invalid instance identifier?
   if(error)
      return error;

   //Sanity check
   if(n != oidLen)
      return ERROR_INSTANCE_NOT_FOUND;

   //Search the remote systems MIB for a matching row
   entry = lldpMgmtFindRemoteTableEntry(lldpMibBase.lldpAgentContext,
      lldpRemTimeMark, lldpRemLocalPortNum, lldpRemIndex);
   //No matching row found?
   if(entry == NULL)
      return ERROR_INSTANCE_NOT_FOUND;

   //Search the remote systems MIB for a matching TLV
   error = lldpMgmtGetRemoteUnknownTlv(entry, lldpRemUnknownTLVType, 0,
      &info, &infoLen);
   //No matching TLV found?
   if(error)
      return ERROR_INSTANCE_NOT_FOUND;

   //lldpRemUnknownTLVInfo object?
   if(!strcmp(object->name, "lldpRemUnknownTLVInfo"))
   {
      //Make sure the buffer is large enough to hold the entire object
      if(*valueLen >= infoLen)
      {
         //Copy object value
         osMemcpy(value->octetString, info, infoLen);
         //Return object length
         *valueLen = infoLen;
      }
      else
      {
         //Report an error
         error = ERROR_BUFFER_OVERFLOW;
      }
   }
   //Unknown object?
   else
   {
      //The specified object does not exist
      error = ERROR_OBJECT_NOT_FOUND;
   }

   //Return status code
   return error;
}


/**
 * @brief Get next lldpRemUnknownTLVEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t lldpMibGetNextLldpRemUnknownTLVEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, uint8_t *nextOid, size_t *nextOidLen)
{
   error_t error;
   uint_t i;
   size_t n;
   bool_t acceptable;
   LldpTlv tlv;
   LldpAgentContext *context;
   LldpNeighborEntry *entry;
   LldpNeighborEntry *nextEntry;
   uint8_t nextType;

   //Initialize variables
   nextEntry = NULL;
   nextType = 0;

   //Point to the LLDP agent context
   context = lldpMibBase.lldpAgentContext;
   //Make sure the context is valid
   if(context == NULL)
      return ERROR_OBJECT_NOT_FOUND;

   //Make sure the buffer is large enough to hold the OID prefix
   if(*nextOidLen < object->oidLen)
      return ERROR_BUFFER_OVERFLOW;

   //Copy OID prefix
   osMemcpy(nextOid, object->oid, object->oidLen);

   //Loop through the remote systems MIB
   for(i = 0; i < context->numNeighbors; i++)
   {
      //Point to the current entry
      entry = &context->neighbors[i];

      //Check whether the entry is valid
      if(entry->rxInfo.length > 0)
      {
         //Extract the first TLV
         error = lldpGetFirstTlv(&entry->rxInfo, &tlv);

         //Loop through the TLVs
         while(!error)
         {
            //Unrecognized TLV?
            if(tlv.type > LLDP_TLV_TYPE_MGMT_ADDR &&
               tlv.type < LLDP_TLV_TYPE_ORG_DEFINED)
            {
               //Append the instance identifier to the OID prefix
               n = object->oidLen;

               //lldpRemTimeMark is used as 1st instance identifier
               error = mibEncodeIndex(nextOid, *nextOidLen, &n, entry->timeMark);
               //Invalid instance identifier?
               if(error)
                  return error;

               //lldpRemLocalPortNum is used as 2nd instance identifier
               error = mibEncodeIndex(nextOid, *nextOidLen, &n, entry->portIndex);
               //Invalid instance identifier?
               if(error)
                  return error;

               //lldpRemIndex is used as 3rd instance identifier
               error = mibEncodeIndex(nextOid, *nextOidLen, &n, entry->index);
               //Invalid instance identifier?
               if(error)
                  return error;

               //lldpRemUnknownTLVType is used as 4th instance identifier
               error = mibEncodeIndex(nextOid, *nextOidLen, &n, tlv.type);
               //Invalid instance identifier?
               if(error)
                  return error;

               //Check whether the resulting object identifier lexicographically
               //follows the specified OID
               if(oidComp(nextOid, n, oid, oidLen) > 0)
               {
                  //Perform lexicographic comparison
                  if(nextEntry == NULL || nextType == 0)
                  {
                     acceptable = TRUE;
                  }
                  else if(entry->timeMark < nextEntry->timeMark)
                  {
                     acceptable = TRUE;
                  }
                  else if(entry->timeMark > nextEntry->timeMark)
                  {
                     acceptable = FALSE;
                  }
                  else if(entry->portIndex < nextEntry->portIndex)
                  {
                     acceptable = TRUE;
                  }
                  else if(entry->portIndex > nextEntry->portIndex)
                  {
                     acceptable = FALSE;
                  }
                  else if(entry->index < nextEntry->index)
                  {
                     acceptable = TRUE;
                  }
                  else if(entry->index > nextEntry->index)
                  {
                     acceptable = FALSE;
                  }
                  else if(tlv.type < nextType)
                  {
                     acceptable = TRUE;
                  }
                  else
                  {
                     acceptable = FALSE;
                  }

                  //Save the closest object identifier that follows the specified
                  //OID in lexicographic order
                  if(acceptable)
                  {
                     nextEntry = entry;
                     nextType = tlv.type;
                  }
               }
            }

            //Extract the next TLV
            error = lldpGetNextTlv(&entry->rxInfo, &tlv);
         }
      }
   }

   //The specified OID does not lexicographically precede the name
   //of some object?
   if(nextEntry == NULL || nextType == 0)
      return ERROR_OBJECT_NOT_FOUND;

   //Append the instance identifier to the OID prefix
   n = object->oidLen;

   //lldpRemTimeMark is used as 1st instance identifier
   error = mibEncodeIndex(nextOid, *nextOidLen, &n, nextEntry->timeMark);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemLocalPortNum is used as 2nd instance identifier
   error = mibEncodeIndex(nextOid, *nextOidLen, &n, nextEntry->portIndex);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemIndex is used as 3rd instance identifier
   error = mibEncodeIndex(nextOid, *nextOidLen, &n, nextEntry->index);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemUnknownTLVType is used as 4th instance identifier
   error = mibEncodeIndex(nextOid, *nextOidLen, &n, nextType);
   //Invalid instance identifier?
   if(error)
      return error;

   //Save the length of the resulting object identifier
   *nextOidLen = n;
   //Next object found
   return NO_ERROR;
}


/**
 * @brief Get lldpRemOrgDefInfoEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpRemOrgDefInfoEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   size_t n;
   uint_t lldpRemTimeMark;
   uint_t lldpRemLocalPortNum;
   uint_t lldpRemIndex;
   uint8_t lldpRemOrgDefInfoOUI[LLDP_OUI_SIZE];
   size_t lldpRemOrgDefInfoOUILen;
   uint_t lldpRemOrgDefInfoSubtype;
   uint_t lldpRemOrgDefInfoIndex;
   LldpNeighborEntry *entry;
   const uint8_t *info;
   size_t infoLen;

   //Point to the instance identifier
   n = object->oidLen;

   //lldpRemTimeMark is used as 1st instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &lldpRemTimeMark);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemLocalPortNum is used as 2nd instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &lldpRemLocalPortNum);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemIndex is used as 3rd instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &lldpRemIndex);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemOrgDefInfoOUI is used as 4th instance identifier
   error = mibDecodeOctetString(oid, oidLen, &n, lldpRemOrgDefInfoOUI,
      LLDP_OUI_SIZE, &lldpRemOrgDefInfoOUILen, FALSE);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemOrgDefInfoSubtype is used as 5th instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &lldpRemOrgDefInfoSubtype);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemOrgDefInfoIndex is used as 6th instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &lldpRemOrgDefInfoIndex);
   //Invalid instance identifier?
   if(error)
      return error;

   //Sanity check
   if(n != oidLen)
      return ERROR_INSTANCE_NOT_FOUND;

   //Check the length of the OUI
   if(lldpRemOrgDefInfoOUILen != LLDP_OUI_SIZE)
      return ERROR_INSTANCE_NOT_FOUND;

   //Check index value
   if(lldpRemOrgDefInfoIndex == 0)
      return ERROR_INSTANCE_NOT_FOUND;

   //Search the remote systems MIB for a matching row
   entry = lldpMgmtFindRemoteTableEntry(lldpMibBase.lldpAgentContext,
      lldpRemTimeMark, lldpRemLocalPortNum, lldpRemIndex);
   //No matching row found?
   if(entry == NULL)
      return ERROR_INSTANCE_NOT_FOUND;

   //Search the remote systems MIB for a matching TLV
   error = lldpMgmtGetRemoteOrgDefInfo(entry, LOAD24BE(lldpRemOrgDefInfoOUI),
      lldpRemOrgDefInfoSubtype, lldpRemOrgDefInfoIndex - 1, &info, &infoLen);
   //No matching TLV found?
   if(error)
      return ERROR_INSTANCE_NOT_FOUND;

   //lldpRemOrgDefInfo object?
   if(!strcmp(object->name, "lldpRemOrgDefInfo"))
   {
      //Make sure the buffer is large enough to hold the entire object
      if(*valueLen >= infoLen)
      {
         //Copy object value
         osMemcpy(value->octetString, info, infoLen);
         //Return object length
         *valueLen = infoLen;
      }
      else
      {
         //Report an error
         error = ERROR_BUFFER_OVERFLOW;
      }
   }
   //Unknown object?
   else
   {
      //The specified object does not exist
      error = ERROR_OBJECT_NOT_FOUND;
   }

   //Return status code
   return error;
}


/**
 * @brief Get next lldpRemOrgDefInfoEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t lldpMibGetNextLldpRemOrgDefInfoEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, uint8_t *nextOid, size_t *nextOidLen)
{
   error_t error;
   uint_t k;
   uint_t i;
   size_t n;
   bool_t acceptable;
   LldpTlv tlv;
   LldpAgentContext *context;
   LldpNeighborEntry *entry;
   LldpNeighborEntry *nextEntry;
   LldpOrgDefTlv *orgDefTlv;
   LldpOrgDefTlv *nextOrgDefTlv;
   uint_t index;
   uint_t nextIndex;

   //Initialize variables
   nextEntry = NULL;
   nextOrgDefTlv = NULL;
   nextIndex = 0;

   //Point to the LLDP agent context
   context = lldpMibBase.lldpAgentContext;
   //Make sure the context is valid
   if(context == NULL)
      return ERROR_OBJECT_NOT_FOUND;

   //Make sure the buffer is large enough to hold the OID prefix
   if(*nextOidLen < object->oidLen)
      return ERROR_BUFFER_OVERFLOW;

   //Copy OID prefix
   osMemcpy(nextOid, object->oid, object->oidLen);

   //Loop through the remote systems MIB
   for(i = 0; i < context->numNeighbors; i++)
   {
      //Point to the current entry
      entry = &context->neighbors[i];

      //Check whether the entry is valid
      if(entry->rxInfo.length > 0)
      {
         //Initialize occurrence index
         k = 0;

         //Extract the first TLV
         error = lldpGetFirstTlv(&entry->rxInfo, &tlv);

         //Loop through the TLVs
         while(!error)
         {
            //Organizationally specific TLV?
            if(tlv.type == LLDP_TLV_TYPE_ORG_DEFINED)
            {
               //Malformed TLV?
               if(tlv.length < sizeof(LldpOrgDefTlv))
               {
                  break;
               }

               //Point to the organizationally specific tag
               orgDefTlv = (LldpOrgDefTlv *) tlv.value;

               //Append the instance identifier to the OID prefix
               n = object->oidLen;

               //lldpRemTimeMark is used as 1st instance identifier
               error = mibEncodeIndex(nextOid, *nextOidLen, &n, entry->timeMark);
               //Invalid instance identifier?
               if(error)
                  return error;

               //lldpRemLocalPortNum is used as 2nd instance identifier
               error = mibEncodeIndex(nextOid, *nextOidLen, &n, entry->portIndex);
               //Invalid instance identifier?
               if(error)
                  return error;

               //lldpRemIndex is used as 3rd instance identifier
               error = mibEncodeIndex(nextOid, *nextOidLen, &n, entry->index);
               //Invalid instance identifier?
               if(error)
                  return error;

               //lldpRemOrgDefInfoOUI is used as 4th instance identifier
               error = mibEncodeOctetString(nextOid, *nextOidLen, &n,
                  orgDefTlv->oui, LLDP_OUI_SIZE, FALSE);
               //Invalid instance identifier?
               if(error)
                  return error;

               //lldpRemOrgDefInfoSubtype is used as 5th instance identifier
               error = mibEncodeIndex(nextOid, *nextOidLen, &n,
                  orgDefTlv->subtype);
               //Invalid instance identifier?
               if(error)
                  return error;

               //lldpRemOrgDefInfoIndex is used to identify a particular
               //instance of the TLV
               if(n <= oidLen && oidComp(nextOid, n, oid, n) == 0)
               {
                  index = ++k;
               }
               else
               {
                  index = 1;
               }

               //lldpRemOrgDefInfoIndex is used as 6th instance identifier
               error = mibEncodeIndex(nextOid, *nextOidLen, &n, index);
               //Invalid instance identifier?
               if(error)
                  return error;

               //Check whether the resulting object identifier lexicographically
               //follows the specified OID
               if(oidComp(nextOid, n, oid, oidLen) > 0)
               {
                  //Perform lexicographic comparison
                  if(nextEntry == NULL || nextOrgDefTlv == NULL)
                  {
                     acceptable = TRUE;
                  }
                  else if(entry->timeMark < nextEntry->timeMark)
                  {
                     acceptable = TRUE;
                  }
                  else if(entry->timeMark > nextEntry->timeMark)
                  {
                     acceptable = FALSE;
                  }
                  else if(entry->portIndex < nextEntry->portIndex)
                  {
                     acceptable = TRUE;
                  }
                  else if(entry->portIndex > nextEntry->portIndex)
                  {
                     acceptable = FALSE;
                  }
                  else if(entry->index < nextEntry->index)
                  {
                     acceptable = TRUE;
                  }
                  else if(entry->index > nextEntry->index)
                  {
                     acceptable = FALSE;
                  }
                  else if(osMemcmp(orgDefTlv->oui, nextOrgDefTlv->oui,
                     LLDP_OUI_SIZE) < 0)
                  {
                     acceptable = TRUE;
                  }
                  else if(osMemcmp(orgDefTlv->oui, nextOrgDefTlv->oui,
                     LLDP_OUI_SIZE) > 0)
                  {
                     acceptable = FALSE;
                  }
                  else if(orgDefTlv->subtype < nextOrgDefTlv->subtype)
                  {
                     acceptable = TRUE;
                  }
                  else if(orgDefTlv->subtype > nextOrgDefTlv->subtype)
                  {
                     acceptable = FALSE;
                  }
                  else if(index < nextIndex)
                  {
                     acceptable = TRUE;
                  }
                  else
                  {
                     acceptable = FALSE;
                  }

                  //Save the closest object identifier that follows the specified
                  //OID in lexicographic order
                  if(acceptable)
                  {
                     nextEntry = entry;
                     nextOrgDefTlv = orgDefTlv;
                     nextIndex = index;
                  }
               }
            }

            //Extract the next TLV
            error = lldpGetNextTlv(&entry->rxInfo, &tlv);
         }
      }
   }

   //The specified OID does not lexicographically precede the name
   //of some object?
   if(nextEntry == NULL || nextOrgDefTlv == NULL || nextIndex == 0)
      return ERROR_OBJECT_NOT_FOUND;

   //Append the instance identifier to the OID prefix
   n = object->oidLen;

   //lldpRemTimeMark is used as 1st instance identifier
   error = mibEncodeIndex(nextOid, *nextOidLen, &n, nextEntry->timeMark);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemLocalPortNum is used as 2nd instance identifier
   error = mibEncodeIndex(nextOid, *nextOidLen, &n, nextEntry->portIndex);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemIndex is used as 3rd instance identifier
   error = mibEncodeIndex(nextOid, *nextOidLen, &n, nextEntry->index);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemOrgDefInfoOUI is used as 4th instance identifier
   error = mibEncodeOctetString(nextOid, *nextOidLen, &n,
      nextOrgDefTlv->oui, LLDP_OUI_SIZE, FALSE);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemOrgDefInfoSubtype is used as 5th instance identifier
   error = mibEncodeIndex(nextOid, *nextOidLen, &n,
      nextOrgDefTlv->subtype);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpRemOrgDefInfoIndex is used as 6th instance identifier
   error = mibEncodeIndex(nextOid, *nextOidLen, &n, nextIndex);
   //Invalid instance identifier?
   if(error)
      return error;

   //Save the length of the resulting object identifier
   *nextOidLen = n;
   //Next object found
   return NO_ERROR;
}

#endif
