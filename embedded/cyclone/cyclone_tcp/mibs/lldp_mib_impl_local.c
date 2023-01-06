/**
 * @file lldp_mib_impl_local.c
 * @brief LLDP MIB module implementation (lldpLocalSystemData subtree)
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
#include "mibs/lldp_mib_impl_local.h"
#include "core/crypto.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "lldp/lldp_mgmt.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (LLDP_MIB_SUPPORT == ENABLED && LLDP_TX_MODE_SUPPORT == ENABLED)


/**
 * @brief Get lldpLocChassisIdSubtype object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpLocChassisIdSubtype(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   LldpChassisIdSubtype chassisIdSubtype;
   const uint8_t *chassisId;
   size_t chassisIdLen;

   //This object indicates the type of chassis identifier encoding used in
   //the associated lldpLocChassisId object
   error = lldpMgmtGetLocalChassisId(lldpMibBase.lldpAgentContext,
      &chassisIdSubtype, &chassisId, &chassisIdLen);

   //Check status code
   if(!error)
   {
      //Return object value
      value->integer = (int32_t) chassisIdSubtype;
   }

   //Return status code
   return error;
}


/**
 * @brief Get lldpLocChassisId object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpLocChassisId(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   LldpChassisIdSubtype chassisIdSubtype;
   const uint8_t *chassisId;
   size_t chassisIdLen;

   //This object identifies the chassis component associated with the local
   //system
   error = lldpMgmtGetLocalChassisId(lldpMibBase.lldpAgentContext,
      &chassisIdSubtype, &chassisId, &chassisIdLen);

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

   //Return status code
   return error;
}


/**
 * @brief Get lldpLocSysName object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpLocSysName(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   const char_t *sysName;
   size_t sysNameLen;

   //This object identifies the system name of the local system
   error = lldpMgmtGetLocalSysName(lldpMibBase.lldpAgentContext,
      &sysName, &sysNameLen);

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

   //Return status code
   return error;
}


/**
 * @brief Get lldpLocSysDesc object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpLocSysDesc(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   const char_t *sysDesc;
   size_t sysDescLen;

   //This object identifies the system description of the local system
   error = lldpMgmtGetLocalSysDesc(lldpMibBase.lldpAgentContext,
      &sysDesc, &sysDescLen);

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

   //Return status code
   return error;
}


/**
 * @brief Get lldpLocSysCapSupported object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpLocSysCapSupported(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint16_t supportedCap;
   uint16_t enabledCap;

   //This object identifies which system capabilities are supported on the
   //local system
   error = lldpMgmtGetLocalSysCap(lldpMibBase.lldpAgentContext,
      &supportedCap, &enabledCap);

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

   //Return status code
   return error;
}


/**
 * @brief Get lldpLocSysCapEnabled object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpLocSysCapEnabled(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint16_t supportedCap;
   uint16_t enabledCap;

   //This object identifies which system capabilities are enabled on the
   //local system
   error = lldpMgmtGetLocalSysCap(lldpMibBase.lldpAgentContext,
      &supportedCap, &enabledCap);

   //Check status code
   if(!error)
   {
      //Each bit in the bitmap corresponds to a given capability
      if(enabledCap != 0)
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

   //Return status code
   return error;
}


/**
 * @brief Get lldpLocPortEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpLocPortEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   size_t n;
   uint_t lldpLocPortNum;

   //Point to the instance identifier
   n = object->oidLen;

   //lldpLocPortNum is used as instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &lldpLocPortNum);
   //Invalid instance identifier?
   if(error)
      return error;

   //Sanity check
   if(n != oidLen)
      return ERROR_INSTANCE_NOT_FOUND;

   //lldpLocPortIdSubtype object?
   if(!strcmp(object->name, "lldpLocPortIdSubtype"))
   {
      LldpPortIdSubtype portIdSubtype;
      const uint8_t *portId;
      size_t portIdLen;

      //This object indicates the type of port identifier encoding used in
      //the associated lldpLocPortId object
      error = lldpMgmtGetLocalPortId(lldpMibBase.lldpAgentContext,
         lldpLocPortNum, &portIdSubtype, &portId, &portIdLen);

      //Check status code
      if(!error)
      {
         //Return object value
         value->integer = (int32_t) portIdSubtype;
      }
   }
   //lldpLocPortId object?
   else if(!strcmp(object->name, "lldpLocPortId"))
   {
      LldpPortIdSubtype portIdSubtype;
      const uint8_t *portId;
      size_t portIdLen;

      //This object identifies the port component associated with a given port
      //in the local system
      error = lldpMgmtGetLocalPortId(lldpMibBase.lldpAgentContext,
         lldpLocPortNum, &portIdSubtype, &portId, &portIdLen);

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
   //lldpLocPortDesc object?
   else if(!strcmp(object->name, "lldpLocPortDesc"))
   {
      const char_t *portDesc;
      size_t portDescLen;

      //This object identifies the station's port description associated with
      //the local system
      error = lldpMgmtGetLocalPortDesc(lldpMibBase.lldpAgentContext,
         lldpLocPortNum, &portDesc, &portDescLen);

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
 * @brief Get next lldpLocPortEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t lldpMibGetNextLldpLocPortEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, uint8_t *nextOid, size_t *nextOidLen)
{
   error_t error;
   uint_t i;
   size_t n;
   uint16_t portNum;
   uint16_t curPortNum;
   LldpAgentContext *context;

   //Initialize variable
   portNum = 0;

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

   //Loop through the ports of the bridge
   for(i = 0; i < context->numPorts; i++)
   {
      //Retrieve the port number associated with the current port
      curPortNum = context->ports[i].portIndex;

      //Append the instance identifier to the OID prefix
      n = object->oidLen;

      //lldpLocPortNum is used as instance identifier
      error = mibEncodeIndex(nextOid, *nextOidLen, &n, curPortNum);
      //Any error to report?
      if(error)
         return error;

      //Check whether the resulting object identifier lexicographically
      //follows the specified OID
      if(oidComp(nextOid, n, oid, oidLen) > 0)
      {
         //Save the closest object identifier that follows the specified
         //OID in lexicographic order
         if(portNum == 0 || curPortNum < portNum)
         {
            portNum = curPortNum;
         }
      }
   }

   //The specified OID does not lexicographically precede the name
   //of some object?
   if(portNum == 0)
      return ERROR_OBJECT_NOT_FOUND;

   //Append the instance identifier to the OID prefix
   n = object->oidLen;

   //lldpLocPortNum is used as instance identifier
   error = mibEncodeIndex(nextOid, *nextOidLen, &n, portNum);
   //Any error to report?
   if(error)
      return error;

   //Save the length of the resulting object identifier
   *nextOidLen = n;
   //Next object found
   return NO_ERROR;
}


/**
 * @brief Get lldpLocManAddrEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpLocManAddrEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   size_t n;
   int_t index;
   uint_t lldpLocManAddrSubtype;
   uint8_t lldpLocManAddr[LLDP_MAX_MGMT_ADDR_LEN];
   size_t lldpLocManAddrLen;
   LldpAgentContext *context;
   LldpIfNumSubtype ifNumSubtype;
   uint32_t ifNum;
   const uint8_t *addrOid;
   size_t addrOidLen;

   //Point to the LLDP agent context
   context = lldpMibBase.lldpAgentContext;
   //Make sure the context is valid
   if(context == NULL)
      return ERROR_OBJECT_NOT_FOUND;

   //Point to the instance identifier
   n = object->oidLen;

   //lldpLocManAddrSubtype is used as 1st instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &lldpLocManAddrSubtype);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpLocManAddr is used as 2nd instance identifier
   error = mibDecodeOctetString(oid, oidLen, &n, lldpLocManAddr,
      LLDP_MAX_MGMT_ADDR_LEN, &lldpLocManAddrLen, FALSE);
   //Invalid instance identifier?
   if(error)
      return error;

   //Sanity check
   if(n != oidLen)
      return ERROR_INSTANCE_NOT_FOUND;

   //Search the local system MIB for a matching address
   index = lldpMgmtFindLocalMgmtAddr(context, lldpLocManAddrSubtype,
      lldpLocManAddr, lldpLocManAddrLen);
   //No matching address found?
   if(index < 0)
      return ERROR_INSTANCE_NOT_FOUND;

   //Extract the management address from the local system MIB
   error = lldpMgmtGetLocalMgmtAddr(context, index, NULL, NULL, NULL,
      &ifNumSubtype, &ifNum, &addrOid, &addrOidLen);
   //No matching address found?
   if(error)
      return ERROR_INSTANCE_NOT_FOUND;

   //lldpLocManAddrLen object?
   if(!strcmp(object->name, "lldpLocManAddrLen"))
   {
      //This objects indicates the total length of the management address
      //subtype and the management address fields in LLDPDUs transmitted by
      //the local LLDP agent
      //Get object value
      value->integer = lldpLocManAddrLen + 1;
   }
   //lldpLocManAddrIfSubtype object?
   else if(!strcmp(object->name, "lldpLocManAddrIfSubtype"))
   {
      //This object identifies the interface numbering method used for defining
      //the interface number, associated with the local system
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
   //lldpLocManAddrIfId object?
   else if(!strcmp(object->name, "lldpLocManAddrIfId"))
   {
      //This object identifies the interface number regarding the management
      //address component associated with the local system
      value->integer = ifNum;
   }
   //lldpLocManAddrOID object?
   else if(!strcmp(object->name, "lldpLocManAddrOID"))
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
 * @brief Get next lldpLocManAddrEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t lldpMibGetNextLldpLocManAddrEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, uint8_t *nextOid, size_t *nextOidLen)
{
   error_t error;
   size_t n;
   bool_t acceptable;
   LldpTlv tlv;
   LldpAgentContext *context;
   const LldpMgmtAddrTlv1 *addr;
   const LldpMgmtAddrTlv1 *nextAddr;

   //Initialize variables
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

   //Extract the first TLV
   error = lldpGetFirstTlv(&context->txInfo, &tlv);

   //Loop through the local system MIB
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

         //lldpLocManAddrSubtype is used as 1st instance identifier
         error = mibEncodeIndex(nextOid, *nextOidLen, &n,
            addr->mgmtAddrSubtype);
         //Invalid instance identifier?
         if(error)
            return error;

         //lldpLocManAddr is used as 5th instance identifier
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
            if(nextAddr == NULL)
            {
               acceptable = TRUE;
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
               nextAddr = addr;
            }
         }
      }

      //Extract the next TLV
      error = lldpGetNextTlv(&context->txInfo, &tlv);
   }

   //The specified OID does not lexicographically precede the name
   //of some object?
   if(nextAddr == NULL)
      return ERROR_OBJECT_NOT_FOUND;

   //Append the instance identifier to the OID prefix
   n = object->oidLen;

   //lldpLocManAddrSubtype is used as 1st instance identifier
   error = mibEncodeIndex(nextOid, *nextOidLen, &n, nextAddr->mgmtAddrSubtype);
   //Invalid instance identifier?
   if(error)
      return error;

   //lldpLocManAddr is used as 5th instance identifier
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

#endif
