/**
 * @file lldp_mib_impl_config.c
 * @brief LLDP MIB module implementation (lldpConfiguration subtree)
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
#include "mibs/lldp_mib_impl_config.h"
#include "core/crypto.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "lldp/lldp_mgmt.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (LLDP_MIB_SUPPORT == ENABLED)


/**
 * @brief Set lldpMessageTxInterval object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t lldpMibSetLldpMessageTxInterval(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit)
{
#if (LLDP_MIB_SET_SUPPORT == ENABLED)
   error_t error;

   //Ensure that the supplied value is valid
   if(value->integer >= 0)
   {
      //This object specifies the interval at which LLDP frames are transmitted
      //on behalf of this LLDP agent
      error = lldpMgmtSetMsgTxInterval(lldpMibBase.lldpAgentContext,
         value->integer, commit);
   }
   else
   {
      //Report an error
      error = ERROR_WRONG_VALUE;
   }

   //Return status code
   return error;
#else
   //SET operation is not supported
   return ERROR_WRITE_FAILED;
#endif
}


/**
 * @brief Get lldpMessageTxInterval object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpMessageTxInterval(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint_t msgTxInterval;

   //This object specifies the interval at which LLDP frames are transmitted
   //on behalf of this LLDP agent
   error = lldpMgmtGetMsgTxInterval(lldpMibBase.lldpAgentContext,
      &msgTxInterval);

   //Check status code
   if(!error)
   {
      //Return the value of the object
      value->integer = msgTxInterval;
   }

   //Return status code
   return error;
}


/**
 * @brief Set lldpMessageTxHoldMultiplier object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t lldpMibSetLldpMessageTxHoldMultiplier(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit)
{
#if (LLDP_MIB_SET_SUPPORT == ENABLED)
   error_t error;

   //Ensure that the supplied value is valid
   if(value->integer >= 0)
   {
      //This object specifies the multiplier on the msgTxInterval that
      //determines the actual TTL value used in an LLDPDU
      error = lldpMgmtSetMsgTxHold(lldpMibBase.lldpAgentContext,
         value->integer, commit);
   }
   else
   {
      //Report an error
      error = ERROR_WRONG_VALUE;
   }

   //Return status code
   return error;
#else
   //SET operation is not supported
   return ERROR_WRITE_FAILED;
#endif
}


/**
 * @brief Get lldpMessageTxHoldMultiplier object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpMessageTxHoldMultiplier(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint_t msgTxHold;

   //This object specifies the multiplier on the msgTxInterval that
   //determines the actual TTL value used in an LLDPDU
   error = lldpMgmtGetMsgTxHold(lldpMibBase.lldpAgentContext, &msgTxHold);

   //Check status code
   if(!error)
   {
      //Return the value of the object
      value->integer = msgTxHold;
   }

   //Return status code
   return error;
}


/**
 * @brief Set lldpReinitDelay object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t lldpMibSetLldpReinitDelay(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit)
{
#if (LLDP_MIB_SET_SUPPORT == ENABLED)
   error_t error;

   //Ensure that the supplied value is valid
   if(value->integer >= 0)
   {
      //This object indicates the delay (in units of seconds) from when
      //lldpPortConfigAdminStatus object of a particular port becomes disabled
      //until re-initialization will be attempted
      error = lldpMgmtSetReinitDelay(lldpMibBase.lldpAgentContext,
         value->integer, commit);
   }
   else
   {
      //Report an error
      error = ERROR_WRONG_VALUE;
   }

   //Return status code
   return error;
#else
   //SET operation is not supported
   return ERROR_WRITE_FAILED;
#endif
}


/**
 * @brief Get lldpReinitDelay object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpReinitDelay(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint_t reinitDelay;

   //This object indicates the delay (in units of seconds) from when
   //lldpPortConfigAdminStatus object of a particular port becomes disabled
   //until re-initialization will be attempted
   error = lldpMgmtGetReinitDelay(lldpMibBase.lldpAgentContext, &reinitDelay);

   //Check status code
   if(!error)
   {
      //Return the value of the object
      value->integer = reinitDelay;
   }

   //Return status code
   return error;
}


/**
 * @brief Set lldpTxDelay object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t lldpMibSetLldpTxDelay(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit)
{
#if (LLDP_MIB_SET_SUPPORT == ENABLED)
   error_t error;

   //Ensure that the supplied value is valid
   if(value->integer >= 0)
   {
      //This object indicates the delay (in units of seconds) between successive
      //LLDP frame transmissions initiated by value/status changes in the LLDP
      //local systems MIB
      error = lldpMgmtSetTxDelay(lldpMibBase.lldpAgentContext,
         value->integer, commit);
   }
   else
   {
      //Report an error
      error = ERROR_WRONG_VALUE;
   }

   //Return status code
   return error;
#else
   //SET operation is not supported
   return ERROR_WRITE_FAILED;
#endif
}


/**
 * @brief Get lldpTxDelay object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpTxDelay(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint_t txDelay;

   //This object indicates the delay (in units of seconds) between successive
   //LLDP frame transmissions initiated by value/status changes in the LLDP
   //local systems MIB
   error = lldpMgmtGetTxDelay(lldpMibBase.lldpAgentContext, &txDelay);

   //Check status code
   if(!error)
   {
      //Return the value of the object
      value->integer = txDelay;
   }

   //Return status code
   return error;
}


/**
 * @brief Set lldpNotificationInterval object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t lldpMibSetLldpNotificationInterval(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit)
{
#if (LLDP_MIB_SET_SUPPORT == ENABLED)
   error_t error;

   //Ensure that the supplied value is valid
   if(value->integer >= 0)
   {
      //This object controls the transmission of LLDP notifications
      error = lldpMgmtSetNotificationInterval(lldpMibBase.lldpAgentContext,
         value->integer, commit);
   }
   else
   {
      //Report an error
      error = ERROR_WRONG_VALUE;
   }

   //Return status code
   return error;
#else
   //SET operation is not supported
   return ERROR_WRITE_FAILED;
#endif
}


/**
 * @brief Get lldpNotificationInterval object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpNotificationInterval(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint_t notificationInterval;

   //This object controls the transmission of LLDP notifications
   error = lldpMgmtGetNotificationInterval(lldpMibBase.lldpAgentContext,
      &notificationInterval);

   //Check status code
   if(!error)
   {
      //Return the value of the object
      value->integer = notificationInterval;
   }

   //Return status code
   return error;
}


/**
 * @brief Set lldpPortConfigEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t lldpMibSetLldpPortConfigEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit)
{
#if (LLDP_MIB_SET_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint_t lldpPortConfigPortNum;

   //Point to the instance identifier
   n = object->oidLen;

   //lldpPortConfigPortNum is used as instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &lldpPortConfigPortNum);
   //Invalid instance identifier?
   if(error)
      return error;

   //Sanity check
   if(n != oidLen)
      return ERROR_INSTANCE_NOT_FOUND;

   //lldpPortConfigAdminStatus object?
   if(!strcmp(object->name, "lldpPortConfigAdminStatus"))
   {
      //This object specifies the administrative status of the local LLDP agent
      if(value->integer == LLDP_MIB_ADMIN_STATUS_DISABLED)
      {
         //The LLDP agent will not transmit or receive LLDP frames on this port
         error = lldpMgmtSetAdminStatus(lldpMibBase.lldpAgentContext,
            lldpPortConfigPortNum, LLDP_ADMIN_STATUS_DISABLED, commit);
      }
      else if(value->integer == LLDP_MIB_ADMIN_STATUS_ENABLED_TX_ONLY)
      {
         //The LLDP agent will transmit LLDP frames on this port, but it will
         //not store any information about the remote systems connected
         error = lldpMgmtSetAdminStatus(lldpMibBase.lldpAgentContext,
            lldpPortConfigPortNum, LLDP_ADMIN_STATUS_ENABLED_TX_ONLY, commit);
      }
      else if(value->integer == LLDP_MIB_ADMIN_STATUS_ENABLED_RX_ONLY)
      {
         //The LLDP agent will receive, but it will not transmit LLDP frames
         //on this port
         error = lldpMgmtSetAdminStatus(lldpMibBase.lldpAgentContext,
            lldpPortConfigPortNum, LLDP_ADMIN_STATUS_ENABLED_RX_ONLY, commit);
      }
      else if(value->integer == LLDP_MIB_ADMIN_STATUS_ENABLED_TX_RX)
      {
         //The LLDP agent will transmit and receive LLDP frames on this port
         error = lldpMgmtSetAdminStatus(lldpMibBase.lldpAgentContext,
            lldpPortConfigPortNum, LLDP_ADMIN_STATUS_ENABLED_TX_RX, commit);
      }
      else
      {
         //Invalid parameter
         error = ERROR_WRONG_VALUE;
      }
   }
   //lldpPortConfigNotificationEnable object?
   else if(!strcmp(object->name, "lldpPortConfigNotificationEnable"))
   {
      //This object controls, on a per port basis, whether or not notifications
      //from the agent are enabled
      if(value->integer == MIB_TRUTH_VALUE_TRUE)
      {
         //Disable notifications
         error = lldpMgmtSetNotificationEnable(lldpMibBase.lldpAgentContext,
            lldpPortConfigPortNum, TRUE, commit);
      }
      else if(value->integer == MIB_TRUTH_VALUE_FALSE)
      {
         //Enable notifications
         error = lldpMgmtSetNotificationEnable(lldpMibBase.lldpAgentContext,
            lldpPortConfigPortNum, FALSE, commit);
      }
      else
      {
         //Report an error
         error = ERROR_WRONG_VALUE;
      }
   }
   //lldpPortConfigTLVsTxEnable object?
   else if(!strcmp(object->name, "lldpPortConfigTLVsTxEnable"))
   {
      //This object specifies the basic set of LLDP TLVs whose transmission is
      //allowed on the local LLDP agent by the network management
      if(valueLen > 0)
      {
         //Each bit in the bitmap corresponds to a TLV type associated with a
         //specific optional TLV
         error = lldpMgmtSetBasicTlvFilter(lldpMibBase.lldpAgentContext,
            lldpPortConfigPortNum, reverseInt8(value->octetString[0]), commit);
      }
      else
      {
         //An empty set means that no enumerated values are set
         error = lldpMgmtSetBasicTlvFilter(lldpMibBase.lldpAgentContext,
            lldpPortConfigPortNum, 0, commit);
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
#else
   //SET operation is not supported
   return ERROR_WRITE_FAILED;
#endif
}


/**
 * @brief Get lldpPortConfigEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpPortConfigEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   size_t n;
   uint_t lldpPortConfigPortNum;

   //Point to the instance identifier
   n = object->oidLen;

   //lldpPortConfigPortNum is used as instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &lldpPortConfigPortNum);
   //Invalid instance identifier?
   if(error)
      return error;

   //Sanity check
   if(n != oidLen)
      return ERROR_INSTANCE_NOT_FOUND;

   //lldpPortConfigAdminStatus object?
   if(!strcmp(object->name, "lldpPortConfigAdminStatus"))
   {
      LldpAdminStatus adminStatus;

      //This object specifies the administrative status of the local LLDP agent
      error = lldpMgmtGetAdminStatus(lldpMibBase.lldpAgentContext,
         lldpPortConfigPortNum, &adminStatus);

      //Check status code
      if(!error)
      {
         //Return the value of the object
         switch(adminStatus)
         {
         case LLDP_ADMIN_STATUS_DISABLED:
            value->integer = LLDP_MIB_ADMIN_STATUS_DISABLED;
            break;
         case LLDP_ADMIN_STATUS_ENABLED_TX_ONLY:
            value->integer = LLDP_MIB_ADMIN_STATUS_ENABLED_TX_ONLY;
            break;
         case LLDP_ADMIN_STATUS_ENABLED_RX_ONLY:
            value->integer = LLDP_MIB_ADMIN_STATUS_ENABLED_RX_ONLY;
            break;
         case LLDP_ADMIN_STATUS_ENABLED_TX_RX:
            value->integer = LLDP_MIB_ADMIN_STATUS_ENABLED_TX_RX;
            break;
         default:
            value->integer = LLDP_MIB_ADMIN_STATUS_INVALID;
            break;
         }
      }
   }
   //lldpPortConfigNotificationEnable object?
   else if(!strcmp(object->name, "lldpPortConfigNotificationEnable"))
   {
      bool_t notificationEnable;

      //This object controls, on a per port basis, whether or not notifications
      //from the agent are enabled
      error = lldpMgmtGetNotificationEnable(lldpMibBase.lldpAgentContext,
         lldpPortConfigPortNum, &notificationEnable);

      //Check status code
      if(!error)
      {
         //Return the value of the object
         if(notificationEnable)
         {
            value->integer = MIB_TRUTH_VALUE_TRUE;
         }
         else
         {
            value->integer = MIB_TRUTH_VALUE_FALSE;
         }
      }
   }
   //lldpPortConfigTLVsTxEnable object?
   else if(!strcmp(object->name, "lldpPortConfigTLVsTxEnable"))
   {
      uint8_t mibBasicTlvsTxEnable;

      //This object specifies the basic set of LLDP TLVs whose transmission is
      //allowed on the local LLDP agent by the network management
      error = lldpMgmtGetMibBasicTlvsTxEnable(lldpMibBase.lldpAgentContext,
         lldpPortConfigPortNum, &mibBasicTlvsTxEnable);

      //Check status code
      if(!error)
      {
         //Each bit in the bitmap corresponds to a TLV type associated with a
         //specific optional TLV
         if(mibBasicTlvsTxEnable != 0)
         {
            //Make sure the buffer is large enough to hold the entire object
            if(*valueLen >= sizeof(uint8_t))
            {
               //Copy object value
               value->octetString[0] = reverseInt8(mibBasicTlvsTxEnable);
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
 * @brief Get next lldpPortConfigEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t lldpMibGetNextLldpPortConfigEntry(const MibObject *object, const uint8_t *oid,
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

      //lldpPortConfigPortNum is used as instance identifier
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

   //lldpPortConfigPortNum is used as instance identifier
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
 * @brief Set lldpConfigManAddrEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t lldpMibSetLldpConfigManAddrEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit)
{
#if (LLDP_MIB_SET_SUPPORT == ENABLED)
   error_t error;
   uint_t i;
   size_t n;
   uint_t lldpLocManAddrSubtype;
   uint8_t lldpLocManAddr[LLDP_MAX_MGMT_ADDR_LEN];
   size_t lldpLocManAddrLen;
   LldpAgentContext *context;
   int_t index;

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

   //Search the local system MIB for a matching management address
   index = lldpMgmtFindLocalMgmtAddr(context, lldpLocManAddrSubtype,
      lldpLocManAddr, lldpLocManAddrLen);
   //No matching address found?
   if(index < 0)
      return ERROR_INSTANCE_NOT_FOUND;

   //lldpConfigManAddrPortsTxEnable object?
   if(!strcmp(object->name, "lldpConfigManAddrPortsTxEnable"))
   {
      //This object is a bit map indicating the system ports through which the
      //particular Management Address TLV is enabled for transmission
      for(i = 0; i < context->numPorts; i++)
      {
         //Each port is represented as a bit
         if(i >= (valueLen * 8))
         {
            context->ports[i].mgmtAddrFilter &= ~(1U << index);
         }
         else if((value->octetString[i / 8] & (0x80 >> (i % 8))) != 0)
         {
            context->ports[i].mgmtAddrFilter |= (1U << index);
         }
         else
         {
            context->ports[i].mgmtAddrFilter &= ~(1U << index);
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
#else
   //SET operation is not supported
   return ERROR_WRITE_FAILED;
#endif
}


/**
 * @brief Get lldpConfigManAddrEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpConfigManAddrEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint_t i;
   uint_t k;
   size_t n;
   uint_t lldpLocManAddrSubtype;
   uint8_t lldpLocManAddr[LLDP_MAX_MGMT_ADDR_LEN];
   size_t lldpLocManAddrLen;
   LldpAgentContext *context;
   int_t index;

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

   //Search the local system MIB for a matching management address
   index = lldpMgmtFindLocalMgmtAddr(context, lldpLocManAddrSubtype,
      lldpLocManAddr, lldpLocManAddrLen);
   //No matching address found?
   if(index < 0)
      return ERROR_INSTANCE_NOT_FOUND;

   //lldpConfigManAddrPortsTxEnable object?
   if(!strcmp(object->name, "lldpConfigManAddrPortsTxEnable"))
   {
      //Get the highest port index
      for(k = context->numPorts; k > 0; k--)
      {
         if((context->ports[k - 1].mgmtAddrFilter & (1U << index)) != 0)
            break;
      }

      //Each octet within the octet string specifies a set of eight ports
      k = (k + 7) / 8;

      //Make sure the buffer is large enough to hold the entire object
      if(*valueLen >= k)
      {
         //This object is a bit map indicating the system ports through which the
         //particular Management Address TLV is enabled for transmission
         for(i = 0; i < (k * 8); i++)
         {
            //Each port is represented as a bit
            if(i >= context->numPorts)
            {
               value->octetString[i / 8] &= ~(0x80 >> (i % 8));
            }
            else if((context->ports[i].mgmtAddrFilter & (1U << index)) != 0)
            {
               value->octetString[i / 8] |= (0x80 >> (i % 8));
            }
            else
            {
               value->octetString[i / 8] &= ~(0x80 >> (i % 8));
            }
         }

         //Return object length
         *valueLen = k;
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
 * @brief Get next lldpConfigManAddrEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t lldpMibGetNextLldpConfigManAddrEntry(const MibObject *object, const uint8_t *oid,
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
