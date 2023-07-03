/**
 * @file lldp_mgmt.c
 * @brief Management of the LLDP agent
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
#include "lldp/lldp_mgmt.h"
#include "lldp/lldp_misc.h"
#include "lldp/lldp_debug.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (LLDP_SUPPORT == ENABLED)


/**
 * @brief Acquire exclusive access to the LLDP agent context
 * @param[in] context Pointer to the LLDP agent context
 **/

void lldpMgmtLock(LldpAgentContext *context)
{
   //Acquire exclusive access
   osAcquireMutex(&context->mutex);
}


/**
 * @brief Release exclusive access to the LLDP agent context
 * @param[in] context Pointer to the LLDP agent context
 **/

void lldpMgmtUnlock(LldpAgentContext *context)
{
   //Release exclusive access
   osReleaseMutex(&context->mutex);
}


/**
 * @brief Set transmit interval
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] msgTxInterval Time interval between successive transmit cycles,
 *   in seconds
 * @param[in] commit If this flag is TRUE, the LLDP agent verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the LLDP agent
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t lldpMgmtSetMsgTxInterval(LldpAgentContext *context,
   uint_t msgTxInterval, bool_t commit)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   //Make sure the LLDP agent context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //Check the value of the parameter
   if(msgTxInterval < LLDP_MIN_MSG_TX_INTERVAL ||
      msgTxInterval > LLDP_MAX_MSG_TX_INTERVAL)
   {
      return ERROR_WRONG_VALUE;
   }

   //Commit phase?
   if(commit)
   {
      //Save the value of the parameter
      context->msgTxInterval = msgTxInterval;

      //The somethingChangedLocal flag must be set whenever the value of an
      //object has changed in the local system MIB
      lldpSomethingChangedLocal(context);
   }

   //Successful processing
   return NO_ERROR;
#else
   //TX mode is not implemented
   return ERROR_WRITE_FAILED;
#endif
}


/**
 * @brief Set transmit hold multiplier
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] msgTxHold Multiplier on the msgTxInterval that determines the
 *   actual TTL value used in an LLDPDU
 * @param[in] commit If this flag is TRUE, the LLDP agent verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the LLDP agent
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t lldpMgmtSetMsgTxHold(LldpAgentContext *context, uint_t msgTxHold,
   bool_t commit)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   //Make sure the LLDP agent context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //Check the value of the parameter
   if(msgTxHold < LLDP_MIN_MSG_TX_HOLD ||
      msgTxHold > LLDP_MAX_MSG_TX_HOLD)
   {
      return ERROR_WRONG_VALUE;
   }

   //Commit phase?
   if(commit)
   {
      //Save the value of the parameter
      context->msgTxHold = msgTxHold;

      //The somethingChangedLocal flag must be set whenever the value of an
      //object has changed in the local system MIB
      lldpSomethingChangedLocal(context);
   }

   //Successful processing
   return NO_ERROR;
#else
   //TX mode is not implemented
   return ERROR_WRITE_FAILED;
#endif
}


/**
 * @brief Set re-initialization delay
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] reinitDelay Delay before re-initialization will be attempted
 * @param[in] commit If this flag is TRUE, the LLDP agent verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the LLDP agent
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t lldpMgmtSetReinitDelay(LldpAgentContext *context, uint_t reinitDelay,
   bool_t commit)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   //Make sure the LLDP agent context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //Check the value of the parameter
   if(reinitDelay < LLDP_MIN_REINIT_DELAY ||
      reinitDelay > LLDP_MAX_REINIT_DELAY)
   {
      return ERROR_WRONG_VALUE;
   }

   //Commit phase?
   if(commit)
   {
      //Save the value of the parameter
      context->reinitDelay = reinitDelay;
   }

   //Successful processing
   return NO_ERROR;
#else
   //TX mode is not implemented
   return ERROR_WRITE_FAILED;
#endif
}


/**
 * @brief Set transmit delay
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] txDelay Delay between successive LLDP frame transmissions
 * @param[in] commit If this flag is TRUE, the LLDP agent verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the LLDP agent
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t lldpMgmtSetTxDelay(LldpAgentContext *context, uint_t txDelay,
   bool_t commit)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   //Make sure the LLDP agent context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //Check the value of the parameter
   if(txDelay < LLDP_MIN_TX_DELAY ||
      txDelay > LLDP_MAX_TX_DELAY)
   {
      return ERROR_WRONG_VALUE;
   }

   //Commit phase?
   if(commit)
   {
      //Save the value of the parameter
      context->txDelay = txDelay;
   }

   //Successful processing
   return NO_ERROR;
#else
   //TX mode is not implemented
   return ERROR_WRITE_FAILED;
#endif
}


/**
 * @brief Set notification interval
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] notificationInterval Notification interval
 * @param[in] commit If this flag is TRUE, the LLDP agent verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the LLDP agent
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t lldpMgmtSetNotificationInterval(LldpAgentContext *context,
   uint_t notificationInterval, bool_t commit)
{
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   //Make sure the LLDP agent context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //Check the value of the parameter
   if(notificationInterval < LLDP_MIN_NOTIFICATION_INTERVAL ||
      notificationInterval > LLDP_MAX_NOTIFICATION_INTERVAL)
   {
      return ERROR_WRONG_VALUE;
   }

   //Commit phase?
   if(commit)
   {
      //Save the value of the parameter
      context->notificationInterval = notificationInterval;
   }

   //Successful processing
   return NO_ERROR;
#else
   //RX mode is not implemented
   return ERROR_WRITE_FAILED;
#endif
}


/**
 * @brief Set administrative status
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[in] adminStatus The administrative status indicates whether or not
 *   the local LLDP agent is enabled
 * @param[in] commit If this flag is TRUE, the LLDP agent verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the LLDP agent
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t lldpMgmtSetAdminStatus(LldpAgentContext *context,
   uint_t portIndex, LldpAdminStatus adminStatus, bool_t commit)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   LldpPortEntry *port;

   //Make sure the LLDP agent context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Check the value of the parameter
   if(adminStatus != LLDP_ADMIN_STATUS_DISABLED &&
      adminStatus != LLDP_ADMIN_STATUS_ENABLED_TX_ONLY &&
      adminStatus != LLDP_ADMIN_STATUS_ENABLED_RX_ONLY &&
      adminStatus != LLDP_ADMIN_STATUS_ENABLED_TX_RX)
   {
      return ERROR_WRONG_VALUE;
   }

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Commit phase?
   if(commit)
   {
      //Save the value of the parameter
      port->adminStatus = adminStatus;

      //The somethingChangedLocal flag must be set whenever the value of an
      //object has changed in the local system MIB
      lldpSomethingChangedLocal(context);
   }

   //Successful processing
   return NO_ERROR;
#else
   //TX mode is not implemented
   return ERROR_WRITE_FAILED;
#endif
}


/**
 * @brief Enable or disable notifications
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[in] notificationEnable This parameter controls whether or not
 *   notifications from the agent are enabled
 * @param[in] commit If this flag is TRUE, the LLDP agent verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the LLDP agent
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t lldpMgmtSetNotificationEnable(LldpAgentContext *context,
   uint_t portIndex, bool_t notificationEnable, bool_t commit)
{
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   LldpPortEntry *port;

   //Make sure the LLDP agent context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Commit phase?
   if(commit)
   {
      //Save the value of the parameter
      port->notificationEnable = notificationEnable;
   }

   //Successful processing
   return NO_ERROR;
#else
   //RX mode is not implemented
   return ERROR_WRITE_FAILED;
#endif
}


/**
 * @brief Set the list of TLVs enabled for transmission
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[in] mask Bit-map indicating the TLVs enabled for transmission
 * @param[in] commit If this flag is TRUE, the LLDP agent verifies the parameter
 *   value and commits the change if the value is valid. If FALSE, the LLDP agent
 *   only performs the verification and does not take any further action
 * @return Error code
 **/

error_t lldpMgmtSetBasicTlvFilter(LldpAgentContext *context, uint_t portIndex,
   uint8_t mask, bool_t commit)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   LldpPortEntry *port;

   //Make sure the LLDP agent context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Commit phase?
   if(commit)
   {
      //Each bit in the bitmap corresponds to a TLV type associated with a
      //specific optional TLV
      port->basicTlvFilter = mask & LLDP_BASIC_TLV_FILTER_ALL;

      //The somethingChangedLocal flag must be set whenever the value of an
      //object has changed in the local system MIB
      lldpSomethingChangedLocal(context);
   }

   //Successful processing
   return NO_ERROR;
#else
   //TX mode is not implemented
   return ERROR_WRITE_FAILED;
#endif
}


/**
 * @brief Get transmit interval
 * @param[in] context Pointer to the LLDP agent context
 * @param[out] msgTxInterval Time interval between successive transmit cycles,
 *   in seconds
 * @return Error code
 **/

error_t lldpMgmtGetMsgTxInterval(LldpAgentContext *context,
   uint_t *msgTxInterval)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || msgTxInterval == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the current value of the parameter
   *msgTxInterval = context->msgTxInterval;

   //Successful processing
   return NO_ERROR;
#else
   //TX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Get transmit hold multiplier
 * @param[in] context Pointer to the LLDP agent context
 * @param[out] msgTxHold Multiplier on the msgTxInterval that determines the
 *   actual TTL value used in an LLDPDU
 * @return Error code
 **/

error_t lldpMgmtGetMsgTxHold(LldpAgentContext *context, uint_t *msgTxHold)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || msgTxHold == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the current value of the parameter
   *msgTxHold = context->msgTxHold;

   //Successful processing
   return NO_ERROR;
#else
   //TX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Get re-initialization delay
 * @param[in] context Pointer to the LLDP agent context
 * @param[out] reinitDelay Delay before re-initialization will be attempted
 * @return Error code
 **/

error_t lldpMgmtGetReinitDelay(LldpAgentContext *context, uint_t *reinitDelay)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || reinitDelay == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the current value of the parameter
   *reinitDelay = context->reinitDelay;

   //Successful processing
   return NO_ERROR;
#else
   //TX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Get transmit delay
 * @param[in] context Pointer to the LLDP agent context
 * @param[out] txDelay Delay between successive LLDP frame transmissions
 * @return Error code
 **/

error_t lldpMgmtGetTxDelay(LldpAgentContext *context, uint_t *txDelay)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || txDelay == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the current value of the parameter
   *txDelay = context->txDelay;

   //Successful processing
   return NO_ERROR;
#else
   //TX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Get notification interval
 * @param[in] context Pointer to the LLDP agent context
 * @param[out] notificationInterval Notification interval
 * @return Error code
 **/

error_t lldpMgmtGetNotificationInterval(LldpAgentContext *context,
   uint_t *notificationInterval)
{
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || notificationInterval == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the current value of the parameter
   *notificationInterval = context->notificationInterval;

   //Successful processing
   return NO_ERROR;
#else
   //RX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Get administrative status
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[out] adminStatus The administrative status indicates whether or not
 *   the local LLDP agent is enabled
 * @return Error code
 **/

error_t lldpMgmtGetAdminStatus(LldpAgentContext *context,
   uint_t portIndex, LldpAdminStatus *adminStatus)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   LldpPortEntry *port;

   //Check parameters
   if(context == NULL || adminStatus == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the current value of the parameter
   *adminStatus = port->adminStatus;

   //Successful processing
   return NO_ERROR;
#else
   //TX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Check whether notifications are enabled or disabled
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[out] notificationEnable This parameter controls whether or not
 *   notifications from the agent are enabled
 * @return Error code
 **/

error_t lldpMgmtGetNotificationEnable(LldpAgentContext *context,
   uint_t portIndex, bool_t *notificationEnable)
{
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   LldpPortEntry *port;

   //Make sure the LLDP agent context is valid
   if(context == NULL)
      return ERROR_WRITE_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the current value of the parameter
   *notificationEnable = port->notificationEnable;

   //Successful processing
   return NO_ERROR;
#else
   //RX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Get the list of TLVs enabled for transmission
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[out] mibBasicTlvsTxEnable Bit-map indicating the TLVs enabled for
 *   transmission
 * @return Error code
 **/

error_t lldpMgmtGetMibBasicTlvsTxEnable(LldpAgentContext *context,
   uint_t portIndex, uint8_t *mibBasicTlvsTxEnable)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   LldpPortEntry *port;

   //Check parameters
   if(context == NULL || mibBasicTlvsTxEnable == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the current value of the parameter
   *mibBasicTlvsTxEnable = port->basicTlvFilter;

   //Successful processing
   return NO_ERROR;
#else
   //TX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Extract chassis ID from local system MIB
 * @param[in] context Pointer to the LLDP agent context
 * @param[out] chassisIdSubtype Type of identifier used for the chassis
 * @param[out] chassisId Administratively assigned name that identifies the chassis
 * @param[out] chassisIdLen Length of the chassis ID, in bytes
 * @return Error code
 **/

error_t lldpMgmtGetLocalChassisId(LldpAgentContext *context,
   LldpChassisIdSubtype *chassisIdSubtype, const uint8_t **chassisId,
   size_t *chassisIdLen)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   const uint8_t *p;
   const LldpChassisIdTlv *tlv;

   //Check parameters
   if(context == NULL || chassisIdSubtype == NULL || chassisId == NULL ||
      chassisIdLen == NULL)
   {
      return ERROR_READ_FAILED;
   }

   //Search the local system MIB for the Chassis ID TLV
   error = lldpGetTlv(&context->txInfo, LLDP_TLV_TYPE_CHASSIS_ID, 0, &p, &n);

   //Chassis ID TLV found?
   if(!error && n >= sizeof(LldpChassisIdTlv))
   {
      //Point to the Chassis ID TLV
      tlv = (const LldpChassisIdTlv *) p;

      //Extract the chassis ID from the local system MIB
      *chassisIdSubtype = (LldpChassisIdSubtype) tlv->chassisIdSubtype;
      *chassisId = tlv->chassisId;
      *chassisIdLen = n - sizeof(LldpChassisIdTlv);
   }
   else
   {
      //The Chassis ID TLV is not present
      *chassisIdSubtype = LLDP_CHASSIS_ID_SUBTYPE_RESERVED;
      *chassisId = NULL;
      *chassisIdLen = 0;
   }

   //Successful processing
   return NO_ERROR;
#else
   //TX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Extract port ID from local system MIB
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[out] portIdSubtype Type of identifier used for the port
 * @param[out] portId Administratively assigned name that identifies the port
 * @param[out] portIdLen Length of the port ID, in bytes
 * @return Error code
 **/

error_t lldpMgmtGetLocalPortId(LldpAgentContext *context, uint_t portIndex,
   LldpPortIdSubtype *portIdSubtype, const uint8_t **portId,
   size_t *portIdLen)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   const uint8_t *p;
   LldpPortEntry *port;
   const LldpPortIdTlv *tlv;

   //Check parameters
   if(context == NULL || portIdSubtype == NULL || portId == NULL ||
      portIdLen == NULL)
   {
      return ERROR_READ_FAILED;
   }

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Search the local system MIB for the Port ID TLV
   error = lldpGetTlv(&port->txInfo, LLDP_TLV_TYPE_PORT_ID, 0, &p, &n);

   //Port ID TLV found?
   if(!error && n >= sizeof(LldpPortIdTlv))
   {
      //Point to the Port ID TLV
      tlv = (const LldpPortIdTlv *) p;

      //Extract the port ID from the remote systems MIB
      *portIdSubtype = (LldpPortIdSubtype) tlv->portIdSubtype;
      *portId = tlv->portId;
      *portIdLen = n - sizeof(LldpPortIdTlv);
   }
   else
   {
      //The Port ID TLV is not present
      *portIdSubtype = LLDP_PORT_ID_SUBTYPE_RESERVED;
      *portId = NULL;
      *portIdLen = 0;
   }

   //Successful processing
   return NO_ERROR;
#else
   //TX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Extract port description from local system MIB
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[out] portDesc Station port's description
 * @param[out] portDescLen Length of the port description, in bytes
 * @return Error code
 **/

error_t lldpMgmtGetLocalPortDesc(LldpAgentContext *context, uint_t portIndex,
   const char_t **portDesc, size_t *portDescLen)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   const uint8_t *p;
   LldpPortEntry *port;

   //Check parameters
   if(context == NULL || portDesc == NULL || portDescLen == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Search the local system MIB for the Port Description TLV
   error = lldpGetTlv(&port->txInfo, LLDP_TLV_TYPE_PORT_DESC, 0, &p, &n);

   //Port Description TLV found?
   if(!error)
   {
      //Extract the port description from the local system MIB
      *portDesc = (const char_t *) p;
      *portDescLen = n;
   }
   else
   {
      //The Port Description TLV is not present
      *portDesc = NULL;
      *portDescLen = 0;
   }

   //Successful processing
   return NO_ERROR;
#else
   //TX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Extract system name from local system MIB
 * @param[in] context Pointer to the LLDP agent context
 * @param[out] sysName System's administratively assigned name
 * @param[out] sysNameLen Length of the system name, in bytes
 * @return Error code
 **/

error_t lldpMgmtGetLocalSysName(LldpAgentContext *context,
   const char_t **sysName, size_t *sysNameLen)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   const uint8_t *p;

   //Check parameters
   if(context == NULL || sysName == NULL || sysNameLen == NULL)
   {
      return ERROR_READ_FAILED;
   }

   //Search the local system MIB for the System Name TLV
   error = lldpGetTlv(&context->txInfo, LLDP_TLV_TYPE_SYS_NAME, 0, &p, &n);

   //System Name TLV found?
   if(!error)
   {
      //Extract the system name from the local system MIB
      *sysName = (const char_t *) p;
      *sysNameLen = n;
   }
   else
   {
      //The System Name TLV is not present
      *sysName = NULL;
      *sysNameLen = 0;
   }

   //Successful processing
   return NO_ERROR;
#else
   //TX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Extract system description from local system MIB
 * @param[in] context Pointer to the LLDP agent context
 * @param[out] sysDesc Textual description of the network entity
 * @param[out] sysDescLen Length of the system description, in bytes
 * @return Error code
 **/

error_t lldpMgmtGetLocalSysDesc(LldpAgentContext *context,
   const char_t **sysDesc, size_t *sysDescLen)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   const uint8_t *p;

   //Check parameters
   if(context == NULL || sysDesc == NULL ||
      sysDescLen == NULL)
   {
      return ERROR_READ_FAILED;
   }

   //Search the local system MIB for the System Description TLV
   error = lldpGetTlv(&context->txInfo, LLDP_TLV_TYPE_SYS_DESC, 0, &p, &n);

   //System Description TLV found?
   if(!error)
   {
      //Extract the system name from the local system MIB
      *sysDesc = (const char_t *) p;
      *sysDescLen = n;
   }
   else
   {
      //The System Description TLV is not present
      *sysDesc = NULL;
      *sysDescLen = 0;
   }

   //Successful processing
   return NO_ERROR;
#else
   //TX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Extract system capabilities from local system MIB
 * @param[in] context Pointer to the LLDP agent context
 * @param[out] supportedCap Bit-map of the capabilities supported by the system
 * @param[out] enabledCap Bit-map of the capabilities currently enabled
 * @return Error code
 **/

error_t lldpMgmtGetLocalSysCap(LldpAgentContext *context,
   uint16_t *supportedCap, uint16_t *enabledCap)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   const uint8_t *p;
   const LldpSysCapTlv *tlv;

   //Check parameters
   if(context == NULL || supportedCap == NULL ||
      enabledCap == NULL)
   {
      return ERROR_READ_FAILED;
   }

   //Search the local system MIB for the System Capabilities TLV
   error = lldpGetTlv(&context->txInfo, LLDP_TLV_TYPE_SYS_CAP, 0, &p, &n);

   //System Capabilities TLV found?
   if(!error && n >= sizeof(LldpChassisIdTlv))
   {
      //Point to the System Capabilities TLV
      tlv = (const LldpSysCapTlv *) p;

      //Extract capabilities from the local system MIB
      *supportedCap = ntohs(tlv->supportedCap);
      *enabledCap = ntohs(tlv->enabledCap);
   }
   else
   {
      //The System Capabilities TLV is not present
      *supportedCap = 0;
      *enabledCap = 0;
   }

   //Successful processing
   return NO_ERROR;
#else
   //TX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Search the local system MIB for a given management address
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] mgmtAddrSubtype Type of management address
 * @param[in] mgmtAddr Octet string indicating a particular management
 *   address
 * @param[in] mgmtAddrLen Length of the management address, in bytes
 * @return index Zero-based index corresponding to the management address
 **/

int_t lldpMgmtFindLocalMgmtAddr(LldpAgentContext *context,
   uint8_t mgmtAddrSubtype, const uint8_t *mgmtAddr, size_t mgmtAddrLen)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   error_t error;
   uint_t k;
   int_t index;
   LldpTlv tlv;
   const LldpMgmtAddrTlv1 *part1;
   const LldpMgmtAddrTlv2 *part2;

   //Initialize index
   index = -1;

   //Get the index of the first management address
   for(k = 0; k < LLDP_MAX_MGMT_ADDRS; k++)
   {
      //Check whether the current management address is configured
      if((context->mgmtAddrMap & (1U << k)) != 0)
      {
         break;
      }
   }

   //Extract the first TLV
   error = lldpGetFirstTlv(&context->txInfo, &tlv);

   //Loop through the TLVs
   while(!error && k < LLDP_MAX_MGMT_ADDRS)
   {
      //Check TLV type
      if(tlv.type == LLDP_TLV_TYPE_MGMT_ADDR)
      {
         //Decode the contents of the Management Address TLV
         error = lldpDecodeMgmtAddrTlv(tlv.value, tlv.length, &part1, &part2);
         //Malformed TLV?
         if(error)
            break;

         //Check the management address against the specified address
         if(part1->mgmtAddrSubtype == mgmtAddrSubtype &&
            part1->mgmtAddrLen == (mgmtAddrLen + 1) &&
            osMemcmp(part1->mgmtAddr, mgmtAddr, mgmtAddrLen) == 0)
         {
            //A matching address has been found
            index = k;
            break;
         }
         else
         {
            //Get the index of the next management address
            for(k++; k < LLDP_MAX_MGMT_ADDRS; k++)
            {
               //Check whether the current management address is configured
               if((context->mgmtAddrMap & (1U << k)) != 0)
               {
                  break;
               }
            }
         }
      }

      //Extract the next TLV
      error = lldpGetNextTlv(&context->txInfo, &tlv);
   }

   //Return the index corresponding to the management address
   return index;
#else
   //TX mode is not implemented
   return -1;
#endif
}


/**
 * @brief Extract management address from local system MIB
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] index Zero-based index identifying a management address
 * @param[out] mgmtAddrSubtype Type of management address
 * @param[out] mgmtAddr Octet string indicating a particular management
 *   address
 * @param[out] mgmtAddrLen Length of the management address, in bytes
 * @param[out] ifNumSubtype Numbering method used for defining the interface
 *   number
 * @param[out] ifNum Number within the system that identifies the specific
 *   interface associated with this management address
 * @param[out] oid OID that identifies the type of hardware component or
 *   protocol entity associated with the indicated management address
 * @param[out] oidLen Length of the OID, in bytes
 * @return Error code
 **/

error_t lldpMgmtGetLocalMgmtAddr(LldpAgentContext *context, uint_t index,
   LldpMgmtAddrSubtype *mgmtAddrSubtype, const uint8_t **mgmtAddr,
   size_t *mgmtAddrLen, LldpIfNumSubtype *ifNumSubtype, uint32_t *ifNum,
   const uint8_t **oid, size_t *oidLen)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   error_t error;
   uint_t i;
   uint_t k;
   size_t n;
   const uint8_t *p;
   const LldpMgmtAddrTlv1 *part1;
   const LldpMgmtAddrTlv2 *part2;

   //Make sure the LLDP agent context is valid
   if(context == NULL)
   {
      return ERROR_READ_FAILED;
   }

   //Check index value
   if(index > LLDP_MAX_MGMT_ADDRS)
   {
      return ERROR_READ_FAILED;
   }

   //The local system MIB may contain more than one Management Address TLV
   for(i = 0, k = 0; i < index; i++)
   {
      //Check whether the current management address is configured
      if((context->mgmtAddrMap & (1U << i)) != 0)
      {
         k++;
      }
   }

   //Extract the management address from the local system MIB
   error = lldpGetTlv(&context->txInfo, LLDP_TLV_TYPE_MGMT_ADDR, k, &p, &n);

   //Check status code
   if(!error)
   {
      //Decode the contents of the Management Address TLV
      error = lldpDecodeMgmtAddrTlv(p, n, &part1, &part2);

      //Check status code
      if(!error)
      {
         //Extract the management address subtype
         if(mgmtAddrSubtype != NULL)
         {
            *mgmtAddrSubtype = (LldpMgmtAddrSubtype) part1->mgmtAddrSubtype;
         }

         //Extract the management address
         if(mgmtAddr != NULL && mgmtAddrLen != NULL)
         {
            *mgmtAddr = part1->mgmtAddr;
            *mgmtAddrLen = part1->mgmtAddrLen;
         }

         //Extract the interface numbering method
         if(ifNumSubtype != NULL)
         {
            *ifNumSubtype = (LldpIfNumSubtype) part2->ifNumSubtype;
         }

         //Extract the management address subtype
         if(ifNum != NULL)
         {
            *ifNum = ntohl(part2->ifNum);
         }

         //Extract the object identifier
         if(oid != NULL && oidLen != NULL)
         {
            *oid = part2->oid;
            *oidLen = part2->oidLen;
         }
      }
   }

   //Return status code
   return error;
#else
   //TX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Search the remote systems MIB for a given entry
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] timeMark Timestamp used to implement time-filtered rows
 * @param[in] portIndex Index value used to identify the port on which the
 *   remote system information was received
 * @param[in] index Arbitrary local integer value used to identify a particular
 *   connection
 * @return Pointer to the matching entry in the remote systems MIB
 **/

LldpNeighborEntry *lldpMgmtFindRemoteTableEntry(LldpAgentContext *context,
   uint32_t timeMark, uint_t portIndex, uint32_t index)
{
   uint_t i;
   LldpNeighborEntry *entry;

   //Loop through the remote systems MIB
   for(i = 0; i < context->numNeighbors; i++)
   {
      //Point to the current entry
      entry = &context->neighbors[i];

      //Check whether the entry is valid
      if(entry->rxInfo.length > 0)
      {
         //Matching entry?
         if(entry->timeMark == timeMark && entry->portIndex == portIndex &&
            entry->index == index)
         {
            //Return the zero-based index of the matching entry
            return entry;
         }
      }
   }

   //No matching entry was found
   return NULL;
}


/**
 * @brief Extract chassis ID from remote systems MIB
 * @param[in] entry Pointer to a given entry of the remote systems MIB
 * @param[out] chassisIdSubtype Type of identifier used for the chassis
 * @param[out] chassisId Administratively assigned name that identifies the chassis
 * @param[out] chassisIdLen Length of the chassis ID, in bytes
 * @return Error code
 **/

error_t lldpMgmtGetRemoteChassisId(LldpNeighborEntry *entry,
   LldpChassisIdSubtype *chassisIdSubtype, const uint8_t **chassisId,
   size_t *chassisIdLen)
{
   error_t error;
   size_t n;
   const uint8_t *p;
   const LldpChassisIdTlv *tlv;

   //Check parameters
   if(entry == NULL || chassisIdSubtype == NULL || chassisId == NULL ||
      chassisIdLen == NULL)
   {
      return ERROR_READ_FAILED;
   }

   //Search the remote systems MIB for the Chassis ID TLV
   error = lldpGetTlv(&entry->rxInfo, LLDP_TLV_TYPE_CHASSIS_ID, 0, &p, &n);

   //Chassis ID TLV found?
   if(!error && n >= sizeof(LldpChassisIdTlv))
   {
      //Point to the Chassis ID TLV
      tlv = (const LldpChassisIdTlv *) p;

      //Extract the chassis ID from the remote systems MIB
      *chassisIdSubtype = (LldpChassisIdSubtype) tlv->chassisIdSubtype;
      *chassisId = tlv->chassisId;
      *chassisIdLen = n - sizeof(LldpChassisIdTlv);
   }
   else
   {
      //The Chassis ID TLV is not present
      *chassisIdSubtype = LLDP_CHASSIS_ID_SUBTYPE_RESERVED;
      *chassisId = NULL;
      *chassisIdLen = 0;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Extract port ID from remote systems MIB
 * @param[in] entry Pointer to a given entry of the remote systems MIB
 * @param[out] portIdSubtype Type of identifier used for the port
 * @param[out] portId Administratively assigned name that identifies the port
 * @param[out] portIdLen Length of the port ID, in bytes
 * @return Error code
 **/

error_t lldpMgmtGetRemotePortId(LldpNeighborEntry *entry,
   LldpPortIdSubtype *portIdSubtype, const uint8_t **portId,
   size_t *portIdLen)
{
   error_t error;
   size_t n;
   const uint8_t *p;
   const LldpPortIdTlv *tlv;

   //Check parameters
   if(entry == NULL || portIdSubtype == NULL || portId == NULL ||
      portIdLen == NULL)
   {
      return ERROR_READ_FAILED;
   }

   //Search the remote systems MIB for the Port ID TLV
   error = lldpGetTlv(&entry->rxInfo, LLDP_TLV_TYPE_PORT_ID, 0, &p, &n);

   //Port ID TLV found?
   if(!error && n >= sizeof(LldpPortIdTlv))
   {
      //Point to the Port ID TLV
      tlv = (const LldpPortIdTlv *) p;

      //Extract the port ID from the remote systems MIB
      *portIdSubtype = (LldpPortIdSubtype) tlv->portIdSubtype;
      *portId = tlv->portId;
      *portIdLen = n - sizeof(LldpPortIdTlv);
   }
   else
   {
      //The Port ID TLV is not present
      *portIdSubtype = LLDP_PORT_ID_SUBTYPE_RESERVED;
      *portId = NULL;
      *portIdLen = 0;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Extract port description from remote systems MIB
 * @param[in] entry Pointer to a given entry of the remote systems MIB
 * @param[out] portDesc Station port's description
 * @param[out] portDescLen Length of the port description, in bytes
 * @return Error code
 **/

error_t lldpMgmtGetRemotePortDesc(LldpNeighborEntry *entry,
   const char_t **portDesc, size_t *portDescLen)
{
   error_t error;
   size_t n;
   const uint8_t *p;

   //Check parameters
   if(entry == NULL || portDesc == NULL || portDescLen == NULL)
   {
      return ERROR_READ_FAILED;
   }

   //Search the remote systems MIB for the Port Description TLV
   error = lldpGetTlv(&entry->rxInfo, LLDP_TLV_TYPE_PORT_DESC, 0, &p, &n);

   //Port Description TLV found?
   if(!error)
   {
      //Extract the port description from the remote systems MIB
      *portDesc = (const char_t *) p;
      *portDescLen = n;
   }
   else
   {
      //The Port Description TLV is not present
      *portDesc = NULL;
      *portDescLen = 0;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Extract system name from remote systems MIB
 * @param[in] entry Pointer to a given entry of the remote systems MIB
 * @param[out] sysName System's administratively assigned name
 * @param[out] sysNameLen Length of the system name, in bytes
 * @return Error code
 **/

error_t lldpMgmtGetRemoteSysName(LldpNeighborEntry *entry,
   const char_t **sysName, size_t *sysNameLen)
{
   error_t error;
   size_t n;
   const uint8_t *p;

   //Check parameters
   if(entry == NULL || sysName == NULL || sysNameLen == NULL)
   {
      return ERROR_READ_FAILED;
   }

   //Search the remote systems MIB for the System Name TLV
   error = lldpGetTlv(&entry->rxInfo, LLDP_TLV_TYPE_SYS_NAME, 0, &p, &n);

   //System Name TLV found?
   if(!error)
   {
      //Extract the system name from the remote systems MIB
      *sysName = (const char_t *) p;
      *sysNameLen = n;
   }
   else
   {
      //The System Name TLV is not present
      *sysName = NULL;
      *sysNameLen = 0;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Extract system description from remote systems MIB
 * @param[in] entry Pointer to a given entry of the remote systems MIB
 * @param[out] sysDesc Textual description of the network entity
 * @param[out] sysDescLen Length of the system description, in bytes
 * @return Error code
 **/

error_t lldpMgmtGetRemoteSysDesc(LldpNeighborEntry *entry,
   const char_t **sysDesc, size_t *sysDescLen)
{
   error_t error;
   size_t n;
   const uint8_t *p;

   //Check parameters
   if(entry == NULL || sysDesc == NULL || sysDescLen == NULL)
   {
      return ERROR_READ_FAILED;
   }

   //Search the remote systems MIB for the System Description TLV
   error = lldpGetTlv(&entry->rxInfo, LLDP_TLV_TYPE_SYS_DESC, 0, &p, &n);

   //System Description TLV found?
   if(!error)
   {
      //Extract the system description from the remote systems MIB
      *sysDesc = (const char_t *) p;
      *sysDescLen = n;
   }
   else
   {
      //The System Description TLV is not present
      *sysDesc = NULL;
      *sysDescLen = 0;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Extract system capabilities from remote systems MIB
 * @param[in] entry Pointer to a given entry of the remote systems MIB
 * @param[out] supportedCap Bit-map of the capabilities supported by the system
 * @param[out] enabledCap Bit-map of the capabilities currently enabled
 * @return Error code
 **/

error_t lldpMgmtGetRemoteSysCap(LldpNeighborEntry *entry,
   uint16_t *supportedCap, uint16_t *enabledCap)
{
   error_t error;
   size_t n;
   const uint8_t *p;
   const LldpSysCapTlv *tlv;

   //Check parameters
   if(entry == NULL || supportedCap == NULL ||
      enabledCap == NULL)
   {
      return ERROR_READ_FAILED;
   }

   //Search the remote systems MIB for the System Capabilities TLV
   error = lldpGetTlv(&entry->rxInfo, LLDP_TLV_TYPE_SYS_CAP, 0, &p, &n);

   //System Capabilities TLV found?
   if(!error && n >= sizeof(LldpChassisIdTlv))
   {
      //Point to the System Capabilities TLV
      tlv = (const LldpSysCapTlv *) p;

      //Extract capabilities from the local system MIB
      *supportedCap = ntohs(tlv->supportedCap);
      *enabledCap = ntohs(tlv->enabledCap);
   }
   else
   {
      //The System Capabilities TLV is not present
      *supportedCap = 0;
      *enabledCap = 0;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Search the remote system MIB for a given management address
 * @param[in] entry Pointer to a given entry of the remote systems MIB
 * @param[in] mgmtAddrSubtype Type of management address
 * @param[in] mgmtAddr Octet string indicating a particular management
 *   address
 * @param[in] mgmtAddrLen Length of the management address, in bytes
 * @return index Zero-based index corresponding to the management address
 **/

int_t lldpMgmtFindRemoteMgmtAddr(LldpNeighborEntry *entry,
   uint8_t mgmtAddrSubtype, const uint8_t *mgmtAddr, size_t mgmtAddrLen)
{
   error_t error;
   int_t index;
   LldpTlv tlv;
   const LldpMgmtAddrTlv1 *part1;
   const LldpMgmtAddrTlv2 *part2;

   //Initialize index
   index = 0;

   //Extract the first TLV
   error = lldpGetFirstTlv(&entry->rxInfo, &tlv);

   //Loop through the TLVs
   while(!error)
   {
      //Check TLV type
      if(tlv.type == LLDP_TLV_TYPE_MGMT_ADDR)
      {
         //Decode the contents of the Management Address TLV
         error = lldpDecodeMgmtAddrTlv(tlv.value, tlv.length, &part1, &part2);
         //Malformed TLV?
         if(error)
            break;

         //Check the management address against the specified address
         if(part1->mgmtAddrSubtype == mgmtAddrSubtype &&
            part1->mgmtAddrLen == (mgmtAddrLen + 1) &&
            osMemcmp(part1->mgmtAddr, mgmtAddr, mgmtAddrLen) == 0)
         {
            //A matching address has been found
            return index;
         }
         else
         {
            //Increment index
            index++;
         }
      }

      //Extract the next TLV
      error = lldpGetNextTlv(&entry->rxInfo, &tlv);
   }

   //The specified management address does not exist
   return -1;
}


/**
 * @brief Extract management address from remote systems MIB
 * @param[in] entry Pointer to a given entry of the remote systems MIB
 * @param[in] index Zero-based index identifying a management address
 * @param[out] mgmtAddrSubtype Type of management address
 * @param[out] mgmtAddr Octet string indicating a particular management
 *   address
 * @param[out] mgmtAddrLen Length of the management address, in bytes
 * @param[out] ifNumSubtype Numbering method used for defining the interface
 *   number
 * @param[out] ifNum Number within the system that identifies the specific
 *   interface associated with this management address
 * @param[out] oid OID that identifies the type of hardware component or
 *   protocol entity associated with the indicated management address
 * @param[out] oidLen Length of the OID, in bytes
 * @return Error code
 **/

error_t lldpMgmtGetRemoteMgmtAddr(LldpNeighborEntry *entry, uint_t index,
   LldpMgmtAddrSubtype *mgmtAddrSubtype, const uint8_t **mgmtAddr,
   size_t *mgmtAddrLen, LldpIfNumSubtype *ifNumSubtype, uint32_t *ifNum,
   const uint8_t **oid, size_t *oidLen)
{
   error_t error;
   size_t n;
   const uint8_t *p;
   const LldpMgmtAddrTlv1 *part1;
   const LldpMgmtAddrTlv2 *part2;

   //Check parameters
   if(entry == NULL)
   {
      return ERROR_READ_FAILED;
   }

   //Extract the management address from the remote systems MIB
   error = lldpGetTlv(&entry->rxInfo, LLDP_TLV_TYPE_MGMT_ADDR, index, &p, &n);

   //Check status code
   if(!error)
   {
      //Decode the contents of the Management Address TLV
      error = lldpDecodeMgmtAddrTlv(p, n, &part1, &part2);

      //Check status code
      if(!error)
      {
         //Extract the management address subtype
         if(mgmtAddrSubtype != NULL)
         {
            *mgmtAddrSubtype = (LldpMgmtAddrSubtype) part1->mgmtAddrSubtype;
         }

         //Extract the management address
         if(mgmtAddr != NULL && mgmtAddrLen != NULL)
         {
            *mgmtAddr = part1->mgmtAddr;
            *mgmtAddrLen = part1->mgmtAddrLen;
         }

         //Extract the interface numbering method
         if(ifNumSubtype != NULL)
         {
            *ifNumSubtype = (LldpIfNumSubtype) part2->ifNumSubtype;
         }

         //Extract the management address subtype
         if(ifNum != NULL)
         {
            *ifNum = ntohl(part2->ifNum);
         }

         //Extract the object identifier
         if(oid != NULL && oidLen != NULL)
         {
            *oid = part2->oid;
            *oidLen = part2->oidLen;
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Extract unknown TLV from remote systems MIB
 * @param[in] entry Pointer to a given entry of the remote systems MIB
 * @param[in] type TLV type field
 * @param[in] index Index identifying a particular instance of the TLV
 * @param[out] info TLV information string
 * @param[out] infoLen Length of the information string, in bytes
 * @return Error code
 **/

error_t lldpMgmtGetRemoteUnknownTlv(LldpNeighborEntry *entry,
   uint8_t type, uint_t index, const uint8_t **info, size_t *infoLen)
{
   //Search the remote systems MIB for a matching TLV
   return lldpGetTlv(&entry->rxInfo, type, index, info, infoLen);
}


/**
 * @brief Extract organizationally defined TLV from remote systems MIB
 * @param[in] entry Pointer to a given entry of the remote systems MIB
 * @param[in] oui Organizationally unique identifier
 * @param[in] subtype Organizationally defined subtype
 * @param[in] index Index identifying a particular instance of the TLV
 * @param[out] info Organizationally defined information string
 * @param[out] infoLen Length of the information string, in bytes
 * @return Error code
 **/

error_t lldpMgmtGetRemoteOrgDefInfo(LldpNeighborEntry *entry,
   uint32_t oui, uint8_t subtype, uint_t index, const uint8_t **info,
   size_t *infoLen)
{
   //Search the remote systems MIB for a matching TLV
   return lldpGetOrgDefTlv(&entry->rxInfo, oui, subtype, index, info,
      infoLen);
}


/**
 * @brief Get the value of the statsFramesOutTotal statistics counter
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[out] statsFramesOutTotal Count of all LLDP frames transmitted through
 *   the port
 * @return Error code
 **/

error_t lldpMgmtGetStatsFramesOutTotal(LldpAgentContext *context,
   uint_t portIndex, uint32_t *statsFramesOutTotal)
{
#if (LLDP_TX_MODE_SUPPORT == ENABLED)
   LldpPortEntry *port;

   //Check parameters
   if(context == NULL || statsFramesOutTotal == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the current value of the statistics counter
   *statsFramesOutTotal = port->statsFramesOutTotal;

   //Successful processing
   return NO_ERROR;
#else
   //TX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Get the value of the statsFramesDiscardedTotal statistics counter
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[out] statsFramesDiscardedTotal Number of LLDP frames received by this
 *   LLDP agent on the indicated port, and then discarded for any reason
 * @return Error code
 **/

error_t lldpMgmtGetStatsFramesDiscardedTotal(LldpAgentContext *context,
   uint_t portIndex, uint32_t *statsFramesDiscardedTotal)
{
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   LldpPortEntry *port;

   //Check parameters
   if(context == NULL || statsFramesDiscardedTotal == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the current value of the statistics counter
   *statsFramesDiscardedTotal = port->statsFramesDiscardedTotal;

   //Successful processing
   return NO_ERROR;
#else
   //RX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Get the value of the statsFramesInErrorsTotal statistics counter
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[out] statsFramesInErrorsTotal Number of invalid LLDP frames received
 *   by this LLDP agent on the indicated port, while this LLDP agent is enabled
 * @return Error code
 **/

error_t lldpMgmtGetStatsFramesInErrorsTotal(LldpAgentContext *context,
   uint_t portIndex, uint32_t *statsFramesInErrorsTotal)
{
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   LldpPortEntry *port;

   //Check parameters
   if(context == NULL || statsFramesInErrorsTotal == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the current value of the statistics counter
   *statsFramesInErrorsTotal = port->statsFramesInErrorsTotal;

   //Successful processing
   return NO_ERROR;
#else
   //RX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Get the value of the statsFramesInTotal statistics counter
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[out] statsFramesInTotal Number of valid LLDP frames received by this
 *   LLDP agent on the indicated port, while this LLDP agent is enabled
 * @return Error code
 **/

error_t lldpMgmtGetStatsFramesInTotal(LldpAgentContext *context,
   uint_t portIndex, uint32_t *statsFramesInTotal)
{
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   LldpPortEntry *port;

   //Check parameters
   if(context == NULL || statsFramesInTotal == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the current value of the statistics counter
   *statsFramesInTotal = port->statsFramesInTotal;

   //Successful processing
   return NO_ERROR;
#else
   //RX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Get the value of the statsTLVsDiscardedTotal statistics counter
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[out] statsTLVsDiscardedTotal Number of LLDP TLVs discarded for any
 *   reason by this LLDP agent on the indicated port
 * @return Error code
 **/

error_t lldpMgmtGetStatsTLVsDiscardedTotal(LldpAgentContext *context,
   uint_t portIndex, uint32_t *statsTLVsDiscardedTotal)
{
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   LldpPortEntry *port;

   //Check parameters
   if(context == NULL || statsTLVsDiscardedTotal == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the current value of the statistics counter
   *statsTLVsDiscardedTotal = port->statsTLVsDiscardedTotal;

   //Successful processing
   return NO_ERROR;
#else
   //RX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Get the value of the statsTLVsUnrecognizedTotal statistics counter
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[out] statsTLVsUnrecognizedTotal Number of LLDP TLVs received on the
 *   given port that are not recognized by this LLDP agent
 * @return Error code
 **/

error_t lldpMgmtGetStatsTLVsUnrecognizedTotal(LldpAgentContext *context,
   uint_t portIndex, uint32_t *statsTLVsUnrecognizedTotal)
{
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   LldpPortEntry *port;

   //Check parameters
   if(context == NULL || statsTLVsUnrecognizedTotal == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the current value of the statistics counter
   *statsTLVsUnrecognizedTotal = port->statsTLVsUnrecognizedTotal;

   //Successful processing
   return NO_ERROR;
#else
   //RX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Get the value of the statsAgeoutsTotal statistics counter
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[out] statsAgeoutsTotal Number of age-outs that occurred on a given port
 * @return Error code
 **/

error_t lldpMgmtGetStatsAgeoutsTotal(LldpAgentContext *context,
   uint_t portIndex, uint32_t *statsAgeoutsTotal)
{
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   LldpPortEntry *port;

   //Check parameters
   if(context == NULL || statsAgeoutsTotal == NULL)
      return ERROR_READ_FAILED;

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
      return ERROR_INVALID_PORT;

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Retrieve the current value of the statistics counter
   *statsAgeoutsTotal = port->statsAgeoutsTotal;

   //Successful processing
   return NO_ERROR;
#else
   //RX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Get the value of the statsRemTablesLastChangeTime statistics counter
 * @param[in] context Pointer to the LLDP agent context
 * @param[out] statsRemTablesLastChangeTime The time at which an entry was
 *   created, modified, or deleted in tables
 * @return Error code
 **/

error_t lldpMgmtGetStatsRemTablesLastChangeTime(LldpAgentContext *context,
   uint32_t *statsRemTablesLastChangeTime)
{
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || statsRemTablesLastChangeTime == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the current value of the statistics counter
   *statsRemTablesLastChangeTime = context->statsRemTablesLastChangeTime;

   //Successful processing
   return NO_ERROR;
#else
   //RX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Get the value of the statsRemTablesInserts statistics counter
 * @param[in] context Pointer to the LLDP agent context
 * @param[out] statsRemTablesInserts The number of times the complete set of
 *   information advertised by a particular MSAP has been inserted into tables
 * @return Error code
 **/

error_t lldpMgmtGetStatsRemTablesInserts(LldpAgentContext *context,
   uint32_t *statsRemTablesInserts)
{
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || statsRemTablesInserts == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the current value of the statistics counter
   *statsRemTablesInserts = context->statsRemTablesInserts;

   //Successful processing
   return NO_ERROR;
#else
   //RX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Get the value of the statsRemTablesDeletes statistics counter
 * @param[in] context Pointer to the LLDP agent context
 * @param[out] statsRemTablesDeletes The number of times the complete set of
 *   information advertised by a particular MSAP has been deleted from tables
 * @return Error code
 **/

error_t lldpMgmtGetStatsRemTablesDeletes(LldpAgentContext *context,
   uint32_t *statsRemTablesDeletes)
{
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || statsRemTablesDeletes == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the current value of the statistics counter
   *statsRemTablesDeletes = context->statsRemTablesDeletes;

   //Successful processing
   return NO_ERROR;
#else
   //RX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Get the value of the statsRemTablesDrops statistics counter
 * @param[in] context Pointer to the LLDP agent context
 * @param[out] statsRemTablesDrops The number of times the complete set of
 *   information advertised by a particular MSAP could not be entered into
 *   tables because of insufficient resources
 * @return Error code
 **/

error_t lldpMgmtGetStatsRemTablesDrops(LldpAgentContext *context,
   uint32_t *statsRemTablesDrops)
{
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || statsRemTablesDrops == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the current value of the statistics counter
   *statsRemTablesDrops = context->statsRemTablesDrops;

   //Successful processing
   return NO_ERROR;
#else
   //RX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}


/**
 * @brief Get the value of the statsRemTablesAgeouts statistics counter
 * @param[in] context Pointer to the LLDP agent context
 * @param[out] statsRemTablesAgeouts The number of times the complete set of
 *   information advertised by a particular MSAP has been deleted from tables
 *   because the information timeliness interval has expired
 * @return Error code
 **/

error_t lldpMgmtGetStatsRemTablesAgeouts(LldpAgentContext *context,
   uint32_t *statsRemTablesAgeouts)
{
#if (LLDP_RX_MODE_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || statsRemTablesAgeouts == NULL)
      return ERROR_READ_FAILED;

   //Retrieve the current value of the statistics counter
   *statsRemTablesAgeouts = context->statsRemTablesAgeouts;

   //Successful processing
   return NO_ERROR;
#else
   //RX mode is not implemented
   return ERROR_READ_FAILED;
#endif
}

#endif
