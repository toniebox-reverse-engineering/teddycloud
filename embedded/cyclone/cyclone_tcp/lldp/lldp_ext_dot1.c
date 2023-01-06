/**
 * @file lldp_ext_dot1.c
 * @brief IEEE 802.1 LLDP extension
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
#include "lldp/lldp_ext_dot1.h"
#include "lldp/lldp_misc.h"
#include "lldp/lldp_debug.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (LLDP_SUPPORT == ENABLED && LLDP_TX_MODE_SUPPORT == ENABLED)


/**
 * @brief Set port VLAN ID
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[in] pvid Port VLAN identifier
 * @return Error code
 **/

error_t lldpDot1SetLocalPortVlanId(LldpAgentContext *context,
   uint_t portIndex, uint16_t pvid)
{
   error_t error;
   size_t n;
   LldpPortEntry *port;
   LldpDot1PortVlanIdTlv *tlv;

   //Make sure the LLDP agent context is valid
   if(context == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
   {
      return ERROR_INVALID_PORT;
   }

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Point to the buffer where to format the TLV
   tlv = (LldpDot1PortVlanIdTlv *) context->lldpdu.data;

   //Set PVID
   tlv->pvid = htons(pvid);

   //Calculate the length of the TLV
   n = sizeof(LldpDot1PortVlanIdTlv);

   //An LLDPDU should contain no more than one Port VLAN ID TLV (refer
   //to IEEE 802.1AB-2005, section F.2.2)
   error = lldpSetOrgDefTlv(&port->txInfo, LLDP_DOT1_OUI,
      LLDP_DOT1_SUBTYPE_PORT_VLAN_ID, 0, (uint8_t *) tlv, n, TRUE);

   //Check status code
   if(!error)
   {
      //The somethingChangedLocal flag must be set whenever the value of an
      //object has changed in the local system MIB
      lldpSomethingChangedLocal(context);
   }

   //Release exclusive access to the LLDP agent context
   osReleaseMutex(&context->mutex);

   //Return status code
   return error;
}


/**
 * @brief Set port and protocol VLAN ID
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[in] flags Bit-map indicating the port and protocol VLAN capability
 *   and status
 * @param[in] ppvid PPVID number for this LAN station
 * @return Error code
 **/

error_t lldpDot1SetLocalPortProtoVlanId(LldpAgentContext *context,
   uint_t portIndex, uint8_t flags, uint16_t ppvid)
{
   error_t error;
   uint_t k;
   size_t n;
   bool_t replace;
   LldpPortEntry *port;
   LldpDot1PortProtoVlanIdTlv *tlv;

   //Make sure the LLDP agent context is valid
   if(context == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
   {
      return ERROR_INVALID_PORT;
   }

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Initialize status code
   error = NO_ERROR;
   //Initialize flag
   replace = FALSE;

   //If more than one Port And Protocol VLAN ID TLV is defined for a port,
   //the PPVID value shall be different from any other PPVID defined for the
   //port (refer to IEEE 802.1AB-2005, section F.3.3)
   for(k = 0; !error; k++)
   {
      //Extract the next Port And Protocol VLAN ID TLV from the local system MIB
      error = lldpGetOrgDefTlv(&port->txInfo, LLDP_DOT1_OUI,
         LLDP_DOT1_SUBTYPE_PORT_PROTO_VLAN_ID, k, (const uint8_t **) &tlv, &n);

      //TLV found?
      if(!error)
      {
         //Sanity check
         if(n >= sizeof(LldpDot1PortProtoVlanIdTlv))
         {
            //Check the value of the PPVID
            if(ntohs(tlv->ppvid) == ppvid)
            {
               //Replace the existing TLV
               replace = TRUE;
               break;
            }
            else if(ntohs(tlv->ppvid) > ppvid)
            {
               //Insert a new TLV
               break;
            }
            else
            {
            }
         }
      }
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_NOT_FOUND)
   {
      //Point to the buffer where to format the TLV
      tlv = (LldpDot1PortProtoVlanIdTlv *) context->lldpdu.data;

      //Set flags
      tlv->flags = flags;
      //Set PPVID
      tlv->ppvid = htons(ppvid);

      //Calculate the length of the TLV
      n = sizeof(LldpDot1PortProtoVlanIdTlv);

      //Set the value of the specified TLV
      error = lldpSetOrgDefTlv(&port->txInfo, LLDP_DOT1_OUI,
         LLDP_DOT1_SUBTYPE_PORT_PROTO_VLAN_ID, k, (uint8_t *) tlv, n, replace);

      //Check status code
      if(!error)
      {
         //The somethingChangedLocal flag must be set whenever the value of an
         //object has changed in the local system MIB
         lldpSomethingChangedLocal(context);
      }
   }

   //Release exclusive access to the LLDP agent context
   osReleaseMutex(&context->mutex);

   //Return status code
   return error;
}


/**
 * @brief Set VLAN name
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[in] vlanId VID number associated with the VLAN name
 * @param[in] vlanName VLAN's name
 * @return Error code
 **/

error_t lldpDot1SetLocalVlanName(LldpAgentContext *context,
   uint_t portIndex, uint16_t vlanId, const char_t *vlanName)
{
   error_t error;
   uint_t k;
   size_t n;
   bool_t replace;
   LldpPortEntry *port;
   LldpDot1VlanNameTlv *tlv;

   //Check parameters
   if(context == NULL || vlanName == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
   {
      return ERROR_INVALID_PORT;
   }

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Get the length of the VLAN name
   n = osStrlen(vlanName);

   //Check the length of the string
   if(n < LLDP_DOT1_MIN_VLAN_NAME_LEN ||
      n > LLDP_DOT1_MAX_VLAN_NAME_LEN)
   {
      return ERROR_INVALID_LENGTH;
   }

   //Initialize status code
   error = NO_ERROR;
   //Initialize flag
   replace = FALSE;

   //If more than one VLAN Name TLV is defined for a port, the VLAN ID and the
   //associated VLAN name combination shall be different from any other VLAN ID
   //and VLAN name combination defined for the port (refer to IEEE 802.1AB-2005,
   //section F.4.5)
   for(k = 0; !error; k++)
   {
      //Extract the next VLAN Name TLV from the local system MIB
      error = lldpGetOrgDefTlv(&port->txInfo, LLDP_DOT1_OUI,
         LLDP_DOT1_SUBTYPE_VLAN_NAME, k, (const uint8_t **) &tlv, &n);

      //TLV found?
      if(!error)
      {
         //Sanity check
         if(n >= sizeof(LldpDot1VlanNameTlv))
         {
            //Check the value of the VLAN ID
            if(ntohs(tlv->vlanId) == vlanId)
            {
               //Replace the existing TLV
               replace = TRUE;
               break;
            }
            else if(ntohs(tlv->vlanId) > vlanId)
            {
               //Insert a new TLV
               break;
            }
            else
            {
            }
         }
      }
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_NOT_FOUND)
   {
      //Point to the buffer where to format the TLV
      tlv = (LldpDot1VlanNameTlv *) context->lldpdu.data;

      //Set VLAN ID
      tlv->vlanId = htons(vlanId);
      //Set VLAN name length
      tlv->vlanNameLen = n;
      //Copy VLAN name
      osMemcpy(tlv->vlanName, vlanName, n);

      //Calculate the length of the TLV
      n += sizeof(LldpDot1VlanNameTlv);

      //Set the value of the specified TLV
      error = lldpSetOrgDefTlv(&port->txInfo, LLDP_DOT1_OUI,
         LLDP_DOT1_SUBTYPE_VLAN_NAME, k, (uint8_t *) tlv, n, replace);

      //Check status code
      if(!error)
      {
         //The somethingChangedLocal flag must be set whenever the value of an
         //object has changed in the local system MIB
         lldpSomethingChangedLocal(context);
      }
   }

   //Release exclusive access to the LLDP agent context
   osReleaseMutex(&context->mutex);

   //Return status code
   return error;
}


/**
 * @brief Set protocol identity
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[in] protocolId First n octets of the protocol after the layer 2
 *   addresses
 * @param[in] protocolIdLen Length of the protocol identity, in bytes
 * @return Error code
 **/

error_t lldpDot1SetLocalProtocolId(LldpAgentContext *context,
   uint_t portIndex, const uint8_t *protocolId, size_t protocolIdLen)
{
   error_t error;
   uint_t k;
   size_t n;
   bool_t replace;
   LldpPortEntry *port;
   LldpDot1ProtocolIdTlv *tlv;

   //Check parameters
   if(context == NULL || protocolId == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Check the length of the protocol identity
   if(protocolIdLen < LLDP_DOT1_MIN_PROTOCOL_ID_LEN ||
      protocolIdLen > LLDP_DOT1_MAX_PROTOCOL_ID_LEN)
   {
      return ERROR_INVALID_LENGTH;
   }

   //Invalid port index?
   if(portIndex < 1 || portIndex > context->numPorts)
   {
      return ERROR_INVALID_PORT;
   }

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //Point to the port that matches the specified port index
   port = &context->ports[portIndex - 1];

   //Initialize status code
   error = NO_ERROR;
   //Initialize flag
   replace = FALSE;

   //If more than one Protocol Identity TLV is defined for a port, the protocol
   //identity field value shall be different from any other Protocol Identity
   //TLV defined for the port (refer to IEEE 802.1AB-2005, section F.5.4)
   for(k = 0; !error; k++)
   {
      //Extract the next Protocol Identity TLV from the local system MIB
      error = lldpGetOrgDefTlv(&port->txInfo, LLDP_DOT1_OUI,
         LLDP_DOT1_SUBTYPE_PROTOCOL_ID, k, (const uint8_t **) &tlv, &n);

      //TLV found?
      if(!error)
      {
         //Sanity check
         if(n >= sizeof(LldpDot1ProtocolIdTlv))
         {
            //Compare protocol identity fields
            if(n == (protocolIdLen + sizeof(LldpDot1ProtocolIdTlv)) &&
               osMemcmp(tlv->protocolId, protocolId, n) == 0)
            {
               //Replace the existing TLV
               replace = TRUE;
               break;
            }
         }
      }
   }

   //Check status code
   if(error == NO_ERROR || error == ERROR_NOT_FOUND)
   {
      //Point to the buffer where to format the TLV
      tlv = (LldpDot1ProtocolIdTlv *) context->lldpdu.data;

      //Set protocol identity length
      tlv->protocolIdLen = protocolIdLen;
      //Copy protocol identity
      osMemcpy(tlv->protocolId, protocolId, protocolIdLen);

      //Calculate the length of the TLV
      n = sizeof(LldpDot1ProtocolIdTlv) + protocolIdLen;

      //Set the value of the specified TLV
      error = lldpSetOrgDefTlv(&port->txInfo, LLDP_DOT1_OUI,
         LLDP_DOT1_SUBTYPE_PROTOCOL_ID, k, (uint8_t *) tlv, n, replace);

      //Check status code
      if(!error)
      {
         //The somethingChangedLocal flag must be set whenever the value of an
         //object has changed in the local system MIB
         lldpSomethingChangedLocal(context);
      }
   }

   //Release exclusive access to the LLDP agent context
   osReleaseMutex(&context->mutex);

   //Return status code
   return error;
}


/**
 * @brief Remove all IEEE 802.1 specific TLVs with specified subtype
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] subtype TLV subtype
 * @return Error code
 **/

error_t lldpDot1DeleteLocalTlv(LldpAgentContext *context,
   LldpDot1Subtype subtype)
{
   error_t error;
   uint_t i;
   bool_t somethingChangedLocal;

   //Make sure the LLDP agent context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //Clear flag
   somethingChangedLocal = FALSE;

   //Loop through the ports
   for(i = 0; i < context->numPorts; i++)
   {
      //Initialize status code
      error = NO_ERROR;

      //Remove all TLVs that match the specified type
      while(!error)
      {
         //Remove one TLV at a time
         error = lldpDeleteOrgDefTlv(&context->ports[i].txInfo, LLDP_DOT1_OUI,
            subtype, 0);

         //Check status code
         if(!error)
         {
            somethingChangedLocal = TRUE;
         }
      }
   }

   //Any change in the LLDP local system MIB?
   if(somethingChangedLocal)
   {
      //The somethingChangedLocal flag must be set whenever the value of an
      //object has changed in the local system MIB
      lldpSomethingChangedLocal(context);

      //Successful processing
      error = NO_ERROR;
   }
   else
   {
      //Report an error
      error = ERROR_NOT_FOUND;
   }

   //Release exclusive access to the LLDP agent context
   osReleaseMutex(&context->mutex);

   //Return status code
   return error;
}

#endif
