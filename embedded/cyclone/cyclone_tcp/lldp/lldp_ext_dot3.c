/**
 * @file lldp_ext_dot3.c
 * @brief IEEE 802.3 LLDP extension
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
#include "lldp/lldp_ext_dot3.h"
#include "lldp/lldp_misc.h"
#include "lldp/lldp_debug.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (LLDP_SUPPORT == ENABLED && LLDP_TX_MODE_SUPPORT == ENABLED)


/**
 * @brief Set MAC/PHY configuration/status
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[in] autoNegSupportStatus Bit-map that identifies the auto-negotiation
 *   support and current status of the local 802.3 LAN station
 * @param[in] pmdAutoNegAdvCap PMD auto-negotiation advertised capability
 * @param[in] operationalMauType MAU type of the sending device
 * @return Error code
 **/

error_t lldpDot3SetLocalMacPhyConfigStatus(LldpAgentContext *context,
   uint_t portIndex, uint8_t autoNegSupportStatus, uint16_t pmdAutoNegAdvCap,
   uint16_t operationalMauType)
{
   error_t error;
   size_t n;
   LldpPortEntry *port;
   LldpDot3MacPhyConfigStatusTlv *tlv;

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
   tlv = (LldpDot3MacPhyConfigStatusTlv *) context->lldpdu.data;

   //Set auto-negotiation support/status
   tlv->autoNegSupportStatus = autoNegSupportStatus;
   //Set PMD auto-negotiation advertised capability
   tlv->pmdAutoNegAdvCap = htons(pmdAutoNegAdvCap);
   //Set operational MAU type
   tlv->operationalMauType = htons(operationalMauType);

   //Calculate the length of the TLV
   n = sizeof(LldpDot3MacPhyConfigStatusTlv);

   //An LLDPDU should contain no more than one MAC/PHY Configuration/Status
   //TLV (refer to IEEE 802.1AB-2005, section G.2.4)
   error = lldpSetOrgDefTlv(&port->txInfo, LLDP_DOT3_OUI,
      LLDP_DOT3_SUBTYPE_MAC_PHY_CONFIG_STATUS, 0, (uint8_t *) tlv, n, TRUE);

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
 * @brief Set power-via-MDI
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[in] mdiPowerSupport Bit-map of the MDI power capabilities and status
 * @param[in] psePowerPair PSE power pair
 * @param[in] powerClass PSE power classification
 * @param[in] dllClassExt DLL classification extension (optional parameter)
 * @param[in] type34Ext Type 3 and Type 4 extension (optional parameter)
 * @return Error code
 **/

error_t lldpDot3SetLocalPowerViaMdi(LldpAgentContext *context,
   uint_t portIndex, uint8_t mdiPowerSupport,
   LldpDot3PsePowerPair psePowerPair, LldpDot3PowerClass powerClass,
   const LldpDot3DllClassExt *dllClassExt, const LldpDot3Type34Ext *type34Ext)
{
   error_t error;
   size_t n;
   LldpPortEntry *port;
   LldpDot3PowerViaMdiTlv *tlv;

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
   tlv = (LldpDot3PowerViaMdiTlv *) context->lldpdu.data;

   //Set MDI power support
   tlv->mdiPowerSupport = mdiPowerSupport;
   //Set PSE power pair
   tlv->psePowerPair = psePowerPair;
   //Set power class
   tlv->powerClass = powerClass;

   //Calculate the length of the TLV
   n = sizeof(LldpDot3PowerViaMdiTlv);

   //The DLL classification extension is optional
   if(dllClassExt != NULL)
   {
      LldpDot3DllClassExt *ext;

      //Point to the buffer where to format the extension
      ext = (LldpDot3DllClassExt *) (context->lldpdu.data + n);

      //Format DLL classification extension
      ext->powerType = dllClassExt->powerType;
      ext->powerSource = dllClassExt->powerSource;
      ext->powerPriority = dllClassExt->powerPriority;
      ext->pdRequestedPower = htons(dllClassExt->pdRequestedPower);
      ext->pseAllocatedPower = htons(dllClassExt->pseAllocatedPower);

      //Adjust the length of the TLV
      n += sizeof(LldpDot3DllClassExt);
   }

   //The Type 3 and Type 4 extension is optional
   if(dllClassExt != NULL && type34Ext != NULL)
   {
      LldpDot3Type34Ext *ext;

      //Point to the buffer where to format the extension
      ext = (LldpDot3Type34Ext *) (context->lldpdu.data + n);

      //Format Type 3 and Type 4 extension
      ext->pdRequestedPowerA = htons(type34Ext->pdRequestedPowerA);
      ext->pdRequestedPowerB = htons(type34Ext->pdRequestedPowerB);
      ext->pseAllocatedPowerA = htons(type34Ext->pseAllocatedPowerA);
      ext->pseAllocatedPowerB = htons(type34Ext->pseAllocatedPowerB);
      ext->powerStatus = htons(type34Ext->powerStatus);
      ext->systemSetup = type34Ext->systemSetup;
      ext->pseMaxAvailablePower = htons(type34Ext->pseMaxAvailablePower);
      ext->autoclass = type34Ext->autoclass;
      osMemcpy(ext->powerDown, type34Ext->powerDown, 3);

      //Adjust the length of the TLV
      n += sizeof(LldpDot3Type34Ext);
   }

   //An LLDPDU should contain no more than one Power Via MDI TLV (refer to
   //IEEE 802.1AB-2005, section G.3.4)
   error = lldpSetOrgDefTlv(&port->txInfo, LLDP_DOT3_OUI,
      LLDP_DOT3_SUBTYPE_POWER_VIA_MDI, 0, (uint8_t *) tlv, n, TRUE);

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
 * @brief Set Link aggregation
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[in] aggregationStatus Bit-map of the link aggregation capabilities
 *   and the current aggregation status of the link
 * @param[in] aggregatedPortId IEEE 802.3 aggregated port identifier,
 * @return Error code
 **/

error_t lldpDot3SetLocalLinkAggregation(LldpAgentContext *context,
   uint_t portIndex, uint8_t aggregationStatus, uint32_t aggregatedPortId)
{
   error_t error;
   size_t n;
   LldpPortEntry *port;
   LldpDot3LinkAggregationTlv *tlv;

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
   tlv = (LldpDot3LinkAggregationTlv *) context->lldpdu.data;

   //Set aggregation status
   tlv->aggregationStatus = aggregationStatus;
   //Set aggregated port ID
   tlv->aggregatedPortId = htonl(aggregatedPortId);

   //Calculate the length of the TLV
   n = sizeof(LldpDot3LinkAggregationTlv);

   //An LLDPDU should contain no more than one Link Aggregation TLV (refer
   //to IEEE 802.1AB-2005, section G.4.3)
   error = lldpSetOrgDefTlv(&port->txInfo, LLDP_DOT3_OUI,
      LLDP_DOT3_SUBTYPE_LINK_AGGREGATION, 0, (uint8_t *) tlv, n, TRUE);

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
 * @brief Set maximum frame size
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[in] maxFrameSize Maximum supported frame size, in octets
 * @return Error code
 **/

error_t lldpDot3SetLocalMaxFrameSize(LldpAgentContext *context,
   uint_t portIndex, uint16_t maxFrameSize)
{
   error_t error;
   size_t n;
   LldpPortEntry *port;
   LldpDot3MaxFrameSizeTlv *tlv;

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
   tlv = (LldpDot3MaxFrameSizeTlv *) context->lldpdu.data;

   //Set maximum frame size
   tlv->maxFrameSize = htons(maxFrameSize);

   //Calculate the length of the TLV
   n = sizeof(LldpDot3MaxFrameSizeTlv);

   //An LLDPDU should contain no more than one Maximum Frame Size TLV (refer
   //to IEEE 802.1AB-2005, section G.5.2)
   error = lldpSetOrgDefTlv(&port->txInfo, LLDP_DOT3_OUI,
      LLDP_DOT3_SUBTYPE_MAX_FRAME_SIZE, 0, (uint8_t *) tlv, n, TRUE);

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
 * @brief Set power-via-MDI measurements
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[in] measurements Measured values
 * @param[in] psePowerPriceIndex Index of the current price of electricity
 *   compared to what the PSE considers the nominal electricity price
 * @return Error code
 **/

error_t lldpDot3SetLocalPowerViaMdiMeas(LldpAgentContext *context,
   uint_t portIndex, uint8_t measurements[20], uint16_t psePowerPriceIndex)
{
   error_t error;
   size_t n;
   LldpPortEntry *port;
   LldpDot3PowerViaMdiMeasTlv *tlv;

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
   tlv = (LldpDot3PowerViaMdiMeasTlv *) context->lldpdu.data;

   //Copy measurements field
   osMemcpy(tlv->measurements, measurements, 20);

   //Set PSE power price index
   tlv->psePowerPriceIndex = htons(psePowerPriceIndex);

   //Calculate the length of the TLV
   n = sizeof(LldpDot3PowerViaMdiMeasTlv);

   //An LLDPDU should contain no more than one Power Via MDI Measurements
   //TLV (refer to IEEE 802.3bt, section 79.3.8.3)
   error = lldpSetOrgDefTlv(&port->txInfo, LLDP_DOT3_OUI,
      LLDP_DOT3_SUBTYPE_POWER_VIA_MDI_MEAS, 0, (uint8_t *) tlv, n, TRUE);

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
 * @brief Remove all IEEE 802.3 specific TLVs with specified subtype
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] subtype TLV subtype
 * @return Error code
 **/

error_t lldpDot3DeleteLocalTlv(LldpAgentContext *context,
   LldpDot3Subtype subtype)
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
         error = lldpDeleteOrgDefTlv(&context->ports[i].txInfo, LLDP_DOT3_OUI,
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
