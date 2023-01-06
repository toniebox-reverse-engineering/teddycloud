/**
 * @file lldp_ext_med.c
 * @brief LLDP-MED extension (LLDP for Media Endpoint Devices)
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
#include "lldp/lldp_ext_med.h"
#include "lldp/lldp_misc.h"
#include "lldp/lldp_debug.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (LLDP_SUPPORT == ENABLED && LLDP_TX_MODE_SUPPORT == ENABLED)


/**
 * @brief Set LLDP-MED capabilities
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] capabilities Bit-map of the supported set of capabilities
 * @param[in] deviceType LLDP-MED device type
 * @return Error code
 **/

error_t lldpMedSetLocalCap(LldpAgentContext *context, uint16_t capabilities,
   LldpMedDeviceType deviceType)
{
   error_t error;
   size_t n;
   LldpMedCapTlv *tlv;

   //Make sure the LLDP agent context is valid
   if(context == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //Point to the buffer where to format the TLV
   tlv = (LldpMedCapTlv *) context->lldpdu.data;

   //Set LLDP-MED capabilities
   tlv->capabilities = htons(capabilities);
   //Set LLDP-MED device type
   tlv->deviceType = deviceType;

   //Calculate the length of the TLV
   n = sizeof(LldpMedCapTlv);

   //All LLDP-MED LLDPDUs shall contain exactly one LLDP-MED Capabilities TLV,
   //and this TLV shall always be the first LLDP-MED TLV contained in the
   //LLDPDU (refer to ANSI/TIA-1057, section 10.2.2.3)
   error = lldpSetOrgDefTlv(&context->txInfo, LLDP_MED_OUI,
      LLDP_MED_SUBTYPE_LLDP_MED_CAP, 0, (uint8_t *) tlv, n, TRUE);

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
 * @brief Set network policy
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[in] appType Primary function of the application
 * @param[in] u Unknown policy flag (U)
 * @param[in] t Tagged flag (T)
 * @param[in] vlanId VLAN identifier for the port
 * @param[in] l2Priority Layer 2 priority to be used
 * @param[in] dscpValue DSCP value to be used
 * @return Error code
 **/

error_t lldpMedSetLocalNetworkPolicy(LldpAgentContext *context,
   uint_t portIndex, LldpMedAppType appType, bool_t u, bool_t t,
   uint16_t vlanId, uint8_t l2Priority, uint8_t dscpValue)
{
   error_t error;
   uint_t k;
   size_t n;
   bool_t replace;
   LldpPortEntry *port;
   LldpMedNetworkPolicyTlv *tlv;

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

   //If more than one Network Policy TLV is defined within an LLDPDU, then the
   //application type shall be different from any other Network Policy TLV
   //in the LLDPDU (refer to ANSI/TIA-1057, section 10.2.3.8)
   for(k = 0; !error; k++)
   {
      //Extract the next Network Policy TLV from the local system MIB
      error = lldpGetOrgDefTlv(&port->txInfo, LLDP_MED_OUI,
         LLDP_MED_SUBTYPE_NETWORK_POLICY, k, (const uint8_t **) &tlv, &n);

      //TLV found?
      if(!error)
      {
         //Sanity check
         if(n >= sizeof(LldpMedNetworkPolicyTlv))
         {
            //Check the application type
            if(tlv->appType == appType)
            {
               //Replace the existing TLV
               replace = TRUE;
               break;
            }
            else if(tlv->appType > appType)
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
      tlv = (LldpMedNetworkPolicyTlv *) context->lldpdu.data;

      //Set application type
      tlv->appType = appType;

      //Set flags
      tlv->u = u;
      tlv->t = t;
      tlv->x = 0;

      //Set VLAN identifier
      tlv->vlanIdH = (vlanId >> 7) & 0x1F;
      tlv->vlanIdL = vlanId & 0x7F;

      //Set layer 2 priority
      tlv->l2PriorityH = (l2Priority >> 2) & 0x01;
      tlv->l2PriorityL = l2Priority & 0x03;

      //Set DSCP value
      tlv->dscpValue = dscpValue;

      //Calculate the length of the TLV
      n = sizeof(LldpMedNetworkPolicyTlv);

      //Set the value of the specified TLV
      error = lldpSetOrgDefTlv(&port->txInfo, LLDP_MED_OUI,
         LLDP_MED_SUBTYPE_NETWORK_POLICY, k, (uint8_t *) tlv, n, replace);

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
 * @brief Set location identification
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[in] locationDataFormat Location ID data format
 * @param[in] locationId Location ID
 * @param[in] locationIdLen Length of the location ID, in bytes
 * @return Error code
 **/

error_t lldpMedSetLocalLocationId(LldpAgentContext *context,
   uint_t portIndex, LldpMedLocationDataFormat locationDataFormat,
   const void *locationId, size_t locationIdLen)
{
   error_t error;
   uint_t k;
   size_t n;
   bool_t replace;
   LldpPortEntry *port;
   LldpMedLocationIdTlv *tlv;

   //Check parameters
   if(context == NULL || locationId == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the location ID data format
   if(locationDataFormat == LLDP_MED_LOCATION_DATA_FORMAT_COORD_BASED_LCI)
   {
      //Check the length of the location ID
      if(locationIdLen != 16)
      {
         return ERROR_INVALID_PARAMETER;
      }
   }
   else if(locationDataFormat == LLDP_MED_LOCATION_DATA_FORMAT_CIVIC_ADDR_LCI)
   {
      //Check the length of the location ID
      if(locationIdLen < 6 || locationIdLen > 256)
      {
         return ERROR_INVALID_PARAMETER;
      }
   }
   else if(locationDataFormat == LLDP_MED_LOCATION_DATA_FORMAT_ECS_ELIN)
   {
      //Check the length of the location ID
      if(locationIdLen < 10 || locationIdLen > 25)
      {
         return ERROR_INVALID_PARAMETER;
      }
   }
   else
   {
      //Invalid data format
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

   //An LLDPDU should contain no more than one Location Identification TLV for
   //each location identifier subtype
   for(k = 0; !error; k++)
   {
      //Extract the next Location Identification TLV from the local system MIB
      error = lldpGetOrgDefTlv(&port->txInfo, LLDP_MED_OUI,
         LLDP_MED_SUBTYPE_LOCATION_ID, k, (const uint8_t **) &tlv, &n);

      //TLV found?
      if(!error)
      {
         //Sanity check
         if(n >= sizeof(LldpMedLocationIdTlv))
         {
            //Check the location data format
            if(tlv->locationDataFormat == locationDataFormat)
            {
               //Replace the existing TLV
               replace = TRUE;
               break;
            }
            else if(tlv->locationDataFormat > locationDataFormat)
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
      tlv = (LldpMedLocationIdTlv *) context->lldpdu.data;

      //Set location ID data format
      tlv->locationDataFormat = locationDataFormat;
      //Copy location ID
      osMemcpy(tlv->locationId, locationId, locationIdLen);

      //Calculate the length of the TLV
      n = sizeof(LldpMedLocationIdTlv) + locationIdLen;

      //Set the value of the specified TLV
      error = lldpSetOrgDefTlv(&port->txInfo, LLDP_MED_OUI,
         LLDP_MED_SUBTYPE_LOCATION_ID, k, (uint8_t *) tlv, n, replace);

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
 * @brief Set extended power-via-MDI
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] portIndex Port index
 * @param[in] powerType Binary value that represents whether LLDP-MED device is
 *   a Power Sourcing Entity (PSE) or Power Device (PD)
 * @param[in] powerSource Binary value that represents the power source being
 *   utilized by a PSE or PD device
 * @param[in] powerPriority Binary value that represents the priority of the PD
 *   type device to the power being supplied by the PSE type device, or the
 *   power priority associated with the PSE type device's port that is sourcing
 *   the power via MDI
 * @param[in] powerValue Numerical value that indicates the total power in watts
 *   required by a PD device from a PSE device, or the total power a PSE device
 *   is capable of sourcing over a maximum length cable based on its current
 *   configuration
 * @return Error code
 **/

error_t lldpMedSetLocalExtPowerViaMdi(LldpAgentContext *context,
   uint_t portIndex, LldpMedPowerType powerType, LldpMedPowerSource powerSource,
   LldpMedPowerPriority powerPriority, uint16_t powerValue)
{
   error_t error;
   size_t n;
   LldpPortEntry *port;
   LldpMedExtPowerViaMdiTlv *tlv;

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
   tlv = (LldpMedExtPowerViaMdiTlv *) context->lldpdu.data;

   //Set power type
   tlv->powerType = powerType;
   //Set power source
   tlv->powerSource = powerSource;
   //Set power priority
   tlv->powerPriority = powerPriority;
   //Set power value
   tlv->powerValue = htons(powerValue);

   //Calculate the length of the TLV
   n = sizeof(LldpMedExtPowerViaMdiTlv);

   //An LLDP-MED device shall advertise at most one Extended Power-Via-MDI TLV
   //per LLDPDU (refer to ANSI/TIA-1057, section 10.2.5.5)
   error = lldpSetOrgDefTlv(&port->txInfo, LLDP_MED_OUI,
      LLDP_MED_SUBTYPE_EXT_POWER_VIA_MDI, 0, (uint8_t *) tlv, n, TRUE);

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
 * @brief Set hardware revision
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] hardwareRevision Alphanumerical string that contains the hardware
 *   revision of the endpoint
 * @return Error code
 **/

error_t lldpMedSetLocalHardwareRevision(LldpAgentContext *context,
   const char_t *hardwareRevision)
{
   error_t error;
   size_t n;

   //Check parameters
   if(context == NULL || hardwareRevision == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Get the length of the hardware revision
   n = osStrlen(hardwareRevision);

   //Check the length of the string
   if(n > LLDP_MED_MAX_INVENTORY_STRING_LEN)
   {
      return ERROR_INVALID_LENGTH;
   }

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //An LLDPDU shall not contain more than one Hardware Revision TLV (refer
   //to ANSI/TIA-1057, section 10.2.6.1.3)
   error = lldpSetOrgDefTlv(&context->txInfo, LLDP_MED_OUI,
      LLDP_MED_SUBTYPE_HARDWARE_REVISION, 0, (uint8_t *) hardwareRevision, n,
      TRUE);

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
 * @brief Set firmware revision
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] firmwareRevision Alphanumerical string that contains the firmware
 *   revision of the endpoint
 * @return Error code
 **/

error_t lldpMedSetLocalFirmwareRevision(LldpAgentContext *context,
   const char_t *firmwareRevision)
{
   error_t error;
   size_t n;

   //Check parameters
   if(context == NULL || firmwareRevision == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Get the length of the firmware revision
   n = osStrlen(firmwareRevision);

   //Check the length of the string
   if(n > LLDP_MED_MAX_INVENTORY_STRING_LEN)
   {
      return ERROR_INVALID_LENGTH;
   }

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //An LLDPDU shall not contain more than one Firmware Revision TLV (refer
   //to ANSI/TIA-1057, section 10.2.6.2.3)
   error = lldpSetOrgDefTlv(&context->txInfo, LLDP_MED_OUI,
      LLDP_MED_SUBTYPE_FIRMWARE_REVISION, 0, (uint8_t *) firmwareRevision, n,
      TRUE);

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
 * @brief Set software revision
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] softwareRevision Alphanumerical string that contains the software
 *   revision of the endpoint
 * @return Error code
 **/

error_t lldpMedSetLocalSoftwareRevision(LldpAgentContext *context,
   const char_t *softwareRevision)
{
   error_t error;
   size_t n;

   //Check parameters
   if(context == NULL || softwareRevision == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Get the length of the software revision
   n = osStrlen(softwareRevision);

   //Check the length of the string
   if(n > LLDP_MED_MAX_INVENTORY_STRING_LEN)
   {
      return ERROR_INVALID_LENGTH;
   }

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //An LLDPDU shall not contain more than one Software Revision TLV (refer
   //to ANSI/TIA-1057, section 10.2.6.3.3)
   error = lldpSetOrgDefTlv(&context->txInfo, LLDP_MED_OUI,
      LLDP_MED_SUBTYPE_SOFTWARE_REVISION, 0, (uint8_t *) softwareRevision, n,
      TRUE);

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
 * @brief Set serial number
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] serialNumber Alphanumerical string that contains the serial
 *   number of the endpoint
 * @return Error code
 **/

error_t lldpMedSetLocalSerialNumber(LldpAgentContext *context,
   const char_t *serialNumber)
{
   error_t error;
   size_t n;

   //Check parameters
   if(context == NULL || serialNumber == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Get the length of the serial number
   n = osStrlen(serialNumber);

   //Check the length of the string
   if(n > LLDP_MED_MAX_INVENTORY_STRING_LEN)
   {
      return ERROR_INVALID_LENGTH;
   }

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //An LLDPDU shall not contain more than one Serial Number TLV (refer
   //to ANSI/TIA-1057, section 10.2.6.4.3)
   error = lldpSetOrgDefTlv(&context->txInfo, LLDP_MED_OUI,
      LLDP_MED_SUBTYPE_SERIAL_NUMBER, 0, (uint8_t *) serialNumber, n, TRUE);

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
 * @brief Set manufacturer name
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] manufacturerName Alphanumerical string that contains the
 *   manufacturer name of the endpoint
 * @return Error code
 **/

error_t lldpMedSetLocalManufacturerName(LldpAgentContext *context,
   const char_t *manufacturerName)
{
   error_t error;
   size_t n;

   //Check parameters
   if(context == NULL || manufacturerName == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Get the length of the manufacturer name
   n = osStrlen(manufacturerName);

   //Check the length of the string
   if(n > LLDP_MED_MAX_INVENTORY_STRING_LEN)
   {
      return ERROR_INVALID_LENGTH;
   }

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //An LLDPDU shall not contain more than one Manufacturer Name TLV (refer
   //to ANSI/TIA-1057, section 10.2.6.5.3)
   error = lldpSetOrgDefTlv(&context->txInfo, LLDP_MED_OUI,
      LLDP_MED_SUBTYPE_MANUFACTURER_NAME, 0, (uint8_t *) manufacturerName, n,
      TRUE);

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
 * @brief Set model name
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] modelName Alphanumerical string that contains the model name of
 *   the endpoint
 * @return Error code
 **/

error_t lldpMedSetLocalModelName(LldpAgentContext *context,
   const char_t *modelName)
{
   error_t error;
   size_t n;

   //Check parameters
   if(context == NULL || modelName == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Get the length of the model name
   n = osStrlen(modelName);

   //Check the length of the string
   if(n > LLDP_MED_MAX_INVENTORY_STRING_LEN)
   {
      return ERROR_INVALID_LENGTH;
   }

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //An LLDPDU shall not contain more than one Model Name TLV (refer
   //to ANSI/TIA-1057, section 10.2.6.6.3)
   error = lldpSetOrgDefTlv(&context->txInfo, LLDP_MED_OUI,
      LLDP_MED_SUBTYPE_MODEL_NAME, 0, (uint8_t *) modelName, n, TRUE);

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
 * @brief Set asset identifier
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] assetId Alphanumerical string that contains the asset identifier
 *   of the endpoint
 * @return Error code
 **/

error_t lldpMedSetLocalAssetId(LldpAgentContext *context,
   const char_t *assetId)
{
   error_t error;
   size_t n;

   //Check parameters
   if(context == NULL || assetId == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Get the length of the asset identifier
   n = osStrlen(assetId);

   //Check the length of the string
   if(n > LLDP_MED_MAX_INVENTORY_STRING_LEN)
   {
      return ERROR_INVALID_LENGTH;
   }

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //An LLDPDU shall not contain more than one Asset ID TLV (refer to
   //ANSI/TIA-1057, section 10.2.6.7.3)
   error = lldpSetOrgDefTlv(&context->txInfo, LLDP_MED_OUI,
      LLDP_MED_SUBTYPE_ASSET_ID, 0, (uint8_t *) assetId, n, TRUE);

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
 * @brief Remove all LLDP-MED specific TLVs with specified subtype
 * @param[in] context Pointer to the LLDP agent context
 * @param[in] subtype TLV subtype
 * @return Error code
 **/

error_t lldpMedDeleteLocalTlv(LldpAgentContext *context,
   LldpMedSubtype subtype)
{
   error_t error;
   uint_t i;
   bool_t somethingChangedLocal;

   //Make sure the LLDP agent context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the LLDP agent context
   osAcquireMutex(&context->mutex);

   //Initialize status code
   error = NO_ERROR;
   //Clear flag
   somethingChangedLocal = FALSE;

   //Remove all TLVs that match the specified type
   while(!error)
   {
      //Remove one TLV at a time
      error = lldpDeleteOrgDefTlv(&context->txInfo, LLDP_MED_OUI, subtype, 0);

      //Check status code
      if(!error)
      {
         somethingChangedLocal = TRUE;
      }
   }

   //Loop through the ports
   for(i = 0; i < context->numPorts; i++)
   {
      //Initialize status code
      error = NO_ERROR;

      //Remove all port-specific TLVs that match the specified type
      while(!error)
      {
         //Remove one TLV at a time
         error = lldpDeleteOrgDefTlv(&context->ports[i].txInfo, LLDP_MED_OUI,
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
