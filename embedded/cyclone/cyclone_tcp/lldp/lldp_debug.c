/**
 * @file lldp_debug.c
 * @brief Data logging functions for debugging purpose (LLDP)
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
#include "lldp/lldp_ext_dot3.h"
#include "lldp/lldp_ext_med.h"
#include "lldp/lldp_ext_pno.h"
#include "lldp/lldp_debug.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (LLDP_SUPPORT == ENABLED)

//TLV type values
const LldpParamName lldpTlvTypeList[] =
{
   {LLDP_TLV_TYPE_END_OF_LLDPDU, "End Of LLDPDU"},
   {LLDP_TLV_TYPE_CHASSIS_ID,    "Chassis ID"},
   {LLDP_TLV_TYPE_PORT_ID,       "Port ID"},
   {LLDP_TLV_TYPE_TIME_TO_LIVE,  "Time To Live"},
   {LLDP_TLV_TYPE_PORT_DESC,     "Port Description"},
   {LLDP_TLV_TYPE_SYS_NAME,      "System Name"},
   {LLDP_TLV_TYPE_SYS_DESC,      "System Description"},
   {LLDP_TLV_TYPE_SYS_CAP,       "System Capabilities"},
   {LLDP_TLV_TYPE_MGMT_ADDR,     "Management Address"},
   {LLDP_TLV_TYPE_ORG_DEFINED,   "Organizationally Specific"}
};

//Organizationally unique identifiers
const LldpParamName lldpOuiList[] =
{
   {LLDP_DOT1_OUI, "IEEE 802.1"},
   {LLDP_DOT3_OUI, "IEEE 802.3"},
   {LLDP_MED_OUI,  "LLDP-MED"},
   {LLDP_PNO_OUI,  "PROFINET"}
};

//IEEE 802.1 subtype values
const LldpParamName lldpDot1SubtypeList[] =
{
   {LLDP_DOT1_SUBTYPE_RESERVED,           "Reserved"},
   {LLDP_DOT1_SUBTYPE_PORT_VLAN_ID,       "Port VLAN ID"},
   {LLDP_DOT1_SUBTYPE_PORT_PROTO_VLAN_ID, "Port And Protocol VLAN ID"},
   {LLDP_DOT1_SUBTYPE_VLAN_NAME,          "VLAN Name"},
   {LLDP_DOT1_SUBTYPE_PROTOCOL_ID,        "Protocol Identity"}
};

//IEEE 802.3 subtype values
const LldpParamName lldpDot3SubtypeList[] =
{
   {LLDP_DOT3_SUBTYPE_RESERVED,              "Reserved"},
   {LLDP_DOT3_SUBTYPE_MAC_PHY_CONFIG_STATUS, "MAC/PHY Configuration/Status"},
   {LLDP_DOT3_SUBTYPE_POWER_VIA_MDI,         "Power Via MDI"},
   {LLDP_DOT3_SUBTYPE_LINK_AGGREGATION,      "Link Aggregation"},
   {LLDP_DOT3_SUBTYPE_MAX_FRAME_SIZE,        "Maximum Frame Size"}
};

//LLDP-MED subtype values
const LldpParamName lldpMedSubtypeList[] =
{
   {LLDP_MED_SUBTYPE_RESERVED,          "Reserved"},
   {LLDP_MED_SUBTYPE_LLDP_MED_CAP,      "LLDP-MED Capabilities"},
   {LLDP_MED_SUBTYPE_NETWORK_POLICY,    "Network Policy"},
   {LLDP_MED_SUBTYPE_LOCATION_ID,       "Location Identification"},
   {LLDP_MED_SUBTYPE_EXT_POWER_VIA_MDI, "Extended Power-via-MDI"},
   {LLDP_MED_SUBTYPE_HARDWARE_REVISION, "Inventory - Hardware Revision"},
   {LLDP_MED_SUBTYPE_FIRMWARE_REVISION, "Inventory - Firmware Revision"},
   {LLDP_MED_SUBTYPE_SOFTWARE_REVISION, "Inventory - Software Revision"},
   {LLDP_MED_SUBTYPE_SERIAL_NUMBER,     "Inventory - Serial Number"},
   {LLDP_MED_SUBTYPE_MANUFACTURER_NAME, "Inventory - Manufacturer Name"},
   {LLDP_MED_SUBTYPE_MODEL_NAME,        "Inventory - Model Name"},
   {LLDP_MED_SUBTYPE_ASSET_ID,          "Inventory - Asset ID"}
};

//PROFINET subtype values
const LldpParamName lldpPnoSubtypeList[] =
{
   {LLDP_PNO_SUBTYPE_RESERVED,              "Reserved"},
   {LLDP_PNO_SUBTYPE_MEASURED_DELAY_VALUES, "Measured Delay Values"},
   {LLDP_PNO_SUBTYPE_PORT_STATUS,           "Port Status"},
   {LLDP_PNO_SUBTYPE_ALIAS,                 "Alias"},
   {LLDP_PNO_SUBTYPE_MRP_PORT_STATUS,       "MRP Port Status"},
   {LLDP_PNO_SUBTYPE_INTERFACE_MAC_ADDR,    "Interface MAC address"},
   {LLDP_PNO_SUBTYPE_PTCP_STATUS,           "PTCP Status"},
};


/**
 * @brief Dump LLDP data unit
 * @param[in] lldpdu Pointer to the LLDPDU
 **/

void lldpDumpDataUnit(LldpDataUnit *lldpdu)
{
#if (TRACE_LEVEL >= TRACE_LEVEL_VERBOSE)
   error_t error;
   LldpTlv tlv;

   //Extract the first TLV
   error = lldpGetFirstTlv(lldpdu, &tlv);

   //Parse the LLDP data unit
   while(!error)
   {
      //Dump TLV structure
      lldpDumpTlv(&tlv);

      //Extract the next TLV
      error = lldpGetNextTlv(lldpdu, &tlv);
   }
#endif
}


/**
 * @brief Dump TLV structure
 * @param[in] tlv Pointer to the TLV
 **/

void lldpDumpTlv(const LldpTlv *tlv)
{
#if (TRACE_LEVEL >= TRACE_LEVEL_VERBOSE)
   uint32_t oui;
   const char_t *name;
   const LldpOrgDefTlv *orgDefTlv;

   //Convert the TLV type to string representation
   name = lldpGetParamName(tlv->type, lldpTlvTypeList,
      arraysize(lldpTlvTypeList));

   //The TLV type field occupies the seven most significant bits of the
   //first octet of the TLV format
   TRACE_VERBOSE("  TLV Type = %" PRIu8 " (%s)\r\n", tlv->type, name);

   //Check TLV type
   if(tlv->type == LLDP_TLV_TYPE_ORG_DEFINED)
   {
      //Check TLV length
      if(tlv->length >= sizeof(LldpOrgDefTlv))
      {
         //Point to the organizationally specific TLV
         orgDefTlv = (LldpOrgDefTlv *) tlv->value;

         //Get the organizationally unique identifier
         oui = LOAD24BE(orgDefTlv->oui);

         //Convert the OUI to string representation
         name = lldpGetParamName(oui, lldpOuiList, arraysize(lldpOuiList));

         //Dump organizationally unique identifier
         TRACE_VERBOSE("    OUI = %02" PRIX8 "-%02" PRIX8 "-%02" PRIX8 " (%s)\r\n",
            orgDefTlv->oui[0], orgDefTlv->oui[1],
            orgDefTlv->oui[2], name);

         //Convert the subtype to string representation
         if(oui == LLDP_DOT1_OUI)
         {
            name = lldpGetParamName(orgDefTlv->subtype,
               lldpDot1SubtypeList, arraysize(lldpDot1SubtypeList));
         }
         else if(oui == LLDP_DOT3_OUI)
         {
            name = lldpGetParamName(orgDefTlv->subtype,
               lldpDot3SubtypeList, arraysize(lldpDot3SubtypeList));
         }
         else if(oui == LLDP_MED_OUI)
         {
            name = lldpGetParamName(orgDefTlv->subtype,
               lldpMedSubtypeList, arraysize(lldpMedSubtypeList));
         }
         else if(oui == LLDP_PNO_OUI)
         {
            name = lldpGetParamName(orgDefTlv->subtype,
               lldpPnoSubtypeList, arraysize(lldpPnoSubtypeList));
         }
         else
         {
            name = "Unknown";
         }

         //Convert the subtype to string representation
         TRACE_VERBOSE("    Subtype = %" PRIu8 " (%s)\r\n",
            orgDefTlv->subtype, name);

         //Dump TLV value
         TRACE_VERBOSE_ARRAY("      ", orgDefTlv->value,
            tlv->length - sizeof(LldpOrgDefTlv));
      }
      else
      {
         //Dump TLV value
         TRACE_VERBOSE_ARRAY("    ", tlv->value, tlv->length);
      }
   }
   else
   {
      //Dump TLV value
      TRACE_VERBOSE_ARRAY("    ", tlv->value, tlv->length);
   }
#endif
}


/**
 * @brief Convert a parameter to string representation
 * @param[in] value Parameter value
 * @param[in] paramList List of acceptable parameters
 * @param[in] paramListLen Number of entries in the list
 * @return NULL-terminated string describing the parameter
 **/

const char_t *lldpGetParamName(uint_t value, const LldpParamName *paramList,
   size_t paramListLen)
{
   uint_t i;

   //Default name for unknown values
   static const char_t defaultName[] = "Unknown";

   //Loop through the list of acceptable parameters
   for(i = 0; i < paramListLen; i++)
   {
      if(paramList[i].value == value)
         return paramList[i].name;
   }

   //Unknown value
   return defaultName;
}

#endif
