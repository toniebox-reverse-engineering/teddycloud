/**
 * @file lldp_mib_impl_stats.c
 * @brief LLDP MIB module implementation (lldpStatistics subtree)
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
#include "mibs/lldp_mib_impl_stats.h"
#include "core/crypto.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "lldp/lldp_mgmt.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (LLDP_MIB_SUPPORT == ENABLED)


/**
 * @brief Get lldpStatsRemTablesLastChangeTime object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpStatsRemTablesLastChangeTime(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint32_t statsRemTablesLastChangeTime;

   //This object indicates the time at which an entry was created, modified,
   //or deleted in tables
   error = lldpMgmtGetStatsRemTablesLastChangeTime(lldpMibBase.lldpAgentContext,
      &statsRemTablesLastChangeTime);

   //Check status code
   if(!error)
   {
      //Return the value of the object
      value->timeTicks = statsRemTablesLastChangeTime;
   }

   //Return status code
   return NO_ERROR;
}


/**
 * @brief Get lldpStatsRemTablesInserts object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpStatsRemTablesInserts(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint32_t statsRemTablesInserts;

   //This object indicates the number of times the complete set of information
   //advertised by a particular MSAP has been inserted into tables
   error = lldpMgmtGetStatsRemTablesInserts(lldpMibBase.lldpAgentContext,
      &statsRemTablesInserts);

   //Check status code
   if(!error)
   {
      //Return the value of the statistics counter
      value->gauge32 = statsRemTablesInserts;
   }

   //Return status code
   return NO_ERROR;
}


/**
 * @brief Get lldpStatsRemTablesDeletes object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpStatsRemTablesDeletes(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint32_t statsRemTablesDeletes;

   //This object indicates the number of times the complete set of information
   //advertised by a particular MSAP has been deleted from tables
   error = lldpMgmtGetStatsRemTablesDeletes(lldpMibBase.lldpAgentContext,
      &statsRemTablesDeletes);

   //Check status code
   if(!error)
   {
      //Return the value of the statistics counter
      value->gauge32 = statsRemTablesDeletes;
   }

   //Return status code
   return NO_ERROR;
}


/**
 * @brief Get lldpStatsRemTablesDrops object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpStatsRemTablesDrops(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint32_t statsRemTablesDrops;

   //This object indicates the number of times the complete set of information
   //advertised by a particular MSAP could not be entered into tables because
   //of insufficient resources
   error = lldpMgmtGetStatsRemTablesDrops(lldpMibBase.lldpAgentContext,
      &statsRemTablesDrops);

   //Check status code
   if(!error)
   {
      //Return the value of the statistics counter
      value->gauge32 = statsRemTablesDrops;
   }

   //Return status code
   return NO_ERROR;
}


/**
 * @brief Get lldpStatsRemTablesAgeouts object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpStatsRemTablesAgeouts(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   uint32_t statsRemTablesAgeouts;

   //This object indicates the number of times the complete set of information
   //advertised by a particular MSAP has been deleted from tables because the
   //information timeliness interval has expired
   error = lldpMgmtGetStatsRemTablesAgeouts(lldpMibBase.lldpAgentContext,
      &statsRemTablesAgeouts);

   //Check status code
   if(!error)
   {
      //Return the value of the statistics counter
      value->gauge32 = statsRemTablesAgeouts;
   }

   //Return status code
   return NO_ERROR;
}


/**
 * @brief Get lldpStatsTxPortEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpStatsTxPortEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   size_t n;
   uint32_t counter;
   uint_t lldpStatsTxPortNum;

   //Initialize the value of the statistics counter
   counter = 0;

   //Point to the instance identifier
   n = object->oidLen;

   //lldpStatsTxPortNum is used as instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &lldpStatsTxPortNum);
   //Invalid instance identifier?
   if(error)
      return error;

   //Sanity check
   if(n != oidLen)
      return ERROR_INSTANCE_NOT_FOUND;

   //lldpStatsTxPortFramesTotal object?
   if(!strcmp(object->name, "lldpStatsTxPortFramesTotal"))
   {
      //This object indicates the number of LLDP frames transmitted by this
      //LLDP agent on the indicated port
      error = lldpMgmtGetStatsFramesOutTotal(lldpMibBase.lldpAgentContext,
         lldpStatsTxPortNum, &counter);
   }
   //Unknown object?
   else
   {
      //The specified object does not exist
      error = ERROR_OBJECT_NOT_FOUND;
   }

   //Check status code
   if(!error)
   {
      //Return the value of the statistics counter
      value->counter32 = counter;
   }

   //Return status code
   return error;
}


/**
 * @brief Get next lldpStatsTxPortEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t lldpMibGetNextLldpStatsTxPortEntry(const MibObject *object, const uint8_t *oid,
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

      //lldpStatsTxPortNum is used as instance identifier
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

   //lldpStatsTxPortNum is used as instance identifier
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
 * @brief Get lldpStatsRxPortEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t lldpMibGetLldpStatsRxPortEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   size_t n;
   uint32_t counter;
   uint_t lldpStatsRxPortNum;

   //Initialize the value of the statistics counter
   counter = 0;

   //Point to the instance identifier
   n = object->oidLen;

   //lldpStatsRxPortNum is used as instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &lldpStatsRxPortNum);
   //Invalid instance identifier?
   if(error)
      return error;

   //Sanity check
   if(n != oidLen)
      return ERROR_INSTANCE_NOT_FOUND;

   //lldpStatsRxPortFramesDiscardedTotal object?
   if(!strcmp(object->name, "lldpStatsRxPortFramesDiscardedTotal"))
   {
      //This object indicates the number of LLDP frames received by this LLDP
      //agent on the indicated port, and then discarded for any reason
      error = lldpMgmtGetStatsFramesDiscardedTotal(lldpMibBase.lldpAgentContext,
         lldpStatsRxPortNum, &counter);
   }
   //lldpStatsRxPortFramesErrors object?
   else if(!strcmp(object->name, "lldpStatsRxPortFramesErrors"))
   {
      //This object indicates the number of invalid LLDP frames received by
      //this LLDP agent on the indicated port, while this LLDP agent is enabled
      error = lldpMgmtGetStatsFramesInErrorsTotal(lldpMibBase.lldpAgentContext,
         lldpStatsRxPortNum, &counter);
   }
   //lldpStatsRxPortFramesTotal object?
   else if(!strcmp(object->name, "lldpStatsRxPortFramesTotal"))
   {
      //This object indicates the number of valid LLDP frames received by this
      //LLDP agent on the indicated port, while this LLDP agent is enabled
      error = lldpMgmtGetStatsFramesInTotal(lldpMibBase.lldpAgentContext,
         lldpStatsRxPortNum, &counter);
   }
   //lldpStatsRxPortTLVsDiscardedTotal object?
   else if(!strcmp(object->name, "lldpStatsRxPortTLVsDiscardedTotal"))
   {
      //This object indicates the number of LLDP TLVs discarded for any reason
      //by this LLDP agent on the indicated port
      error = lldpMgmtGetStatsTLVsDiscardedTotal(lldpMibBase.lldpAgentContext,
         lldpStatsRxPortNum, &counter);
   }
   //lldpStatsRxPortTLVsUnrecognizedTotal object?
   else if(!strcmp(object->name, "lldpStatsRxPortTLVsUnrecognizedTotal"))
   {
      //This object indicates the number of LLDP TLVs received on the given
      //port that are not recognized by this LLDP agent
      error = lldpMgmtGetStatsTLVsUnrecognizedTotal(lldpMibBase.lldpAgentContext,
         lldpStatsRxPortNum, &counter);
   }
   //lldpStatsRxPortAgeoutsTotal object?
   else if(!strcmp(object->name, "lldpStatsRxPortAgeoutsTotal"))
   {
      //This object indicates the number of age-outs that occurred on a given
      //port. An age-out is the number of times the complete set of information
      //advertised by a particular MSAP has been deleted from tables contained
      //in lldpRemoteSystemsData and lldpExtensions objects because the
      //information timeliness interval has expired
      error = lldpMgmtGetStatsAgeoutsTotal(lldpMibBase.lldpAgentContext,
         lldpStatsRxPortNum, &counter);
   }
   //Unknown object?
   else
   {
      //The specified object does not exist
      error = ERROR_OBJECT_NOT_FOUND;
   }

   //Check status code
   if(!error)
   {
      //Return the value of the statistics counter
      value->counter32 = counter;
   }

   //Return status code
   return error;
}


/**
 * @brief Get next lldpStatsRxPortEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t lldpMibGetNextLldpStatsRxPortEntry(const MibObject *object, const uint8_t *oid,
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

      //lldpStatsRxPortNum is used as instance identifier
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

   //lldpStatsRxPortNum is used as instance identifier
   error = mibEncodeIndex(nextOid, *nextOidLen, &n, portNum);
   //Any error to report?
   if(error)
      return error;

   //Save the length of the resulting object identifier
   *nextOidLen = n;
   //Next object found
   return NO_ERROR;
}

#endif
