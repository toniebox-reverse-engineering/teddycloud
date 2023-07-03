/**
 * @file dhcp_common.c
 * @brief Definitions common to DHCP client and server
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
#define TRACE_LEVEL DHCP_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "dhcp/dhcp_common.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (IPV4_SUPPORT == ENABLED)


/**
 * @brief Append an option to a DHCP message
 * @param[in] message Pointer to the DHCP message
 * @param[in,out] messageLen Actual length of the DHCP message
 * @param[in] optionCode Option code
 * @param[in] optionValue Option value
 * @param[in] optionLen Length of the option value
 * @return Error code
 **/

error_t dhcpAddOption(DhcpMessage *message, size_t *messageLen,
   uint8_t optionCode, const void *optionValue, size_t optionLen)
{
   size_t n;
   DhcpOption *option;

   //Check parameters
   if(message == NULL || messageLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the DHCP message
   if(*messageLen < (sizeof(DhcpMessage) + sizeof(uint8_t)))
      return ERROR_INVALID_LENGTH;

   //Check the length of the option
   if(optionLen > 0 && optionValue == NULL)
      return ERROR_INVALID_PARAMETER;

   if(optionLen > UINT8_MAX)
      return ERROR_INVALID_LENGTH;

   //Ensure that the length of the resulting message will not exceed the
   //maximum DHCP message size
   if((*messageLen + sizeof(DhcpOption) + optionLen) > DHCP_MAX_MSG_SIZE)
      return ERROR_BUFFER_OVERFLOW;

   //Retrieve the total length of the options field, excluding the end option
   n = *messageLen - sizeof(DhcpMessage) - sizeof(uint8_t);

   //Point to the buffer where to format the option
   option = (DhcpOption *) (message->options + n);

   //Set option code
   option->code = optionCode;
   //Set option length
   option->length = (uint8_t) optionLen;
   //Copy option value
   osMemcpy(option->value, optionValue, optionLen);

   //Determine the length of the options field
   n += sizeof(DhcpOption) + option->length;

   //Always terminate the options field with 255
   message->options[n++] = DHCP_OPT_END;

   //Update the length of the DHCPv6 message
   *messageLen = sizeof(DhcpMessage) + n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Search a DHCP message for a given option
 * @param[in] message Pointer to the DHCP message
 * @param[in] length Length of the message
 * @param[in] optionCode Code of the option to find
 * @return If the specified option is found, a pointer to the corresponding
 *   option is returned. Otherwise NULL pointer is returned
 **/

DhcpOption *dhcpGetOption(const DhcpMessage *message, size_t length,
   uint8_t optionCode)
{
   size_t i;
   DhcpOption *option;

   //Make sure the DHCP header is valid
   if(length >= sizeof(DhcpMessage))
   {
      //Get the length of the options field
      length -= sizeof(DhcpMessage);

      //Loop through the list of options
      for(i = 0; i < length; i++)
      {
         //Point to the current option
         option = (DhcpOption *) (message->options + i);

         //Check option code
         if(option->code == DHCP_OPT_PAD)
         {
            //The pad option can be used to cause subsequent fields to align
            //on word boundaries
         }
         else if(option->code == DHCP_OPT_END)
         {
            //The end option marks the end of valid information in the vendor
            //field
            break;
         }
         else
         {
            //The option code is followed by a one-byte length field
            if((i + 1) >= length)
            {
               break;
            }

            //Check the length of the option
            if((i + sizeof(DhcpOption) + option->length) > length)
            {
               break;
            }

            //Matching option code?
            if(option->code == optionCode)
            {
               return option;
            }

            //Jump to the next option
            i += option->length + 1;
         }
      }
   }

   //The specified option code was not found
   return NULL;
}

#endif
