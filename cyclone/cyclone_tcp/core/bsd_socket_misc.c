/**
 * @file bsd_socket_misc.c
 * @brief Helper function for BSD socket API
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
#define TRACE_LEVEL BSD_SOCKET_TRACE_LEVEL

//Dependencies
#include <string.h>
#include "core/net.h"
#include "core/bsd_socket.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (BSD_SOCKET_SUPPORT == ENABLED)


/**
 * @brief Initializes a descriptor set
 * @param[in] fds Pointer to a descriptor set
 **/

void socketFdZero(fd_set *fds)
{
   //Reset the descriptor count
   fds->fd_count = 0;
}


/**
 * @brief Add a descriptor to an existing set
 * @param[in] fds Pointer to a descriptor set
 * @param[in] s Descriptor that identifies the socket to add
 **/

void socketFdSet(fd_set *fds, int_t s)
{
   int_t i;

   //Loop through descriptors
   for(i = 0; i < fds->fd_count; i++)
   {
      //The specified descriptor is already set?
      if(fds->fd_array[i] == s)
         return;
   }

   //Ensure the descriptor set is not full
   if(i < FD_SETSIZE)
   {
      //The specified descriptor can be safely added
      fds->fd_array[i] = s;
      //Adjust the size of the descriptor set
      fds->fd_count++;
   }
}


/**
 * @brief Remove a descriptor from an existing set
 * @param[in] fds Pointer to a descriptor set
 * @param[in] s Descriptor that identifies the socket to remove
 **/

void socketFdClr(fd_set *fds, int_t s)
{
   int_t i;
   int_t j;

   //Loop through descriptors
   for(i = 0; i < fds->fd_count; i++)
   {
      //Specified descriptor found?
      if(fds->fd_array[i] == s)
      {
         //Adjust the size of the descriptor set
         fds->fd_count--;

         //Remove the entry from the descriptor set
         for(j = i; j < fds->fd_count; j++)
         {
            fds->fd_array[j] = fds->fd_array[j + 1];
         }

         //Return immediately
         return;
      }
   }
}


/**
 * @brief Check whether a descriptor is set
 * @param[in] fds Pointer to a descriptor set
 * @param[in] s Descriptor that identifies the socket to test
 * @return Nonzero if s is a member of the set. Otherwise, zero
 **/

int_t socketFdIsSet(fd_set *fds, int_t s)
{
   int_t i;

   //Loop through descriptors
   for(i = 0; i < fds->fd_count; i++)
   {
      //Check whether the specified descriptor is set
      if(fds->fd_array[i] == s)
      {
         return TRUE;
      }
   }

   //The specified descriptor is not currently set
   return FALSE;
}


/**
 * @brief Set BSD error code
 * @param[in] socket Handle that identifies a socket
 * @param[in] errnoCode BSD error code
 **/

void socketSetErrnoCode(Socket *socket, uint_t errnoCode)
{
   //Valid socket handle?
   if(socket != NULL)
   {
      //Save error code
      socket->errnoCode = errnoCode;
   }

   //Save the code of the last error
   BSD_SOCKET_SET_ERRNO(errnoCode);
}


/**
 * @brief Translate error code
 * @param[in] socket Handle that identifies a socket
 * @param[in] errorCode Error code
 **/

void socketTranslateErrorCode(Socket *socket, error_t errorCode)
{
   uint_t errnoCode;

   //Translate error code
   switch(errorCode)
   {
   case NO_ERROR:
      errnoCode = 0;
      break;

   case ERROR_TIMEOUT:
      errnoCode = EWOULDBLOCK;
      break;

   case ERROR_INVALID_PARAMETER:
      errnoCode = EINVAL;
      break;

   case ERROR_CONNECTION_RESET:
      errnoCode = ECONNRESET;
      break;

   case ERROR_ALREADY_CONNECTED:
      errnoCode = EISCONN;
      break;

   case ERROR_NOT_CONNECTED:
      errnoCode = ENOTCONN;
      break;

   case ERROR_CONNECTION_CLOSING:
      errnoCode = ESHUTDOWN;
      break;

   case ERROR_CONNECTION_FAILED:
      errnoCode = ECONNREFUSED;
      break;

   default:
      errnoCode = EFAULT;
      break;
   }

   //Valid socket handle?
   if(socket != NULL)
   {
      //Save error code
      socket->errnoCode = errnoCode;
   }

   //Save the code of the last error
   BSD_SOCKET_SET_ERRNO(errnoCode);
}

#endif
