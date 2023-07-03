/**
 * @file tftp_server.c
 * @brief TFTP server
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
 * @section Description
 *
 * TFTP is a very simple protocol used to transfer files. Refer to the
 * following RFCs for complete details:
 * - RFC 1123:  Requirements for Internet Hosts
 * - RFC 1350: The TFTP Protocol (Revision 2)
 * - RFC 1782: TFTP Option Extension
 * - RFC 1783: TFTP Blocksize Option
 * - RFC 1784: TFTP Timeout Interval and Transfer Size Options
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL TFTP_TRACE_LEVEL

//Dependencies
#include "tftp/tftp_server.h"
#include "tftp/tftp_server_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (TFTP_SERVER_SUPPORT == ENABLED)


/**
 * @brief Initialize settings with default values
 * @param[out] settings Structure that contains TFTP server settings
 **/

void tftpServerGetDefaultSettings(TftpServerSettings *settings)
{
   //The TFTP server is not bound to any interface
   settings->interface = NULL;

   //TFTP port number
   settings->port = TFTP_PORT;

   //Open file callback function
   settings->openFileCallback = NULL;
   //Write file callback function
   settings->writeFileCallback = NULL;
   //Read file callback function
   settings->readFileCallback = NULL;
   //Close file callback function
   settings->closeFileCallback = NULL;
}


/**
 * @brief TFTP server initialization
 * @param[in] context Pointer to the TFTP server context
 * @param[in] settings TFTP server specific settings
 * @return Error code
 **/

error_t tftpServerInit(TftpServerContext *context,
   const TftpServerSettings *settings)
{
   error_t error;

   //Debug message
   TRACE_INFO("Initializing TFTP server...\r\n");

   //Ensure the parameters are valid
   if(context == NULL || settings == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear the TFTP server context
   osMemset(context, 0, sizeof(TftpServerContext));

   //Save user settings
   context->settings = *settings;

   //Initialize status code
   error = NO_ERROR;

   //Create an event object to poll the state of sockets
   if(!osCreateEvent(&context->event))
   {
      //Failed to create event
      error = ERROR_OUT_OF_RESOURCES;
   }

   //Check status code
   if(error)
   {
      //Clean up side effects
      tftpServerDeinit(context);
   }

   //Return status code
   return error;
}


/**
 * @brief Start TFTP server
 * @param[in] context Pointer to the TFTP server context
 * @return Error code
 **/

error_t tftpServerStart(TftpServerContext *context)
{
   error_t error;

   //Make sure the TFTP server context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Starting TFTP server...\r\n");

   //Make sure the TFTP server is not already running
   if(context->running)
      return ERROR_ALREADY_RUNNING;

   //Start of exception handling block
   do
   {
      //Open a UDP socket
      context->socket = socketOpen(SOCKET_TYPE_DGRAM, SOCKET_IP_PROTO_UDP);
      //Failed to open socket?
      if(context->socket == NULL)
      {
         //Report an error
         error = ERROR_OPEN_FAILED;
         break;
      }

      //Associate the socket with the relevant interface
      error = socketBindToInterface(context->socket,
         context->settings.interface);
      //Unable to bind the socket to the desired interface?
      if(error)
         break;

      //The TFTP server listens for connection requests on port 69
      error = socketBind(context->socket, &IP_ADDR_ANY, context->settings.port);
      //Unable to bind the socket to the desired port?
      if(error)
         break;

      //Start the TFTP server
      context->stop = FALSE;
      context->running = TRUE;

#if (OS_STATIC_TASK_SUPPORT == ENABLED)
      //Create a task using statically allocated memory
      context->taskId = osCreateStaticTask("TFTP Server",
         (OsTaskCode) tftpServerTask, context, &context->taskTcb,
         context->taskStack, TFTP_SERVER_STACK_SIZE, TFTP_SERVER_PRIORITY);
#else
      //Create a task
      context->taskId = osCreateTask("TFTP Server", (OsTaskCode) tftpServerTask,
         context, TFTP_SERVER_STACK_SIZE, TFTP_SERVER_PRIORITY);
#endif

      //Failed to create task?
      if(context->taskId == OS_INVALID_TASK_ID)
      {
         //Report an error
         error = ERROR_OUT_OF_RESOURCES;
         break;
      }

      //End of exception handling block
   } while(0);

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      context->running = FALSE;

      //Close the UDP socket
      socketClose(context->socket);
      context->socket = NULL;
   }

   //Return status code
   return error;
}


/**
 * @brief Stop TFTP server
 * @param[in] context Pointer to the TFTP server context
 * @return Error code
 **/

error_t tftpServerStop(TftpServerContext *context)
{
   uint_t i;

   //Make sure the TFTP server context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Stopping TFTP server...\r\n");

   //Check whether the TFTP server is running
   if(context->running)
   {
      //Stop the TFTP server
      context->stop = TRUE;
      //Send a signal to the task to abort any blocking operation
      osSetEvent(&context->event);

      //Wait for the task to terminate
      while(context->running)
      {
         osDelayTask(1);
      }

      //Loop through the connection table
      for(i = 0; i < TFTP_SERVER_MAX_CONNECTIONS; i++)
      {
         //Close client connection
         tftpServerCloseConnection(&context->connection[i]);
      }

      //Close the UDP socket
      socketClose(context->socket);
      context->socket = NULL;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief TFTP server task
 * @param[in] context Pointer to the TFTP server context
 **/

void tftpServerTask(TftpServerContext *context)
{
   error_t error;
   uint_t i;
   TftpClientConnection *connection;

#if (NET_RTOS_SUPPORT == ENABLED)
   //Task prologue
   osEnterTask();

   //Process events
   while(1)
   {
#endif
      //Clear event descriptor set
      osMemset(context->eventDesc, 0, sizeof(context->eventDesc));

      //Specify the events the application is interested in
      for(i = 0; i < TFTP_SERVER_MAX_CONNECTIONS; i++)
      {
         //Point to the structure describing the current connection
         connection = &context->connection[i];

         //Loop through active connections only
         if(connection->state != TFTP_STATE_CLOSED)
         {
            //Wait for a packet to be received
            context->eventDesc[i].socket = connection->socket;
            context->eventDesc[i].eventMask = SOCKET_EVENT_RX_READY;
         }
      }

      //The TFTP server listens for connection requests on port 69
      context->eventDesc[i].socket = context->socket;
      context->eventDesc[i].eventMask = SOCKET_EVENT_RX_READY;

      //Wait for one of the set of sockets to become ready to perform I/O
      error = socketPoll(context->eventDesc, TFTP_SERVER_MAX_CONNECTIONS + 1,
         &context->event, TFTP_SERVER_TICK_INTERVAL);

      //Check status code
      if(error == NO_ERROR || error == ERROR_TIMEOUT)
      {
         //Stop request?
         if(context->stop)
         {
            //Stop TFTP server operation
            context->running = FALSE;
            //Task epilogue
            osExitTask();
            //Kill ourselves
            osDeleteTask(OS_SELF_TASK_ID);
         }

         //Event-driven processing
         for(i = 0; i < TFTP_SERVER_MAX_CONNECTIONS; i++)
         {
            //Point to the structure describing the current connection
            connection = &context->connection[i];

            //Loop through active connections only
            if(connection->state != TFTP_STATE_CLOSED)
            {
               //Check whether a packet has been received
               if((context->eventDesc[i].eventFlags & SOCKET_EVENT_RX_READY) != 0)
               {
                  //Process incoming packet
                  tftpServerProcessPacket(context, connection);
               }
            }
         }

         //Any connection request received on port 69?
         if((context->eventDesc[i].eventFlags & SOCKET_EVENT_RX_READY) != 0)
         {
            //Accept connection request
            tftpServerAcceptRequest(context);
         }
      }

      //Handle periodic operations
      tftpServerTick(context);

#if (NET_RTOS_SUPPORT == ENABLED)
   }
#endif
}


/**
 * @brief Release TFTP server context
 * @param[in] context Pointer to the TFTP server context
 **/

void tftpServerDeinit(TftpServerContext *context)
{
   //Make sure the TFTP server context is valid
   if(context != NULL)
   {
      //Free previously allocated resources
      osDeleteEvent(&context->event);

      //Clear TFTP server context
      osMemset(context, 0, sizeof(TftpServerContext));
   }
}

#endif
