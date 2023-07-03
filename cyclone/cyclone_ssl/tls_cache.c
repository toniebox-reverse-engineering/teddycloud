/**
 * @file tls_cache.c
 * @brief Session cache management
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneSSL Open.
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
#define TRACE_LEVEL TLS_TRACE_LEVEL

//Dependencies
#include <string.h>
#include "tls.h"
#include "tls_cache.h"
#include "tls_misc.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief Session cache initialization
 * @param[in] size Maximum number of cache entries
 * @return Handle referencing the fully initialized session cache
 **/

TlsCache *tlsInitCache(uint_t size)
{
   size_t n;
   TlsCache *cache;

   //Make sure the parameter is acceptable
   if(size < 1)
      return NULL;

   //Size of the memory required
   n = sizeof(TlsCache) + size * sizeof(TlsSessionState);

   //Allocate a memory buffer to hold the session cache
   cache = tlsAllocMem(n);
   //Failed to allocate memory?
   if(cache == NULL)
      return NULL;

   //Clear memory
   osMemset(cache, 0, n);

   //Create a mutex to prevent simultaneous access to the cache
   if(!osCreateMutex(&cache->mutex))
   {
      //Clean up side effects
      tlsFreeMem(cache);
      //Report an error
      return NULL;
   }

   //Save the maximum number of cache entries
   cache->size = size;

   //Return a pointer to the newly created cache
   return cache;
}


/**
 * @brief Search the session cache for a given session ID
 * @param[in] cache Pointer to the session cache
 * @param[in] sessionId Expected session ID
 * @param[in] sessionIdLen Length of the session ID
 * @return A pointer to the matching session is returned. NULL is returned
 *   if the specified ID could not be found in the session cache
 **/

TlsSessionState *tlsFindCache(TlsCache *cache, const uint8_t *sessionId,
   size_t sessionIdLen)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   uint_t i;
   systime_t time;
   TlsSessionState *session;

   //Check parameters
   if(cache == NULL || sessionId == NULL || sessionIdLen == 0)
      return NULL;

   //Initialize session state
   session = NULL;

   //Get current time
   time = osGetSystemTime();

   //Acquire exclusive access to the session cache
   osAcquireMutex(&cache->mutex);

   //Flush expired entries
   for(i = 0; i < cache->size; i++)
   {
      //Skip unused entries
      if(cache->sessions[i].sessionIdLen != 0)
      {
         //Outdated entry?
         if((time - cache->sessions[i].timestamp) >= TLS_SESSION_CACHE_LIFETIME)
         {
            //This session is no more valid and should be removed from the cache
            tlsFreeSessionState(&cache->sessions[i]);
         }
      }
   }

   //Search the cache for the specified session ID
   for(i = 0; i < cache->size; i++)
   {
      //Check whether the current identifier matches the specified session ID
      if(cache->sessions[i].sessionIdLen == sessionIdLen &&
         !osMemcmp(cache->sessions[i].sessionId, sessionId, sessionIdLen))
      {
         //A matching session has been found
         session = &cache->sessions[i];
         break;
      }
   }

   //Release exclusive access to the session cache
   osReleaseMutex(&cache->mutex);

   //Return a pointer to the matching session, if any
   return session;
#else
   //Not implemented
   return NULL;
#endif
}


/**
 * @brief Save current session in cache
 * @param[in] context TLS context
 * @return Error code
 **/

error_t tlsSaveToCache(TlsContext *context)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   error_t error;
   uint_t i;
   systime_t time;
   TlsSessionState *session;
   TlsSessionState *firstFreeEntry;
   TlsSessionState *oldestEntry;

   //Check parameters
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check whether session caching is supported
   if(context->cache == NULL)
      return ERROR_FAILURE;

   //Ensure the session ID is valid
   if(context->sessionIdLen == 0)
      return NO_ERROR;

   //Acquire exclusive access to the session cache
   osAcquireMutex(&context->cache->mutex);

   //Get current time
   time = osGetSystemTime();

   //Keep track of the first free entry
   firstFreeEntry = NULL;
   //Keep track of the oldest entry
   oldestEntry = NULL;

   //Search the cache for the specified session ID
   for(i = 0; i < context->cache->size; i++)
   {
      //Point to the current entry
      session = &context->cache->sessions[i];

      //If the session ID already exists, we are done
      if(session->sessionIdLen == context->sessionIdLen &&
         !osMemcmp(session->sessionId, context->sessionId, session->sessionIdLen))
      {
         //Do not write to session cache
         firstFreeEntry = NULL;
         oldestEntry = NULL;
         //Exit immediately
         break;
      }

      //Check whether current entry is free
      if(session->sessionIdLen == 0)
      {
         //Keep track of the first free entry
         if(!firstFreeEntry)
         {
            firstFreeEntry = session;
         }
      }
      else
      {
         //Keep track of the oldest entry in the table
         if(oldestEntry == NULL)
         {
            oldestEntry = session;
         }
         else if((time - session->timestamp) > (time - oldestEntry->timestamp))
         {
            oldestEntry = session;
         }
      }
   }

   //Add current session to cache if necessary
   if(firstFreeEntry != NULL)
   {
      error = tlsSaveSessionId(context, firstFreeEntry);
   }
   else if(oldestEntry != NULL)
   {
      error = tlsSaveSessionId(context, oldestEntry);
   }
   else
   {
      error = NO_ERROR;
   }

   //Release exclusive access to the session cache
   osReleaseMutex(&context->cache->mutex);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Remove current session from cache
 * @param[in] context TLS context
 * @return Error code
 **/

error_t tlsRemoveFromCache(TlsContext *context)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   uint_t i;
   TlsSessionState *session;

   //Check parameters
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check whether session caching is supported
   if(context->cache == NULL)
      return ERROR_FAILURE;

   //Ensure the session ID is valid
   if(context->sessionIdLen == 0)
      return NO_ERROR;

   //Acquire exclusive access to the session cache
   osAcquireMutex(&context->cache->mutex);

   //Search the cache for the specified session ID
   for(i = 0; i < context->cache->size; i++)
   {
      //Point to the current entry
      session = &context->cache->sessions[i];

      //Check whether the current identifier matches the specified session ID
      if(session->sessionIdLen == context->sessionIdLen &&
         !osMemcmp(session->sessionId, context->sessionId, session->sessionIdLen))
      {
         //Drop current entry
         tlsFreeSessionState(session);
      }
   }

   //Release exclusive access to the session cache
   osReleaseMutex(&context->cache->mutex);
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Properly dispose a session cache
 * @param[in] cache Pointer to the session cache to be released
 **/

void tlsFreeCache(TlsCache *cache)
{
   uint_t i;

   //Valid session cache?
   if(cache != NULL)
   {
      //Loop through the session cache
      for(i = 0; i < cache->size; i++)
      {
         //Release current entry
         tlsFreeSessionState(&cache->sessions[i]);
      }

      //Release mutex object
      osDeleteMutex(&cache->mutex);

      //Properly dispose the session cache
      tlsFreeMem(cache);
   }
}

#endif
