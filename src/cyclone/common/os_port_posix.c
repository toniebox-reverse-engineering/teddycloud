/**
 * @file os_port_posix.c
 * @brief RTOS abstraction layer (POSIX Threads)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2023 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.3.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL TRACE_LEVEL_OFF

//Dependencies
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "os_port.h"
#include "os_port_posix.h"
#include "debug.h"

//Pthread start routine
typedef void *(*PthreadTaskCode) (void *param);


/**
 * @brief Kernel initialization
 **/

void osInitKernel(void)
{
   //Not implemented
}


/**
 * @brief Start kernel
 **/

void osStartKernel(void)
{
   //Not implemented
}


/**
 * @brief Create a task
 * @param[in] name A name identifying the task
 * @param[in] taskCode Pointer to the task entry function
 * @param[in] param A pointer to a variable to be passed to the task
 * @param[in] stackSize The initial size of the stack, in words
 * @param[in] priority The priority at which the task should run
 * @return Task identifier referencing the newly created task
 **/

OsTaskId osCreateTask(const char_t *name, OsTaskCode taskCode,
   void *param, size_t stackSize, int_t priority)
{
   int_t ret;
   pthread_t thread;

   //Create a new thread
   ret = pthread_create(&thread, NULL, (PthreadTaskCode) taskCode, param);

   //Return a pointer to the newly created thread
   if(ret == 0)
   {
      return (OsTaskId) thread;
   }
   else
   {
      return OS_INVALID_TASK_ID;
   }
}


/**
 * @brief Delete a task
 * @param[in] taskId Task identifier referencing the task to be deleted
 **/

void osDeleteTask(OsTaskId taskId)
{
   //Delete the calling thread?
   if(taskId == OS_SELF_TASK_ID)
   {
      //Kill ourselves
      pthread_exit(NULL);
   }
   else
   {
      pthread_t thread = (pthread_t)taskId;

      pthread_cancel(thread);
   }
}

/**
 * @brief Delay routine
 * @param[in] delay Amount of time for which the calling task should block
 **/

void osDelayTask(systime_t delay)
{
   //Delay the task for the specified duration
   usleep(delay * 1000);
}


/**
 * @brief Yield control to the next task
 **/

void osSwitchTask(void)
{
   //Not implemented
}

static pthread_mutex_t mutex;
static pthread_once_t init_once = PTHREAD_ONCE_INIT;

void osMutexInit(void)
{
   pthread_mutexattr_t attr;
   pthread_mutexattr_init(&attr);
   pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
   pthread_mutex_init(&mutex, &attr);
   pthread_mutexattr_destroy(&attr);
}

/**
 * @brief Suspend scheduler activity
 **/
void osSuspendAllTasks(void)
{
   pthread_once(&init_once, osMutexInit);
   pthread_mutex_lock(&mutex);
}

/**
 * @brief Resume scheduler activity
 **/
void osResumeAllTasks(void)
{
   pthread_mutex_unlock(&mutex);
}


/**
 * @brief Create an event object
 * @param[in] event Pointer to the event object
 * @return The function returns TRUE if the event object was successfully
 *   created. Otherwise, FALSE is returned
 **/

bool_t osCreateEvent(OsEvent *event)
{
   int_t ret;

   //Create a semaphore object
   ret = sem_init(event, 0, 0);

   //Check whether the semaphore was successfully created
   if(ret == 0)
   {
      return TRUE;
   }
   else
   {
      return FALSE;
   }
}


/**
 * @brief Delete an event object
 * @param[in] event Pointer to the event object
 **/

void osDeleteEvent(OsEvent *event)
{
   //Properly dispose the event object
   sem_destroy(event);
}


/**
 * @brief Set the specified event object to the signaled state
 * @param[in] event Pointer to the event object
 **/

void osSetEvent(OsEvent *event)
{
   int_t ret;
   int_t value;

   //Get the current value of the semaphore
   ret = sem_getvalue(event, &value);

   //Nonsignaled state?
   if(ret == 0 && value == 0)
   {
      //Set the specified event to the signaled state
      sem_post(event);
   }
}


/**
 * @brief Set the specified event object to the nonsignaled state
 * @param[in] event Pointer to the event object
 **/

void osResetEvent(OsEvent *event)
{
   int_t ret;

   //Force the specified event to the nonsignaled state
   do
   {
      //Decrement the semaphore's count by one
      ret = sem_trywait(event);

      //Check status
   } while(ret == 0);
}


/**
 * @brief Wait until the specified event is in the signaled state
 * @param[in] event Pointer to the event object
 * @param[in] timeout Timeout interval
 * @return The function returns TRUE if the state of the specified object is
 *   signaled. FALSE is returned if the timeout interval elapsed
 **/

bool_t osWaitForEvent(OsEvent *event, systime_t timeout)
{
   int_t ret;
   struct timespec ts;

   //Wait until the specified event is in the signaled state or the timeout
   //interval elapses
   if(timeout == 0)
   {
      //Non-blocking call
      ret = sem_trywait(event);
   }
   else if(timeout == INFINITE_DELAY)
   {
      //Infinite timeout period
      ret = sem_wait(event);
   }
   else
   {
      //Get current time
      clock_gettime(CLOCK_REALTIME, &ts);

      //Set absolute timeout
      ts.tv_sec += timeout / 1000;
      ts.tv_nsec += (timeout % 1000) * 1000000;

      //Normalize time stamp value
      if(ts.tv_nsec >= 1000000000)
      {
         ts.tv_sec += 1;
         ts.tv_nsec -= 1000000000;
      }

      //Wait until the specified event becomes set
      ret = sem_timedwait(event, &ts);
   }

   //Check whether the specified event is set
   if(ret == 0)
   {
      //Force the event back to the nonsignaled state
      do
      {
         //Decrement the semaphore's count by one
         ret = sem_trywait(event);

         //Check status
      } while(ret == 0);

      //The specified event is in the signaled state
      return TRUE;
   }
   else
   {
      //The timeout interval elapsed
      return FALSE;
   }
}


/**
 * @brief Set an event object to the signaled state from an interrupt service routine
 * @param[in] event Pointer to the event object
 * @return TRUE if setting the event to signaled state caused a task to unblock
 *   and the unblocked task has a priority higher than the currently running task
 **/

bool_t osSetEventFromIsr(OsEvent *event)
{
   //Not implemented
   return FALSE;
}


/**
 * @brief Create a semaphore object
 * @param[in] semaphore Pointer to the semaphore object
 * @param[in] count The maximum count for the semaphore object. This value
 *   must be greater than zero
 * @return The function returns TRUE if the semaphore was successfully
 *   created. Otherwise, FALSE is returned
 **/

bool_t osCreateSemaphore(OsSemaphore *semaphore, uint_t count)
{
   int_t ret;

   //Create a semaphore object
   ret = sem_init(semaphore, 0, count);

   //Check whether the semaphore was successfully created
   if(ret == 0)
   {
      return TRUE;
   }
   else
   {
      return FALSE;
   }
}


/**
 * @brief Delete a semaphore object
 * @param[in] semaphore Pointer to the semaphore object
 **/

void osDeleteSemaphore(OsSemaphore *semaphore)
{
   //Properly dispose the semaphore object
   sem_destroy(semaphore);
}


/**
 * @brief Wait for the specified semaphore to be available
 * @param[in] semaphore Pointer to the semaphore object
 * @param[in] timeout Timeout interval
 * @return The function returns TRUE if the semaphore is available. FALSE is
 *   returned if the timeout interval elapsed
 **/

bool_t osWaitForSemaphore(OsSemaphore *semaphore, systime_t timeout)
{
   int_t ret;
   struct timespec ts;

   //Wait until the semaphore is available or the timeout interval elapses
   if(timeout == 0)
   {
      //Non-blocking call
      ret = sem_trywait(semaphore);
   }
   else if(timeout == INFINITE_DELAY)
   {
      //Infinite timeout period
      ret = sem_wait(semaphore);
   }
   else
   {
      //Get current time
      clock_gettime(CLOCK_REALTIME, &ts);

      //Set absolute timeout
      ts.tv_sec += timeout / 1000;
      ts.tv_nsec += (timeout % 1000) * 1000000;

      //Normalize time stamp value
      if(ts.tv_nsec >= 1000000000)
      {
         ts.tv_sec += 1;
         ts.tv_nsec -= 1000000000;
      }

      //Wait until the specified semaphore becomes available
      ret = sem_timedwait(semaphore, &ts);
   }

   //Check whether the specified semaphore is available
   if(ret == 0)
   {
      return TRUE;
   }
   else
   {
      return FALSE;
   }
}


/**
 * @brief Release the specified semaphore object
 * @param[in] semaphore Pointer to the semaphore object
 **/

void osReleaseSemaphore(OsSemaphore *semaphore)
{
   if (semaphore == NULL)
   {
      TRACE_ERROR("osReleaseSemaphore() failed because semaphore is NULL\r\n");
      return;
   }
   //Release the semaphore
   sem_post(semaphore);
}


/**
 * @brief Create a mutex object
 * @param[in] mutex Pointer to the mutex object
 * @return The function returns TRUE if the mutex was successfully
 *   created. Otherwise, FALSE is returned
 **/

bool_t osCreateMutex(OsMutex *mutex)
{
   int_t ret;

   //Create a mutex object
   ret = pthread_mutex_init(mutex, NULL);

   //Check whether the mutex was successfully created
   if(ret == 0)
   {
      return TRUE;
   }
   else
   {
      return FALSE;
   }
}


/**
 * @brief Delete a mutex object
 * @param[in] mutex Pointer to the mutex object
 **/

void osDeleteMutex(OsMutex *mutex)
{
   //Properly dispose the mutex object
   pthread_mutex_destroy(mutex);
}


/**
 * @brief Acquire ownership of the specified mutex object
 * @param[in] mutex Pointer to the mutex object
 **/

void osAcquireMutex(OsMutex *mutex)
{
   //Obtain ownership of the mutex object
   pthread_mutex_lock(mutex);
}


/**
 * @brief Release ownership of the specified mutex object
 * @param[in] mutex Pointer to the mutex object
 **/

void osReleaseMutex(OsMutex *mutex)
{
   //Release ownership of the mutex object
   pthread_mutex_unlock(mutex);
}


/**
 * @brief Retrieve system time
 * @return Number of milliseconds elapsed since the system was last started
 **/

systime_t osGetSystemTime(void)
{
   struct timeval tv;

   //Get current time
   gettimeofday(&tv, NULL);

   //Convert resulting value to milliseconds
   return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}


/**
 * @brief Allocate a memory block
 * @param[in] size Bytes to allocate
 * @return A pointer to the allocated memory block or NULL if
 *   there is insufficient memory available
 **/

__weak_func void *osAllocMem(size_t size)
{
   //Allocate a memory block
   return malloc(size);
}


/**
 * @brief Release a previously allocated memory block
 * @param[in] p Previously allocated memory block to be freed
 **/

__weak_func void osFreeMem(void *p)
{
   //Free memory block
   free(p);
}
