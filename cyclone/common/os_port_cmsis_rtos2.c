/**
 * @file os_port_cmsis_rtos2.c
 * @brief RTOS abstraction layer (CMSIS-RTOS 2 / RTX v5)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
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
#define TRACE_LEVEL TRACE_LEVEL_OFF

//Dependencies
#include <stdio.h>
#include <stdlib.h>
#include "os_port.h"
#include "os_port_cmsis_rtos2.h"
#include "debug.h"


/**
 * @brief Kernel initialization
 **/

void osInitKernel(void)
{
   //Initialize the kernel
   osKernelInitialize();
}


/**
 * @brief Start kernel
 **/

void osStartKernel(void)
{
   //Start the kernel
   osKernelStart();
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
   osThreadId_t threadId;
   osThreadAttr_t threadAttr;

   //Set thread attributes
   threadAttr.name = name;
   threadAttr.attr_bits = 0;
   threadAttr.cb_mem = NULL;
   threadAttr.cb_size = 0;
   threadAttr.stack_mem = NULL;
   threadAttr.stack_size = stackSize * sizeof(uint32_t);
   threadAttr.priority = (osPriority_t) priority;
   threadAttr.tz_module = 0;
   threadAttr.reserved = 0;

   //Create a new thread
   threadId = osThreadNew(taskCode, param, &threadAttr);

   //Return a handle to the newly created thread
   return (OsTaskId) threadId;
}


/**
 * @brief Create a task with statically allocated memory
 * @param[in] name A name identifying the task
 * @param[in] taskCode Pointer to the task entry function
 * @param[in] param A pointer to a variable to be passed to the task
 * @param[in] tcb Pointer to the task control block
 * @param[in] stack Pointer to the stack
 * @param[in] stackSize The initial size of the stack, in words
 * @param[in] priority The priority at which the task should run
 * @return Task identifier referencing the newly created task
 **/

OsTaskId osCreateStaticTask(const char_t *name, OsTaskCode taskCode,
   void *param, OsTaskTcb *tcb, OsStackType *stack, size_t stackSize,
   int_t priority)
{
   osThreadId_t threadId;
   osThreadAttr_t threadAttr;

   //Set thread attributes
   threadAttr.name = name;
   threadAttr.attr_bits = 0;
#if defined(os_CMSIS_RTX)
   threadAttr.cb_mem = &tcb->cb;
   threadAttr.cb_size = sizeof(os_thread_t);
   threadAttr.stack_mem = stack;
   threadAttr.stack_size = stackSize * sizeof(uint32_t);
#elif defined(osRtxVersionKernel)
   threadAttr.cb_mem = &tcb->cb;
   threadAttr.cb_size = sizeof(osRtxThread_t);
   threadAttr.stack_mem = stack;
   threadAttr.stack_size = stackSize * sizeof(uint32_t);
#elif defined(configSUPPORT_STATIC_ALLOCATION)
   threadAttr.cb_mem = &tcb->cb;
   threadAttr.cb_size = sizeof(StaticTask_t);
   threadAttr.stack_mem = stack;
   threadAttr.stack_size = stackSize * sizeof(uint32_t);
#else
   threadAttr.cb_mem = NULL;
   threadAttr.cb_size = 0;
   threadAttr.stack_mem = NULL;
   threadAttr.stack_size = 0;
#endif
   threadAttr.priority = (osPriority_t) priority;
   threadAttr.tz_module = 0;
   threadAttr.reserved = 0;

   //Create a new thread
   threadId = osThreadNew(taskCode, param, &threadAttr);

   //Return a handle to the newly created thread
   return (OsTaskId) threadId;
}


/**
 * @brief Delete a task
 * @param[in] taskId Task identifier referencing the task to be deleted
 **/

void osDeleteTask(OsTaskId taskId)
{
   //Delete the specified thread
   if(taskId == OS_SELF_TASK_ID)
   {
      osThreadExit();
   }
   else
   {
      osThreadTerminate((osThreadId_t) taskId);
   }
}


/**
 * @brief Delay routine
 * @param[in] delay Amount of time for which the calling task should block
 **/

void osDelayTask(systime_t delay)
{
   //Delay the thread for the specified duration
   osDelay(OS_MS_TO_SYSTICKS(delay));
}


/**
 * @brief Yield control to the next task
 **/

void osSwitchTask(void)
{
   //Force a context switch
   osThreadYield();
}


/**
 * @brief Suspend scheduler activity
 **/

void osSuspendAllTasks(void)
{
   //Make sure the operating system is running
   if(osKernelGetState() != osKernelInactive)
   {
      //Suspend all task switches
      osKernelLock();
   }
}


/**
 * @brief Resume scheduler activity
 **/

void osResumeAllTasks(void)
{
   //Make sure the operating system is running
   if(osKernelGetState() != osKernelInactive)
   {
      //Resume lock all task switches
      osKernelUnlock();
   }
}


/**
 * @brief Create an event object
 * @param[in] event Pointer to the event object
 * @return The function returns TRUE if the event object was successfully
 *   created. Otherwise, FALSE is returned
 **/

bool_t osCreateEvent(OsEvent *event)
{
   osEventFlagsAttr_t eventFlagsAttr;

   //Set event flags attributes
   eventFlagsAttr.name = NULL;
   eventFlagsAttr.attr_bits = 0;

#if defined(os_CMSIS_RTX)
   eventFlagsAttr.cb_mem = &event->cb;
   eventFlagsAttr.cb_size = sizeof(os_event_flags_t);
#elif defined(osRtxVersionKernel)
   eventFlagsAttr.cb_mem = &event->cb;
   eventFlagsAttr.cb_size = sizeof(osRtxEventFlags_t);
#else
   eventFlagsAttr.cb_mem = NULL;
   eventFlagsAttr.cb_size = 0;
#endif

   //Create an event flags object
   event->id = osEventFlagsNew(&eventFlagsAttr);

   //Check whether the returned semaphore ID is valid
   if(event->id != NULL)
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
   //Make sure the event flags ID is valid
   if(event->id != NULL)
   {
      //Properly dispose the event flags object
      osEventFlagsDelete(event->id);
   }
}


/**
 * @brief Set the specified event object to the signaled state
 * @param[in] event Pointer to the event object
 **/

void osSetEvent(OsEvent *event)
{
   //Set the specified event to the signaled state
   osEventFlagsSet(event->id, 1);
}


/**
 * @brief Set the specified event object to the nonsignaled state
 * @param[in] event Pointer to the event object
 **/

void osResetEvent(OsEvent *event)
{
   //Force the specified event to the nonsignaled state
   osEventFlagsClear(event->id, 1);
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
   uint32_t flags;

   //Wait until the specified event is in the signaled state or the timeout
   //interval elapses
   if(timeout == INFINITE_DELAY)
   {
      //Infinite timeout period
      flags = osEventFlagsWait(event->id, 1, osFlagsWaitAny, osWaitForever);
   }
   else
   {
      //Wait for the specified time interval
      flags = osEventFlagsWait(event->id, 1, osFlagsWaitAny,
         OS_MS_TO_SYSTICKS(timeout));
   }

   //The function returns the event flags before clearing or an error code
   if(flags == 1)
   {
      return TRUE;
   }
   else
   {
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
   //Set the specified event to the signaled state
   osEventFlagsSet(event->id, 1);

   //The return value is not relevant
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
   osSemaphoreAttr_t semaphoreAttr;

   //Set semaphore attributes
   semaphoreAttr.name = NULL;
   semaphoreAttr.attr_bits = 0;

#if defined(os_CMSIS_RTX)
   semaphoreAttr.cb_mem = &semaphore->cb;
   semaphoreAttr.cb_size = sizeof(os_semaphore_t);
#elif defined(osRtxVersionKernel)
   semaphoreAttr.cb_mem = &semaphore->cb;
   semaphoreAttr.cb_size = sizeof(osRtxSemaphore_t);
#else
   semaphoreAttr.cb_mem = NULL;
   semaphoreAttr.cb_size = 0;
#endif

   //Create a semaphore object
   semaphore->id = osSemaphoreNew(count, count, &semaphoreAttr);

   //Check whether the returned semaphore ID is valid
   if(semaphore->id != NULL)
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
   //Make sure the semaphore ID is valid
   if(semaphore->id != NULL)
   {
      //Properly dispose the specified semaphore
      osSemaphoreDelete(semaphore->id);
   }
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
   osStatus_t status;

   //Wait until the semaphore is available or the timeout interval elapses
   if(timeout == INFINITE_DELAY)
   {
      //Infinite timeout period
      status = osSemaphoreAcquire(semaphore->id, osWaitForever);
   }
   else
   {
      //Wait for the specified time interval
      status = osSemaphoreAcquire(semaphore->id, OS_MS_TO_SYSTICKS(timeout));
   }

   //Check return value
   if(status == osOK)
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
   //Release the semaphore
   osSemaphoreRelease(semaphore->id);
}


/**
 * @brief Create a mutex object
 * @param[in] mutex Pointer to the mutex object
 * @return The function returns TRUE if the mutex was successfully
 *   created. Otherwise, FALSE is returned
 **/

bool_t osCreateMutex(OsMutex *mutex)
{
   osMutexAttr_t mutexAttr;

   //Set mutex attributes
   mutexAttr.name = NULL;
   mutexAttr.attr_bits = 0;

#if defined(os_CMSIS_RTX)
   mutexAttr.cb_mem = &mutex->cb;
   mutexAttr.cb_size = sizeof(os_mutex_t);
#elif defined(osRtxVersionKernel)
   mutexAttr.cb_mem = &mutex->cb;
   mutexAttr.cb_size = sizeof(osRtxMutex_t);
#else
   mutexAttr.cb_mem = NULL;
   mutexAttr.cb_size = 0;
#endif

   //Create a mutex object
   mutex->id = osMutexNew(&mutexAttr);

   //Check whether the returned mutex ID is valid
   if(mutex->id != NULL)
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
   //Make sure the mutex ID is valid
   if(mutex->id != NULL)
   {
      //Properly dispose the specified mutex
      osMutexDelete(mutex->id);
   }
}


/**
 * @brief Acquire ownership of the specified mutex object
 * @param[in] mutex Pointer to the mutex object
 **/

void osAcquireMutex(OsMutex *mutex)
{
   //Obtain ownership of the mutex object
   osMutexAcquire(mutex->id, osWaitForever);
}


/**
 * @brief Release ownership of the specified mutex object
 * @param[in] mutex Pointer to the mutex object
 **/

void osReleaseMutex(OsMutex *mutex)
{
   //Release ownership of the mutex object
   osMutexRelease(mutex->id);
}


/**
 * @brief Retrieve system time
 * @return Number of milliseconds elapsed since the system was last started
 **/

systime_t osGetSystemTime(void)
{
   systime_t time;

   //Get current tick count
   time = osKernelGetTickCount();

   //Convert system ticks to milliseconds
   return OS_SYSTICKS_TO_MS(time);
}


/**
 * @brief Allocate a memory block
 * @param[in] size Bytes to allocate
 * @return A pointer to the allocated memory block or NULL if
 *   there is insufficient memory available
 **/

__weak_func void *osAllocMem(size_t size)
{
   void *p;

   //Enter critical section
   osSuspendAllTasks();
   //Allocate a memory block
   p = malloc(size);
   //Leave critical section
   osResumeAllTasks();

   //Debug message
   TRACE_DEBUG("Allocating %" PRIuSIZE " bytes at 0x%08" PRIXPTR "\r\n",
      size, (uintptr_t) p);

   //Return a pointer to the newly allocated memory block
   return p;
}


/**
 * @brief Release a previously allocated memory block
 * @param[in] p Previously allocated memory block to be freed
 **/

__weak_func void osFreeMem(void *p)
{
   //Make sure the pointer is valid
   if(p != NULL)
   {
      //Debug message
      TRACE_DEBUG("Freeing memory at 0x%08" PRIXPTR "\r\n", (uintptr_t) p);

      //Enter critical section
      osSuspendAllTasks();
      //Free memory block
      free(p);
      //Leave critical section
      osResumeAllTasks();
   }
}
