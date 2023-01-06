/**
 * @file os_port_rtx.h
 * @brief RTOS abstraction layer (Keil RTX)
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

#ifndef _OS_PORT_RTX_H
#define _OS_PORT_RTX_H

//Dependencies
#ifdef RTX_CUSTOM_HEADER
   #include RTX_CUSTOM_HEADER
#else
   #include "rtl.h"
#endif

//Use static or dynamic memory allocation for tasks
#ifndef OS_STATIC_TASK_SUPPORT
   #define OS_STATIC_TASK_SUPPORT DISABLED
#elif (OS_STATIC_TASK_SUPPORT != ENABLED && OS_STATIC_TASK_SUPPORT != DISABLED)
   #error OS_STATIC_TASK_SUPPORT parameter is not valid
#endif

//Invalid task identifier
#define OS_INVALID_TASK_ID 0
//Self task identifier
#define OS_SELF_TASK_ID 0

//Task priority (normal)
#ifndef OS_TASK_PRIORITY_NORMAL
   #define OS_TASK_PRIORITY_NORMAL 1
#endif

//Task priority (high)
#ifndef OS_TASK_PRIORITY_HIGH
   #define OS_TASK_PRIORITY_HIGH 2
#endif

//Milliseconds to system ticks
#ifndef OS_MS_TO_SYSTICKS
   #define OS_MS_TO_SYSTICKS(n) (n)
#endif

//System ticks to milliseconds
#ifndef OS_SYSTICKS_TO_MS
   #define OS_SYSTICKS_TO_MS(n) (n)
#endif

//Retrieve 64-bit system time (not implemented)
#ifndef osGetSystemTime64
   #define osGetSystemTime64() osGetSystemTime()
#endif

//Task prologue
#define osEnterTask()
//Task epilogue
#define osExitTask()
//Interrupt service routine prologue
#define osEnterIsr()
//Interrupt service routine epilogue
#define osExitIsr(flag)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief System time
 **/

typedef uint32_t systime_t;


/**
 * @brief Task identifier
 **/

typedef OS_TID OsTaskId;


/**
 * @brief Task control block
 **/

typedef struct
{
   uint32_t dummy;
} OsTaskTcb;


/**
 * @brief Stack data type
 **/

typedef uint32_t OsStackType;


/**
 * @brief Event object
 **/

typedef OS_SEM OsEvent;


/**
 * @brief Semaphore object
 **/

typedef OS_SEM OsSemaphore;


/**
 * @brief Mutex object
 **/

typedef OS_MUT OsMutex;


/**
 * @brief Task routine
 **/

typedef void (*OsTaskCode)(void *param);


/**
 * @brief Initialization task
 **/

typedef void (*OsInitTaskCode)(void);


//Kernel management
void osInitKernel(void);
void osStartKernel(OsInitTaskCode task);

//Task management
OsTaskId osCreateTask(const char_t *name, OsTaskCode taskCode,
   void *param, size_t stackSize, int_t priority);

OsTaskId osCreateStaticTask(const char_t *name, OsTaskCode taskCode,
   void *param, OsTaskTcb *tcb, OsStackType *stack, size_t stackSize,
   int_t priority);

void osDeleteTask(OsTaskId taskId);
void osDelayTask(systime_t delay);
void osSwitchTask(void);
void osSuspendAllTasks(void);
void osResumeAllTasks(void);

//Event management
bool_t osCreateEvent(OsEvent *event);
void osDeleteEvent(OsEvent *event);
void osSetEvent(OsEvent *event);
void osResetEvent(OsEvent *event);
bool_t osWaitForEvent(OsEvent *event, systime_t timeout);
bool_t osSetEventFromIsr(OsEvent *event);

//Semaphore management
bool_t osCreateSemaphore(OsSemaphore *semaphore, uint_t count);
void osDeleteSemaphore(OsSemaphore *semaphore);
bool_t osWaitForSemaphore(OsSemaphore *semaphore, systime_t timeout);
void osReleaseSemaphore(OsSemaphore *semaphore);

//Mutex management
bool_t osCreateMutex(OsMutex *mutex);
void osDeleteMutex(OsMutex *mutex);
void osAcquireMutex(OsMutex *mutex);
void osReleaseMutex(OsMutex *mutex);

//System time
systime_t osGetSystemTime(void);

//Memory management
void *osAllocMem(size_t size);
void osFreeMem(void *p);

//Undefine conflicting definitions
#undef htons
#undef htonl
#undef ntohs
#undef ntohl
#undef TCP_STATE_CLOSED
#undef TCP_STATE_LISTEN
#undef TCP_STATE_SYN_SENT
#undef TCP_STATE_CLOSING
#undef TCP_STATE_LAST_ACK

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
