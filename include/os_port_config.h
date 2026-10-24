/**
 * @file os_port_config.h
 * @brief RTOS port configuration file
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

#ifndef _OS_PORT_CONFIG_H
#define _OS_PORT_CONFIG_H

#define HTTP_SERVER_FS_SUPPORT ENABLED
#define HTTP_SERVER_ROOT_DIR_MAX_LEN 128

/* extra entries for Cyclone's MIME table (http/mime.c) */
#define MIME_CUSTOM_TYPES {".wasm", "application/wasm"},

/*
 * Cyclone's osSuspendAllTasks()/osResumeAllTasks() are no-ops in the stock
 * ports and only used to serialize trace output. Use a teddycloud log lock
 * (platform_*.c) so the ports can stay unmodified.
 */
void tc_log_lock(void);
void tc_log_unlock(void);

#define TRACE_PRINTF(...) (tc_log_lock(), fprintf(stderr, __VA_ARGS__), tc_log_unlock())
#define TRACE_ARRAY(p, a, n) (tc_log_lock(), debugDisplayArray(stderr, p, a, n), tc_log_unlock())
#define TRACE_MPI(p, a) (tc_log_lock(), mpiDump(stderr, p, a), tc_log_unlock())

#endif
