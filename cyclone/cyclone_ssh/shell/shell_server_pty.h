/**
 * @file shell_server_pty.h
 * @brief Pseudo-terminal emulation
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2019-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneSSH Open.
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

#ifndef _SHELL_SERVER_PTY_H
#define _SHELL_SERVER_PTY_H

//Dependencies
#include "shell/shell_server.h"

//Escape character code
#define VT100_BS_CODE  0x08
#define VT100_ESC_CODE 0x1B
#define VT100_DEL_CODE 0x7F

//VT100 escape sequences
#define VT100_BACKSPACE           "\x08"
#define VT100_ESC                 "\x1b"
#define VT100_CLEAR_SCREEN_DOWN   VT100_ESC "[J"
#define VT100_CLEAR_SCREEN_UP     VT100_ESC "[1J"
#define VT100_CLEAR_ENTIRE_SCREEN VT100_ESC "[2J"
#define VT100_CLEAR_LINE_RIGHT    VT100_ESC "[K"
#define VT100_CLEAR_LINE_LEFT     VT100_ESC "[1K"
#define VT100_CLEAR_ENTIRE_LINE   VT100_ESC "[2K"
#define VT100_MOVE_CURSOR_UP      VT100_ESC "[A"
#define VT100_MOVE_CURSOR_UP_N    VT100_ESC "[%uA"
#define VT100_MOVE_CURSOR_DOWN    VT100_ESC "[B"
#define VT100_MOVE_CURSOR_DOWN_N  VT100_ESC "[%uB"
#define VT100_MOVE_CURSOR_RIGHT   VT100_ESC "[C"
#define VT100_MOVE_CURSOR_RIGHT_N VT100_ESC "[%uC"
#define VT100_MOVE_CURSOR_LEFT    VT100_ESC "[D"
#define VT100_MOVE_CURSOR_LEFT_N  VT100_ESC "[%uD"
#define VT100_SAVE_CURSOR_POS     VT100_ESC "[s"
#define VT100_RESTORE_CURSOR_POS  VT100_ESC "[u"
#define VT100_INSERT              VT100_ESC "[2~"
#define VT100_DELETE              VT100_ESC "[3~"
#define VT100_PAGE_UP             VT100_ESC "[5~"
#define VT100_PAGE_DOWN           VT100_ESC "[6~"
#define VT100_HOME                VT100_ESC "[H"
#define VT100_END                 VT100_ESC "[F"
#define VT100_F1                  VT100_ESC "OP"
#define VT100_F2                  VT100_ESC "OQ"
#define VT100_F3                  VT100_ESC "OR"
#define VT100_F4                  VT100_ESC "OS"
#define VT100_F5                  VT100_ESC "[15~"
#define VT100_F6                  VT100_ESC "[17~"
#define VT100_F7                  VT100_ESC "[18~"
#define VT100_F8                  VT100_ESC "[19~"
#define VT100_F9                  VT100_ESC "[20~"
#define VT100_F10                 VT100_ESC "[21~"
#define VT100_F11                 VT100_ESC "[23~"
#define VT100_F12                 VT100_ESC "[24~"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Encoded terminal modes
 **/

typedef enum
{
   SHELL_TERM_MODE_TTY_OP_END    = 0,
   SHELL_TERM_MODE_VINTR         = 1,
   SHELL_TERM_MODE_VQUIT         = 2,
   SHELL_TERM_MODE_VERASE        = 3,
   SHELL_TERM_MODE_VKILL         = 4,
   SHELL_TERM_MODE_VEOF          = 5,
   SHELL_TERM_MODE_VEOL          = 6,
   SHELL_TERM_MODE_VEOL2         = 7,
   SHELL_TERM_MODE_VSTART        = 8,
   SHELL_TERM_MODE_VSTOP         = 9,
   SHELL_TERM_MODE_VSUSP         = 10,
   SHELL_TERM_MODE_VDSUSP        = 11,
   SHELL_TERM_MODE_VREPRINT      = 12,
   SHELL_TERM_MODE_VWERASE       = 13,
   SHELL_TERM_MODE_VLNEXT        = 14,
   SHELL_TERM_MODE_VFLUSH        = 15,
   SHELL_TERM_MODE_VSWTCH        = 16,
   SHELL_TERM_MODE_VSTATUS       = 17,
   SHELL_TERM_MODE_VDISCARD      = 18,
   SHELL_TERM_MODE_IGNPAR        = 30,
   SHELL_TERM_MODE_PARMRK        = 31,
   SHELL_TERM_MODE_INPCK         = 32,
   SHELL_TERM_MODE_ISTRIP        = 33,
   SHELL_TERM_MODE_INLCR         = 34,
   SHELL_TERM_MODE_IGNCR         = 35,
   SHELL_TERM_MODE_ICRNL         = 36,
   SHELL_TERM_MODE_IUCLC         = 37,
   SHELL_TERM_MODE_IXON          = 38,
   SHELL_TERM_MODE_IXANY         = 39,
   SHELL_TERM_MODE_IXOFF         = 40,
   SHELL_TERM_MODE_IMAXBEL       = 41,
   SHELL_TERM_MODE_ISIG          = 50,
   SHELL_TERM_MODE_ICANON        = 51,
   SHELL_TERM_MODE_XCASE         = 52,
   SHELL_TERM_MODE_ECHO          = 53,
   SHELL_TERM_MODE_ECHOE         = 54,
   SHELL_TERM_MODE_ECHOK         = 55,
   SHELL_TERM_MODE_ECHONL        = 56,
   SHELL_TERM_MODE_NOFLSH        = 57,
   SHELL_TERM_MODE_TOSTOP        = 58,
   SHELL_TERM_MODE_IEXTEN        = 59,
   SHELL_TERM_MODE_ECHOCTL       = 60,
   SHELL_TERM_MODE_ECHOKE        = 61,
   SHELL_TERM_MODE_PENDIN        = 62,
   SHELL_TERM_MODE_OPOST         = 70,
   SHELL_TERM_MODE_OLCUC         = 71,
   SHELL_TERM_MODE_ONLCR         = 72,
   SHELL_TERM_MODE_OCRNL         = 73,
   SHELL_TERM_MODE_ONOCR         = 74,
   SHELL_TERM_MODE_ONLRET        = 75,
   SHELL_TERM_MODE_CS7           = 90,
   SHELL_TERM_MODE_CS8           = 91,
   SHELL_TERM_MODE_PARENB        = 92,
   SHELL_TERM_MODE_PARODD        = 93,
   SHELL_TERM_MODE_TTY_OP_ISPEED = 128,
   SHELL_TERM_MODE_TTY_OP_OSPEED = 129
} ShellTermModes;


//Shell server related functions
error_t shellServerProcessWindowResize(ShellServerSession *session);
error_t shellServerProcessChar(ShellServerSession *session);

error_t shellServerInsertChar(ShellServerSession *session, char_t c);

error_t shellServerProcessBackspaceKey(ShellServerSession *session);
error_t shellServerProcessDeleteKey(ShellServerSession *session);
error_t shellServerProcessLeftKey(ShellServerSession *session);
error_t shellServerProcessRightKey(ShellServerSession *session);
error_t shellServerProcessUpKey(ShellServerSession *session);
error_t shellServerProcessDownKey(ShellServerSession *session);
error_t shellServerProcessPageUpKey(ShellServerSession *session);
error_t shellServerProcessPageDownKey(ShellServerSession *session);

error_t shellClearCommandLine(ShellServerSession *session);

error_t shellRestoreCommandLine(ShellServerSession *session,
   const char_t *commandLine, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
