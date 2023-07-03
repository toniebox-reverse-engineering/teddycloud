/**
 * @file ssh_modp_groups.h
 * @brief Modular exponentiation (MODP) groups
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

#ifndef _SSH_MODP_GROUPS_H
#define _SSH_MODP_GROUPS_H

//Dependencies
#include "ssh/ssh.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Modular exponentiation (MODP) group
 **/

typedef struct
{
   const char_t *name;                           ///<Group name
   const uint8_t p[SSH_MAX_DH_MODULUS_SIZE / 8]; ///<Prime modulus
   size_t pLen;                                  ///<Length of the prime modulus, in bytes
   uint8_t g;                                    ///<Generator
} SshDhModpGroup;


//MODP groups
extern const SshDhModpGroup sshDhModpGroup1;
extern const SshDhModpGroup sshDhModpGroup14;
extern const SshDhModpGroup sshDhModpGroup15;
extern const SshDhModpGroup sshDhModpGroup16;
extern const SshDhModpGroup sshDhModpGroup17;
extern const SshDhModpGroup sshDhModpGroup18;

//MODP group related functions
const SshDhModpGroup *sshGetDhModpGroup(const char_t *kexAlgo);
error_t sshLoadDhModpGroup(DhParameters *params, const char_t *kexAlgo);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
