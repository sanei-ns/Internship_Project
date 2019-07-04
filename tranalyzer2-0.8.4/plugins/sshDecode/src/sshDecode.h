/*
 * sshDecode.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef __SSHDECODE_H__
#define __SSHDECODE_H__

// local includes
#include "global.h"

#include <openssl/evp.h>
#include <openssl/md5.h>


// user defines

#define SSH_USE_PORT 0 // whether to count all packets to/from port SSH_PORT as SSH
#define SSH_DEBUG    0 // whether or not to activate debug output
#define SSH_DECODE   0 // whether or not to decode SSH messages (experimental)


// plugin defines

#define SSH_BUFSIZE     255
#define SSH_COOKIE_SIZE  16

// Ports
#define SSH_PORT 22

// Protocols
#define SSH_MAGIC 0x5353482d // SSH- in network order

#define SSH_MSG_KEXINIT 20 // [RFC4253]
#define SSH_MSG_NEWKEYS 21 // [RFC4253]

// Status
#define SSH_STAT_SSH       0x01 // Flow contains SSH protocol
#define SSH_STAT_VER_FIRST 0x02 // Keep track of who sent the SSH banner first
#define SSH_STAT_VER_TRUNC 0x40 // version truncated.. increase SSH_VER_MAXLEN
#define SSH_STAT_MALFORMED 0x80 // Banner does not end with CRLF or contains NULL


// Structs

typedef struct {
    uint8_t stat;
    char version[SSH_BUFSIZE+1];
#if SSH_DECODE == 1
    char cookie[2*SSH_COOKIE_SIZE+1];
    char host_key_type[16];
    char srv_host_key_algo[SSH_BUFSIZE+1];
    char fingerprint[3*MD5_DIGEST_LENGTH];
    // malloc?
    char kex_algo[SSH_BUFSIZE+1];
    char enc_cs[SSH_BUFSIZE+1];
    char enc_sc[SSH_BUFSIZE+1];
    char mac_cs[SSH_BUFSIZE+1];
    char mac_sc[SSH_BUFSIZE+1];
    char comp_cs[SSH_BUFSIZE+1];
    char comp_sc[SSH_BUFSIZE+1];
    char lang_cs[SSH_BUFSIZE+1];
    char lang_sc[SSH_BUFSIZE+1];
    char kex_dh_h_sig[SSH_BUFSIZE+1];
    uint32_t dh_key_exchange_init;
#endif // SSH_DECODE == 1
} sshFlow_t;

// plugin struct pointer for potential dependencies
extern sshFlow_t *sshFlows;

#endif // __SSHDECODE_H__
