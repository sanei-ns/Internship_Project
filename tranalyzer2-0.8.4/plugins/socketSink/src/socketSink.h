/*
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

#ifndef SOCKET_SINK_H_
#define SOCKET_SINK_H_

// global includes
#include <ifaddrs.h>
#include <netdb.h>
#ifndef __APPLE__
#include <netpacket/packet.h> // for struct sockaddr_ll
#else // __APPLE__
// See the definition of struct sockaddr_ll at the end of this file
#endif // __APPLE__
#include <sys/types.h>
#include <sys/utsname.h>

// local includes
#include "global.h"

// User configuration
#define SERVADD      "127.0.0.1" // destination address
#define DPORT        6666        // hex destination port host order
#define SOCKTYPE     1           // 0: UDP; 1: TCP
#define CONTENT_TYPE 1           // 0: binary; 1: text; 2: json
#define HOST_INFO    0           // 0: no info; 1: all info about host
                                 // (only if CONTENT_TYPE == 1)
#if SOCKTYPE == 1
#define GZ_COMPRESS  0           // whether or not to compress the output (gzip) [TCP ONLY]
#endif // SOCKTYPE == 1

// Local plugin defines

#define SOCK_BUFSHFT (BUF_DATA_SHFT * 4)
#define MAXBHBUF     2047

#ifdef __APPLE__
// netpacket/packet.h does not exist on Mac OSX
// so we copy the structure here.
struct sockaddr_ll {
    unsigned short int sll_family;
    unsigned short int sll_protocol;
    int sll_ifindex;
    unsigned short int sll_hatype;
    unsigned char sll_pkttype;
    unsigned char sll_halen;
    unsigned char sll_addr[8];
};
#endif // __APPLE__

#endif // SOCKET_SINK_H_
