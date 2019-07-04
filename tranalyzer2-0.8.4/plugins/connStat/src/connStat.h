/*
 * connStat.h
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

/*
 * Counts the number of connections between two hosts regarding the initiation
 * and termination of a communication and the number of distinct connections of
 * one host. Here, distinct means that only the number of different hosts the
 * actual host is connected to, are counted.
 *
 * Please note that because of the nature of this program, not all connections
 * of a host might be observed. For example if the program is sniffing the
 * traffic between a gateway and a local intranet, it is not able to observe
 * the connections between two hosts inside the intranet. Therefore, these
 * values are to be handled with care.
 */

#ifndef CONNSTAT_H_
#define CONNSTAT_H_

// includes

// local includes
#include "global.h"


// user definitions
#define CS_HSDRM   1 // decrement IP counters when flows die
#define CS_SDIPMAX 1 // 0: number of src dst IP connnections
                     // 1: IP src dst connection with the highest count

// MAC OSX only
#define CS_GEOLOC  0 // whether (1) or not (0) to add the country to the IPs
                     // with max connections

// plugin definitions

#ifndef __APPLE__
#include "basicFlow.h"
#if BFO_SUBNET_TEST == 1
// CS_GEOLOC is automatically activated (when possible) on Linux
#undef CS_GEOLOC
#define CS_GEOLOC 1
#endif // BFO_SUBNET_TEST == 1
#endif // !__APPLE__

typedef struct {
#if IPV6_ACTIVATE > 0
	ipAddr_t srcIP, dstIP;
#else // IPV6_ACTIVATE == 0
	ip4Addr_t srcIP, dstIP;
#endif // IPV6_ACTIVATE == 0
#if IPV6_ACTIVATE == 2
	uint8_t ver;
#endif // IPV6_ACTIVATE == 2
} __attribute__((packed)) ipPID_t;

typedef struct {
#if IPV6_ACTIVATE > 0
	ipAddr_t addr;
#else // IPV6_ACTIVATE == 0
	ip4Addr_t addr;
#endif // IPV6_ACTIVATE == 0
#if IPV6_ACTIVATE == 2
	uint8_t ver;
#endif // IPV6_ACTIVATE == 2
} __attribute__((packed)) ipHash_t;

typedef struct {
#if IPV6_ACTIVATE > 0
	ipAddr_t addr;
#else // IPV6_ACTIVATE == 0
	ip4Addr_t addr;
#endif // IPV6_ACTIVATE == 0
	uint16_t port;
#if IPV6_ACTIVATE == 2
	uint8_t ver;
#endif // IPV6_ACTIVATE == 2
} __attribute__((packed)) ipPort_t;

#if ESOM_DEP == 1
float sconn, dconn, iconn, pconn, fconn;
#endif // ESOM_DEP == 1

#endif // CONNSTAT_H_
