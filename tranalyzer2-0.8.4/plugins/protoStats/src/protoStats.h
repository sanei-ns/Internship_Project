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

#ifndef __PROTO_STATS_H__
#define __PROTO_STATS_H__

// local includes
#include "global.h"

// User defines

#define ETH_STAT     1 // output layer 2 statistics
#define UDPLITE_STAT 0 // output UDP-Lite statistics
#define SCTP_STAT    0 // output SCTP statistics

#define PROTO_SUFFIX "_protocols.txt"

#define L2ETHFILE "ethertypes.txt"
#define PROTOFILE "proto.txt"
#define PORTFILE  "portmap.txt"

// Local defines
#define L2ETHTYPEMAX 65535
#define L2ETHMAXLEN     99

#define MAXFILENAMELEN 255
#define IPPROTMAX      255
#define IPPROTMAXLEN    99

#define L4PORTMAX    65535
#define L4PORTMAXLEN    99

#endif // __PROTO_STATS_H__
