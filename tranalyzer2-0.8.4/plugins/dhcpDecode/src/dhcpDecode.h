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

#ifndef __DHCP_DECODE_H__
#define __DHCP_DECODE_H__

// global includes

// local includes
#include "global.h"

// user defines
#define DHCPBITFLD        0 // Options: 1: bitfield, 0: option numbers in a row
#define DHCPMAXOPT       50 // if (DHCPBITFLD == 0) maximum stored options
#define DHCPNMMAX        10 // maximal number of domain/host names per flow
#define DHCPMASKFRMT      1 // Netmask representation: 0: hex, 1: IP
#define DHCP_ADD_CNT      0 // Print the number of times a given mac/domain/host appeared
#define DHCP_FLAG_MAC     0 // Store a global mapping IP->MAC and add the source and
                            // destination MAC address to every flow [EXPERIMENTAL, IPv4 only]
#define DHCP_FM_DEBUG     0 // print debug information about DHCP_FLAG_MAC operations

// plugin defines
#if DHCPMASKFRMT == 1
#define DHCPMASKTYP bt_ip4_addr
#else // DHCPMASKFRMT == 0
#define DHCPMASKTYP bt_hex_32
#endif // DHCPMASKFRMT

#define DHCP64MSK     0x3f
#define DHCPBCST      0x0080                // network order
#define MAGICNUMBERn  0x63538263            // DHCP/BOOTP option magic number
#define DHCP_HDRLEN   sizeof(dhcpHeader_t)  // DHCP header length
#define DHCPOPTUDPOFF (DHCP_HDRLEN + 8)     // DHCP header + UDP header
#define DHCPOPTEND    0xff                  // DHCP option end marker

// IPv4
#define DHCP4UDPCP    68  // DHCP client port 68
#define DHCP4UDPSP    67  // DHCP server port 67

// IPv6
#define DHCP6UDPCP    546  // DHCP client port 546
#define DHCP6UDPSP    547  // DHCP server port 547

// Number of message type
#define DHCP_NUM_MSGT   8
#define DHCP_NUM_MSGT6 23

// Message Type
#define DHCP_MSGT_DISCOVER 1
#define DHCP_MSGT_OFFER    2
#define DHCP_MSGT_REQUEST  3
#define DHCP_MSGT_DECLINE  4
#define DHCP_MSGT_ACK      5
#define DHCP_MSGT_NACK     6
#define DHCP_MSGT_RELEASE  7
#define DHCP_MSGT_INFORM   8

// status bit field
#define DHCPPRTDT       0x0001 // DHCP detected
#define DHCPREQ         0x0002 // Boot request
#define DHCPREPLY       0x0004 // Boot reply
#define DHCPBCAST       0x0008 // Broadcast
#define DHCPMISCLID     0x0010 // Client identifier (option 61) different from Client MAC address (DHCP header)
#define DHCPOPTOVERL    0x0020 // option overload (server host name and/or boot file name carry options)
#define DHCPSECELNDIAN  0x0040 // seconds elapsed probably encoded as little endian
#define DHCPNONETHHW    0x0080 // Non Ethernet hardware
#define DHCPOPTTRUNC    0x0100 // option list truncated... increase DHCPMAXOPT
#define DHCPNMTRUNC     0x0200 // domain or host name list truncated... increase DHCPNMMAX
#define DHCPINVALIDLEN  0x1000 // Error: DHCP invalid length
#define DHCPMAGNUMERR   0x2000 // Error: DHCP magic number corrupt
#define DHCPOPTCORRPT   0x4000 // Error: DHCP options corrupt
#define DHCPMALFORMD    0x8000 // something is weird

typedef struct {
    uint8_t  opcode; // 1: BOOTREQUEST, 2: BOOTREPLY
    uint8_t  hwType; // 1: Ethernet
    uint8_t  hwAddrLen;
    uint8_t  hopCnt;
    uint32_t transID;
    uint16_t num_sec;
    uint16_t flags;
    uint32_t clientIP;
    uint32_t yourIP;
    uint32_t servIP;
    uint32_t gwIP;
    uint32_t clientHWaddr[4];
    uint8_t  servHostName[64];
    uint8_t  bootFname[128];
    uint32_t optMagNum;
} __attribute__((packed)) dhcpHeader_t;

typedef struct {
    uint64_t hwType;
#if DHCP_ADD_CNT == 1
    uint32_t clHWAdd[DHCPNMMAX][3];
#else
    uint32_t clHWAdd[DHCPNMMAX][2];
#endif
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    uint64_t lflow; // linked flow
    uint64_t optT[3];
    uint32_t hopCnt;
    uint32_t netMsk;
    uint32_t gw;
    uint32_t dns;
    uint32_t cliIP;     // client IP address
    uint32_t yourIP;    // your (client) IP address
    uint32_t nextSrvr;  // next server IP address
    uint32_t relay;     // relay agent IP address
    uint32_t srvId;     // server ID
    uint32_t reqIP;     // requested IP address
    uint32_t leaseT;    // lease time
    uint32_t renewT;    // renewal time
    uint32_t rebindT;   // rebind time
    uint16_t maxSecEl;  // maximum seconds elapsed
    uint16_t optCntT;
    uint16_t optNum;
    uint16_t hostNCnt;
#if DHCP_ADD_CNT == 1
    uint16_t hostrep[DHCPNMMAX];
#endif
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

    uint16_t domainNCnt, HWAddCnt;

#if DHCP_ADD_CNT == 1
    uint16_t domainrep[DHCPNMMAX];
#endif

    uint16_t stat;
#if IPV6_ACTIVATE > 0
    uint32_t MType;
#else // IPV6_ACTIVATE == 0
    uint16_t MType;
#endif // IPV6_ACTIVATE > 0
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    uint8_t opt[DHCPMAXOPT];
    char serverName[64];
    char bootFile[128];
    char msg[256];
    char *hostN[DHCPNMMAX];
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    char *domainN[DHCPNMMAX];
} dhcpFlow_t;

extern dhcpFlow_t *dhcpFlow;

#endif // __DHCP_DECODE_H__
