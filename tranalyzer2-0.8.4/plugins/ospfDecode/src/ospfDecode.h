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

/*
 * References:
 *   [RFC 1131] The OSPF Specification (obsolete)
 *   [RFC 2328] OSPF Version 2
 *   [RFC 5340] OSPF for IPv6
 */

#ifndef __OSPFDECODE_H__
#define __OSPFDECODE_H__

// global includes

// local includes
#include "global.h"

// user defines
#define OSPF_OUTPUT_DBD 0   // whether or not to output routing tables
#define OSPF_OUTPUT_MSG 0   // whether or not to output all messages

#define OSPF_MASK_AS_IP 0   // whether or not to display netmasks as IP
                            // (0: hex, 1: IP)
#define OSPF_AREA_AS_IP 0   // whether or not to display areas as IP
                            // (0: int, 1: IP, 2: hex)

// Suffixes for output files
#define OSPF_SUFFIX       "_ospfStats.txt"
#define OSPF_HELLO_SUFFIX "_ospfHello.txt"  // OSPF hello messages
#define OSPF_DBD_SUFFIX   "_ospfDBD.txt"    // OSPF database description (routing tables)
#define OSPF_MSG_SUFFIX   "_ospfMsg.txt"    // All other messages from OSPF (Link State Request/Update/Ack)

// plugin defines
#if OSPF_AREA_AS_IP == 1
#define OSPF_AREA_TYPE bt_ip4_addr  // Area as IP (string)
#define OSPF_PRI_AREA "s"
#elif OSPF_AREA_AS_IP == 2
#define OSPF_AREA_TYPE bt_hex_32    // Area as hex
#define OSPF_PRI_AREA "#08x"
#else // OSPF_AREA_TYPE == 0
#define OSPF_AREA_TYPE bt_uint_32   // Area as int
#define OSPF_PRI_AREA PRIu32
#endif // OSPF_AREA_AS_IP

// OSPF length
#define OSPF2_HDR_LEN 24
#define OSPF3_HDR_LEN 16
#define OSPF2_LSA_LEN 20 // LSA Header = sizeof(ospfLSA_t)
#define OSPF2_DBD_LEN  8 // sizeof(ospfDBD_t) - sizeof(uint32_t) [optional fields]

// OSPF types
#define OSPF_HELLO     1 // Discovers/maintains neighbors
#define OSPF_DB_DESCR  2 // Summarizes database contents
#define OSPF_LS_REQ    3 // (Link State) Database download
#define OSPF_LS_UPDATE 4 // (Link State) Database upload
#define OSPF_LS_ACK    5 // (Link State) Flooding acknowledgment
#define OSPF_TYPE_N    6 // Size of array to store OSPF types

// IP Multicast addresses
// Packets sent to those addresses MUST have their IP TTL set to 1
#define OSPF_ALL_SPF_ROUTERS htonl(0xe0000005) // 224.0.0.5
#define OSPF_ALL_D_ROUTERS   htonl(0xe0000006) // 224.0.0.6 (designated routers)

// OSPF Authentication Type
#define OSPF_AUTH_NULL   0
#define OSPF_AUTH_PASSWD 1
#define OSPF_AUTH_CRYPTO 2
#define OSPF_AUTH_N      3 // Size of array to store OSPF auth types

// OSPF LS Type
#define OSPF_LSTYPE_ROUTER      1 // Router-LSA
#define OSPF_LSTYPE_NETWORK     2 // Network-LSA
#define OSPF_LSTYPE_SUMMARY     3 // Summary-LSA (IP network)
#define OSPF_LSTYPE_ASBR        4 // Summary-LSA (ASBR)
#define OSPF_LSTYPE_ASEXT       5 // AS-external-LSA
#define OSPF_LSTYPE_MCAST       6 // Multicast group LSA (not implemented by Cisco)
#define OSPF_LSTYPE_NSSA        7 // Not-so-stubby area External LSA
#define OSPF_LSTYPE_EXTATTR     8 // External attribute LSA for BGP
#define OSPF_LSTYPE_OPAQUE_LLS  9 // Opaque LSA: Link-local scope
#define OSPF_LSTYPE_OPAQUE_ALS 10 // Opaque LSA: Area-local scope
#define OSPF_LSTYPE_OPAQUE_ASS 11 // Opaque LSA: autonomous system scope
#define OSPF_LSTYPE_N          12 // Size of array to store LS types

#define OSPF_LINK_PTP    1 // Point-to-point connection to another router
#define OSPF_LINK_TRAN   2 // Connection to a transit network
#define OSPF_LINK_STUB   3 // Connection to a stub network
#define OSPF_LINK_VIRT   4 // Virtual link
#define OSPF_LINK_TYPE_N 5 // Size fo array to store link types

// OSPF options
#define OSPF_OPT_DN 0x80 // BGP/MPLS VPNs [rfc4576]
#define OSPF_OPT_O  0x40 // Opaque LSA capable
#define OSPF_OPT_DC 0x20 // Demand circuits
#define OSPF_OPT_L  0x10 // packet contains LLS data block
#define OSPF_OPT_NP 0x08 // NSSA is supported (N) / Propagate (P)
#define OSPF_OPT_MC 0x04 // Multicast Capable
#define OSPF_OPT_E  0x02 // External Routing Capability
#define OSPF_OPT_MT 0x01 // Multi-Topology Routing

// Error status for T2 output
#define OSPF_STAT_BAD_TTL    1 // TTL != 1 when dst addr is mcast
#define OSPF_STAT_BAD_DST    2 // invalid destination address, e.g. HELLO always sent to ALL_SPF_ROUTERS
#define OSPF_STAT_BAD_TYPE   4 // invalid OSPFv2 type
#define OSPF_STAT_BAD_CSUM   8 // invalid checksum (TODO)
#define OSPF_STAT_MALFORMED 16 // unused fields in use... covert channel?
#define OSPF_STAT_N          9 // Size of array to store OSPF stat (not interested in counting MALFORMED for now)

// plugin structs

typedef struct {
    uint8_t version;
    uint8_t type;
    uint16_t len;
    struct in_addr routerID;
    uint32_t areaID;
    uint16_t chksum;
    union {
        uint16_t auType;    // v2 (IPv4)
        struct {            // v3 (IPv6)
            uint8_t instID;
            uint8_t zero8;
        };
    };
    union { // v2 only
        uint64_t auField;   // auType == 1
        struct {            // auType == 2
            uint16_t zero16;
            uint8_t  keyID;
            uint8_t  auDataLen;
            uint32_t cryptoSeqNum;
        };
    };
    uint8_t data;
} ospfHeader_t;

typedef struct {
    uint16_t lsAge;
#define OSPF_LSA_DNA(lsa) (ntohs((lsa)->lsAge) >> 0xf) // Do Not Age
    uint8_t options;
    uint8_t lsType;
    struct in_addr lsaID;
    struct in_addr advRtr;
    uint32_t lsSeqNum;
    uint16_t lsChksum;
    uint16_t lsLen;
} ospfLSA_t;

typedef struct {
    struct in_addr linkID; // type=1 or 4: neighboring router's Router ID,
                           // type=2: IP adddress of Designated Router
                           // type=3: IP network/subnet number
    uint32_t linkData; // type=3: netmask, type=1: interface MIB-II ifIndex value,
                       // other types: router's associated IP interface address
    uint8_t type;
    uint8_t numTOS;
    uint16_t tos0Metric;
    // TOS (8), 0 (8), Metric (16)
} ospfRouterLSALink_t;

typedef struct {
    ospfLSA_t lsaHdr;
    uint16_t flags;
#define OSPF_RLSA_V(rlsa) ((rlsa)->flags & 0x4) // virtual link endpoint
#define OSPF_RLSA_E(rlsa) ((rlsa)->flags & 0x2) // AS boundary router (external)
#define OSPF_RLSA_B(rlsa) ((rlsa)->flags & 0x1) // area border router
    uint16_t numLinks;
    uint8_t link;
} ospfRouterLSA_t;

typedef struct {
    ospfLSA_t lsaHdr;
    uint32_t netmask;
    struct in_addr router; // attached router(s)
} ospfNetworkLSA_t;

typedef struct {
    ospfLSA_t lsaHdr;
    uint32_t netmask;
    uint32_t tos:8;
    uint32_t metric:24;
} ospfSummaryLSA_t; // lsType = 3 or 4

typedef struct {
    ospfLSA_t lsaHdr;
    uint32_t netmask;
    uint32_t e:1; // External bit (1: Type 2 external metric, 0: Type 1)
    uint32_t tos:7;
    uint32_t metric:24;
    struct in_addr forwardAddr; // forwarding address
    uint32_t extRouteTag; // External Route Tag (not used by OSPF)
} ospfASExtLSA_t;

typedef struct {
    uint16_t type;
    uint16_t len;
    uint32_t value; // of length 'len', 32-bit aligned
} ospfLLSTLV_t;

typedef struct {
    uint16_t chksum;
    uint16_t len;
    // Followed by TLVs
} ospfLLS_t;

typedef struct {
    uint32_t netmask;
    uint16_t helloInt;     // default is 10
    uint8_t options;
    uint8_t routPrio;
    uint32_t routDeadInt;  // default is 4*helloInt
    struct in_addr desRtr;
    struct in_addr backupRtr;
    struct in_addr neighbors;
} ospfHello_t;

typedef struct {
    uint16_t intMTU;
    uint8_t options;
    uint8_t flags;
#define OSPF_T2_I_BIT(dbd)  ((dbd)->flags & 0x4)// Init bit: 1->first packet
#define OSPF_T2_M_BIT(dbd)  ((dbd)->flags & 0x2)// More bit: 1->more packets follow
#define OSPF_T2_MS_BIT(dbd) ((dbd)->flags & 0x1)// Master/Slave bit: 1->master, 2->slave
    uint32_t DDSeqNum;
    uint8_t lsaHdr;
} ospfDBD_t; // Database description

typedef struct {
    uint32_t lsType;
    struct in_addr lsID;
    struct in_addr advRtr;
} ospfLSR_t; // LS Request

typedef struct {
    uint32_t numLSA;
    uint8_t lsaHdr;
} ospfLSU_t; // LS Update

typedef struct {
    uint8_t version;
    uint32_t areaID;
    uint16_t auType; // authentication type (0: none, 1: password, 2: crypto)
    uint8_t type;
    uint8_t stat;
    char auPass[9];  // authentication password
} ospfFlow_t;

extern ospfFlow_t *ospfFlow;

#endif // __OSPFDECODE_H__
