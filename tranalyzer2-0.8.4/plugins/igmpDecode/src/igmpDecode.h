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


#ifndef __IGMPDECODE_H__
#define __IGMPDECODE_H__

// user defines

#define IGMP_TC_MD  0   // type code 0: bit field 1: explicit array of type code 2: type code statistics
#define IGMP_NUM    10  // if IGMP_TC_MD == 1: number of type info / flow
#define IGMP_SUFFIX "_igmpStats.txt"

// includes

// local includes
#include "global.h"

#define IGMP_UNKNOWN -1
#define IGMP_V0 0
#define IGMP_V1 1
#define IGMP_V2 2
#define IGMP_V3 3
#define IGMP_V_N 4 // number of different IGMP version

#define IGMP_MIN_LEN           8 // min length for IGMP
#define IGMP_V3_QUERY_MIN_LEN 12 // min length for IGMPv3 membership query

// IGMP types
// 0x00: reserved
// IGMP v0 [RFC988] (obsolete)
#define IGMP_V0_CREATE_GROUP_REQUEST    0x01
#define IGMP_V0_CREATE_GROUP_REPLY      0x02
#define IGMP_V0_JOIN_GROUP_REQUEST      0x03
#define IGMP_V0_JOIN_GROUP_REPLY        0x04
#define IGMP_V0_LEAVE_GROUP_REQUEST     0x05
#define IGMP_V0_LEAVE_GROUP_REPLY       0x06
#define IGMP_V0_CONFIRM_GROUP_REQUEST   0x07
#define IGMP_V0_CONFIRM_GROUP_REPLY     0x08
// 0x09-0x10: unassigned
#define IGMP_MEMBERSHIP_QUERY           0x11 // [RFC1112]
#define IGMP_V1_MEMBERSHIP_REPORT       0x12 // [RFC1112]
#define IGMP_DVMRP                      0x13 // DVMRP routing
#define IGMP_PIM_V1                     0x14 // PIM routing
#define IGMP_CISCO_TRACE_MSG            0x15
// IGMP v2 [RFC2236]
#define IGMP_V2_MEMBERSHIP_REPORT       0x16
#define IGMP_V2_LEAVE_GROUP             0x17
// Multicast Traceroute
#define IGMP_MTRACE_RESP                0x1e
#define IGMP_MTRACE                     0x1f
// IGMP v3 [RFC3376]
#define IGMP_V3_MEMBERSHIP_REPORT       0x22
// Multicast Router Discovery (MRD) [RFC4286]
#define IGMP_MRD_ROUTER_ADVERT          0x30
#define IGMP_MRD_ROUTER_SOLICIT         0x31
#define IGMP_MRD_ROUTER_TERM            0x32
// IGAP
#define IGMP_IGAP_MEMBERSHIP_REPORT     0x40
#define IGMP_IGAP_MEMBERSHIP_QUERY      0x41
#define IGMP_IGAP_LEAVE_GROUP           0x42
// 0xf0-0xff: Reserved for experimentation
// Router-Port Group Management Protocol (RGMP) [RFC3488]
#define IGMP_RGMP_LEAVE_GROUP           0xfc
#define IGMP_RGMP_JOIN_GROUP            0xfd
#define IGMP_RGMP_BYE                   0xfe
#define IGMP_RGMP_HELLO                 0xff

#define IGMP_TYPE_N 256

// DVMRP codes
#define DVMRP_PROBE                1 // for neighbor discovery
#define DVMRP_ROUTE_REPORT         2 // for route exchange
#define DVMRP_OLD_ASK_NEIGHBORS    3
#define DVMRP_OLD_NEIGHBORS_REPLY  4
#define DVMRP_ASK_NEIGHBORS        5
#define DVMRP_NEIGHBORS_REPLY      6
#define DVMRP_PRUNE                7 // for pruning multicast delivery trees
#define DVMRP_GRAFT                8 // for grafting multicast delivery trees
#define DVMRP_GRAFT_ACK            9 // for acknowledging graft messages
#define DVMRP_CODES_N             10

// PIMv1 codes
#define PIM_V1_QUERY         0
#define PIM_V1_REGISTER      1
#define PIM_V1_REGISTER_STOP 2
#define PIM_V1_JOIN_PRUNE    3
#define PIM_V1_RP_REACHABLE  4
#define PIM_V1_ASSERT        5
#define PIM_V1_GRAFT         6
#define PIM_V1_GRAFT_ACK     7
#define PIM_V1_MODE          8
#define PIM_V1_CODES_N       9

// IGMPv3 group record types
#define IGMP_V3_MODE_IS_INCLUDE   1
#define IGMP_V3_MODE_IS_EXCLUDE   2
#define IGMP_V3_CHANGE_TO_INCLUDE 3
#define IGMP_V3_CHANGE_TO_EXCLUDE 4
#define IGMP_V3_ALLOW_NEW_SOURCES 5
#define IGMP_V3_BLOCK_OLD_SOURCES 6

// IGMP group address
// http://www.iana.org/assignments/multicast-addresses
#define IGMP_LOCAL_GROUP      htonl(0xe0000000L) // 224.0.0.0
#define IGMP_ALL_HOSTS        htonl(0xe0000001L) // 224.0.0.1
#define IGMP_V2_ALL_ROUTERS   htonl(0xe0000002L) // 224.0.0.2
#define IGMP_V3_ALL_ROUTERS   htonl(0xe0000016L) // 224.0.0.22
#define IGMP_RGMP_ADDR        htonl(0xe0000019L) // 224.0.0.25

#define IGMP_LOCAL_GROUP_MASK htonl(0xffffff00L) // 255.255.255.0

#define IGMP_STAT_BAD_LENGTH      1
#define IGMP_STAT_BAD_CHECKSUM    2
#define IGMP_STAT_BAD_TTL         4 // TTL != 1
#define IGMP_STAT_INVALID_QUERY   8 // group must be 0 for queries

#define IGMP_TYPEFIELD 32   // if you change this value: %2 & change the datatype of igmptype if necessary
#define IGMP_CODEFIELD 16   // if you change this value: %2 & change the datatype of igmptype if necessary

// IGMP v3 membership query
typedef struct {
    uint8_t type;               // 0x11 (IGMP_MEMBERSHIP_QUERY)
    uint8_t max_resp_code;
    uint16_t checksum;
    struct in_addr group;
    uint8_t resv:4;             // reserved
    uint8_t suppress:1;         // Suppress Router-Side Processing
    uint8_t qrv:3;              // Querier's Robustness Variable
    uint8_t qqic;               // Querier's Query Interval Code
    uint16_t nsrcs;             // number of sources
    struct in_addr saddr[0];    // nsrcs struct in_addr (source addresses)
} igmpv3_query_t;

// IGMP v3 group record (part of igmpv3_report_t)
typedef struct {
    uint8_t type;
    uint8_t aux_len;    // length of the auxiliary data field
    uint16_t nsrcs;
    struct in_addr mcast_addr;
    struct in_addr saddr[0];
} igmpv3_grec_t;

// IGMP v3 membership report
typedef struct {
    uint8_t  type;          // 0x22 (IGMP_V3_MEMBERSHIP_REPORT)
    uint8_t  resv1;         // reserved
    uint16_t checksum;
    uint16_t resv2;         // reserved
    uint16_t ngrec;         // number of group records
    igmpv3_grec_t grec[0];  // ngrec igmpv3_grec_t structures
} igmpv3_report_t;

// IGMP multicast traceroute
typedef struct {
    uint8_t type;               // 0x1e (IGMP_MTRACE_RESP) or 0x1f (IGMP_MTRACE)
    uint8_t hops;               // number of hops
    uint16_t checksum;
    struct in_addr group;       // multicast group address
    struct in_addr saddr;       // source address
    struct in_addr daddr;       // destination address
    struct in_addr resp_addr;   // response address
    uint32_t resp_ttl:8;
    uint32_t query_id:24;
} igmp_mtrace_t;

// DVMR
typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t resv;        // Reserved
    uint16_t min_version; // Minor version
    uint16_t maj_version; // Major version
} igmp_dvmrp_t;

// Plugin Structs
typedef struct igmpDecodeFlow_s {
    int8_t igmp_version;
    struct in_addr mcast_addr;
#if IGMP_TC_MD == 0
    uint32_t igmp_type_bfield;
    //uint16_t igmp_code_bfield;
#elif IGMP_TC_MD == 1
    uint8_t igmp_type[IGMP_NUM];
    //uint8_t igmp_code[IGMP_NUM];
#elif IGMP_TC_MD == 2
    uint8_t igmp_type[IGMP_TYPEFIELD];
    //uint8_t igmp_code[IGMP_CODEFIELD];
#endif // IGMP_TC_MD == 2
    uint8_t igmp_stat;
    //uint8_t rec_type;
    uint16_t igmp_nrec; // number of group records (IGMP_V3_MEMBERSHIP_REPORT)
                        // number of source addresses (IGMP_MEMBERSHIP_QUERY v3)
                        // number of hops (IGMP_MTRACE or IGMP_MTRACE_RESP)
} igmp_flow_t;

extern igmp_flow_t *igmp_flows;

#endif //__IGMPDECODE_H__
