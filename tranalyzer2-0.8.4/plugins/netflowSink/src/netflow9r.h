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

#ifndef _NETFLOW_NV9_H
#define _NETFLOW_NV9_H

// global includes
#include "netflowSink.h"

// NV9 header defines

#define NF9_VER       0x0900
#define NF9_TMPLT     0x0200
#define NF9_OPT_TMPLT 0x0300

#define NF9_OBS_DOMID 0x9a020000
#define NF9_TID       0x0001

// Netflow 9 definition

#define NF9_IN_BYTES                    0x0100 // 1
#define NF9_IN_PKTS                     0x0200 // 2
#define NF9_FLOWS                       0x0300 // 3
#define NF9_PROTOCOL                    0x0400 // 4
#define NF9_SRC_TOS                     0x0500 // 5
#define NF9_TCP_FLAGS                   0x0600 // 6
#define NF9_L4_SRC_PORT                 0x0700 // 7
#define NF9_IPV4_SRC_ADDR               0x0800 // 8
#define NF9_SRC_MASK                    0x0900 // 9
#define NF9_INPUT_SNMP                  0x0a00 // 10
#define NF9_L4_DST_PORT                 0x0b00 // 11
#define NF9_IPV4_DST_ADDR               0x0c00 // 12
#define NF9_DST_MASK                    0x0d00 // 13
#define NF9_OUTPUT_SNMP                 0x0e00 // 14
#define NF9_IPV4_NEXT_HOP               0x0f00 // 15
#define NF9_SRC_AS                      0x1000 // 16
#define NF9_DST_AS                      0x1100 // 17
#define NF9_BGP_IPV4_NEXT_HOP           0x1200 // 18
#define NF9_MUL_DST_PKTS                0x1300 // 19
#define NF9_MUL_DST_BYTES               0x1400 // 20
#define NF9_LAST_SWITCHED               0x1500 // 21
#define NF9_FIRST_SWITCHED              0x1600 // 22
#define NF9_OUT_BYTES                   0x1700 // 23
#define NF9_OUT_PKTS                    0x1800 // 24
#define NF9_MIN_PKT_LNGTH               0x1900 // 25
#define NF9_MAX_PKT_LNGTH               0x1a00 // 26
#define NF9_IPV6_SRC_ADDR               0x1b00 // 27
#define NF9_IPV6_DST_ADDR               0x1c00 // 28
#define NF9_IPV6_SRC_MASK               0x1d00 // 29
#define NF9_IPV6_DST_MASK               0x1e00 // 30
#define NF9_IPV6_FLOW_LABEL             0x1f00 // 31
#define NF9_ICMP_TYPE                   0x2000 // 32
#define NF9_MUL_IGMP_TYPE               0x2100 // 33
#define NF9_SAMPLING_INTERVAL           0x2200 // 34
#define NF9_SAMPLING_ALGORITHM          0x2300 // 35
#define NF9_FLOW_ACTIVE_TIMEOUT         0x2400 // 36
#define NF9_FLOW_INACTIVE_TIMEOUT       0x2500 // 37
#define NF9_ENGINE_TYPE                 0x2600 // 38
#define NF9_ENGINE_ID                   0x2700 // 39
#define NF9_TOTAL_BYTES_EXP             0x2800 // 40
#define NF9_TOTAL_PKTS_EXP              0x2900 // 41
#define NF9_TOTAL_FLOWS_EXP             0x2a00 // 42
#define NF9_IPV4_SRC_PREFIX             0x2c00 // 44
#define NF9_IPV4_DST_PREFIX             0x2d00 // 45
#define NF9_MPLS_TOP_LABEL_TYPE         0x2e00 // 46
#define NF9_MPLS_TOP_LABEL_IP_ADDR      0x2f00 // 47
#define NF9_FLOW_SAMPLER_ID             0x3000 // 48
#define NF9_FLOW_SAMPLER_MODE           0x3100 // 49
#define NF9_FLOW_SAMPLER_RANDOM_INTRVL  0x3200 // 50
#define NF9_MIN_TTL                     0x3400 // 52
#define NF9_MAX_TTL                     0x3500 // 53
#define NF9_IPV4_IDENT                  0x3600 // 54
#define NF9_DST_TOS                     0x3700 // 55
#define NF9_IN_SRC_MAC                  0x3800 // 56
#define NF9_OUT_DST_MAC                 0x3900 // 57
#define NF9_SRC_VLAN                    0x3a00 // 58
#define NF9_DST_VLAN                    0x3b00 // 59
#define NF9_IP_VER                      0x3c00 // 60
#define NF9_DIRECTION                   0x3d00 // 61
#define NF9_IPV6_NEXT_HOP               0x3e00 // 62
#define NF9_BPG_IPV6_NEXT_HOP           0x3f00 // 63
#define NF9_IPV6_OPTION_HEADERS         0x4000 // 64
#define NF9_MPLS_LABEL_1                0x4600 // 70
#define NF9_MPLS_LABEL_2                0x4700 // 71
#define NF9_MPLS_LABEL_3                0x4800 // 72
#define NF9_MPLS_LABEL_4                0x4900 // 73
#define NF9_MPLS_LABEL_5                0x4a00 // 74
#define NF9_MPLS_LABEL_6                0x4b00 // 75
#define NF9_MPLS_LABEL_7                0x4c00 // 76
#define NF9_MPLS_LABEL_8                0x4d00 // 77
#define NF9_MPLS_LABEL_9                0x4e00 // 78
#define NF9_MPLS_LABEL_10               0x4f00 // 79
#define NF9_IN_DST_MAC                  0x5000 // 80
#define NF9_OUT_SRC_MAC                 0x5100 // 81
#define NF9_IF_NAME                     0x5200 // 82
#define NF9_IF_DESC                     0x5300 // 83
#define NF9_SAMPLER_NAME                0x5400 // 84
#define NF9_IN_PERMANENT_BYTES          0x5500 // 85
#define NF9_IN_PERMANENT_PKTS           0x5600 // 86
#define NF9_FRAGMENT_OFFSET             0x5800 // 88
#define NF9_FORWARDING_STATUS           0x5900 // 89
#define NF9_MPLS_PAL_RD                 0x5a00 // 90
#define NF9_MPLS_PREFIX_LEN             0x5b00 // 91
#define NF9_SRC_TRAFFIC_INDEX           0x5c00 // 92
#define NF9_DST_TRAFFIC_INDEX           0x5d00 // 93
#define NF9_APPLICATION_DESCRIPTION     0x5e00 // 94
#define NF9_APPLICATION_TAG             0x5f00 // 95
#define NF9_APPLICATION_NAME            0x6000 // 96
#define NF9_postipDiffServCodePoint     0x6200 // 98
#define NF9_replication_factor          0x6300 // 99

// len
#define NF9_IN_BYTES_LEN                    0x0800 // 8
#define NF9_IN_PKTS_LEN                     0x0800 // 8
#define NF9_FLOWS_LEN                       0x0000 // N
#define NF9_PROTOCOL_LEN                    0x0100 // 1
#define NF9_SRC_TOS_LEN                     0x0100 // 1
#define NF9_TCP_FLAGS_LEN                   0x0100 // 1
#define NF9_L4_SRC_PORT_LEN                 0x0200 // 2
#define NF9_IPV4_SRC_ADDR_LEN               0x0400 // 4
#define NF9_SRC_MASK_LEN                    0x0100 // 1
#define NF9_INPUT_SNMP_LEN                  0x0000 // N
#define NF9_L4_DST_PORT_LEN                 0x0200 // 2
#define NF9_IPV4_DST_ADDR_LEN               0x0400 // 4
#define NF9_DST_MASK_LEN                    0x0100 // 1
#define NF9_OUTPUT_SNMP_LEN                 0x0000 // N
#define NF9_IPV4_NEXT_HOP_LEN               0x0400 // 4
#define NF9_SRC_AS_LEN                      0x0200 // 2
#define NF9_DST_AS_LEN                      0x0200 // 2
#define NF9_BGP_IPV4_NEXT_HOP_LEN           0x0400 // 4
#define NF9_MUL_DST_PKTS_LEN                0x0400 // 4
#define NF9_MUL_DST_BYTES_LEN               0x0400 // 4
#define NF9_LAST_SWITCHED_LEN               0x0400 // 4
#define NF9_FIRST_SWITCHED_LEN              0x0400 // 4
#define NF9_OUT_BYTES_LEN                   0x0800 // 8
#define NF9_OUT_PKTS_LEN                    0x0800 // 8
#define NF9_MIN_PKT_LNGTH_LEN               0x0200 // 2
#define NF9_MAX_PKT_LNGTH_LEN               0x0200 // 2
#define NF9_IPV6_SRC_ADDR_LEN               0x1000 // 16
#define NF9_IPV6_DST_ADDR_LEN               0x1000 // 16
#define NF9_IPV6_SRC_MASK_LEN               0x0100 // 1
#define NF9_IPV6_DST_MASK_LEN               0x0100 // 1
#define NF9_IPV6_FLOW_LABEL_LEN             0x0300 // 3
#define NF9_ICMP_TYPE_LEN                   0x0200 // 2
#define NF9_MUL_IGMP_TYPE_LEN               0x0100 // 1
#define NF9_SAMPLING_INTERVAL_LEN           0x0400 // 4
#define NF9_SAMPLING_ALGORITHM_LEN          0x0100 // 1
#define NF9_FLOW_ACTIVE_TIMEOUT_LEN         0x0200 // 2
#define NF9_FLOW_INACTIVE_TIMEOUT_LEN       0x0200 // 2
#define NF9_ENGINE_TYPE_LEN                 0x0100 // 1
#define NF9_ENGINE_ID_LEN                   0x0100 // 1
#define NF9_TOTAL_BYTES_EXP_LEN             0x0400 // 4
#define NF9_TOTAL_PKTS_EXP_LEN              0x0400 // 4
#define NF9_TOTAL_FLOWS_EXP_LEN             0x0400 // 4
#define NF9_IPV4_SRC_PREFIX_LEN             0x0400 // 4
#define NF9_IPV4_DST_PREFIX_LEN             0x0400 // 4
#define NF9_MPLS_TOP_LABEL_TYPE_LEN         0x0100 // 1
#define NF9_MPLS_TOP_LABEL_IP_ADDR_LEN      0x0400 // 4
#define NF9_FLOW_SAMPLER_ID_LEN             0x0100 // 1
#define NF9_FLOW_SAMPLER_MODE_LEN           0x0100 // 1
#define NF9_FLOW_SAMPLER_RANDOM_INTRVL_LEN  0x0400 // 4
#define NF9_MIN_TTL_LEN                     0x0100 // 1
#define NF9_MAX_TTL_LEN                     0x0100 // 1
#define NF9_IPV4_IDENT_LEN                  0x0200 // 2
#define NF9_DST_TOS_LEN                     0x0100 // 1
#define NF9_IN_SRC_MAC_LEN                  0x0600 // 6
#define NF9_OUT_DST_MAC_LEN                 0x0600 // 6
#define NF9_SRC_VLAN_LEN                    0x0200 // 2
#define NF9_DST_VLAN_LEN                    0x0200 // 2
#define NF9_IP_VER_LEN                       0x0100 // 1
#define NF9_DIRECTION_LEN                   0x0100 // 1
#define NF9_IPV6_NEXT_HOP_LEN               0x1000 // 16
#define NF9_BPG_IPV6_NEXT_HOP_LEN           0x1000 // 16
#define NF9_IPV6_OPTION_HEADERS_LEN         0x0400 // 4
#define NF9_MPLS_LABEL_1_LEN                0x0300 // 3
#define NF9_MPLS_LABEL_2_LEN                0x0300 // 3
#define NF9_MPLS_LABEL_3_LEN                0x0300 // 3
#define NF9_MPLS_LABEL_4_LEN                0x0300 // 3
#define NF9_MPLS_LABEL_5_LEN                0x0300 // 3
#define NF9_MPLS_LABEL_6_LEN                0x0300 // 3
#define NF9_MPLS_LABEL_7_LEN                0x0300 // 3
#define NF9_MPLS_LABEL_8_LEN                0x0300 // 3
#define NF9_MPLS_LABEL_9_LEN                0x0300 // 3
#define NF9_MPLS_LABEL_10_LEN               0x0300 // 3
#define NF9_IN_DST_MAC_LEN                  0x0600 // 6
#define NF9_OUT_SRC_MAC_LEN                 0x0600 // 6
#define NF9_IF_NAME_LEN                     0x0000 // N
#define NF9_IF_DESC_LEN                     0x0000 // N
#define NF9_SAMPLER_NAME_LEN                0x0000 // N
#define NF9_IN_PERMANENT_BYTES_LEN          0x0400 // 4
#define NF9_IN_PERMANENT_PKTS_LEN           0x0400 // 4
#define NF9_FRAGMENT_OFFSET_LEN             0x0200 // 2
#define NF9_FORWARDING_STATUS_LEN           0x0100 // 1
#define NF9_MPLS_PAL_RD_LEN                 0x0800 // 8
#define NF9_MPLS_PREFIX_LEN_LEN             0x0100 // 1
#define NF9_SRC_TRAFFIC_INDEX_LEN           0x0400 // 4
#define NF9_DST_TRAFFIC_INDEX_LEN           0x0400 // 4
#define NF9_APPLICATION_DESCRIPTION_LEN     0x0000 // N
#define NF9_APPLICATION_TAG_LEN             0x0100 // 1+N
#define NF9_APPLICATION_NAME_LEN            0x0000 // N
#define NF9_postipDiffServCodePoint_LEN     0x0100 // 1
#define NF9_replicationfactor_LEN           0x0400 // 4

#define FLSID   0x0000 // flowset ID 0
#define TPLIDT4 0x0001 // template IPv4
#define TPLIDT6 0x0101 // template IPv6

#define NFDPAD4 ((4-sizeof(nf9Data4_t)%4)%4)
#define NFDPAD6 ((4-sizeof(nf9Data6_t)%4)%4)

#define INV9T4LEN htons(sizeof(nv9Tv4)+8)
#define INV9T6LEN htons(sizeof(nv9Tv6)+8)

#define MAXFB4CNT (int)((0xffff-sizeof(netv9Hdr_t)-4-NFDPAD4)/sizeof(nf9Data4_t) - 1)
#define MAXFB6CNT (int)((0xffff-sizeof(netv9Hdr_t)-4-NFDPAD6)/sizeof(nf9Data6_t) - 1)

#define NFB4CNTC (int)MIN(NF_NUM4FLWS, MAXFB4CNT)
#define NFB6CNTC (int)MIN(NF_NUM6FLWS, MAXFB6CNT)

#define MSG4LEN (sizeof(nf9Data4_t)*NFB4CNTC+4+NFDPAD4)
#define MSG6LEN (sizeof(nf9Data6_t)*NFB6CNTC+4+NFDPAD6)

// netflow V9 structures

const uint16_t nv9Tv4[] = {
	NF9_FIRST_SWITCHED, NF9_FIRST_SWITCHED_LEN,
	NF9_LAST_SWITCHED , NF9_LAST_SWITCHED_LEN,
	NF9_IN_PKTS, NF9_IN_PKTS_LEN,
	NF9_IN_BYTES, NF9_IN_BYTES_LEN,
	NF9_IPV4_SRC_ADDR, NF9_IPV4_SRC_ADDR_LEN,
	NF9_IPV4_DST_ADDR, NF9_IPV4_DST_ADDR_LEN,
	NF9_L4_SRC_PORT, NF9_L4_SRC_PORT_LEN,
	NF9_L4_DST_PORT, NF9_L4_DST_PORT_LEN,
	NF9_MIN_PKT_LNGTH, NF9_MIN_PKT_LNGTH_LEN,
	NF9_MAX_PKT_LNGTH, NF9_MAX_PKT_LNGTH_LEN,
	NF9_SRC_VLAN, NF9_SRC_VLAN_LEN,
	NF9_TCP_FLAGS, NF9_TCP_FLAGS_LEN,
	NF9_IP_VER, NF9_IP_VER_LEN,
	NF9_DIRECTION, NF9_DIRECTION_LEN,
	NF9_PROTOCOL, NF9_PROTOCOL_LEN,
	NF9_SRC_TOS, NF9_SRC_TOS_LEN,
	NF9_MIN_TTL, NF9_MIN_TTL_LEN,
	NF9_MAX_TTL, NF9_MAX_TTL_LEN,
	NF9_ENGINE_ID, NF9_ENGINE_ID_LEN,
	NF9_IN_DST_MAC, NF9_IN_DST_MAC_LEN,
	NF9_IN_SRC_MAC, NF9_IN_SRC_MAC_LEN,
#if ETH_ACTIVATE < 2
	NF9_OUT_DST_MAC, NF9_OUT_DST_MAC_LEN,
	NF9_OUT_SRC_MAC, NF9_OUT_SRC_MAC_LEN,
#endif
#if (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)
	NF9_MPLS_LABEL_1, NF9_MPLS_LABEL_1_LEN,
#endif
};

const uint16_t nv9Tv6[] = { NF9_FIRST_SWITCHED, NF9_FIRST_SWITCHED_LEN,
	NF9_LAST_SWITCHED , NF9_LAST_SWITCHED_LEN,
	NF9_IN_PKTS, NF9_IN_PKTS_LEN,
	NF9_IN_BYTES, NF9_IN_BYTES_LEN,
	NF9_IPV6_SRC_ADDR, NF9_IPV6_SRC_ADDR_LEN,
	NF9_IPV6_DST_ADDR, NF9_IPV6_DST_ADDR_LEN,
	NF9_L4_SRC_PORT, NF9_L4_SRC_PORT_LEN,
	NF9_L4_DST_PORT, NF9_L4_DST_PORT_LEN,
	NF9_MIN_PKT_LNGTH, NF9_MIN_PKT_LNGTH_LEN,
	NF9_MAX_PKT_LNGTH, NF9_MAX_PKT_LNGTH_LEN,
	NF9_SRC_VLAN, NF9_SRC_VLAN_LEN,
	NF9_TCP_FLAGS, NF9_TCP_FLAGS_LEN,
	NF9_IP_VER, NF9_IP_VER_LEN,
	NF9_DIRECTION, NF9_DIRECTION_LEN,
	NF9_PROTOCOL, NF9_PROTOCOL_LEN,
	NF9_SRC_TOS, NF9_SRC_TOS_LEN,
	NF9_MIN_TTL, NF9_MIN_TTL_LEN,
	NF9_MAX_TTL, NF9_MAX_TTL_LEN,
	NF9_ENGINE_ID, NF9_ENGINE_ID_LEN,
	NF9_IN_DST_MAC, NF9_IN_DST_MAC_LEN,
	NF9_IN_SRC_MAC, NF9_IN_SRC_MAC_LEN,
#if ETH_ACTIVATE < 2
	NF9_OUT_DST_MAC, NF9_OUT_DST_MAC_LEN,
	NF9_OUT_SRC_MAC, NF9_OUT_SRC_MAC_LEN,
#endif
#if (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)
	NF9_MPLS_LABEL_1, NF9_MPLS_LABEL_1_LEN,
#endif
};

typedef struct netv9Hdr_s {
	uint16_t version;
	uint16_t count;
	uint32_t upTime;
	uint32_t unixSec;
	uint32_t ipseq;
	uint32_t srcID;
} __attribute__((packed)) netv9Hdr_t;

typedef struct nv9T_s {
	uint16_t setID4;
	uint16_t len4;
	uint16_t tmpltID4;
	uint16_t fieldCnt4;
	uint16_t nTDef4[sizeof(nv9Tv4)/2];
	uint16_t setID6;
	uint16_t len6;
	uint16_t tmpltID6;
	uint16_t fieldCnt6;
	uint16_t nTDef6[sizeof(nv9Tv6)/2];
} __attribute__((packed)) nv9T_t;

typedef struct nf9Data4_s { // data set
	uint32_t flowSSec;      // 1
	uint32_t flowESec;
	uint64_t pktCnt;
	uint64_t byteCnt;
	uint32_t srcIPv4;
	uint32_t dstIPv4;
	uint16_t srcPort;
	uint16_t dstPort;
	uint16_t minL3Len;
	uint16_t maxL3Len;
	uint16_t srcVlanId;
	uint8_t tcpFlags;
	uint8_t ipVer;
	uint8_t dir;
	uint8_t l4Proto;
	uint8_t ipToS;
	uint8_t minTTL;
	uint8_t maxTTL;         // 18
	uint8_t engID;          // 19
	uint8_t dsInMac[12];    // 20
#if ETH_ACTIVATE < 2
	uint8_t dsOutMac[12];   // 22
#endif
#if (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)
	char nfMpls[BFO_MAX_MPLS*3];
#endif
} __attribute__((packed)) nf9Data4_t;

typedef struct nf9Data6_s { // data set
	uint32_t flowSSec;      // 1
	uint32_t flowESec;
	uint64_t pktCnt;
	uint64_t byteCnt;
	ipAddr_t srcIP;
	ipAddr_t dstIP;
	uint16_t srcPort;
	uint16_t dstPort;
	uint16_t minL3Len;
	uint16_t maxL3Len;
	uint16_t srcVlanId;
	uint8_t tcpFlags;
	uint8_t ipVer;
	uint8_t dir;
	uint8_t l4Proto;
	uint8_t ipToS;
	uint8_t minTTL;
	uint8_t maxTTL;         // 18
	uint8_t engID;          // 19
	uint8_t dsInMac[12];    // 20
#if ETH_ACTIVATE < 2
	uint8_t dsOutMac[12];   // 22
#endif
#if (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)
	char nfMpls[BFO_MAX_MPLS*3];
#endif
} __attribute__((packed)) nf9Data6_t;

// Buffered structs
typedef struct {
	netv9Hdr_t netv9H;
	nv9T_t nv9T;
} __attribute__((packed)) nfMsgT_t;

typedef struct {
	netv9Hdr_t netv9H;
	uint16_t flwSet;
	uint16_t len;
	nf9Data4_t nfD4[NFB4CNTC];
	char pad[NFDPAD4];
} __attribute__((packed)) nfMsg4_t;

typedef struct {
	netv9Hdr_t netv9H;
	uint16_t flwSet;
	uint16_t len;
	nf9Data6_t nfD6[NFB6CNTC];
	char pad[NFDPAD6];
} __attribute__((packed)) nfMsg6_t;

typedef union {
	char nfBuff[sizeof(nfMsgT_t)];
	nfMsgT_t nfMsgT;
} __attribute__((packed)) nfBfT_t;

typedef union {
	char nfBuff[sizeof(nfMsg4_t)];
	nfMsg4_t nfMsg4;
} __attribute__((packed)) nfBf4_t;

typedef union {
	char nfBuff[sizeof(nfMsg6_t)];
	nfMsg6_t nfMsg6;
} __attribute__((packed)) nfBf6_t;

#endif // NETFLOW_NV9_H_
