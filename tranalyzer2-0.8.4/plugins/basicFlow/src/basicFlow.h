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

#ifndef __BASIC_FLOW_H__
#define __BASIC_FLOW_H__

// external includes

// local includes
#include "global.h"

// User defined switches

#define BFO_SENSORID       0 // 1: sensorID on; 0: sensorID off

#define BFO_HDRDESC_PKTCNT 0 // 1: Enables / 0: Disables packet count for header description

#define BFO_MAC       1 // 1: Enables / 0: Disables MAC addresses output
#define BFO_ETHERTYPE 1 // 1: Enables / 0: Disables EtherType output (requires IPV6_ACTIVATE=2||ETH_ACTIVATE>0)

#define BFO_VLAN   1 // 0: Do not output VLAN information,
                     // 1: Output VLAN numbers,
                     // 2: Output VLAN headers as hex
                     // 3: Output decoded VLAN headers as TPID_PCP_DEI_VID (TODO)
#define BFO_MPLS   0 // 0: Do not output MPLS information,
                     // 1: Output MPLS labels,
                     // 2: Output MPLS headers as hex,
                     // 3: Output decoded MPLS headers as label_ToS_S_TTL
#define BFO_L2TP   0 // 1: Enables / 0: Disables L2TP header output
#define BFO_GRE    0 // 1: Enables / 0: Disables GRE header output
#define BFO_PPP    0 // 1: Enables / 0: Disables PPP header output
#define BFO_ETHIP  0 // 1: Enables / 0: Disables ETHIP header output
#define BFO_TEREDO 0 // 1: Enables / 0: disables Teredo IP, port output

#define BFO_SUBNET_TEST        1 // 1: Enables / 0: Disables subnet test

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
#define BFO_SUBNET_TEST_GRE    0 // 1: Enables / 0: Disables subnet test on GRE addresses
#define BFO_SUBNET_TEST_L2TP   0 // 1: Enables / 0: Disables subnet test on L2TP addresses
#endif

#define BFO_SUBNET_TEST_TEREDO 0 // 1: Enables / 0: Disables subnet test on Teredo addresses

#define BFO_SUBNET_ASN  0 // 1: ASN, 0: no ASN
#define BFO_SUBNET_LL   0 // 1: Longitude_latitude_reliability, 0: none
#define BFO_SUBNET_HEX  0 // Country code and who information representation:
                          //   0: Two columns (country code and who), human readable
                          //   1: One column, hex ID output

// Maximum number of values to store
#define BFO_MAX_HDRDESC 4 // Maximum number of headers descriptions to store
#define BFO_MAX_MAC     3 // Maximum different MAC addresses to output
#define BFO_MAX_MPLS    3 // Maximum MPLS headers/tags to output
#define BFO_MAX_VLAN    3 // Maximum VLAN headers/numbers to output

// Plugin definitons
#if (BFO_SUBNET_TEST     == 1 || BFO_SUBNET_TEST_L2TP   == 1 || \
     BFO_SUBNET_TEST_GRE == 1 || BFO_SUBNET_TEST_TEREDO == 1)
#define BFO_SUBNETHL_INCLUDED 1
#include "subnetHL4.h"
#include "subnetHL6.h"
#endif

#define BFO_READ_U48(p) (be64toh(*(uint64_t*)(p)) >> 16)

#if IPV6_ACTIVATE == 2
#define BFO_IP_TYPE bt_ipx_addr
#elif IPV6_ACTIVATE == 1
#define BFO_IP_TYPE bt_ip6_addr
#else // IPV6_ACTIVATE == 0
#define BFO_IP_TYPE bt_ip4_addr
#endif // IPV6_ACTIVATE == 0

#if BFO_SUBNET_HEX == 1
#define BFO_NET_TYPE bt_hex_32
#else // BFO_SUBNET_HEX == 0
#define BFO_NET_TYPE bt_string_class
#endif // BFO_SUBNET_HEX

#define SUBTORADD 0x00800000

// Macros to facilitate access to fields in subnets table

#define SUBNET_TEST_IP(dest, tables, ip, ipver) \
	if (ipver == 6) { \
		dest = subnet_testHL6((subnettable6_t*)(tables)[1], ip); \
	} else { \
		dest = subnet_testHL4((subnettable4_t*)(tables)[0], ip.IPv4.s_addr); \
	}

#define SUBNET_WRAPPER(dest, tables, ipver, num, field) \
	if (ipver == 6) { \
		dest = ((subnettable6_t*)(tables)[1])->subnets[num].field; \
	} else { \
		dest = ((subnettable4_t*)(tables)[0])->subnets[num].field; \
	}

#define SUBNET_ASN(dest, tables, ipver, num) SUBNET_WRAPPER(dest, tables, ipver, num, asn)
#define SUBNET_HEX(dest, tables, ipver, num) SUBNET_WRAPPER(dest, tables, ipver, num, netID)
#define SUBNET_LAT(dest, tables, ipver, num) SUBNET_WRAPPER(dest, tables, ipver, num, lat)
#define SUBNET_LNG(dest, tables, ipver, num) SUBNET_WRAPPER(dest, tables, ipver, num, lng)
#define SUBNET_LOC(dest, tables, ipver, num) SUBNET_WRAPPER(dest, tables, ipver, num, loc)
#define SUBNET_PREC(dest, tables, ipver, num) SUBNET_WRAPPER(dest, tables, ipver, num, oP)
#define SUBNET_WHO(dest, tables, ipver, num) SUBNET_WRAPPER(dest, tables, ipver, num, who)


// Plugin Flow structures

typedef struct {
#if (T2_PRI_HDRDESC == 1 && BFO_MAX_HDRDESC > 0)
	uint64_t pktCnt[BFO_MAX_HDRDESC];
#endif

	struct timeval lastPktTime;

#if (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)
	mplsh_t mplsh[BFO_MAX_MPLS];
	uint32_t num_mpls;
#endif

#if BFO_PPP == 1
	pppHu_t pppHdr;
#endif

#if BFO_GRE == 1
	struct in_addr gre_srcIP;
	struct in_addr gre_dstIP;
	uint32_t greHdrBF;
#endif

#if (BFO_MAC == 1 && BFO_MAX_MAC > 0)
	uint32_t num_srcMac;
	uint32_t num_dstMac;
	uint8_t srcMac[BFO_MAX_MAC][ETH_ALEN];
	uint8_t dstMac[BFO_MAX_MAC][ETH_ALEN];
#endif

#if (BFO_VLAN > 0 && BFO_MAX_VLAN > 0)
	uint32_t num_vlans;
	uint32_t vlans[BFO_MAX_VLAN];
#endif

#if BFO_SUBNET_TEST == 1
	uint32_t subNSrc;
	uint32_t subNDst;
#endif

#if BFO_TEREDO == 1
	uint32_t trdoIP;
	uint16_t trdoPort;
#endif

#if BFO_L2TP == 1
	struct in_addr l2tp_srcIP;
	struct in_addr l2tp_dstIP;
	uint16_t l2tpHdrBF;
	union {
		struct {
			uint16_t l2tpHdrTID;
			uint16_t l2tpHdrSID;
		};
		uint32_t l2tpv3HdrccID;
	};
#endif

#if (T2_PRI_HDRDESC == 1 && BFO_MAX_HDRDESC > 0)
	char hdrDesc[BFO_MAX_HDRDESC][T2_HDRDESC_LEN];
	uint16_t hdrCnt[BFO_MAX_HDRDESC];
	uint8_t hDCnt;
#endif

} bfoFlow_t;

// plugin struct pointer for potential dependencies
extern bfoFlow_t *bfoFlow;

#if BFO_SUBNETHL_INCLUDED == 1
extern void *bfo_subnet_tableP[2];
extern subnettable4_t *bfo_subnet_table4P;
extern subnettable6_t *bfo_subnet_table6P;
#endif

#endif // __BASIC_FLOW_H__
