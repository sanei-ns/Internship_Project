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

#include "basicFlow.h"
#include "t2utils.h"
#include "proto/vlan.h"


#if BFO_SUBNETHL_INCLUDED == 1
void *bfo_subnet_tableP[2];
subnettable4_t *bfo_subnet_table4P;
subnettable6_t *bfo_subnet_table6P;
#endif

bfoFlow_t *bfoFlow;


static inline void claimInfo(packet_t *packet, unsigned long flowIndex);
#if BFO_SUBNETHL_INCLUDED == 1
static inline void bfo_add_ip_geo_info(outputBuffer_t *buf, uint_fast8_t ipver, uint32_t subnetNr);
#if BFO_SUBNET_TEST_GRE    == 1 || \
    BFO_SUBNET_TEST_L2TP   == 1 || \
    BFO_SUBNET_TEST_TEREDO == 1
static inline void bfo_test_and_add_ip_geo_info(outputBuffer_t *buf, ipAddr_t ip, uint_fast8_t ipver);
static inline void bfo_test_and_add_ipv4_geo_info(outputBuffer_t *buf, uint32_t ipv4);
#endif
#if BFO_SUBNET_TEST_TEREDO == 1
static inline void bfo_add_empty_geo_info(outputBuffer_t *buf);
#endif
#endif // BFO_SUBNETHL_INCLUDED == 1


// Tranalyzer Plugin Functions

T2_PLUGIN_INIT("basicFlow", "0.8.4", 0, 8);


void initialize() {
	if (UNLIKELY(!(bfoFlow = calloc(mainHashMap->hashChainTableSize, sizeof(bfoFlow_t))))) {
		T2_PERR("basicFlow", "failed to allocate memory for bfoFlow");
		exit(-1);
	}

#if BFO_SUBNETHL_INCLUDED == 1
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
	if (UNLIKELY(!(bfo_subnet_table4P = subnet_init4(pluginFolder, SUBNETFILE4)))) {
		exit(1);
	}
	bfo_subnet_tableP[0] = bfo_subnet_table4P;
#endif
#if IPV6_ACTIVATE > 0
	if (UNLIKELY(!(bfo_subnet_table6P = subnet_init6(pluginFolder, SUBNETFILE6)))) {
		exit(1);
	}
	bfo_subnet_tableP[1] = bfo_subnet_table6P;
#endif
#endif // BFO_SUBNETHL_INCLUDED == 1

	if (sPktFile) {
		fputs("flowInd\tflowStat\t"
#if RELTIME == 1
			"relTime\t"
#else // RELTIME == 0
			"time\t"
#endif // RELTIME
			"pktIAT\tflowDuration\t"
#if T2_PRI_HDRDESC == 1
			"numHdrs\thdrDesc\t"
#endif
			"ethVlanID\tsrcMac\tdstMac\tethType\tsrcIP\t"
#if BFO_SUBNET_TEST == 1
			"srcIPCC\tsrcIPWho\t"
#endif
			"srcPort\tdstIP\t"
#if BFO_SUBNET_TEST == 1
			"dstIPCC\tdstIPWho\t"
#endif
			"dstPort\tl4Proto\t", sPktFile);
	}
}


binary_value_t* printHeader() {
	binary_value_t *bv = NULL;

	bv = bv_append_bv(bv, bv_new_bv("Flow index", "flowInd", 0, 1, bt_uint_64));

#if BFO_SENSORID == 1
	bv = bv_append_bv(bv, bv_new_bv("Sensor ID", "sensorID", 0, 1, bt_uint_32));
#endif

	bv = bv_append_bv(bv, bv_new_bv("Flow status and warnings", "flowStat", 0, 1, bt_hex_64));

	bv = bv_append_bv(bv, bv_new_bv("Date time of first packet", "timeFirst", 0, 1, bt_timestamp));
	bv = bv_append_bv(bv, bv_new_bv("Date time of last packet", "timeLast", 0, 1, bt_timestamp));

	bv = bv_append_bv(bv, bv_new_bv("Flow duration", "duration", 0, 1, bt_duration));

#if (T2_PRI_HDRDESC == 1 && BFO_MAX_HDRDESC > 0)
	bv = bv_append_bv(bv, bv_new_bv("Number of different headers descriptions", "numHdrDesc", 0, 1, bt_uint_8));
	bv = bv_append_bv(bv, bv_new_bv("Number of headers (depth) in hdrDesc", "numHdrs", 1, 1, bt_uint_16));
#if BFO_HDRDESC_PKTCNT == 1
	bv = bv_append_bv(bv, bv_new_bv("Headers description and packet count", "hdrDesc_PktCnt", 1, 2, bt_string_class, bt_uint_64));
#else // BFO_HDRDESC_PKTCNT == 0
	bv = bv_append_bv(bv, bv_new_bv("Headers description", "hdrDesc", 1, 1, bt_string_class));
#endif // BFO_HDRDESC_PKTCNT == 0
#endif // (T2_PRI_HDRDESC == 1 && BFO_MAX_HDRDESC > 0)

#if (BFO_MAC == 1 && BFO_MAX_MAC > 0)
	bv = bv_append_bv(bv, bv_new_bv("Mac source", "srcMac", 1, 1, bt_mac_addr));
	bv = bv_append_bv(bv, bv_new_bv("Mac destination", "dstMac", 1, 1, bt_mac_addr));
#endif

#if ((ETH_ACTIVATE > 0 || IPV6_ACTIVATE == 2) && BFO_ETHERTYPE == 1)
	bv = bv_append_bv(bv, bv_new_bv("Ethernet type", "ethType", 0, 1, bt_hex_16));
#endif

#if (BFO_VLAN > 0 && BFO_MAX_VLAN > 0)
#if BFO_VLAN == 2
	bv = bv_append_bv(bv, bv_new_bv("VLAN headers (hex)", "ethVlanHdr", 1, 1, bt_hex_32));
#else // BFO_VLAN == 1
	bv = bv_append_bv(bv, bv_new_bv("VLAN IDs", "ethVlanID", 1, 1, bt_uint_16));
#endif // BFO_VLAN == 1
#endif // (BFO_VLAN > 0 && BFO_MAX_VLAN > 0)

#if (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)
#if BFO_MPLS == 3
	bv = bv_append_bv(bv, bv_new_bv("MPLS tags detail", "mplsLabel_ToS_S_TTL", 1, 4, bt_uint_32, bt_uint_8, bt_uint_8, bt_uint_8));
#elif BFO_MPLS == 2
	bv = bv_append_bv(bv, bv_new_bv("MPLS tags (hex)", "mplsTagsHex", 1, 1, bt_hex_32));
#else // BFO_MPLS == 1
	bv = bv_append_bv(bv, bv_new_bv("MPLS labels", "mplsLabels", 1, 1, bt_uint_32));
#endif // BFO_MPLS == 1
#endif // (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)

#if BFO_PPP == 1
	bv = bv_append_bv(bv, bv_new_bv("PPP header", "pppHdr", 0, 1, bt_hex_32));
#endif

#if BFO_L2TP == 1
	bv = bv_append_bv(bv, bv_new_bv("L2TP header", "l2tpHdr", 0, 1, bt_hex_16));
	bv = bv_append_bv(bv, bv_new_bv("L2TPv2 tunnel ID", "l2tpTID", 0, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("L2TPv2 session ID", "l2tpSID", 0, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("L2TPv3 control connection/session ID", "l2tpCCSID", 0, 1, bt_uint_32));

#if (AGGREGATIONFLAG & SUBNET) == 0
	bv = bv_append_bv(bv, bv_new_bv("L2TP source IP address", "l2tpSrcIP", 0, 1, bt_ip4_addr));
#endif

#if BFO_SUBNET_TEST_L2TP == 1
#if BFO_SUBNET_ASN == 1
	bv = bv_append_bv(bv, bv_new_bv("L2TP source ASN", "l2tpSrcIPASN", 0, 1, bt_uint_32));
#endif
	bv = bv_append_bv(bv, bv_new_bv("L2TP source IP country code", "l2tpSrcIPCC", 0, 1, BFO_NET_TYPE));
#if BFO_SUBNET_HEX == 0
	bv = bv_append_bv(bv, bv_new_bv("L2TP source IP who", "l2tpSrcIPWho", 0, 1, bt_string));
#endif
#if BFO_SUBNET_LL == 1
	bv = bv_append_bv(bv, bv_new_bv("L2TP source IP latitude, longitude, reliability", "l2tpSrcIPLat_Lng_relP", 0, 3, bt_float, bt_float, bt_float));
#endif
#endif // BFO_SUBNET_TEST_L2TP == 1

#if (AGGREGATIONFLAG & SUBNET) == 0
	bv = bv_append_bv(bv, bv_new_bv("L2TP destination IP address", "l2tpDstIP", 0, 1, bt_ip4_addr));
#endif

#if BFO_SUBNET_TEST_L2TP == 1
#if BFO_SUBNET_ASN == 1
	bv = bv_append_bv(bv, bv_new_bv("L2TP destination ASN", "l2tpDstIPASN", 0, 1, bt_uint_32));
#endif
	bv = bv_append_bv(bv, bv_new_bv("L2TP destination IP country code", "l2tpDstIPCC", 0, 1, BFO_NET_TYPE));
#if BFO_SUBNET_HEX == 0
	bv = bv_append_bv(bv, bv_new_bv("L2TP destination IP who", "l2tpDstIPWho", 0, 1, bt_string));
#endif
#if BFO_SUBNET_LL == 1
	bv = bv_append_bv(bv, bv_new_bv("L2TP destination IP latitude, longitude, reliability", "l2tpDstIPLat_Lng_relP", 0, 3, bt_float, bt_float, bt_float));
#endif
#endif // BFO_SUBNET_TEST_L2TP == 1

#endif // BFO_L2TP == 1

#if BFO_GRE == 1
	bv = bv_append_bv(bv, bv_new_bv("GRE header", "greHdr", 0, 1, bt_hex_32));

#if (AGGREGATIONFLAG & SUBNET) == 0
	bv = bv_append_bv(bv, bv_new_bv("GRE source IP address", "greSrcIP", 0, 1, bt_ip4_addr));
#endif

#if BFO_SUBNET_TEST_GRE == 1
#if BFO_SUBNET_ASN == 1
	bv = bv_append_bv(bv, bv_new_bv("GRE source ASN", "greSrcIPASN", 0, 1, bt_uint_32));
#endif
	bv = bv_append_bv(bv, bv_new_bv("GRE source IP country code", "greSrcIPCC", 0, 1, BFO_NET_TYPE));
#if BFO_SUBNET_HEX == 0
	bv = bv_append_bv(bv, bv_new_bv("GRE source IP who", "greSrcIPWho", 0, 1, bt_string));
#endif
#if BFO_SUBNET_LL == 1
	bv = bv_append_bv(bv, bv_new_bv("GRE source IP latitude, longitude, reliability", "greSrcIPLat_Lng_relP", 0, 3, bt_float, bt_float, bt_float));
#endif
#endif // BFO_SUBNET_TEST_GRE == 1

#if (AGGREGATIONFLAG & SUBNET) == 0
	bv = bv_append_bv(bv, bv_new_bv("GRE destination IP address", "greDstIP", 0, 1, bt_ip4_addr));
#endif

#if BFO_SUBNET_TEST_GRE == 1
#if BFO_SUBNET_ASN == 1
	bv = bv_append_bv(bv, bv_new_bv("GRE destination ASN", "greDstIPASN", 0, 1, bt_uint_32));
#endif
	bv = bv_append_bv(bv, bv_new_bv("GRE destination IP country code", "greDstIPCC", 0, 1, BFO_NET_TYPE));
#if BFO_SUBNET_HEX == 0
	bv = bv_append_bv(bv, bv_new_bv("GRE destination IP who", "greDstIPWho", 0, 1, bt_string));
#endif
#if BFO_SUBNET_LL == 1
	bv = bv_append_bv(bv, bv_new_bv("GRE destination IP latitude, longitude, reliability", "greDstIPLat_Lng_relP", 0, 3, bt_float, bt_float, bt_float));
#endif
#endif // BFO_SUBNET_TEST_GRE == 1

#endif // BFO_GRE == 1

#if BFO_TEREDO == 1
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv4 address", "trdoDstIP", 0, 1, bt_ip4_addr));
#if BFO_SUBNET_TEST_TEREDO == 1
#if BFO_SUBNET_ASN == 1
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv4 ASN", "trdoDstIPASN", 0, 1, bt_uint_32));
#endif
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv4 country code", "trdoDstIPCC", 0, 1, BFO_NET_TYPE));
#if BFO_SUBNET_HEX == 0
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv4 who", "trdoDstIPWho", 0, 1, bt_string));
#endif
#if BFO_SUBNET_LL == 1
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv4 latitude, longitude, reliability", "trdoDstIPLat_Lng_relP", 0, 3, bt_float, bt_float, bt_float));
#endif
#endif // BFO_SUBNET_TEST_TEREDO == 1
	bv = bv_append_bv(bv, bv_new_bv("Teredo destination port", "trdoDstPort", 0, 1, bt_uint_16));
#if IPV6_ACTIVATE > 0
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 source address decode: Flags", "trdo6SrcFlgs", 0, 1, bt_hex_8));
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 source address decode: Server IPv4", "trdo6SrcSrvIP4", 0, 1, bt_ip4_addr));
#if BFO_SUBNET_TEST_TEREDO == 1
#if BFO_SUBNET_ASN == 1
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 source address decode: Server IPv4 ASN", "trdo6SrcSrvIP4ASN", 0, 1, bt_uint_32));
#endif
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 source address decode: Server IPv4 country code", "trdo6SrcSrvIP4CC", 0, 1, BFO_NET_TYPE));
#if BFO_SUBNET_HEX == 0
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 source address decode: Server IPv4 who", "trdo6SrcSrvIP4Who", 0, 1, bt_string));
#endif
#if BFO_SUBNET_LL == 1
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 source address decode: Server IPv4 latitude, longitude, reliability", "trdo6SrcSrvIP4Lat_Lng_relP", 0, 3, bt_float, bt_float, bt_float));
#endif
#endif // BFO_SUBNET_TEST_TEREDO == 1
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 source address decode: Client public IPv4", "trdo6SrcCPIP4", 0, 1, bt_ip4_addr));
#if BFO_SUBNET_TEST_TEREDO == 1
#if BFO_SUBNET_ASN == 1
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 source address decode: Client public IPv4 ASN", "trdo6SrcCPIP4ASN", 0, 1, bt_uint_32));
#endif
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 source address decode: Client public IPv4 country code", "trdo6SrcCPIP4CC", 0, 1, BFO_NET_TYPE));
#if BFO_SUBNET_HEX == 0
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 source address decode: Client public IPv4 who", "trdo6SrcCPIP4Who", 0, 1, bt_string));
#endif
#if BFO_SUBNET_LL == 1
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 source address decode: Client public IPv4 latitude, longitude, reliability", "trdo6SrcCPIP4Lat_Lng_relP", 0, 3, bt_float, bt_float, bt_float));
#endif
#endif // BFO_SUBNET_TEST_TEREDO == 1
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 source address decode: Client public port", "trdo6SrcCPPort", 0, 1, bt_uint_16));

	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 destination address decode: Flags", "trdo6DstFlgs", 0, 1, bt_hex_8));
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 destination address decode: Server IPv4", "trdo6DstSrvIP4", 0, 1, bt_ip4_addr));
#if BFO_SUBNET_TEST_TEREDO == 1
#if BFO_SUBNET_ASN == 1
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 destination address decode: Server IPv4 ASN", "trdo6DstSrvIP4ASN", 0, 1, bt_uint_32));
#endif
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 destination address decode: Server IPv4 country code", "trdo6DstSrvIP4CC", 0, 1, BFO_NET_TYPE));
#if BFO_SUBNET_HEX == 0
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 destination address decode: Server IPv4 who", "trdo6DstSrvIP4Who", 0, 1, bt_string));
#endif
#if BFO_SUBNET_LL == 1
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 destination address decode: Server IPv4 latitude, longitude, reliability", "trdo6DstSrvIP4Lat_Lng_relP", 0, 3, bt_float, bt_float, bt_float));
#endif
#endif // BFO_SUBNET_TEST_TEREDO == 1
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 destination address decode: Client public IPv4", "trdo6DstCPIP4", 0, 1, bt_ip4_addr));
#if BFO_SUBNET_TEST_TEREDO == 1
#if BFO_SUBNET_ASN == 1
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 destination address decode: Client public IPv4 ASN", "trdo6DstCPIP4ASN", 0, 1, bt_uint_32));
#endif
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 destination address decode: Client public IPv4 country code", "trdo6DstCPIP4CC", 0, 1, BFO_NET_TYPE));
#if BFO_SUBNET_HEX == 0
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 destination address decode: Client public IPv4 who", "trdo6DstCPIP4Who", 0, 1, bt_string));
#endif
#if BFO_SUBNET_LL == 1
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 destination address decode: Client public IPv4 latitude, longitude, reliability", "trdo6DstCPIP4Lat_Lng_relP", 0, 3, bt_float, bt_float, bt_float));
#endif
#endif // BFO_SUBNET_TEST_TEREDO == 1
	bv = bv_append_bv(bv, bv_new_bv("Teredo IPv6 destination address decode: Client public port", "trdo6DstCPPort", 0, 1, bt_uint_16));
#endif // IPV6_ACTIVATE > 0
#endif // BFO_TEREDO == 1

#if (AGGREGATIONFLAG & SUBNET) == 0
	bv = bv_append_bv(bv, bv_new_bv("Source IP address", "srcIP", 0, 1, BFO_IP_TYPE));
#endif

#if BFO_SUBNET_TEST == 1
#if BFO_SUBNET_ASN == 1
	bv = bv_append_bv(bv, bv_new_bv("Source ASN", "srcIPASN", 0, 1, bt_uint_32));
#endif
	bv = bv_append_bv(bv, bv_new_bv("Source IP country code", "srcIPCC", 0, 1, BFO_NET_TYPE));
#if BFO_SUBNET_HEX == 0
	bv = bv_append_bv(bv, bv_new_bv("Source IP who", "srcIPWho", 0, 1, bt_string));
#endif
#if BFO_SUBNET_LL == 1
	bv = bv_append_bv(bv, bv_new_bv("Source IP latitude, longitude, reliability", "srcIPLat_Lng_relP", 0, 3, bt_float, bt_float, bt_float));
#endif
#endif // BFO_SUBNET_TEST == 1

	bv = bv_append_bv(bv, bv_new_bv("Source port", "srcPort", 0, 1, bt_uint_16));

#if (AGGREGATIONFLAG & SUBNET) == 0
	bv = bv_append_bv(bv, bv_new_bv("Destination IP address", "dstIP", 0, 1, BFO_IP_TYPE));
#endif

#if BFO_SUBNET_TEST == 1
#if BFO_SUBNET_ASN == 1
	bv = bv_append_bv(bv, bv_new_bv("Destination ASN", "dstIPASN", 0, 1, bt_uint_32));
#endif
	bv = bv_append_bv(bv, bv_new_bv("Destination IP country code", "dstIPCC", 0, 1, BFO_NET_TYPE));
#if BFO_SUBNET_HEX == 0
	bv = bv_append_bv(bv, bv_new_bv("Destination IP who", "dstIPWho", 0, 1, bt_string));
#endif
#if BFO_SUBNET_LL == 1
	bv = bv_append_bv(bv, bv_new_bv("Destination IP latitude, longitude, reliability", "dstIPLat_Lng_relP", 0, 3, bt_float, bt_float, bt_float));
#endif
#endif // BFO_SUBNET_TEST == 1

	bv = bv_append_bv(bv, bv_new_bv("Destination port", "dstPort", 0, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("Layer 4 protocol", "l4Proto", 0, 1, bt_uint_8));

	return bv;
}


void onFlowGenerated(packet_t* packet, unsigned long flowIndex) {

	bfoFlow_t * const bfoFlowP = &bfoFlow[flowIndex];
	memset(bfoFlowP, '\0', sizeof(bfoFlow_t));

	flow_t * const flowP = &flows[flowIndex];
	bfoFlowP->lastPktTime = flowP->lastSeen;

#if (BFO_VLAN > 0 && BFO_MAX_VLAN > 0)
	// TODO warn if bfoFlowP->vlans is not large enough to store all the vlans
	// alternatively output num_vlans
	if ((packet->status & L2_VLAN) && packet->vlans) {
		uint32_t * const vlans = bfoFlowP->vlans;
		uint32_t i = 0;
		uint16_t ethType;
		do {
			vlans[i] = ntohl(packet->vlans[i]);
			ethType = (vlans[i] & VLAN_ETYPE_MASK32);
			i++;
		} while (i < BFO_MAX_VLAN && (ethType == ETHERTYPE_VLAN || ethType == ETHERTYPE_QINQ));
		bfoFlowP->num_vlans = i;
	}
#endif

#if (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)
	// TODO warn if bfoFlowP->mplsh is not large enough to store all the tags
	// alternatively output num_mpls
	if (packet->status & L2_MPLS) {
		uint32_t * const mpls = (uint32_t*)bfoFlowP->mplsh;
		uint32_t i = 0;
		do {
			mpls[i] = ntohl(packet->mpls[i]);
			i++;
		} while (i < BFO_MAX_MPLS && !(packet->mpls[i-1] & BTM_MPLS_STKn32));
		bfoFlowP->num_mpls = i;
	}
#endif

#if BFO_PPP == 1
	if ((packet->status & L2_PPP) && packet->pppHdr) {
		bfoFlowP->pppHdr = (pppHu_t)ntohl(packet->pppHdr->pppHdrc);
	}
#endif

#if BFO_L2TP == 1
	if ((packet->status & L2_L2TP) && packet->l2tpLayer3Hdr) {
		bfoFlowP->l2tp_srcIP = packet->l2tpLayer3Hdr->ipHeader.ip_src;
		bfoFlowP->l2tp_dstIP = packet->l2tpLayer3Hdr->ipHeader.ip_dst;
		bfoFlowP->l2tpHdrBF = ntohs(*(uint16_t*)packet->l2TPHdr);
		const uint_fast8_t i = (bfoFlowP->l2tpHdrBF & L2TP_LEN) ? 1 : 0;
		const uint16_t * const l2tph = packet->l2TPHdr;
		if (packet->layer3Type == L2TP_V3) {
			bfoFlowP->l2tpv3HdrccID = ntohl(*(uint32_t*)(l2tph+i+2));
		} else {
			bfoFlowP->l2tpHdrTID = ntohs(*(l2tph+i+1));
			bfoFlowP->l2tpHdrSID = ntohs(*(l2tph+i+2));
		}
	}
#endif

#if BFO_GRE == 1
	if (packet->status & L2_GRE && packet->greLayer3Hdr) {
		bfoFlowP->greHdrBF = *(uint32_t*)packet->greHdr;
		bfoFlowP->gre_srcIP = packet->greLayer3Hdr->ipHeader.ip_src;
		bfoFlowP->gre_dstIP = packet->greLayer3Hdr->ipHeader.ip_dst;
	}
#endif

#if BFO_TEREDO == 1
	if (packet->status & L3_TRDO && packet->trdoOIHdr) {
		const uint8_t * const teredo = packet->trdoOIHdr;
		bfoFlowP->trdoPort = ntohs((*(uint16_t*)(teredo+2)) ^ 0xffff);
		bfoFlowP->trdoIP = (*(uint32_t*)(teredo+4)) ^ 0xffffffff;
	}
#endif

#if BFO_SUBNET_TEST == 1
	if (PACKET_IS_IPV6(packet)) {
#if IPV6_ACTIVATE > 0
		bfoFlowP->subNSrc = subnet_testHL6(bfo_subnet_table6P, flowP->srcIP); // subnet test source ip6
		bfoFlowP->subNDst = subnet_testHL6(bfo_subnet_table6P, flowP->dstIP); // subnet test dest ip6
#endif
	} else { // IPv4
		bfoFlowP->subNSrc = subnet_testHL4(bfo_subnet_table4P, flowP->srcIP.IPv4.s_addr); // subnet test source ip4
		bfoFlowP->subNDst = subnet_testHL4(bfo_subnet_table4P, flowP->dstIP.IPv4.s_addr); // subnet test dest ip4

		const uint32_t torAdd = (bfo_subnet_table4P->subnets[bfoFlowP->subNSrc].netID | bfo_subnet_table4P->subnets[bfoFlowP->subNDst].netID) & SUBTORADD;
		if (torAdd) {
			T2_SET_STATUS(flowP, TORADD);
		}
	}
#endif // BFO_SUBNET_TEST == 1
}


#if (T2_PRI_HDRDESC == 1 && BFO_MAX_HDRDESC > 0)
static inline void bfo_copy_hdrDesc(packet_t *packet, unsigned long flowIndex) {
	bfoFlow_t * const bfoFlowP = &bfoFlow[flowIndex];

	if (bfoFlowP->hDCnt >= BFO_MAX_HDRDESC) { // New header description
		flows[flowIndex].status |= HDOVRN;
		return;
	}

	//const char tmp = packet->hdrDesc[packet->lastParsedHdr];
	//packet->hdrDesc[packet->lastParsedHdr] = '\0';

	uint8_t i = 0;
	for (i = 0; i < bfoFlowP->hDCnt; i++) {
		if (strcmp(bfoFlowP->hdrDesc[i], packet->hdrDesc) == 0) {
			bfoFlowP->hdrCnt[i] = packet->numHdrDesc;
			bfoFlowP->pktCnt[i]++;
			//packet->hdrDesc[packet->lastParsedHdr] = tmp;
			return;
		}
	}

	if (i == bfoFlowP->hDCnt) {
		memcpy(bfoFlowP->hdrDesc[i], packet->hdrDesc, strlen(packet->hdrDesc));
		bfoFlowP->hdrCnt[i] = packet->numHdrDesc;
		bfoFlowP->pktCnt[i]++;
		bfoFlowP->hDCnt = ++i;
	}

	//packet->hdrDesc[packet->lastParsedHdr] = tmp;
}
#endif // (T2_PRI_HDRDESC == 1 && BFO_MAX_HDRDESC > 0)


#if ETH_ACTIVATE > 0
void claimLayer2Information(packet_t *packet, unsigned long flowIndex) {
	if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
	claimInfo(packet, flowIndex);
}
#endif


void claimLayer4Information(packet_t *packet, unsigned long flowIndex) {
	claimInfo(packet, flowIndex);
}


static inline void claimInfo(packet_t *packet, unsigned long flowIndex) {
#if (T2_PRI_HDRDESC == 1 && BFO_MAX_HDRDESC > 0)
	bfo_copy_hdrDesc(packet, flowIndex);
#endif

	flow_t * const flowP = &flows[flowIndex];
	bfoFlow_t * const bfoFlowP = &bfoFlow[flowIndex];

#if (BFO_MAC == 1 && BFO_MAX_MAC > 0)
	const ethernetHeader_t * const l2HdrP = (ethernetHeader_t*)packet->layer2Header;
	if (l2HdrP) {
		if (bfoFlowP->num_srcMac >= BFO_MAX_MAC) {
			// TODO warn if bfoFlowP->num_srcMac is not large enough to store all the addresses
			// alternatively output num_srcMac
		} else {
			uint_fast32_t i;
			const uint8_t *srcMac = &l2HdrP->ethDS.ether_shost[0];
			for (i = 0; i < bfoFlowP->num_srcMac; i++) {
				if (memcmp(bfoFlowP->srcMac[i], srcMac, ETH_ALEN) == 0) break;
			}
			if (i == bfoFlowP->num_srcMac) {
				memcpy(&bfoFlowP->srcMac[i][0], srcMac, ETH_ALEN);
				bfoFlowP->num_srcMac++;
			}
		}

		if (bfoFlowP->num_dstMac >= BFO_MAX_MAC) {
			// TODO warn if bfoFlowP->num_dstMac is not large enough to store all the addresses
			// alternatively output num_dstMac
		} else {
			uint_fast32_t i;
			const uint8_t *dstMac = &l2HdrP->ethDS.ether_dhost[0];
			for (i = 0; i < bfoFlowP->num_dstMac; i++) {
				if (memcmp(&bfoFlowP->dstMac[i][0], dstMac, ETH_ALEN) == 0) break;
			}
			if (i == bfoFlowP->num_dstMac) {
				memcpy(&bfoFlowP->dstMac[i][0], dstMac, ETH_ALEN);
				bfoFlowP->num_dstMac++;
			}
		}
	}
#endif // (BFO_MAC == 1 && BFO_MAX_MAC > 0)

	if (!sPktFile) return;

	const float flwDur = flowP->lastSeen.tv_sec - flowP->firstSeen.tv_sec + (flowP->lastSeen.tv_usec - flowP->firstSeen.tv_usec) / 1000000.0f;
	const float pktInterDis = flowP->lastSeen.tv_sec - bfoFlowP->lastPktTime.tv_sec + (flowP->lastSeen.tv_usec - bfoFlowP->lastPktTime.tv_usec) / 1000000.0f;
	if (pktInterDis < 0) {
		globalWarn |= TIMEJUMP;
		flowP->status |= TIMEJUMP;
	}

	bfoFlowP->lastPktTime = flowP->lastSeen;

#if RELTIME == 1
	struct timeval relTime;
	timersub(&flowP->lastSeen, &startTStamp, &relTime);
#endif

	fprintf(sPktFile, "%"PRIu64"\t0x%016"B2T_PRIX64"\t", flowP->findex, flowP->status);

#if B2T_TIMESTR == 1
	// Human readable date
	const struct tm *t;
#if TSTAMP_UTC == 1
	t = gmtime(&flows[flowIndex].lastSeen.tv_sec);
#else // TSTAMP_UTC == 0
	t = localtime(&flows[flowIndex].lastSeen.tv_sec);
#endif // TSTAMP_UTC == 0
	char timeBuf[20];
	strftime(timeBuf, sizeof(timeBuf), "%FT%T", t);
	char timeOff[6];
#if TSTAMP_UTC == 1 && defined(__APPLE__)
	memcpy(timeOff, "+0000", 5);
#else // TSTAMP_UTC == 0 || !defined(__APPLE__)
	strftime(timeOff, sizeof(timeOff), "%z", t);
#endif // TSTAMP_UTC == 0 || !defined(__APPLE__)
	fprintf(sPktFile, "%s.%06jd%s"
#else // B2T_TIMESTR == 0
	// Unix timestamp
	fprintf(sPktFile, "%ld.%06jd"
#endif // B2T_TIMESTR == 0
		"\t%f\t%f\t", // iat, flowDuration
#if B2T_TIMESTR == 1
		timeBuf, (intmax_t)flowP->lastSeen.tv_usec, timeOff,
#elif RELTIME == 1 // && B2T_TIMESTR == 0
		relTime.tv_sec, (intmax_t)relTime.tv_usec,
#else // RELTIME == 0 && B2T_TIMESTR == 0
		flowP->lastSeen.tv_sec, (intmax_t)flowP->lastSeen.tv_usec,
#endif // RELTIME == 0 && B2T_TIMESTR == 0
		pktInterDis, flwDur);

#if T2_PRI_HDRDESC == 1
	fprintf(sPktFile, "%"PRIu16"\t%s\t", packet->numHdrDesc, packet->hdrDesc);
#endif

	if (!(packet->status & L2_VLAN)) fputs("\t", sPktFile);
	else fprintf(sPktFile, "%"PRIu16"\t", packet->innerVLANID);

	char srcMac[32] = {}, dstMac[32] = {};
	if (packet->layer2Header) {
		const uint8_t * const l2Hdr = (uint8_t*)packet->layer2Header;
		t2_mac_to_str(&l2Hdr[6], srcMac, sizeof(srcMac));
		t2_mac_to_str(&l2Hdr[0], dstMac, sizeof(dstMac));
	}
	fprintf(sPktFile, "%s\t%s\t0x%04"B2T_PRIX16"\t", srcMac, dstMac, packet->layer2Type);

	if (!packet->layer3Header) {
#if BFO_SUBNET_TEST == 1
		fputs("\t\t\t\t\t\t\t\t\t", sPktFile);
#else // BFO_SUBNET_TEST == 0
		fputs("\t\t\t\t\t", sPktFile);
#endif // BFO_SUBNET_TEST == 0
	} else {
		const uint_fast8_t ipver = PACKET_IS_IPV6(flowP) ? 6 : 4;

		char srcIP[INET6_ADDRSTRLEN], dstIP[INET6_ADDRSTRLEN];
		T2_IP_TO_STR(flowP->srcIP, ipver, srcIP, INET6_ADDRSTRLEN);
		T2_IP_TO_STR(flowP->dstIP, ipver, dstIP, INET6_ADDRSTRLEN);

#if BFO_SUBNET_TEST == 1
		char *srcWho, *dstWho;
		SUBNET_WHO(srcWho, bfo_subnet_tableP, ipver, bfoFlowP->subNSrc);
		SUBNET_WHO(dstWho, bfo_subnet_tableP, ipver, bfoFlowP->subNDst);

		char *srcLoc, *dstLoc;
		SUBNET_LOC(srcLoc, bfo_subnet_tableP, ipver, bfoFlowP->subNSrc);
		SUBNET_LOC(dstLoc, bfo_subnet_tableP, ipver, bfoFlowP->subNDst);
#endif

		const uint_fast8_t proto = packet->layer4Type;
		if (proto != L3_TCP && proto != L3_UDP && proto != L3_UDPLITE && proto != L3_SCTP) {
#if BFO_SUBNET_TEST == 1
			fprintf(sPktFile, "%s\t%s\t%s\t\t%s\t%s\t%s\t\t%"PRIu8"\t",
					srcIP, srcLoc, srcWho, dstIP, dstLoc, dstWho, proto);
#else // BFO_SUBNET_TEST == 0
			fprintf(sPktFile, "%s\t\t%s\t\t%"PRIu8"\t", srcIP, dstIP, proto);
#endif // BFO_SUBNET_TEST == 0
		} else {
#if BFO_SUBNET_TEST == 1
			fprintf(sPktFile, "%s\t%s\t%s\t%"PRIu16"\t%s\t%s\t%s\t%"PRIu16"\t%"PRIu8"\t",
					srcIP, srcLoc, srcWho, flowP->srcPort,
					dstIP, dstLoc, dstWho, flowP->dstPort,
					proto);
#else // BFO_SUBNET_TEST == 0
			fprintf(sPktFile, "%s\t%"PRIu16"\t%s\t%"PRIu16"\t%"PRIu8"\t",
					srcIP, flowP->srcPort, dstIP, flowP->dstPort, proto);
#endif // BFO_SUBNET_TEST == 0
		}
	}
}


#if BLOCK_BUF == 0
void onFlowTerminate(unsigned long flowIndex) {
	const flow_t * const flowP = &flows[flowIndex];
	const bfoFlow_t * const bfoFlowP = &bfoFlow[flowIndex];

#if (BFO_TEREDO == 1 && IPV6_ACTIVATE > 0) || \
    (BFO_VLAN   == 1 && BFO_MAX_VLAN  > 0)
	uint16_t temp16;
#endif

	uint32_t temp32;
	uint_fast32_t i;

	outputBuffer_append(main_output_buffer, (char*)&flowP->findex, sizeof(uint64_t));

#if BFO_SENSORID == 1
	outputBuffer_append(main_output_buffer, (char*)&sensorID, sizeof(uint32_t));
#endif

	outputBuffer_append(main_output_buffer, (char*)&flowP->status, sizeof(uint64_t));

	uint64_t secs;
	struct timeval timeFirst, timeLast;

	// timeFirst
#if RELTIME == 1
	timersub(&flowP->firstSeen, &startTStamp, &timeFirst);
#else // RELTIME == 1
	timeFirst = flowP->firstSeen;
#endif // RELTIME == 1
	secs = timeFirst.tv_sec;
	temp32 = timeFirst.tv_usec * 1000;
	OUTBUF_APPEND_TIME(main_output_buffer, secs, temp32);

	// timeLast
#if RELTIME == 1
	timersub(&flowP->lastSeen, &startTStamp, &timeLast);
#else // RELTIME == 0
	timeLast = flowP->lastSeen;
#endif // RELTIME
	secs = timeLast.tv_sec;
	temp32 = timeLast.tv_usec * 1000;
	OUTBUF_APPEND_TIME(main_output_buffer, secs, temp32);

	// duration
	secs = flowP->duration.tv_sec;
	temp32 = flowP->duration.tv_usec * 1000;
	OUTBUF_APPEND_TIME(main_output_buffer, secs, temp32);

#if (T2_PRI_HDRDESC == 1 && BFO_MAX_HDRDESC > 0)

	//for (temp32 = 0; temp32 < BFO_MAX_HDRDESC; temp32++) {
	//	if (bfoFlowP->hdrDesc[temp32][0] == '\0') break;
	//}
	//for (i = 0; i < temp32; i++) {
	//	outputBuffer_append(main_output_buffer, (char*)&bfoFlowP->hdrCnt[i], sizeof(uint16_t));
	//}

	outputBuffer_append(main_output_buffer, (char*)&bfoFlowP->hDCnt, sizeof(uint8_t));

	temp32 = (uint32_t)bfoFlowP->hDCnt;
	outputBuffer_append(main_output_buffer, (char*)&temp32, sizeof(uint32_t));
	for (i = 0; i < temp32; i++) {
		outputBuffer_append(main_output_buffer, (char*)&bfoFlowP->hdrCnt[i], sizeof(uint16_t));
	}

	outputBuffer_append(main_output_buffer, (char*)&temp32, sizeof(uint32_t));
	for (i = 0; i < temp32; i++) {
		outputBuffer_append(main_output_buffer, bfoFlowP->hdrDesc[i], strlen(bfoFlowP->hdrDesc[i])+1);
#if BFO_HDRDESC_PKTCNT == 1
		outputBuffer_append(main_output_buffer, (char*)&bfoFlowP->pktCnt[i], sizeof(uint64_t));
#endif
	}
#endif // (T2_PRI_HDRDESC == 1 && BFO_MAX_HDRDESC > 0)

#if (BFO_MAC == 1 && BFO_MAX_MAC > 0)
	outputBuffer_append(main_output_buffer, (char*)&bfoFlowP->num_srcMac, sizeof(uint32_t));
	for (i = 0; i < bfoFlowP->num_srcMac; i++) {
		outputBuffer_append(main_output_buffer, (char*)bfoFlowP->srcMac[i], ETH_ALEN);
	}
	outputBuffer_append(main_output_buffer, (char*)&bfoFlowP->num_dstMac, sizeof(uint32_t));
	for (i = 0; i < bfoFlowP->num_dstMac; i++) {
		outputBuffer_append(main_output_buffer, (char*)bfoFlowP->dstMac[i], ETH_ALEN);
	}
#endif

#if ((ETH_ACTIVATE > 0 || IPV6_ACTIVATE == 2) && BFO_ETHERTYPE == 1)
	outputBuffer_append(main_output_buffer, (char*)&flowP->ethType, sizeof(uint16_t));
#endif

#if (BFO_VLAN > 0 && BFO_MAX_VLAN > 0)
	const uint32_t num_vlans = bfoFlowP->num_vlans;
	const uint32_t * const vlans = bfoFlowP->vlans;
	outputBuffer_append(main_output_buffer, (char*)&num_vlans, sizeof(uint32_t));
	for (i = 0; i < num_vlans; i++) {
#if BFO_VLAN == 2
		outputBuffer_append(main_output_buffer, (char*)&vlans[i], sizeof(uint32_t));
#else // BFO_VLAN == 1
		temp16 = ((vlans[i] & VLAN_ID_MASK32) >> 16);
		outputBuffer_append(main_output_buffer, (char*)&temp16, sizeof(uint16_t));
#endif // BFO_VLAN == 1
	}
#endif // (BFO_VLAN > 0 && BFO_MAX_VLAN > 0)

#if (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)
	const uint32_t num_mpls = bfoFlowP->num_mpls;
	const mplsh_t * const mpls = (mplsh_t*)bfoFlowP->mplsh;
	outputBuffer_append(main_output_buffer, (char*)&num_mpls, sizeof(uint32_t));
	for (i = 0; i < num_mpls; i++) {
#if BFO_MPLS == 1
		const uint32_t label = mpls[i].mplshs.label;
		outputBuffer_append(main_output_buffer, (char*)&label, sizeof(uint32_t));
#elif BFO_MPLS == 2
		outputBuffer_append(main_output_buffer, (char*)&mpls[i], sizeof(uint32_t));
#else // BFO_MPLS == 3
		const uint32_t label = mpls[i].mplshs.label;
		outputBuffer_append(main_output_buffer, (char*)&label, sizeof(uint32_t));
		uint8_t tmp8 = mpls[i].mplshs.Exp_ToS;
		outputBuffer_append(main_output_buffer, (char*)&tmp8, sizeof(uint8_t));
		tmp8 = mpls[i].mplshs.S;
		outputBuffer_append(main_output_buffer, (char*)&tmp8, sizeof(uint8_t));
		tmp8 = mpls[i].mplshs.TTL;
		outputBuffer_append(main_output_buffer, (char*)&tmp8, sizeof(uint8_t));
#endif // BFO_MPLS == 3
	}
#endif // (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)

#if BFO_PPP == 1
	outputBuffer_append(main_output_buffer, (char*)&bfoFlowP->pppHdr.pppHdrc, sizeof(uint32_t));
#endif

#if BFO_L2TP == 1
	outputBuffer_append(main_output_buffer, (char*)&bfoFlowP->l2tpHdrBF, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*)&bfoFlowP->l2tpHdrTID, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*)&bfoFlowP->l2tpHdrSID, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*)&bfoFlowP->l2tpv3HdrccID, sizeof(uint32_t));

#if (AGGREGATIONFLAG & SUBNET) == 0
	outputBuffer_append(main_output_buffer, (char*)&bfoFlowP->l2tp_srcIP.s_addr, sizeof(uint32_t));
#endif

#if BFO_SUBNET_TEST_L2TP == 1
	bfo_test_and_add_ipv4_geo_info(main_output_buffer, bfoFlowP->l2tp_srcIP.s_addr);
#endif

#if (AGGREGATIONFLAG & SUBNET) == 0
	outputBuffer_append(main_output_buffer, (char*)&bfoFlowP->l2tp_dstIP.s_addr, sizeof(uint32_t));
#endif

#if BFO_SUBNET_TEST_L2TP == 1
	bfo_test_and_add_ipv4_geo_info(main_output_buffer, bfoFlowP->l2tp_dstIP.s_addr);
#endif
#endif // BFO_L2TP == 1

#if BFO_GRE == 1
	temp32 = ntohl(bfoFlowP->greHdrBF);
	outputBuffer_append(main_output_buffer, (char*)&temp32, sizeof(uint32_t));

#if (AGGREGATIONFLAG & SUBNET) == 0
	outputBuffer_append(main_output_buffer, (char*)&bfoFlowP->gre_srcIP.s_addr, sizeof(uint32_t));
#endif

#if BFO_SUBNET_TEST_GRE == 1
	bfo_test_and_add_ipv4_geo_info(main_output_buffer, bfoFlowP->gre_srcIP.s_addr);
#endif

#if (AGGREGATIONFLAG & SUBNET) == 0
	outputBuffer_append(main_output_buffer, (char*)&bfoFlowP->gre_dstIP.s_addr, sizeof(uint32_t));
#endif

#if BFO_SUBNET_TEST_GRE == 1
	bfo_test_and_add_ipv4_geo_info(main_output_buffer, bfoFlowP->gre_dstIP.s_addr);
#endif
#endif // BFO_GRE == 1

#if BFO_TEREDO == 1
	outputBuffer_append(main_output_buffer, (char*)&bfoFlowP->trdoIP, sizeof(uint32_t));
#if BFO_SUBNET_TEST_TEREDO == 1
	bfo_test_and_add_ipv4_geo_info(main_output_buffer, bfoFlowP->trdoIP);
#endif
	outputBuffer_append(main_output_buffer, (char*)&bfoFlowP->trdoPort, sizeof(uint16_t));
#if IPV6_ACTIVATE > 0
	// Teredo IPv6 source and destination addresses
	const uint32_t * const sA[] = {
		(uint32_t*)flowP->srcIP.IPv4x,
		(uint32_t*)flowP->dstIP.IPv4x,
	};
	for (i = 0; i < 2; i++) {
		if (FLOW_IS_IPV6(flowP) && *sA[i] == 0x00000120) {
			const char ss = (char)(sA[i][2] & 0xc3000000);
			temp32 = sA[i][3] ^ 0xffffffff;
			temp16 = (htobe32(sA[i][2]) ^ 0xffff) & 0xffff;
			outputBuffer_append(main_output_buffer, (char*)&ss, sizeof(uint8_t)); // flags
			outputBuffer_append(main_output_buffer, (char*)&sA[i][1], sizeof(uint32_t)); // server IP
#if BFO_SUBNET_TEST_TEREDO == 1
			bfo_test_and_add_ipv4_geo_info(main_output_buffer, sA[i][1]);
#endif
			outputBuffer_append(main_output_buffer, (char*)&temp32, sizeof(uint32_t)); // client IP
#if BFO_SUBNET_TEST_TEREDO == 1
			bfo_test_and_add_ipv4_geo_info(main_output_buffer, temp32);
#endif
			outputBuffer_append(main_output_buffer, (char*)&temp16, sizeof(uint16_t)); // port
		} else {
			outputBuffer_append(main_output_buffer, (char*)&ZERO, sizeof(uint8_t));  // flags
			outputBuffer_append(main_output_buffer, (char*)&ZERO, sizeof(uint32_t)); // server IP
#if BFO_SUBNET_TEST_TEREDO == 1
			bfo_add_empty_geo_info(main_output_buffer);
#endif
			outputBuffer_append(main_output_buffer, (char*)&ZERO, sizeof(uint32_t)); // client IP
#if BFO_SUBNET_TEST_TEREDO == 1
			bfo_add_empty_geo_info(main_output_buffer);
#endif
			outputBuffer_append(main_output_buffer, (char*)&ZERO, sizeof(uint16_t)); // port
		}
	}
#endif // IPV6_ACTIVATE > 0
#endif // BFO_TEREDO == 1

#if ((AGGREGATIONFLAG & SUBNET) == 0 && IPV6_ACTIVATE == 2) || BFO_SUBNET_TEST == 1
	const uint_fast8_t ipver = FLOW_IS_IPV6(flowP) ? 6 : 4;
#endif

#if (AGGREGATIONFLAG & SUBNET) == 0
#if IPV6_ACTIVATE == 2
	OUTBUF_APPEND_IPVX(main_output_buffer, ipver, flowP->srcIP);
#elif IPV6_ACTIVATE == 1
	OUTBUF_APPEND_IP6(main_output_buffer, flowP->srcIP);
#else // IPV6_ACTIVATE == 0
	OUTBUF_APPEND_IP4(main_output_buffer, flowP->srcIP);
#endif // IPV6_ACTIVATE == 0
#endif // (AGGREGATIONFLAG & SUBNET) == 0

#if BFO_SUBNET_TEST == 1
	bfo_add_ip_geo_info(main_output_buffer, ipver, bfoFlowP->subNSrc);
#endif

	outputBuffer_append(main_output_buffer, (char*)&flowP->srcPort, sizeof(uint16_t));

#if (AGGREGATIONFLAG & SUBNET) == 0
#if IPV6_ACTIVATE == 2
	OUTBUF_APPEND_IPVX(main_output_buffer, ipver, flowP->dstIP);
#elif IPV6_ACTIVATE == 1
	OUTBUF_APPEND_IP6(main_output_buffer, flowP->dstIP);
#else // IPV6_ACTIVATE == 0
	OUTBUF_APPEND_IP4(main_output_buffer, flowP->dstIP);
#endif // IPV6_ACTIVATE == 0
#endif // (AGGREGATIONFLAG & SUBNET) == 0

#if BFO_SUBNET_TEST == 1
	bfo_add_ip_geo_info(main_output_buffer, ipver, bfoFlowP->subNDst);
#endif

	outputBuffer_append(main_output_buffer, (char*)&flowP->dstPort, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*)&flowP->layer4Protocol, sizeof(uint8_t));
}
#endif // BLOCK_BUF == 0


#if BFO_SUBNET_TEST_GRE    == 1 || \
    BFO_SUBNET_TEST_L2TP   == 1 || \
    BFO_SUBNET_TEST_TEREDO == 1
static inline void bfo_test_and_add_ipv4_geo_info(outputBuffer_t *buf, uint32_t ipv4) {
	ipAddr_t ip = { .IPv4x[0] = ipv4 };
	bfo_test_and_add_ip_geo_info(buf, ip, 4);
}
#endif


#if BFO_SUBNET_TEST_GRE    == 1 || \
    BFO_SUBNET_TEST_L2TP   == 1 || \
    BFO_SUBNET_TEST_TEREDO == 1
static inline void bfo_test_and_add_ip_geo_info(outputBuffer_t *buf, ipAddr_t ip, uint_fast8_t ipver) {
	uint_fast32_t subnetNr;
	SUBNET_TEST_IP(subnetNr, bfo_subnet_tableP, ip, ipver);
	bfo_add_ip_geo_info(buf, ipver, subnetNr);
}
#endif


#if BFO_SUBNETHL_INCLUDED == 1
static inline void bfo_add_ip_geo_info(outputBuffer_t *buf, uint_fast8_t ipver, uint32_t subnetNr) {

#if BFO_SUBNET_ASN == 1
	uint32_t asn;
	SUBNET_ASN(asn, bfo_subnet_tableP, ipver, subnetNr);
	outputBuffer_append(buf, (char*)&asn, sizeof(uint32_t));
#endif

#if BFO_SUBNET_HEX == 1
	uint32_t netID;
	SUBNET_HEX(netID, bfo_subnet_tableP, ipver, subnetNr);
	outputBuffer_append(buf, (char*)&netID, sizeof(uint32_t));
#else // BFO_SUBNET_HEX == 0
	char *loc, *who;
	SUBNET_LOC(loc, bfo_subnet_tableP, ipver, subnetNr);
	outputBuffer_append(buf, loc, strlen(loc)+1);
	SUBNET_WHO(who, bfo_subnet_tableP, ipver, subnetNr);
	outputBuffer_append(buf, who, strlen(who)+1);
#endif // BFO_SUBNET_HEX == 0

#if BFO_SUBNET_LL == 1
	float lat_lng_oP[3];
	SUBNET_LAT(lat_lng_oP[0], bfo_subnet_tableP, ipver, subnetNr);
	SUBNET_LNG(lat_lng_oP[1], bfo_subnet_tableP, ipver, subnetNr);
	SUBNET_PREC(lat_lng_oP[2], bfo_subnet_tableP, ipver, subnetNr);
	outputBuffer_append(buf, (char*)&lat_lng_oP, 3*sizeof(float));
#endif
}
#endif // BFO_SUBNETHL_INCLUDED == 1


#if BFO_SUBNET_TEST_TEREDO == 1
static inline void bfo_add_empty_geo_info(outputBuffer_t *buf) {
#if BFO_SUBNET_ASN == 1
	outputBuffer_append(buf, (char*)&ZERO sizeof(uint32_t)); // asn
#endif
#if BFO_SUBNET_HEX == 1
	outputBuffer_append(buf, (char*)&ZERO, sizeof(uint32_t)); // netID
#else // BFO_SUBNET_HEX == 0
	outputBuffer_append(buf, "", 1); // loc
	outputBuffer_append(buf, "", 1); // who
#endif // BFO_SUBNET_HEX == 0
#if BFO_SUBNET_LL == 1
	const float lat_lng_oP[3] = { 0.0f, 0.0f, 0.0f };
	outputBuffer_append(buf, (char*)&lat_lng_oP, 3*sizeof(float));
#endif
}
#endif // BFO_SUBNET_TEST_TEREDO == 1


void onApplicationTerminate() {
#if BFO_SUBNETHL_INCLUDED == 1
	subnettable4_destroy(bfo_subnet_table4P);
	subnettable6_destroy(bfo_subnet_table6P);
#endif

	free(bfoFlow);
}
