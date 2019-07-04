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

#include "packetCapture.h"
#include "proto/t2_proto.h"
#include "hashTable.h"
#include "hdrDesc.h"
#include "main.h"


#define T2_CHECK_SNAP_L2(packet, l2size, action_if_fail) \
	if (UNLIKELY((packet)->snapL2Length < (uint32_t)(l2size))) { \
		(packet)->status |= L2SNAPLENGTH; \
		if (!(globalWarn & L2SNAPLENGTH)) { \
			globalWarn |= L2SNAPLENGTH; \
		} \
		action_if_fail; \
	}


// Static inline functions prototypes

#if ETH_ACTIVATE > 0
static inline unsigned long flowETHCreate(packet_t *packet, flow_t *hashHelper);
#endif
static inline unsigned long flowCreate(packet_t *packet, flow_t *hashHelper);

static inline void processPacket(const struct pcap_pkthdr *pcapHeader, const u_char *packet);
static inline void updateLRUList(flow_t *flow);
static inline void t2_dispatch_l2_packet(packet_t *packet);
static inline void t2_print_l7payload(FILE *stream, packet_t *packet);


// Variables

flow_t lruHead, lruTail;
#if FRAGMENTATION >= 1
unsigned long *fragPend;
#endif


// Static variables

#if MONINTTMPCP == 1
static float timeDiff0;
#endif


// callback function triggered every time we receive/read a new packet from the pcap descriptor
inline void perPacketCallback(u_char *inqueue __attribute__((unused)), const struct pcap_pkthdr *pcapHeader, const u_char *packet) {

	actTime = pcapHeader->ts;

	if (UNLIKELY(numPackets == 0)) {
		startTStamp = startTStamp0 = actTime;
#if VERBOSE > 0
		t2_log_date(dooF, "Dump start: ", startTStamp, TSTAMP_UTC);
#endif
	}

#if MONINTTMPCP == 1
	const float timeDiff = actTime.tv_sec - startTStamp.tv_sec;
	if (timeDiff - timeDiff0 >= MONINTV) {
		globalInt |= GI_RPRT;
		timeDiff0 = timeDiff;
	}
#endif

	cycleLRULists();
	processPacket(pcapHeader, packet);
}


// the function that starts the processing of a packet
static inline void processPacket(const struct pcap_pkthdr *pcapHeader, const u_char *packet) {

	const uint32_t len = pcapHeader->len;
	const uint32_t caplen = pcapHeader->caplen;

	numPackets++;
	rawBytesOnWire += pcapHeader->len;

	if (UNLIKELY(caplen == 0)) {
#if VERBOSE > 0
		T2_WRN("No data available for packet %"PRIu64, numPackets);
#endif
		return;
	}

	packet_t newPacket = {
		.raw_packet   = packet,
		.end_packet   = packet + caplen,
		.pcapHeader   = pcapHeader,
		.snapLength   = caplen,
		.snapL2Length = caplen,
		.rawLength    = len,
	};

	bytesProcessed += caplen;

#if ENABLE_IO_BUFFERING == 1
	if (gBufStat) {
		gBufStat = 0;
		newPacket.status = PCAPSNPD;
	}
#endif

	uint8_t *pktptr = (uint8_t*)packet;

#if NOLAYER2 == 1 // manual mode: set your own L3 pointer
	newPacket.layer2Header = (l2Header_t*)pktptr;
	pktptr += NOL2_L3HDROFFSET;
	T2_SET_STATUS(&newPacket, L2_NO_ETH);
	newPacket.layer3Header = (l3Header_t*)pktptr;
	const uint_fast8_t ipver = (*pktptr & 0xf0);
	if (ipver == 0x40) {
		dissembleIPv4Packet(&newPacket);
	} else if (ipver == 0x60) {
		dissembleIPv6Packet(&newPacket);
	} // TODO should we really count those bytes as processed?!?
	goto endpPkt;
#endif // NOLAYER2 == 1

	// Real traffic

	int linkType = pcap_datalink(captureDescriptor);

	// Per-Packet Information (PPI)
	if (linkType == DLT_PPI) {
		T2_PKTDESC_ADD_HDR(&newPacket, "ppi:");
		const ppi_hdr_t * const ppi = (ppi_hdr_t*)pktptr;
		T2_CHECK_SNAP_L2(&newPacket, ppi->len+1, goto endpPkt);
		pktptr += ppi->len; // skip PPI header
		newPacket.snapL2Length -= ppi->len;
		linkType = ppi->dlt;
	}

	_8021Q_t *shape = NULL;

	switch (linkType) {
		// IEEE 802.3 Ethernet
		case DLT_EN10MB: {
			T2_CHECK_SNAP_L2(&newPacket, sizeof(ethernetHeader_t), goto endpPkt);
			newPacket.layer2Header = (l2Header_t*)pktptr;
			const uint8_t * const dMac = newPacket.layer2Header->ethernetHeader.ethDS.ether_dhost;
			static const uint8_t isl1[5] = { 0x01, 0x00, 0x0c, 0x00, 0x00 };
			static const uint8_t isl2[5] = { 0x03, 0x00, 0x0c, 0x00, 0x00 };
			if (memcmp(dMac, isl1, 5) == 0 || memcmp(dMac, isl2, 5) == 0) {
				T2_PKTDESC_ADD_HDR(&newPacket, "isl:");
				// Jump over the ISL header
				T2_CHECK_SNAP_L2(&newPacket, sizeof(ethernetHeader_t)+ISL_HEADER_LEN, goto endpPkt);
				pktptr += ISL_HEADER_LEN;
				newPacket.layer2Header = (l2Header_t*)pktptr;
			}
			T2_PKTDESC_ADD_HDR(&newPacket, "eth");
			shape = (_8021Q_t*) (pktptr + 12); // advance 12 bytes to ether type
			break;
		}

		// BSD Loopback encapsulation
		case DLT_NULL: {
			T2_PKTDESC_ADD_HDR(&newPacket, "null");
			T2_CHECK_SNAP_L2(&newPacket, 4, goto endpPkt); // Family (Null/Loopback header)
			newPacket.layer2Header = (l2Header_t*)pktptr;
			newPacket.layer3Header = (l3Header_t*)(pktptr + 4);
			// Family encoding depends on the machine on which the traffic was captured...
			uint32_t family = *(uint32_t*)pktptr;
			if (family > 30) family = ntohl(family);
			T2_SET_STATUS(&newPacket, L2_NO_ETH);
			switch (family) {
				case PF_INET: // 2
					dissembleIPv4Packet(&newPacket);
					break;
				case 10: // Linux
				case 23: // WinSock
				case 24: // BSD
				case 26: // Solaris
				case 28: // FreeBSD
				case 30: // Darwin
					dissembleIPv6Packet(&newPacket);
					break;
				default:
					T2_WRN("Null/Loopback header: unhandled family %"PRIu32, newPacket.layer3Type);
					break;
			}
			goto endpPkt;
		}

		// Raw IP
		case DLT_RAW:
			T2_PKTDESC_ADD_HDR(&newPacket, "raw");
			newPacket.layer2Header = (l2Header_t*)pktptr;
			newPacket.layer3Header = (l3Header_t*)pktptr;
			T2_SET_STATUS(&newPacket, L2_NO_ETH);
			if ((*pktptr & 0xf0) == 0x40) {
				dissembleIPv4Packet(&newPacket);
			} else if ((*pktptr & 0xf0) == 0x60) {
				dissembleIPv6Packet(&newPacket);
			} else {
				T2_WRN("Unknown IP protocol %"PRIu8" in raw pcap", (uint8_t)((*pktptr & 0xf0) >> 4));
			}
			goto endpPkt;

		// Raw IPv4
		case DLT_IPV4:
			newPacket.layer2Header = (l2Header_t*)pktptr;
			newPacket.layer3Header = (l3Header_t*)pktptr;
			T2_SET_STATUS(&newPacket, L2_NO_ETH);
			dissembleIPv4Packet(&newPacket);
			goto endpPkt;

		// Raw IPv6
		case DLT_IPV6:
			newPacket.layer2Header = (l2Header_t*)pktptr;
			newPacket.layer3Header = (l3Header_t*)pktptr;
			T2_SET_STATUS(&newPacket, L2_NO_ETH);
			dissembleIPv6Packet(&newPacket);
			goto endpPkt;

		// Linux cooked capture
		case DLT_LINUX_SLL:
			T2_PKTDESC_ADD_HDR(&newPacket, "sll");
			T2_CHECK_SNAP_L2(&newPacket, sizeof(linux_cooked_t), goto endpPkt);
			newPacket.layer2Header = (l2Header_t*)pktptr;
			shape = (_8021Q_t*)(pktptr + 14); // advance to ether type
			break;

		// Point-to-Point Protocol
		case DLT_PPP_WITH_DIR: // PPP with direction
			pktptr++;
			/* FALLTHRU */
		case DLT_PPP_SERIAL:
		case DLT_PPP: {
			T2_PKTDESC_ADD_HDR(&newPacket, "ppp");
			newPacket.pppHdr = (pppHu_t*)pktptr;
			if (linkType != DLT_PPP_WITH_DIR) {
				newPacket.layer2Header = (l2Header_t*)pktptr;
			} else {
				newPacket.layer2Header = (l2Header_t*)(pktptr-1);
			}
			// FIXME PPP header may be one byte only...?!?
			T2_SET_STATUS(&newPacket, L2_NO_ETH);
			pppHdr_t *ppp = (pppHdr_t*)pktptr;
			if (ppp->addctl == 0x000f || ppp->addctl == 0x008f) { // Cisco HDLC
				T2_PKTDESC_ADD_HDR(&newPacket, ":chdlc");
				shape = (_8021Q_t*)(pktptr + 2);
			} else {
				switch (ppp->prot) {
					case PPP_IP4n:
						newPacket.layer3Header = (l3Header_t*)(pktptr+4);
						dissembleIPv4Packet(&newPacket);
						goto endpPkt;
					case PPP_IP6n:
						newPacket.layer3Header = (l3Header_t*)(pktptr+4);
						dissembleIPv6Packet(&newPacket);
						goto endpPkt;
					case PPP_MPLS_UCASTn:
						shape = (_8021Q_t*)(pktptr + 2);
						shape->identifier = ETHERTYPE_MPLS_UNICASTn;
						break;
					case PPP_MPLS_MCASTn:
						shape = (_8021Q_t*)(pktptr + 2);
						shape->identifier = ETHERTYPE_MPLS_MULTICASTn;
						break;
					default:
						// TODO
						T2_PKTDESC_ADD_PPPPROTO(&newPacket, ppp->prot);
						goto endpPkt;
				}
			}
			break;
		}

		// Cisco PPP with HDLC framing / Frame Relay
		case DLT_C_HDLC_WITH_DIR: // CISCO HDLC with direction
		case DLT_FRELAY_WITH_DIR: // Frame Relay with direction
			pktptr += 1; // direction
			/* FALLTHRU */
		case DLT_FRELAY: // Frame Relay
		case DLT_C_HDLC: // CISCO HDLC
			if (linkType == DLT_FRELAY_WITH_DIR || linkType == DLT_FRELAY) {
				T2_PKTDESC_ADD_HDR(&newPacket, "fr");
			} else if (linkType == DLT_C_HDLC_WITH_DIR || linkType == DLT_C_HDLC) {
				T2_PKTDESC_ADD_HDR(&newPacket, "chdlc");
			}
			if (linkType == DLT_C_HDLC_WITH_DIR || linkType == DLT_FRELAY_WITH_DIR) {
				newPacket.layer2Header = (l2Header_t*)(pktptr-1);
			} else {
				newPacket.layer2Header = (l2Header_t*)pktptr;
			}
			T2_SET_STATUS(&newPacket, L2_NO_ETH);
			shape = (_8021Q_t*)(pktptr + 2);
			break;

#if LINKTYPE_JUNIPER == 1
		// Juniper (Experimental)
		case DLT_JUNIPER_ATM1:
		case DLT_JUNIPER_ETHER:
		case DLT_JUNIPER_PPPOE: {
			// TODO
			//T2_CHECK_SNAP_L2(&newPacket, sizeof(???), goto endpPkt);
			T2_PKTDESC_ADD_HDR(&newPacket, "juniper");
			const juniper_eth_hdr_t * const juniper = (juniper_eth_hdr_t*)pktptr;
			if (juniper->magic != JUNIPER_PCAP_MAGIC_N) {
				T2_WRN("Juniper magic cookie not found");
				goto endpPkt;
			}
			if ((juniper->flags & JUNIPER_FLAG_EXT) == JUNIPER_FLAG_EXT) {
				pktptr += 6 + ntohs(juniper->ext_len); // magic, flags and extlen
			} else {
				pktptr += 4; // magic and flags
			}
			if ((juniper->flags & JUNIPER_FLAG_NOL2) == JUNIPER_FLAG_NOL2) {
				const uint32_t proto = *(uint32_t*)pktptr;
				pktptr += 4;
				switch (proto) {
					case 2: // IP
						T2_SET_STATUS(&newPacket, L2_NO_ETH);
						newPacket.layer2Header = (l2Header_t*)juniper;
						newPacket.layer3Header = (l3Header_t*)pktptr;
						dissembleIPv4Packet(&newPacket);
						goto endpPkt;
					//case 3: // MPLS_IP
					//case 4: // IP_MPLS
					//case 5: // MPLS
					case 6: // IP6
						T2_SET_STATUS(&newPacket, L2_NO_ETH);
						newPacket.layer2Header = (l2Header_t*)juniper;
						newPacket.layer3Header = (l3Header_t*)pktptr;
						dissembleIPv6Packet(&newPacket);
						goto endpPkt;
					//case 7:   // MPLS_IP6
					//case 8:   // IP6_MPLS
					//case 10:  // CLNP
					//case 32:  // CLNP_MPLS
					//case 33:  // MPLS_CLNP
					//case 200: // PPP
					//case 201: // ISO
					//case 202: // LLC
					//case 203: // LLC_SNAP
					case 204: // ETHER
						T2_PKTDESC_ADD_HDR(&newPacket, ":eth");
						newPacket.layer2Header = (l2Header_t*)pktptr;
						shape = (_8021Q_t*) (pktptr + 12); // advance 12 bytes to ether type
						break;
					//case 205: // OAM
					//case 206: // Q933
					//case 207: // FRELAY
					//case 208: // CHDLC
					//case 0: // Unknown
					default:
						T2_WRN("Unhandled Juniper protocol %"PRIu32, proto);
						goto endpPkt;
				}
			} else {
				if (linkType == DLT_JUNIPER_ATM1) pktptr += 4; // cookie
				newPacket.layer3Header = (l3Header_t*)pktptr;
				if ((*pktptr & 0xf0) == 0x40) {
					newPacket.layer2Header = (l2Header_t*)juniper;
					T2_SET_STATUS(&newPacket, L2_NO_ETH);
					dissembleIPv4Packet(&newPacket);
					goto endpPkt;
				} else if ((*pktptr & 0xf0) == 0x60) {
					newPacket.layer2Header = (l2Header_t*)juniper;
					T2_SET_STATUS(&newPacket, L2_NO_ETH);
					dissembleIPv6Packet(&newPacket);
					goto endpPkt;
				} else {
					T2_PKTDESC_ADD_HDR(&newPacket, ":eth");
					newPacket.layer2Header = (l2Header_t*)pktptr;
					shape = (_8021Q_t*) (pktptr + 12); // advance 12 bytes to ether type
				}
			}
			break;
		}
#endif // LINKTYPE_JUNIPER == 1

		// Symantec Enterprise Firewall
		case DLT_SYMANTEC_FIREWALL: {
			T2_PKTDESC_ADD_HDR(&newPacket, "symantec");
			const symantec_fw_v2_hdr_t * const v2 = (symantec_fw_v2_hdr_t*)pktptr;
			const symantec_fw_v3_hdr_t * const v3 = (symantec_fw_v3_hdr_t*)pktptr;
			if (UNLIKELY(v2->type == 0 && v3->type == 0)) goto endpPkt;
			uint16_t ethType;
			if (v2->type != 0) {
				T2_CHECK_SNAP_L2(&newPacket, sizeof(*v2), goto endpPkt);
				ethType = v2->type;
				pktptr += sizeof(*v2);
			} else {
				T2_CHECK_SNAP_L2(&newPacket, sizeof(*v3), goto endpPkt);
				ethType = v3->type;
				pktptr += sizeof(*v3);
			}
			newPacket.layer2Header = (l2Header_t*)v2;
			newPacket.layer3Header = (l3Header_t*)pktptr;
			T2_SET_STATUS(&newPacket, L2_NO_ETH);
			if (ethType == ETHERTYPE_IPn) {
				dissembleIPv4Packet(&newPacket);
				goto endpPkt;
			} else if (ethType == ETHERTYPE_IPV6n) {
				dissembleIPv6Packet(&newPacket);
				goto endpPkt;
			} else {
				T2_WRN("Unhandled Ethertype 0x%04"PRIx16" for Symantec Enterprise Firewall", ethType);
			}
			goto endpPkt;
		}

		case DLT_PRISM_HEADER: {
			T2_PKTDESC_ADD_HDR(&newPacket, "prism");
			const prism_hdr_t * const prism = (prism_hdr_t*)pktptr;
			if (UNLIKELY(prism->msglen != PRISM_HDR_LEN)) {
				T2_WRN("Prism message length %"PRIu32" different from default value %u", prism->msglen, PRISM_HDR_LEN);
			}
			pktptr += PRISM_HDR_LEN; // skip prism header
			goto ieee80211;
		}
		case DLT_IEEE802_11_RADIO: {
			T2_PKTDESC_ADD_HDR(&newPacket, "radiotap");
			const radiotap_hdr_t * const radio = (radiotap_hdr_t*)pktptr;
			pktptr += radio->len; // skip radiotap header
		}
		/* FALLTHRU */
ieee80211:
		// IEEE 802.11 wireless LAN
		case DLT_IEEE802_11:
			newPacket.layer2Header = (l2Header_t*)pktptr;
			pktptr = t2_process_ieee80211(pktptr, false, &newPacket);
			if (!pktptr) goto endpPkt;
			shape = (_8021Q_t*)pktptr;
			break;

		default: {
			static const char * const msg = "Unsupported link-layer type";
			// Only continue if linkType is PPI (Per-Packet Information)
			if (linkType == pcap_datalink(captureDescriptor)) {
				T2_ERR("%s %d", msg, linkType);
				exit(1);
			}
			T2_WRN("%s %d", msg, linkType);
			goto endpPkt;
		}
	}

#if DEBUG > 0
	if (UNLIKELY(!shape)) {
		T2_ERR("shape is NULL"); // Programming error
		exit(1);
	}
#endif

	// check for 802.1Q/ad signature (VLANs)
	shape = t2_process_vlans(shape, &newPacket);

	// check for LLC
	const uint32_t shape_id = ntohs(shape->identifier);
	if (shape_id > LLC_LEN && shape_id != ETHERTYPE_JUMBO_LLC) {
		newPacket.outerL2Type = shape_id; // Not LLC
		newPacket.layer2Type = newPacket.outerL2Type;
	} else {
		T2_PKTDESC_ADD_HDR(&newPacket, ":llc");
		numLLCPackets++;
		newPacket.etherLLC = (etherLLCHeader_t*)shape;
		if (newPacket.etherLLC->dssap == 0xaaaa) { // SNAP
			shape = (_8021Q_t*)((uint8_t*)shape + 8);
			newPacket.layer2Type = ntohs(shape->identifier);
			newPacket.outerL2Type = newPacket.layer2Type;
		} else {
			uint32_t llc_len = 5; // 3 for DSAP, SSAP, Ctrl, 2 for Ethernet length
			// Information and Supervisory frames use 2 bytes for Control
			if ((newPacket.etherLLC->cmd.cntrl & 0x3) != 3) llc_len++;

			pktptr = (uint8_t*)shape + llc_len;

			const uint8_t dsap = (newPacket.etherLLC->dssap & 0xff);
			if (dsap == LLC_SAP_IP) {
				switch (*pktptr & 0xf0) {
					case 0x40:
						newPacket.layer3Header = (l3Header_t*)pktptr;
						dissembleIPv4Packet(&newPacket);
						goto endpPkt;
					case 0x60:
						newPacket.layer3Header = (l3Header_t*)pktptr;
						dissembleIPv6Packet(&newPacket);
						goto endpPkt;
					default:
						T2_PKTDESC_ADD_HDR(&newPacket, ":ipvx");
						T2_SET_STATUS(&newPacket, L3_IPVX);
						break;
				}
			} else {
				T2_PKTDESC_ADD_LLCPROTO(&newPacket, dsap);
			}

			newPacket.layer2Type = ntohs(newPacket.etherLLC->dssap);
			newPacket.outerL2Type = newPacket.layer2Type;

			// TODO detect that the trailing bytes are padding and not part of l7

			// No flow could be created... flag the packet as L2_FLOW and create a L2 flow
			newPacket.layer7Header = pktptr;
			t2_dispatch_l2_packet(&newPacket);

			goto endpPkt;
		} // SNAP
	} // LLC

shape_id:
	//newPacket.layer3Type = ntohs(*(uint16_t*)shape);
	switch (shape->identifier) {

		case ETHERTYPE_IPn:
			newPacket.layer3Header = (l3Header_t*) ((uint8_t*)shape + 2);
			if ((*((uint8_t*)shape + 2) & 0xf0) != 0x40) { // non IPv4 packets
				numVxPackets++;
#if IPVX_INTERPRET == 0
				T2_PKTDESC_ADD_HDR(&newPacket, ":ipvx");
				T2_SET_STATUS(&newPacket, L3_IPVX);
				break;
#endif
			}
			dissembleIPv4Packet(&newPacket);
			goto endpPkt;

		case ETHERTYPE_IPV6n:
			newPacket.layer3Header = (l3Header_t*) ((uint8_t*)shape + 2);
			if ((*((uint8_t*)shape + 2) & 0xf0) != 0x60) { // non IPv6 packets
				numVxPackets++;
#if IPVX_INTERPRET == 0
				T2_PKTDESC_ADD_HDR(&newPacket, ":ipvx");
				T2_SET_STATUS(&newPacket, L3_IPVX);
				break;
#endif
			}
			dissembleIPv6Packet(&newPacket);
			goto endpPkt;

		case ETHERTYPE_AARPn:
			T2_PKTDESC_ADD_HDR(&newPacket, ":aarp");
			T2_SET_STATUS(&newPacket, L2_ARP);
			break;

		case ETHERTYPE_ARPn:
			T2_PKTDESC_ADD_HDR(&newPacket, ":arp");
			T2_SET_STATUS(&newPacket, L2_ARP);
			break;

		case ETHERTYPE_RARPn:
			T2_PKTDESC_ADD_HDR(&newPacket, ":rarp");
			T2_SET_STATUS(&newPacket, L2_RARP);
			break;

		case ETHERTYPE_MPLS_MULTICASTn:
			T2_SET_STATUS(&newPacket, L2_MPLS_MCAST);
			goto mpls_ucast;

		case ETHERTYPE_MPLS_UNICASTn: {
			T2_SET_STATUS(&newPacket, L2_MPLS_UCAST);
mpls_ucast:	shape = (_8021Q_t*)&shape->vlanID;
			newPacket.mpls = (uint32_t*)shape;
			newPacket.mplsHdrCnt++;
			const uint8_t * const endPkt = newPacket.end_packet - 4;
			while (!(shape->vlanID & BTM_MPLS_STKn16) && (uint8_t*)shape <= endPkt) {
				shape++; // test MPLS end of stack bit
				newPacket.mplsHdrCnt++;
			}
			T2_PKTDESC_ADD_REPHDR(&newPacket, ":mpls", newPacket.mplsHdrCnt);
			mplsHdrCntMx = MAX(mplsHdrCntMx, newPacket.mplsHdrCnt);
			shape++; // advance 4 bytes to IP Header
			newPacket.layer3Header = (l3Header_t*)shape;

			switch (shape->identifier & 0xf0) {
				case 0x40:
					dissembleIPv4Packet(&newPacket);
					goto endpPkt;
				case 0x60:
					dissembleIPv6Packet(&newPacket);
					goto endpPkt;
				default:
					// Invalid IP version
					T2_PKTDESC_ADD_HDR(&newPacket, ":ipvx");
					T2_SET_STATUS(&newPacket, L3_IPVX);
					numVxPackets++;
					break;
			}
			break;
		}

		case ETHERTYPE_ERSPANn:
			T2_PKTDESC_ADD_HDR(&newPacket, ":erspan");
			T2_SET_STATUS(&newPacket, L2_ERSPAN);
			T2_PKTDESC_ADD_HDR(&newPacket, ":eth");
			// skip ERSPAN header (8 bytes) and ethertype (2 bytes)
			newPacket.layer2Header = (l2Header_t*)((uint8_t*)shape + 10);
			// skip ethernet addresses
			shape = (_8021Q_t*)((uint8_t*)newPacket.layer2Header + 12);
			goto shape_id;

		case ETHERTYPE_PPPoE_Dn: // discovery stage
			T2_PKTDESC_ADD_HDR(&newPacket, ":pppoed");
			T2_SET_STATUS(&newPacket, L2_PPPoE_D);
			newPacket.pppoEHdr = (pppoEH_t*)&shape->vlanID;
			break;

		case ETHERTYPE_PPPoE_Sn: // session stage
			T2_PKTDESC_ADD_HDR(&newPacket, ":pppoes");
			T2_SET_STATUS(&newPacket, L2_PPPoE_S);
			newPacket.pppoEHdr = (pppoEH_t*)&shape->vlanID;
			newPacket.pppHdr = (pppHu_t*)(newPacket.pppoEHdr + 1);
			T2_PKTDESC_ADD_HDR(&newPacket, ":ppp");
			switch (newPacket.pppoEHdr->pppProt) {
				case PPP_IP4n:
					newPacket.layer3Header = (l3Header_t*)newPacket.pppHdr;
					dissembleIPv4Packet(&newPacket);
					goto endpPkt;
				case PPP_IP6n:
					newPacket.layer3Header = (l3Header_t*)newPacket.pppHdr;
					dissembleIPv6Packet(&newPacket);
					goto endpPkt;
				default:
					T2_PKTDESC_ADD_PPPPROTO(&newPacket, newPacket.pppoEHdr->pppProt);
					break;
			}
			break;

		case ETHERTYPE_LLDPn:
			T2_PKTDESC_ADD_HDR(&newPacket, ":lldp");
			T2_SET_STATUS(&newPacket, L2_LLDP);
			break;

		//case ETHERTYPE_EAPOLn:
		//	T2_PKTDESC_ADD_HDR(&newPacket, ":eapol");
		//	// TODO there may be some TLS further down...
		//	break;

#if T2_PRI_HDRDESC == 1
		case ETHERTYPE_SLOWn:
			T2_PKTDESC_ADD_HDR(&newPacket, ":slow");
			switch (*((uint8_t*)shape + 3)) {
				case  1: T2_PKTDESC_ADD_HDR(&newPacket, ":lacp");   break; // Link Aggregation Control Protocol
				case  2: T2_PKTDESC_ADD_HDR(&newPacket, ":marker"); break; // Link Aggregation - Marker Protocol
				case  3: T2_PKTDESC_ADD_HDR(&newPacket, ":oampdu"); break; // Operations, Administration, and Maintenance
				case 10: T2_PKTDESC_ADD_HDR(&newPacket, ":ossp");   break; // Organization Specific Slow Protocol
				default: break;
			}
			break;
#endif // T2_PRI_HDRDESC == 1

		default:
			T2_PKTDESC_ADD_ETHPROTO(&newPacket, shape->identifier);
			break;
	} // Switch shape->identifier (ethertype) end

	// No flow could be created... flag the packet as L2_FLOW and create a L2 flow
	newPacket.layer7Header = ((uint8_t*)shape + 2);
	t2_dispatch_l2_packet(&newPacket);

endpPkt:;

	globalWarn |= newPacket.status;

#if T2_PRI_HDRDESC == 1
	maxHdrDesc = MAX(newPacket.numHdrDesc, maxHdrDesc);
	minHdrDesc = MIN(newPacket.numHdrDesc, minHdrDesc);
	const float t = 1.0 / numPackets;
	aveHdrDesc = (1.0 - t) * aveHdrDesc + t * (float)newPacket.numHdrDesc;
#endif
}


#if ETH_ACTIVATE > 0
static inline unsigned long flowETHCreate(packet_t *packet, flow_t *hashHelper) {
	const unsigned long flowIndex = hashTable_insert(mainHashMap, (char*)&hashHelper->srcIP);
	if (UNLIKELY(flowIndex == HASHTABLE_ENTRY_NOT_FOUND)) {
		T2_PERR("flowETHCreate", "failed to insert flow into mainHashMap"); // Should not happen
		exit(1);
	}

	flow_t * const flow = &flows[flowIndex];
	memset(flow, '\0', sizeof(flow_t));

	flow->timeout = FLOW_TIMEOUT;
	flow->flowIndex = flowIndex;
	flow->oppositeFlowIndex = HASHTABLE_ENTRY_NOT_FOUND;
	flow->firstSeen = packet->pcapHeader->ts;
	flow->lastSeen = flow->firstSeen;
	flow->ethDS = ((ethernetHeader_t*)packet->layer2Header)->ethDS;
	flow->ethType = packet->layer2Type;
	flow->vlanID = packet->innerVLANID;

	T2_SET_STATUS(flow, L2_FLOW);

	// append the flow at the head of the LRU list
	updateLRUList(flow);

	// check whether the reverse flow exists and link both flows
	char a[ETH_ALEN];
	memcpy(a, &hashHelper->ethDS, ETH_ALEN);
	memcpy(&hashHelper->ethDS, flow->ethDS.ether_shost, ETH_ALEN);
	memcpy(hashHelper->ethDS.ether_shost, a, ETH_ALEN);

	const unsigned long reverseFlowIndex = hashTable_lookup(mainHashMap, (char*)&hashHelper->srcIP);
	if (UNLIKELY(reverseFlowIndex == flowIndex)) {
		flow->findex = ++totalfIndex;
		totalAFlows++;
	} else if (reverseFlowIndex == HASHTABLE_ENTRY_NOT_FOUND) {
		flow->findex = ++totalfIndex;
		totalAFlows++;
	} else {
		// reverse flow is in the hashTable
		flow_t * const revflow = &flows[reverseFlowIndex];
		revflow->oppositeFlowIndex = flowIndex;
		flow->oppositeFlowIndex = reverseFlowIndex;
		flow->findex = revflow->findex;
		totalBFlows++;
		if (!(revflow->status & L3FLOWINVERT)) flow->status |= L3FLOWINVERT;
	}

	if (++maxNumFlows > maxNumFlowsPeak) maxNumFlowsPeak = maxNumFlows;

	FOREACH_PLUGIN_DO(onFlowGen, packet, flowIndex);

	return flowIndex;
}
#endif // ETH_ACTIVATE > 0


inline void dissembleIPv4Packet(packet_t *packet) {

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

	int32_t packetLen;

#if FRAGMENTATION == 1 && FRAG_HLST_CRFT == 1
	uint64_t sw_fnohead = 0;
#endif

	flow_t *flow = NULL;
	unsigned long flowIndex = HASHTABLE_ENTRY_NOT_FOUND;

#if SCTP_ACTIVATE == 1
	int32_t sctpL7Len = 0, sctpChnkLen = 0;
	sctpChunk_t *sctpChunkP = NULL;
	uint8_t *sctpL7P = NULL;
#endif

#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

	packet->layer2Type = ETHERTYPE_IP;
	packet->layer3Type = packet->layer2Type;
	globalWarn |= L2_IPV4;
	numV4Packets++;

#if IPVX_INTERPRET == 1
	if ((*(uint8_t*)packet->layer3Header & 0xf0) != 0x40) {
		T2_PKTDESC_ADD_HDR(packet, ":ipvx");
		T2_SET_STATUS(packet, L3_IPVX);
	} else
#endif
		T2_PKTDESC_ADD_HDR(packet, ":ipv4");

	const ipHeader_t *ipHeader = (ipHeader_t*) packet->layer3Header;
	packet->l3HdrLen = IP_HL(ipHeader) << 2;

	// adjust header to the beginning of the encapsulated protocol
	packet->layer4Header = (l4Header_t*) ((uint8_t*)ipHeader + (IP_HL(ipHeader) << 2));

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
	bool priproto = true;
#endif

	if (ipHeader->ip_off & FRAGID_N) { // if 2nd++ fragmented packet, stop processing
		T2_SET_STATUS(packet, STPDSCT);
	}

#if L2TP == 1 || TEREDO == 1 || AYIYA == 1 || GTP == 1 || VXLAN == 1 || CAPWAP == 1 || GENEVE == 1 || LWAPP == 1
#define NEEDS_HDRLEN (AYIYA == 1 || GTP == 1 || VXLAN == 1 || CAPWAP == 1 || GENEVE == 1 || LWAPP == 1)
	const uint_fast8_t proto = ipHeader->ip_p;

	uint16_t sport = 0;
	uint16_t dport = 0;
#if NEEDS_HDRLEN == 1
	size_t hdrlen = 0;
#endif

	if (!(ipHeader->ip_off & FRAGID_N)) { // if NOT 2nd++ fragmented packet
		if (proto == L3_TCP) {
			const tcpHeader_t tcpHdr = packet->layer4Header->tcpHeader;
			sport = ntohs(tcpHdr.source);
			dport = ntohs(tcpHdr.dest);
#if NEEDS_HDRLEN == 1
			hdrlen = tcpHdr.doff << 2;
#endif
		} else if (proto == L3_UDP || proto == L3_UDPLITE) {
			const udpHeader_t udpHdr = packet->layer4Header->udpHeader;
			sport = ntohs(udpHdr.source);
			dport = ntohs(udpHdr.dest);
#if NEEDS_HDRLEN == 1
			hdrlen = sizeof(udpHdr);
#endif
		} else if (proto == L3_SCTP) {
			const sctpHeader_t sctpHdr = packet->layer4Header->sctpHeader;
			sport = ntohs(sctpHdr.source);
			dport = ntohs(sctpHdr.dest);
#if NEEDS_HDRLEN == 1
			hdrlen = sizeof(sctpHdr);
#endif
		}
	}

	packet->srcPort = sport;
	packet->dstPort = dport;

	// AYIYA, L2TP, TEREDO, GTP, VXLAN, CAPWAP and LWAPP all require a port
	if (sport != 0 && dport != 0) {

#if AYIYA == 1 // AYIYA: Anything in Anything
		if (!(packet->status & STPDSCT)) {
			if (t2_is_ayiya(sport, dport)) {
				if (proto == L3_SCTP) {
					T2_PKTDESC_ADD_PROTO(packet, proto);
					T2_PKTDESC_ADD_HDR(packet, ":ayiya");
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
					priproto = false;
#endif
					T2_SET_STATUS(packet, STPDSCT);
				} else {
					const int reqlen = ntohs(ipHeader->ip_len) - (IP_HL(ipHeader) << 2) - hdrlen - sizeof(ayiyaHeader_t);
					if (reqlen >= 0) {
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
						priproto = false;
#endif
						T2_PKTDESC_ADD_PROTO(packet, proto);
						uint8_t *pktptr = (uint8_t*)packet->layer4Header;
						pktptr += hdrlen; // advance to AYIYA
						pktptr = t2_process_ayiya(pktptr, packet);
						if (!pktptr) return;
						// AYIYA could not be processed...
					}
				}
			}
		}
#endif // AYIYA == 1

#if L2TP == 1 || TEREDO == 1 || GTP == 1 || VXLAN == 1 || CAPWAP == 1 || GENEVE == 1 || LWAPP == 1
		if (proto == L3_UDP && !(packet->status & STPDSCT)) {
#if GTP == 1
			// GPRS Tunneling Protocol (GTP)
			if (t2_is_gtp(sport, dport)) {
				T2_PKTDESC_ADD_HDR(packet, ":udp");
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
				priproto = false;
#endif
				uint8_t *pktptr = (uint8_t*)packet->layer4Header;
				pktptr += hdrlen; // advance to GTP
				pktptr = t2_process_gtp(pktptr, packet);
				if (!pktptr) return;
				// GTP could not be processed...
			}
#endif // GTP == 1

#if VXLAN == 1
			// Virtual eXtensible Local Area Network (VXLAN)
			if (!(packet->status & STPDSCT) && t2_is_vxlan(sport, dport)) {
				T2_PKTDESC_ADD_HDR(packet, ":udp");
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
				priproto = false;
#endif
				uint8_t *pktptr = (uint8_t*)packet->layer4Header;
				pktptr += hdrlen; // advance to VXLAN
				pktptr = t2_process_vxlan(pktptr, packet);
				if (!pktptr) return;
				// VXLAN could not be processed...
			}
#endif // VXLAN == 1

#if GENEVE == 1
			// Generic Network Virtualization Encapsulation (GENEVE)
			if (!(packet->status & STPDSCT) && t2_is_geneve(sport, dport)) {
				T2_PKTDESC_ADD_HDR(packet, ":udp");
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
				priproto = false;
#endif
				uint8_t *pktptr = (uint8_t*)packet->layer4Header;
				pktptr += hdrlen; // advance to GENEVE
				pktptr = t2_process_geneve(pktptr, packet);
				if (!pktptr) return;
				// GENEVE could not be processed...
			}
#endif // GENEVE == 1

#if CAPWAP == 1
			// Control And Provisioning of Wireless Access Points (CAPWAP)
			if (!(packet->status & STPDSCT) && t2_is_capwap(sport, dport)) {
				T2_PKTDESC_ADD_HDR(packet, ":udp");
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
				priproto = false;
#endif
				uint8_t *pktptr = (uint8_t*)packet->layer4Header;
				pktptr += hdrlen; // advance to CAPWAP
				pktptr = t2_process_capwap(pktptr, packet);
				if (!pktptr) return;
				// CAPWAP could not be processed...
			}
#endif // CAPWAP == 1

#if LWAPP == 1
			// Lightweight Access Point Protocol (LWAPP)
			if (!(packet->status & STPDSCT) && t2_is_lwapp(sport, dport)) {
				T2_PKTDESC_ADD_HDR(packet, ":udp");
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
				priproto = false;
#endif
				uint8_t *pktptr = (uint8_t*)packet->layer4Header;
				pktptr += hdrlen; // advance to LWAPP
				pktptr = t2_process_lwapp(pktptr, packet);
				if (!pktptr) return;
				// LWAPP could not be processed...
			}
#endif // LWAPP == 1

#if L2TP == 1 || TEREDO == 1
			uint16_t *l2TPPP = (uint16_t*) packet->layer4Header;

#if L2TP == 1
			if (!(packet->status & STPDSCT) &&
			     (sport == L2TP_PORT || dport == L2TP_PORT))
			{
				T2_PKTDESC_ADD_HDR(packet, ":udp");
				T2_PKTDESC_ADD_HDR(packet, ":l2tp");
				T2_SET_STATUS(packet, L2_L2TP);
				packet->l2tpLayer3Hdr = packet->layer3Header;
				l2TPPP += 4; // advance to L2TP
				const uint16_t * const l2TPH = l2TPPP;
				packet->l2TPHdr = l2TPH;
				//if ((*l2TPH & (L2TP_TYP | L2TP_RES | L2TP_VER)) != L2TP_V2) return; // only data
				if (*l2TPH & L2TP_TYP) {
					T2_SET_STATUS(packet, STPDSCT);
				} else {
					l2TPPP++;
					if (*l2TPH & L2TP_LEN) l2TPPP++;
					l2TPPP += 2; // tunnel / session ID
					if (*l2TPH & L2TP_SQN) l2TPPP += 2;
					if (*l2TPH & L2TP_OFF) l2TPPP += (ntohs(*l2TPPP) >> 1) + 1;

					//if (*l2TPPP == PPP_ADD_CTL) { // HDLC PPP present 0xff03
						T2_PKTDESC_ADD_HDR(packet, ":ppp");
						T2_SET_STATUS(packet, L2_PPP);
						packet->pppHdr = (pppHu_t*)l2TPPP; // save PPP header
						l2TPPP++; // advance HDLC PPP header add field 0xff03, following HDLC PPP encapsulated prot code

						if (*l2TPPP == PPP_MPn) { // PPP multilink protocol
							T2_PKTDESC_ADD_HDR(packet, ":mp");
							l2TPPP += 3; // skip protocol and multilink header
						}

						if (*l2TPPP == PPP_IP4n) {
							// PPP IP encapsulation?
							//packet->layer2Type = L2TP_V2;
							packet->layer3Header = (l3Header_t*) (uint8_t*)(++l2TPPP);
							packet->layer3Type = ETHERTYPE_IP;
							T2_PKTDESC_ADD_HDR(packet, ":ipv4");
							ipHeader = (ipHeader_t*)packet->layer3Header;
							packet->l3HdrLen = IP_HL(ipHeader) << 2;
							l2TPPP += IP_HL(ipHeader) << 1;
						} else {
							T2_PKTDESC_ADD_PPPPROTO(packet, *l2TPPP);
							T2_SET_STATUS(packet, STPDSCT);
						}
					//} else { // TODO: check for IPC etc
					//	return;
					//}
				}
			}
#endif // L2TP == 1

#if TEREDO == 1
			uint8_t *l2TPPPC = (uint8_t*)(l2TPPP+4);
			if (!(packet->status & STPDSCT) &&
			     (ntohs(*l2TPPP) > 1024 && ntohs(*(l2TPPP+1)) > 1024) &&
			     (*l2TPPPC == 0x60 || *(l2TPPP+4) == 0x0100 || !*(l2TPPP+4)))
			{
				//uint16_t i = 0;

				// Teredo Authentication Header
				if (*(l2TPPP+4) == 0x0100) {
					packet->trdoAHdr = l2TPPPC;
					// Skip Authentication Header, client id (len) and auth value (len)
					uint16_t i = 12 + *l2TPPPC;
					i += *(l2TPPPC + 1);
					l2TPPPC += i;
				}

				// Teredo Origin Indication Header
				if (!*l2TPPPC) {
					packet->trdoOIHdr = l2TPPPC;
					l2TPPPC += 8;
					//i += 8;
				}

				// IPv6 header?
				if (*l2TPPPC == 0x60) {
					const ip6Header_t * const ip6H = (ip6Header_t*)l2TPPPC;
					if (*l2TPPP == TRDO_PORT_N || *(l2TPPP+1) == TRDO_PORT_N ||
					    ip6H->ip_dst.IPv4x[0] == 0x00000120 ||
					    ip6H->ip_src.IPv4x[0] == 0x00000120)
					{
						//l3Len = ntohs(ip6H->payload_len);
						//if (l3Len + 48 + i == ntohs(*(l2TPPP-2))) globalWarn |= TRDO_XPLD;
						T2_PKTDESC_ADD_HDR(packet, ":udp");
						T2_PKTDESC_ADD_HDR(packet, ":teredo");
						numTeredoPackets++;
						T2_SET_STATUS(packet, L3_TRDO);
						numV4Packets--;
#if IPV6_ACTIVATE > 0
						packet->layer3Header = (l3Header_t*)l2TPPPC;
						dissembleIPv6Packet(packet);
						return;
#else // IPV6_ACTIVATE == 0
						priproto = false;
						T2_PKTDESC_ADD_HDR(packet, ":ipv6");
						T2_PKTDESC_ADD_PROTO(packet, ip6H->next_header);
						T2_SET_STATUS(packet, STPDSCT);
						numV6Packets++;
#endif // IPV6_ACTIVATE == 0
					}
				}
			}
#endif // TEREDO == 1
#endif // L2TP == 1 || TEREDO == 1
		} // UDP
#endif // L2TP == 1 || TEREDO == 1 || GTP == 1 || VXLAN == 1 || CAPWAP == 1 || GENEVE == 1 || LWAPP == 1
#endif // L2TP == 1 || TEREDO == 1 || AYIYA == 1 || GTP == 1 || VXLAN == 1 || CAPWAP == 1 || GENEVE == 1 || LWAPP == 1

	} // sport != 0 && dport != 0

#if GRE == 1
	uint32_t *grePPP = NULL, *greHD = NULL;
	if (ipHeader->ip_p == L3_GRE && !(packet->status & STPDSCT)) {
		T2_PKTDESC_ADD_HDR(packet, ":gre");
		T2_SET_STATUS(packet, L2_GRE);
		numGREPackets++;
		packet->layer4Header = (l4Header_t*) ((uint8_t*)ipHeader + (IP_HL(ipHeader) << 2)); // adjust header to the beginning of the encapsulated protocol
		grePPP = (uint32_t*) packet->layer4Header;
		greHD = grePPP++;
		packet->greHdr = (greHeader_t*)greHD;
		packet->greLayer3Hdr = packet->layer3Header;
		if (*greHD & GRE_CKSMn) grePPP++;
		if (*greHD & GRE_RTn) grePPP++;
		if (*greHD & GRE_KEYn) grePPP++;
		if (*greHD & GRE_SQn) grePPP++;
		if (*greHD & GRE_SSRn) grePPP++;
		if (*greHD & GRE_ACKn) grePPP++;
		if ((*greHD & GRE_PROTOn) == GRE_IP4n) {
			T2_PKTDESC_ADD_HDR(packet, ":ipv4");
			packet->layer3Header = (l3Header_t*)grePPP;
			packet->layer3Type = ETHERTYPE_IP;
			ipHeader = (ipHeader_t*)packet->layer3Header;
			packet->l3HdrLen = IP_HL(ipHeader) << 2;
		} else if ((*greHD & GRE_PROTOn) == GRE_PPPn) {
			T2_PKTDESC_ADD_HDR(packet, ":ppp");
			T2_SET_STATUS(packet, L2_PPP);
			packet->pppHdr = (pppHu_t*)grePPP; // save PPP header
			if ((*grePPP & 0x000000ff) == GRE_PPP_CMPRSS) {
				// compressed, no readable header; info for later processing of flow
				T2_PKTDESC_ADD_HDR(packet, ":comp_data");
				T2_SET_STATUS(packet, (PPP_NRHD | STPDSCT));
			// Enhanced GRE (1) with payload length == 0
			} else if ((*greHD & GRE_Vn) == 0x100 && (*(uint16_t*)((uint16_t*)greHD + 2) == 0)) {
				packet->pppHdr = NULL; // reset PPP header (not present)
				T2_SET_STATUS(packet, STPDSCT);
			} else if ((*grePPP & 0x000000ff) != 0xff) { // address and control are null
				if (*grePPP & 0x00000001) {
					// One byte protocol ID
					if ((*grePPP & 0x000000ff) == 0x21) {
						T2_PKTDESC_ADD_HDR(packet, ":ipv4");
						packet->layer3Header = (l3Header_t*)((uint8_t*)grePPP+1);
						packet->layer3Type = ETHERTYPE_IP;
						ipHeader = (ipHeader_t*)packet->layer3Header;
						packet->l3HdrLen = IP_HL(ipHeader) << 2;
					}
				} else {
					// Two bytes protocol ID
					if ((*grePPP & 0x0000ffff) == PPP_IP4n) {
						T2_PKTDESC_ADD_HDR(packet, ":ipv4");
						packet->layer3Header = (l3Header_t*) (uint8_t*)(++grePPP);
						packet->layer3Type = ETHERTYPE_IP;
						ipHeader = (ipHeader_t*)packet->layer3Header;
						packet->l3HdrLen = IP_HL(ipHeader) << 2;
					//} else if ((*grePPP & 0x0000ffff) == PPP_IP6n) { // TODO
					} else {
						T2_PKTDESC_ADD_PPPPROTO(packet, (*grePPP & 0x0000ffff));
						T2_SET_STATUS(packet, STPDSCT);
					}
				}
			} else if (((pppHdr_t*)grePPP)->prot == PPP_IP4n) {
				T2_PKTDESC_ADD_HDR(packet, ":ipv4");
				packet->layer3Header = (l3Header_t*) (uint8_t*)(++grePPP);
				packet->layer3Type = ETHERTYPE_IP;
				ipHeader = (ipHeader_t*)packet->layer3Header;
				packet->l3HdrLen = IP_HL(ipHeader) << 2;
			} else if (((pppHdr_t*)grePPP)->prot == PPP_IP6n) {
				numV4Packets--;
#if IPV6_ACTIVATE > 0
				packet->layer3Header = (l3Header_t*) (uint8_t*)(++grePPP);
				dissembleIPv6Packet(packet);
				return;
#else // IPV6_ACTIVATE == 0
				T2_PKTDESC_ADD_HDR(packet, ":ipv6");
				T2_PKTDESC_ADD_PROTO(packet, ((ip6Header_t*)(++grePPP))->next_header);
				T2_SET_STATUS(packet, STPDSCT);
				numV6Packets++;
#endif // IPV6_ACTIVATE == 0
			} else {
				// Enhanced GRE (1) with payload length == 0
				if ((*greHD & GRE_Vn) == 0x100 && (*(uint16_t*)((uint16_t*)greHD + 2) == 0)) {
					packet->pppHdr = NULL; // reset PPP header (not present)
				} else {
					T2_PKTDESC_ADD_PPPPROTO(packet, ((pppHdr_t*)grePPP)->prot);
				}
				T2_SET_STATUS(packet, STPDSCT);
			}
		} else if ((*greHD & GRE_PROTOn) == GRE_TEBn ||
		           (*greHD & GRE_PROTOn) == GRE_ERSPANn)
		{
			if ((*greHD & GRE_PROTOn) == GRE_ERSPANn) {
				T2_PKTDESC_ADD_HDR(packet, ":erspan");
				T2_SET_STATUS(packet, L2_ERSPAN);
				grePPP += 2; // skip ERSPAN header (64 bytes)
			}
			const uint8_t *hp = (uint8_t*)grePPP;
			const uint8_t * const hp1 = hp;
			const uint16_t i = (uint16_t)(hp - (uint8_t*)packet->layer2Header); // L2,VLAN length
			hp += 12;
			T2_PKTDESC_ADD_HDR(packet, ":eth");
			// check for 802.1Q/ad signature (VLANs)
			_8021Q_t *shape = (_8021Q_t*)hp;
			if (packet->snapL2Length >= sizeof(_8021Q_t)) {
				shape = t2_process_vlans(shape, packet);
			}
			if (hp != (uint8_t*)shape) hp = (uint8_t*)shape;
			const uint16_t shapeid = ntohs(shape->identifier);
			if (shapeid <= LLC_LEN || shapeid == ETHERTYPE_JUMBO_LLC) {
				T2_PKTDESC_ADD_HDR(packet, ":llc");
				packet->etherLLC = (etherLLCHeader_t*)hp;
				hp = ((uint8_t*)packet->etherLLC+8); // jump to ether type
				shape = (_8021Q_t*)hp;
			} else hp += 2; // skip ethertype

			if (shape->identifier == ETHERTYPE_IPn) {
				T2_PKTDESC_ADD_HDR(packet, ":ipv4");
				packet->layer2Header = (l2Header_t*)hp1;
				packet->snapL2Length -= i;
				packet->layer3Header = (l3Header_t*)hp;
				ipHeader = (ipHeader_t*)packet->layer3Header;
				packet->l3HdrLen = IP_HL(ipHeader) << 2;
				packet->layer3Type = ETHERTYPE_IP;
			} else if (shape->identifier == ETHERTYPE_IPV6n) {
				numV4Packets--;
#if IPV6_ACTIVATE > 0
				packet->layer2Header = (l2Header_t*)hp1;
				packet->layer3Header = (l3Header_t*)hp;
				packet->snapL2Length -= i;
				dissembleIPv6Packet(packet);
				return;
#else // IPV6_ACTIVATE == 0
				T2_PKTDESC_ADD_HDR(packet, ":ipv6");
				T2_SET_STATUS(packet, STPDSCT);
				numV6Packets++;
#endif // IPV6_ACTIVATE
			} else {
				T2_PKTDESC_ADD_ETHPROTO(packet, shape->identifier);
				T2_SET_STATUS(packet, STPDSCT);
			}
		} else if ((*greHD & GRE_PROTOn) == GRE_WCCPn) {
			T2_PKTDESC_ADD_HDR(packet, ":wccp");
			T2_SET_STATUS(packet, L2_WCCP);
			const uint8_t *pktptr = (uint8_t*)grePPP;
			pktptr += 4;
			if ((*pktptr & 0xf0) == 0x40) {
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
				numV4Packets--;
				packet->layer3Header = (l3Header_t*)pktptr;
				dissembleIPv4Packet(packet);
				return;
#else // IPV6_ACTIVATE == 1
				T2_PKTDESC_ADD_HDR(packet, ":ipv4");
				T2_PKTDESC_ADD_PROTO(packet, ((ipHeader_t*)pktptr)->ip_p);
#endif // IPV6_ACTIVATE == 1
			} else if ((*pktptr & 0xf0) == 0x60) {
				numV4Packets--;
#if IPV6_ACTIVATE > 0
				packet->layer3Header = (l3Header_t*)pktptr;
				dissembleIPv6Packet(packet);
				return;
#else // IPV6_ACTIVATE == 0
				T2_PKTDESC_ADD_HDR(packet, ":ipv6");
				T2_PKTDESC_ADD_PROTO(packet, ((ip6Header_t*)pktptr)->next_header);
				numV6Packets++;
#endif // IPV6_ACTIVATE == 0
			} else {
				T2_SET_STATUS(packet, STPDSCT);
			}
		} else {
			T2_PKTDESC_ADD_ETHPROTO(packet, ((*greHD & GRE_PROTOn) >> 16));
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
			priproto = false;
#endif
			T2_SET_STATUS(packet, STPDSCT);
		}
	}
#endif // GRE == 1

#if ETHIP == 1
	const uint8_t *hp = (uint8_t*)packet->layer3Header + packet->l3HdrLen;
	if (ipHeader->ip_p == L3_ETHIP && (*hp & 0xf0) >= ETHIPVERN && !(packet->status & STPDSCT)) {
		T2_PKTDESC_ADD_HDR(packet, ":etherip");
		T2_PKTDESC_ADD_HDR(packet, ":eth");
		T2_SET_STATUS(packet, L3_ETHIPF);

		const uint16_t i = (uint16_t)(hp - (uint8_t*)packet->layer2Header) + 2; // L2,VLAN length
		packet->snapL2Length -= i;
		packet->layer2Header = (l2Header_t*)(hp+2);

		hp += 14;

		// check for 802.1Q/ad signature (VLANs)
		_8021Q_t *shape = (_8021Q_t*)hp;
		shape = t2_process_vlans(shape, packet);
		hp = (uint8_t*)shape + 2;
		if (shape->identifier == ETHERTYPE_IPn) {
			T2_PKTDESC_ADD_HDR(packet, ":ipv4");
			packet->layer3Header = (l3Header_t*)hp;
			ipHeader = (ipHeader_t*)hp;
			packet->l3HdrLen = IP_HL(ipHeader) << 2;
			packet->layer3Type = ntohs(*(uint16_t*)(hp-2));
		} else if (shape->identifier == ETHERTYPE_IPV6n) {
			numV4Packets--;
#if IPV6_ACTIVATE > 0
			packet->layer3Header = (l3Header_t*)hp;
			dissembleIPv6Packet(packet);
			return;
#else // IPV6_ACTIVATE == 0
			T2_PKTDESC_ADD_HDR(packet, ":ipv6");
			T2_SET_STATUS(packet, STPDSCT);
			numV6Packets++;
#endif // IPV6_ACTIVATE
		} else {
			T2_PKTDESC_ADD_ETHPROTO(packet, shape->identifier);
			T2_SET_STATUS(packet, STPDSCT);
		}
	}
#endif // ETHIP == 1

	if (ipHeader->ip_p == L3_IPIP4 && !(packet->status & STPDSCT)) {
		T2_SET_STATUS(packet, L3_IPIP);
#if IPIP == 1
		const char * const hp = (char*)packet->layer3Header + packet->l3HdrLen;
		packet->layer3Header = (l3Header_t*)hp;
		ipHeader = (ipHeader_t*)packet->layer3Header;
		packet->l3HdrLen = IP_HL(ipHeader) << 2;
		T2_PKTDESC_ADD_HDR(packet, ":ipv4");
#endif // IPIP == 1
	} else if (ipHeader->ip_p == L3_IPIP6 && !(packet->status & STPDSCT)) {
		T2_SET_STATUS(packet, L3_IPIP);
		numV4Packets--;
#if IPIP == 1 && IPV6_ACTIVATE > 0
		const char * const hp = (char*)packet->layer3Header + packet->l3HdrLen;
		packet->layer3Header = (l3Header_t*)hp;
		dissembleIPv6Packet(packet);
		return;
#else // IPIP == 0 || IPV6_ACTIVATE == 0
		T2_PKTDESC_ADD_HDR(packet, ":ipv6");
		T2_SET_STATUS(packet, STPDSCT);
		numV6Packets++;
#endif // IPV6_ACTIVATE == 0
	}
#if IPV6_ACTIVATE == 1
} // END OF FUNCTION dissembleIPv4Packet
#else // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

	if ((ipHeader->ip_vhl & 0xf0) != 0x40) {
		T2_SET_STATUS(packet, L3_IPVX);
		numVxPackets++;
#if IPVX_INTERPRET == 0
		T2_PKTDESC_ADD_HDR(packet, ":ipvx");
		return;
#endif
	}

#if FRAGMENTATION == 0
	// do not handle fragmented packets
	if (ipHeader->ip_off & FRAGID_N) {
		globalWarn |= IPV4_FRAG;
		numFragV4Packets++;
		return; // fragmentation switch off: ignore fragmented packets except the 1. protocol header
	}
#endif // FRAGMENTATION

	uint16_t i = (uint16_t)((uint8_t*) packet->layer3Header - (uint8_t*) packet->layer2Header); // L2,VLAN length
	packet->snapL3Length = packet->snapL2Length - i; // L3 packet length
	const uint16_t l3Len = ntohs(ipHeader->ip_len); // get IP packet length from IP header

	packet->l2HdrLen = i;
	const uint16_t l2Len = l3Len + i;
	packet->packetL2Length = l2Len;
	bytesOnWire += l2Len; // estimate all Ethernet & IP bytes seen on wire

	if (packet->snapL3Length < l3Len) { // Layer3 snaplength too short or IP packet too short?
		packet->status |= L3SNAPLENGTH;
		if (!(globalWarn & L3SNAPLENGTH)) { // Snap length warning
			globalWarn |= L3SNAPLENGTH;
#if VERBOSE > 0
			T2_WRN("snapL2Length: %"PRIu32" - snapL3Length: %"PRIu32" - IP length in header: %d", packet->snapL2Length, packet->snapL3Length, l3Len);
#endif
		}
	} else if (packet->snapL3Length > l3Len) {
		padBytesOnWire += packet->rawLength - packet->snapL2Length;
		packet->snapL2Length = l2Len;
		packet->snapL3Length = l3Len;
	}

	if (l3Len < 20) { // Layer3 snaplength too short or IP packet too short?
		T2_SET_STATUS(packet, L3HDRSHRTLEN);
	}

#if PACKETLENGTH == 0
	packetLen = l2Len;
#else // PACKETLENGTH != 0
	packetLen = l3Len;
#endif // PACKETLENGTH != 0

	// -------------------------------- layer 3 --------------------------------

#if PACKETLENGTH <= 1

#if (FRGIPPKTLENVIEW == 1 && FRAGMENTATION == 1) // IP packet view mode in case of fragmentation
	if (ipHeader->ip_off & FRAGID_N) packetLen -= packet->l3HdrLen; // remove IP header len only from 2nd++ frag if whole packet statistical view is required: default
#endif

	if (packetLen >= 0) {
		packet->packetLength = packetLen;
	} else {
		packet->packetLength = 0;
		T2_SET_STATUS(packet, L3HDRSHRTLEN);
	}
#endif // PACKETLENGTH <= 1

	// -------------------------------- layer 4 --------------------------------

	packet->layer4Type = ipHeader->ip_p; // set layer4Type already for global plugins such as protoStats
	packet->layer4Header = (l4Header_t*) ((uint8_t*)ipHeader + packet->l3HdrLen); // adjust header to the beginning of the encapsulated protocol

	uint16_t l4HdrOff;
#if FRAGMENTATION == 1
	if ((ipHeader->ip_off & FRAGID_N) != FRAGID_1P_N) l4HdrOff = 0;
	else
#endif
		switch (ipHeader->ip_p) {
#if IPIP == 1
			case L3_IPIP4:
				l4HdrOff = (ipHeader->ip_vhl & 0x0f) << 2;
				break;
#endif
			case L3_ICMP:
				l4HdrOff = sizeof(icmpHeader_t);
				break;
			case L3_TCP:
				l4HdrOff = packet->layer4Header->tcpHeader.doff << 2;
				break;
			case L3_GRE:
#if GRE == 1
				l4HdrOff = (uint16_t)((uint8_t*)grePPP - (uint8_t*)greHD);
#else // GRE == 0
				l4HdrOff = 0;
#endif // GRE == 1
				break;
			case L3_OSPF:
				l4HdrOff = 16;
				break;
			case L3_SCTP:
				l4HdrOff = 12;
				break;
			default:
				l4HdrOff = 8;
				break;
		}

	packet->l4HdrLen = l4HdrOff;

#if PACKETLENGTH >= 2
	packetLen -= IP_HL(ipHeader) << 2;
#if PACKETLENGTH == 3 // subtract L4 header
	packetLen -= l4HdrOff;
#endif
	if (packetLen >= 0) {
		packet->packetLength = packetLen;
	} else {
		packet->packetLength = 0;
		T2_SET_STATUS(packet, L4HDRSHRTLEN);
	}
#endif // PACKETLENGTH >= 2

	// -------------------------------- layer 7 --------------------------------

	packet->packetL7Length = l3Len - packet->l3HdrLen - l4HdrOff;

	packet->layer7Header = (uint8_t*)packet->layer4Header + l4HdrOff;
	if (packet->snapL3Length >= l3Len) { // L3 length not snapped
		if (UNLIKELY(packet->snapL3Length < packet->l3HdrLen)) packet->snapL4Length = 0; // return or frag??? todo
		else packet->snapL4Length = l3Len - packet->l3HdrLen;
		if (LIKELY(l4HdrOff < packet->snapL4Length)) packet->snapL7Length = packet->snapL4Length - l4HdrOff; // Protocol L3/4 Hdr lengths are valid
		else packet->snapL7Length = 0;
	} else { // L3 length snapped so calculate real hdr L7 length
		if (UNLIKELY(packet->snapL3Length < packet->l3HdrLen)) packet->snapL4Length = 0; // return or frag??? todo
		else packet->snapL4Length = packet->snapL3Length - packet->l3HdrLen;
		packet->snapL7Length = (uint16_t)(packet->layer7Header - (uint8_t*)packet->layer3Header); // offset between L3 and L7
		if (UNLIKELY(packet->snapL3Length < packet->snapL7Length)) packet->snapL7Length = 0;
		else packet->snapL7Length = packet->snapL3Length - packet->snapL7Length; // real L7 length
	}

	// source and destination port of a layer 4 header

#if AGGREGATIONFLAG & SUBNET
	//if (subnet_table) {
	//	packet->subnetSrc = subnet_testP(subnet_table, ipHeader->srcIP.s_addr); // subnet test src ip
	//	packet->subnetDst = subnet_testP(subnet_table, ipHeader->dstIP.s_addr); // subnet test dst ip
	//}
#else // AGGREGATIONFLAG & SUBNET == 0

#if (AGGREGATIONFLAG & SRCIP)
	packet->srcIP.IPv4.s_addr = ipHeader->ip_src.s_addr & ntohl(SRCIP4MSK);
#else // AGGREGATIONFLAG & SRCIP == 0
	packet->srcIP.IPv4 = ipHeader->ip_src;
#endif // AGGREGATIONFLAG & SRCIP

#if (AGGREGATIONFLAG & DSTIP)
	packet->dstIP.IPv4.s_addr = ipHeader->ip_dst.s_addr & ntohl(DSTIP4MSK);
#else // AGGREGATIONFLAG & DSTIP == 0
	packet->dstIP.IPv4 = ipHeader->ip_dst;
#endif // AGGREGATIONFLAG & DSTIP

#endif // AGGREGATIONFLAG & SUBNET

	flow_t hashHelper = {
#if ETH_ACTIVATE == 2
		.ethDS = ((ethernetHeader_t*)packet->layer2Header)->ethDS,
#endif
#if (IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0)
		.ethType = packet->layer2Type,
#endif
		.vlanID = packet->innerVLANID,
		.srcIP = packet->srcIP,
		.dstIP = packet->dstIP,
	};

	if (!(packet->status & STPDSCT)) {
		packet->srcPort = 0;
		packet->dstPort = 0;
	}

#if FRAGMENTATION == 1

	unsigned long fragPendIndex;

	if (ipHeader->ip_off & FRAGID_N) { // if 2nd++ fragmented packet

		if (priproto) T2_PKTDESC_ADD_PROTO(packet, ipHeader->ip_p);

		hashHelper.fragID = ipHeader->ip_id;
		fragPendIndex = hashTable_lookup(fragPendMap, (char*)&hashHelper.srcIP);

		if (fragPendIndex == HASHTABLE_ENTRY_NOT_FOUND) { // probably missed 1. frag packet or packet mangling
			globalWarn |= (IPV4_FRAG | IPV4_FRAG_HDSEQ_ERR);
#if (VERBOSE > 0 && FRAG_ERROR_DUMP == 1)
			char srcIP[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &(hashHelper.srcIP), srcIP, INET_ADDRSTRLEN);
			char dstIP[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &(hashHelper.dstIP), dstIP, INET_ADDRSTRLEN);
			T2_PWRN("packetCapture", "1. frag not found @ %ld.%ld %d %s %d %s %d %d - 0x%04x 0x%04x",
					packet->pcapHeader->ts.tv_sec, (long int)packet->pcapHeader->ts.tv_usec, hashHelper.vlanID,
					srcIP, ntohs(packet->layer4Header->tcpHeader.source),
					dstIP, ntohs(packet->layer4Header->tcpHeader.dest),
					packet->layer4Type, ntohs(ipHeader->ip_id), ntohs(ipHeader->ip_off));
#endif // (VERBOSE > 0 && FRAG_ERROR_DUMP == 1)

#if FRAG_HLST_CRFT == 1
			sw_fnohead = IPV4_FRAG_HDSEQ_ERR;
			goto create_packetF; // we dont know the flow, but create one anyway, because might be interesting crafted packet
#else // FRAG_HLST_CRFT == 0
			return; // we don't know the flow, so ignore packet
#endif // FRAG_HLST_CRFT == 0
		} else {
			numFragV4Packets++;
			flowIndex = fragPend[fragPendIndex];
			flow = &flows[flowIndex];
			if (!(ipHeader->ip_off & MORE_FRAG_N)) { // remove packet from frag queue when last fragment received
				if (hashTable_remove(fragPendMap, (char*) &hashHelper.srcIP) == HASHTABLE_ENTRY_NOT_FOUND) T2_PWRN("packetCapture", "fragPend remove failed");
				if (flow->status & IPV4_FRAG_PENDING) flow->status &= ~IPV4_FRAG_PENDING;
			}
		}

	} else { // not fragmented or 1. fragmented packet

#endif // FRAGMENTATION == 1

		// encapsulated packet
		if (packet->status & STPDSCT) goto create_packetF;

		switch (packet->layer4Type) {
			case L3_IPIP4: { // IP in IP
				T2_SET_STATUS(packet, L3_IPIP);
#if IPIP == 0
				T2_PKTDESC_ADD_HDR(packet, ":ipv4");
				break;
#else // IPIP != 0
				numV4Packets--;
				if (packet->l3HdrLen == 0) break; // avoid infinite loops
				char *hp = (char*)packet->layer3Header;
				hp += packet->l3HdrLen;
				packet->layer3Header = (l3Header_t*)hp;
				dissembleIPv4Packet(packet);
				return;
#endif // IPIP
			}

			case L3_IPIP6: {
				const ip6Header_t *ip6H = (ip6Header_t*) packet->layer4Header;
				numV4Packets--;
#if IPV6_ACTIVATE == 0 && IPIP == 0
				numV6Packets++;
				T2_PKTDESC_ADD_HDR(packet, ":ipv6");
				T2_PKTDESC_ADD_PROTO(packet, ip6H->next_header);
				break;
#else // IPV6_ACTIVATE != 0 || IPIP == 1
				packet->layer3Header = (l3Header_t*)ip6H;
				dissembleIPv6Packet(packet);
				return;
#endif // IPV6_ACTIVATE != 0 || IPIP == 1
			}

			case L3_TCP:
				if (priproto) {
					T2_PKTDESC_ADD_HDR(packet, ":tcp");
				}
				if (l3Len < 40) {
					T2_SET_STATUS(packet, L4HDRSHRTLEN);
				} else {
					packet->srcPort = ntohs(packet->layer4Header->tcpHeader.source);
					packet->dstPort = ntohs(packet->layer4Header->tcpHeader.dest);
					if ((packet->dstPort == UPNP_PORT && packet->srcPort > 1024) ||
					    (packet->srcPort == UPNP_PORT && packet->dstPort > 1024))
					{
						T2_PKTDESC_ADD_HDR(packet, ":ssdp");
						T2_SET_STATUS(packet, L4_UPNP);
					}
				}
				break;

			case L3_UDPLITE:
				if (priproto) {
					T2_PKTDESC_ADD_HDR(packet, ":udplite");
					priproto = false;
				}
				/* FALLTHRU */
			case L3_UDP:
				if (priproto) {
					T2_PKTDESC_ADD_HDR(packet, ":udp");
				}
				if (l3Len < 28) {
					T2_SET_STATUS(packet, L4HDRSHRTLEN);
				} else {
					const uint16_t sport = ntohs(packet->layer4Header->udpHeader.source);
					const uint16_t dport = ntohs(packet->layer4Header->udpHeader.dest);
					packet->srcPort = sport;
					packet->dstPort = dport;
#if L2TP == 0
					if (sport == L2TP_PORT || dport == L2TP_PORT) {
						T2_PKTDESC_ADD_HDR(packet, ":l2tp");
						T2_SET_STATUS(packet, L2_L2TP);
						packet->layer3Type = L2TP_V2;
					}
#endif // L2TP == 0
					if ((dport == UPNP_PORT && sport > 1024) ||
					    (sport == UPNP_PORT && dport > 1024))
					{
						T2_PKTDESC_ADD_HDR(packet, ":ssdp");
						T2_SET_STATUS(packet, L4_UPNP);
					} else if (dport == UDPENCAP_PORT || sport == UDPENCAP_PORT) { // checksum should be 0
						// UDP Encapsulation of IPsec
						const uint8_t * const pktptr = (uint8_t*)((uint8_t*)packet->layer4Header + sizeof(udpHeader_t));
						T2_PKTDESC_ADD_HDR(packet, ":udpencap");
						if (*pktptr == 0xff && (ntohs(packet->layer4Header->udpHeader.len) - sizeof(udpHeader_t)) == 1) {
							// NAT-keepalive
						} else if (*((uint32_t*)pktptr) != 0) {
							T2_PKTDESC_ADD_HDR(packet, ":esp");
							T2_SET_STATUS(packet, L3_IPSEC_ESP);
						} else {
							// TODO *(pktptr+4) == 0xff? wireshark labels as data instead of isakmp
							T2_PKTDESC_ADD_HDR(packet, ":isakmp");
						}
					}
				}
				break;

			case L3_GRE:
				if (priproto) {
					T2_PKTDESC_ADD_HDR(packet, ":gre");
				}
				T2_SET_STATUS(packet, L2_GRE);
#if GRE == 1
				grePPP = (uint32_t*) packet->layer4Header;
				greHD = grePPP++;
				packet->greHdr = (greHeader_t*)greHD;
				packet->greLayer3Hdr = packet->layer3Header;
				if (*greHD & GRE_CKSMn) grePPP++;
				if (*greHD & GRE_RTn) grePPP++;
				if (*greHD & GRE_KEYn) grePPP++;
				if (*greHD & GRE_SQn) grePPP++;
				if (*greHD & GRE_SSRn) grePPP++;
				if (*greHD & GRE_ACKn) grePPP++;
				if ((*greHD & GRE_PROTOn) == GRE_IP4n) {
					T2_PKTDESC_ADD_HDR(packet, ":ipv4");
					packet->layer3Header = (l3Header_t*)grePPP;
					packet->layer3Type = ETHERTYPE_IP;
					ipHeader = (ipHeader_t*)packet->layer3Header;
					packet->l3HdrLen = IP_HL(ipHeader) << 2;
				} else if ((*greHD & GRE_PROTOn) == GRE_PPPn) {
					T2_PKTDESC_ADD_HDR(packet, ":ppp");
					T2_SET_STATUS(packet, L2_PPP);
					packet->pppHdr = (pppHu_t*)grePPP; // save PPP header
					if ((*grePPP & 0x000000ff) == GRE_PPP_CMPRSS) {
						// compressed, no readable header; info for later processing of flow
						T2_PKTDESC_ADD_HDR(packet, ":comp_data");
						T2_SET_STATUS(packet, (PPP_NRHD | STPDSCT));
						break;
					} else if (((pppHdr_t*)grePPP)->prot == PPP_IP4n) {
						T2_PKTDESC_ADD_HDR(packet, ":ipv4");
						packet->layer3Header = (l3Header_t*) (uint8_t*)(++grePPP);
						packet->layer3Type = ETHERTYPE_IP;
						ipHeader = (ipHeader_t*)packet->layer3Header;
						packet->l3HdrLen = IP_HL(ipHeader) << 2;
					} else if (((pppHdr_t*)grePPP)->prot == PPP_IP6n) {
						numV4Packets--;
#if IPV6_ACTIVATE > 0
						packet->layer3Header = (l3Header_t*) (uint8_t*)(++grePPP);
						dissembleIPv6Packet(packet);
						return;
#else // IPV6_ACTIVATE == 0
						T2_PKTDESC_ADD_HDR(packet, ":ipv6");
						T2_SET_STATUS(packet, STPDSCT);
						numV6Packets++;
						break;
#endif // IPV6_ACTIVATE == 0
					} else {
						// Enhanced GRE (1) with payload length == 0
						if ((*greHD & GRE_Vn) == 0x100 && (*(uint16_t*)((uint16_t*)greHD + 2) == 0)) {
							packet->pppHdr = NULL; // reset PPP header (not present)
						} else {
							T2_PKTDESC_ADD_PPPPROTO(packet, ((pppHdr_t*)grePPP)->prot);
						}
						T2_SET_STATUS(packet, STPDSCT);
						break;
					}
				} else if ((*greHD & GRE_PROTOn) == GRE_TEBn) {
					const uint8_t *hp = (uint8_t*)grePPP;
					const uint8_t * const hp1 = hp;
					i = (uint16_t)(hp - (uint8_t*)packet->layer2Header); // L2,VLAN length
					hp += 12;
					// check for 802.1Q/ad signature (VLANs)
					_8021Q_t *shape = (_8021Q_t*)hp;
					shape = t2_process_vlans(shape, packet);
					if (hp != (uint8_t*)shape) hp = (uint8_t*)shape;
					else hp += 2;

					if (shape->identifier == ETHERTYPE_IPn) {
						numV4Packets--;
						packet->layer2Header = (l2Header_t*)hp1;
						packet->snapL2Length -= i;
						packet->layer3Header = (l3Header_t*)hp;
						dissembleIPv4Packet(packet);
						return;
					} else if (shape->identifier == ETHERTYPE_IPV6n) {
						numV4Packets--;
#if IPV6_ACTIVATE > 0
						packet->layer2Header = (l2Header_t*)hp1;
						packet->layer3Header = (l3Header_t*)hp;
						packet->snapL2Length -= i;
						dissembleIPv6Packet(packet);
						return;
#else // IPV6_ACTIVATE == 0
						T2_PKTDESC_ADD_HDR(packet, ":ipv6");
						T2_SET_STATUS(packet, STPDSCT);
						numV6Packets++;
						break;
#endif // IPV6_ACTIVATE
					} else {
						T2_PKTDESC_ADD_ETHPROTO(packet, shape->identifier);
						return;
					}
				} else return;
#endif // GRE == 1
				break;

			case L3_ESP:
				T2_PKTDESC_ADD_HDR(packet, ":esp");
				T2_SET_STATUS(packet, L3_IPSEC_ESP);
				// TODO
				break;

			case L3_AH:
				// TODO: check encapsulated protocol
				T2_PKTDESC_ADD_HDR(packet, ":ah");
				T2_SET_STATUS(packet, L3_IPSEC_AH);
				T2_PKTDESC_ADD_PROTO(packet, *(uint8_t*)(packet->layer4Header));
				break;

			case L3_L2TP: // L2TPv3
				T2_PKTDESC_ADD_HDR(packet, ":l2tp");
				T2_SET_STATUS(packet, L2_L2TP);
				packet->layer3Type = L2TP_V3;
				break;

			case L3_SCTP: // SCTP, ports at the same position as TCP
				if (priproto) {
					T2_PKTDESC_ADD_HDR(packet, ":sctp");
				}
				T2_SET_STATUS(packet, L4_SCTP);
				if (l3Len < 36) {
					T2_SET_STATUS(packet, L4HDRSHRTLEN);
				} else {
					packet->srcPort = ntohs(packet->layer4Header->sctpHeader.source);
					packet->dstPort = ntohs(packet->layer4Header->sctpHeader.dest);
				}
#if SCTP_ACTIVATE == 1
				sctpL7P = (uint8_t*)packet->layer7Header;
				packet->layer7SCTPHeader = sctpL7P;
				sctpChunkP = (sctpChunk_t*)sctpL7P;
				sctpChnkLen = ntohs(sctpChunkP->len);
				sctpL7Len = packet->snapL7Length;
				if ((sctpChunkP->type & SCTP_C_TYPE) == 0) {
					packet->layer7Header += 16;
					if (sctpL7Len >= sctpChnkLen) {
						packet->snapSCTPL7Length = sctpChnkLen;
						packet->snapL7Length = sctpChnkLen - 16;
					} else {
						packet->snapSCTPL7Length = sctpL7Len;
						packet->snapL7Length = sctpL7Len - 16;
					}
					packet->packetL7Length = sctpChnkLen - 16;
					packet->packetLength = packet->packetL7Length;
				} else {
					packet->layer7Header += sctpChnkLen;
					packet->snapSCTPL7Length = sctpChnkLen;
					packet->snapL7Length = 0;
				}
#endif // SCTP_ACTIVATE == 1
				break;

#if T2_PRI_HDRDESC == 1
			case L3_IGMP: {
				T2_PKTDESC_ADD_HDR(packet, ":igmp");
				const igmpHeader_t * const igmp = (igmpHeader_t*)packet->layer4Header;
				switch (igmp->type) {
					case IGMP_TYPE_DVMRP:
						T2_PKTDESC_ADD_HDR(packet, ":dvmrp");
						break;
					case IGMP_TYPE_PIM:
						T2_PKTDESC_ADD_HDR(packet, ":pim");
						break;
					case IGMP_TYPE_RGMP_LEAVE:
					case IGMP_TYPE_RGMP_JOIN:
					case IGMP_TYPE_RGMP_BYE:
					case IGMP_TYPE_RGMP_HELLO:
						if (ipHeader->ip_dst.s_addr == IGMP_RGMP_DADDRn) { // 224.0.0.25
							T2_PKTDESC_ADD_HDR(packet, ":rgmp");
						}
						break;
					default:
						break;
				}
				break;
			}
#endif // T2_PRI_HDRDESC == 1

			case L3_PIM: {
				T2_PKTDESC_ADD_HDR(packet, ":pim");
				const pimHeader_t * const pim = (pimHeader_t*)packet->layer4Header;
				if (pim->type == PIM_TYPE_REGISTER) {
					const uint8_t * const pktptr = ((uint8_t*)pim + PIM_REGISTER_LEN);
					if ((*pktptr & 0xf0) == 0x40) {
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
						numV4Packets--;
						packet->layer3Header = (l3Header_t*)pktptr;
						dissembleIPv4Packet(packet);
						return;
#else // IPV6_ACTIVATE == 1
						T2_PKTDESC_ADD_HDR(packet, ":ipv4");
						T2_PKTDESC_ADD_PROTO(packet, ((ipHeader_t*)pktptr)->ip_p);
#endif // IPV6_ACTIVATE == 1
					} else if ((*pktptr & 0xf0) == 0x60) {
						numV4Packets--;
#if IPV6_ACTIVATE > 0
						packet->layer3Header = (l3Header_t*)pktptr;
						dissembleIPv6Packet(packet);
						return;
#else // IPV6_ACTIVATE == 0
						T2_PKTDESC_ADD_HDR(packet, ":ipv6");
						T2_PKTDESC_ADD_PROTO(packet, ((ip6Header_t*)pktptr)->next_header);
						numV6Packets++;
#endif // IPV6_ACTIVATE == 0
					}
				}
				break;
			}

			default: // every other port = 0
				T2_PKTDESC_ADD_PROTO(packet, packet->layer4Type);
				break;
		}

create_packetF:

		packet->status |= L2_IPV4;

#if AGGREGATIONFLAG & SRCPORT
		packet->srcPort = (packet->srcPort >= SRCPORTLW && packet->srcPort <= SRCPORTHW) ? 1 : 0;
#endif
		hashHelper.srcPort = packet->srcPort;

#if AGGREGATIONFLAG & DSTPORT
		packet->dstPort = (packet->dstPort >= DSTPORTLW && packet->dstPort <= DSTPORTHW) ? 1 : 0;
#endif
		hashHelper.dstPort = packet->dstPort;

#if AGGREGATIONFLAG & L4PROT
		packet->layer4Type = 0;
#endif
		hashHelper.layer4Protocol = packet->layer4Type;

#if (IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0)
		hashHelper.ethType = packet->layer2Type;
#endif

#if SCTP_ACTIVATE == 1
		if (sctpChunkP) hashHelper.sctpStrm = sctpChunkP->sis;
#endif

		flowIndex = hashTable_lookup(mainHashMap, (char*)&hashHelper.srcIP);
		if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) {
			flowIndex = flowCreate(packet, &hashHelper);
			flow = &flows[flowIndex];
		} else {
			flow = &flows[flowIndex];
			updateLRUList(flow);
			if ((uint32_t)ipHeader->ip_id == flow->lastIPID) {
				T2_SET_STATUS(flow, DUPIPID);
#if MULTIPKTSUP == 1
				return;
#endif
			}
			flow->lastIPID = ipHeader->ip_id;
		}

#if FRAGMENTATION >= 1
		if ((ipHeader->ip_off & FRAGIDM_N) == MORE_FRAG_N
#if FRAG_HLST_CRFT == 1
				|| sw_fnohead
#endif
		) { // if 1. fragmented packet or mangled fragment
#if FRAG_HLST_CRFT == 1
			if (sw_fnohead) {
				T2_SET_STATUS(flow, IPV4_FRAG_HDSEQ_ERR);
				//sw_fnohead = 0; // reset error state of fragmentation machine
			}
#endif // FRAG_HLST_CRFT == 1
			numFragV4Packets++;
			T2_SET_STATUS(flow, IPV4_FRAG);
#if ETH_ACTIVATE == 2
			hashHelper.ethDS = ((ethernetHeader_t*)packet->layer2Header)->ethDS;
#endif
			hashHelper.srcIP = packet->srcIP; // flowCreate looked into reverse flow
			hashHelper.dstIP = packet->dstIP; // so set orig flow again
			hashHelper.fragID = ipHeader->ip_id;
			fragPendIndex = HASHTABLE_ENTRY_NOT_FOUND; // no collision

			if (flow->status & IPV4_FRAG_PENDING) {
				hashHelper.fragID = flow->lastFragIPID;
				if (hashTable_remove(fragPendMap, (char*) &hashHelper.srcIP) == HASHTABLE_ENTRY_NOT_FOUND) {
#if VERBOSE > 2
					char srcIP[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, &(hashHelper.srcIP), srcIP, INET_ADDRSTRLEN);
					char dstIP[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, &(hashHelper.dstIP), dstIP, INET_ADDRSTRLEN);
					T2_PWRN("packetCapture", "IPv4 remove IPID notfound: "
							"findex: %"PRIu64", flowIndex: %lu, "
							"srcIP: %s, srcPort: %"PRIu16", "
							"dstIP: %s, dstPort: %"PRIu16", "
							"IPID: 0x%04"PRIx16", flowStat: 0x%016"PRIx64,
							flow->findex, flowIndex,
							srcIP, packet->srcPort,
							dstIP, packet->dstPort,
							ipHeader->ip_id, flow->status);
#endif // VERBOSE > 2
					T2_SET_STATUS(flow, IPV4_FRAG_ERR);
				} else if (flow->lastFragIPID != ipHeader->ip_id) {
					T2_SET_STATUS(flow, IPV4_FRAG_ERR);
				}
				// put back current IPID in hashHelper for the hashtable insert below
				hashHelper.fragID = ipHeader->ip_id;
			} else if ((fragPendIndex = hashTable_lookup(fragPendMap, (char*)&hashHelper.srcIP)) != HASHTABLE_ENTRY_NOT_FOUND) {
				// IPID hash collision between two flows
				flow_t* flow2 = &flows[fragPend[fragPendIndex]];
#if VERBOSE > 2
				T2_PWRN("packetCapture", "two IPv4 flows (%" PRIu64 " and %" PRIu64 ") with same IPID hash", flow2->findex, flow->findex);
				T2_PINF("packetCapture", "removing fragment of flow %" PRIu64, flow2->findex);
#endif
				flow2->status &= ~IPV4_FRAG_PENDING;
				// instead of removing fragment from hashmap here and adding the exact same
				// key below, we just check for collision before adding.
				fragPend[fragPendIndex] = flowIndex;
			}
			// if no collision, add new fragment to hashmap, on collision fragment is already in it.
			if (fragPendIndex == HASHTABLE_ENTRY_NOT_FOUND) {
				fragPendIndex = hashTable_insert(fragPendMap, (char*)&hashHelper.srcIP);
				if (UNLIKELY(fragPendIndex == HASHTABLE_ENTRY_NOT_FOUND)) { // Should not happen
					T2_PERR("packetCapture", "IPv4 frag insert failed: "
							"findex: %"PRIu64", flowIndex: %lu, "
							"srcPort: %"PRIu16", dstPort: %"PRIu16", "
							"IPID: 0x%04"PRIx16", flowStat: 0x%016"PRIx64,
							flow->findex, flowIndex,
							packet->srcPort, packet->dstPort,
							ipHeader->ip_id, flow->status);
					exit(3);
				}
				fragPend[fragPendIndex] = flowIndex;
			}
			flow->lastFragIPID = ipHeader->ip_id;
			flow->status |= IPV4_FRAG_PENDING;
		} else if (flow->status & IPV4_FRAG_PENDING) {
			T2_SET_STATUS(flow, IPV4_FRAG_ERR);
		}
	} // endif
#endif // FRAGMENTATION

#if ETH_STAT_MODE == 1
	numPacketsL2[packet->outerL2Type]++;
	numBytesL2[packet->outerL2Type] += packet->snapLength;
#else // ETH_STAT_MODE == 0
	numPacketsL2[packet->layer2Type]++;
	numBytesL2[packet->layer2Type] += packet->snapLength;
#endif // ETH_STAT_MODE == 0

	numPacketsL3[packet->layer4Type]++;
	numBytesL3[packet->layer4Type] += packet->snapLength;

	// Layer 2
	FOREACH_PLUGIN_DO(claimL2Info, packet, HASHTABLE_ENTRY_NOT_FOUND);

	// Layer 3
	//FOREACH_PLUGIN_DO(claimL3Info, packet);

#if SCTP_ACTIVATE == 1
	while (1) {
#endif
		T2_SET_STATUS(flow, packet->status);
		flow->lastSeen = packet->pcapHeader->ts;

#if SPKTMD_PKTNO == 1
		if (sPktFile) fprintf(sPktFile, "%"PRIu64"\t", numPackets);
#endif

		// Layer 4
		FOREACH_PLUGIN_DO(claimL4Info, packet, flowIndex);

		if (sPktFile) t2_print_l7payload(sPktFile, packet);

#if SCTP_ACTIVATE == 1
		if (packet->layer4Type != L3_SCTP || sctpChnkLen < 1) break;
		sctpL7P += sctpChnkLen;
		sctpL7Len -= sctpChnkLen;
		if (sctpL7Len < 4) break;

#if ETH_ACTIVATE == 2
		hashHelper.ethDS = ((ethernetHeader_t*)packet->layer2Header)->ethDS;
#endif
		hashHelper.srcIP = packet->srcIP; // flowCreate looked into reverse flow
		hashHelper.dstIP = packet->dstIP; // so set orig flow again
		hashHelper.srcPort = packet->srcPort;
		hashHelper.dstPort = packet->dstPort;

		sctpChunkP = (sctpChunk_t*)sctpL7P;
		sctpChnkLen = ntohs(sctpChunkP->len);
		packet->layer7SCTPHeader = sctpL7P;
		if ((sctpChunkP->type & SCTP_C_TYPE) == 0) {
			hashHelper.sctpStrm = sctpChunkP->sis;
			packet->layer7Header += sctpChnkLen;
			if (sctpL7Len >= sctpChnkLen) {
				packet->snapSCTPL7Length = sctpChnkLen;
				packet->snapL7Length = sctpChnkLen - 16;
			} else {
				packet->snapSCTPL7Length = sctpL7Len;
				packet->snapL7Length = sctpL7Len - 16;
			}
			packet->packetL7Length = sctpChnkLen - 16;
			packet->packetLength = packet->packetL7Length;
		} else {
			hashHelper.sctpStrm = 0;
			packet->layer7Header += sctpChnkLen;
			packet->snapSCTPL7Length = sctpChnkLen;
			packet->snapL7Length = 0;
		}

		flowIndex = hashTable_lookup(mainHashMap, (char*)&hashHelper.srcIP);
		if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) {
			flowIndex = flowCreate(packet, &hashHelper);
			flow = &flows[flowIndex];
		} else {
			flow = &flows[flowIndex];
			updateLRUList(flow);
		}
	}
#endif // SCTP_ACTIVATE == 1

	if (flow->status & L3FLOWINVERT) {
		numBPackets++;
		numBBytes += packet->snapLength;
	} else {
		numAPackets++;
		numABytes += packet->snapLength;
	}
}
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2


static inline unsigned long flowCreate(packet_t *packet, flow_t *hashHelper) {
	const unsigned long flowIndex = hashTable_insert(mainHashMap, (char*)&hashHelper->srcIP);
	if (UNLIKELY(flowIndex == HASHTABLE_ENTRY_NOT_FOUND)) {
		T2_PERR("flowCreate", "failed to insert flow into mainHashMap"); // Should not happen
		exit(1);
	}

	flow_t * const flow = &flows[flowIndex];
	memset(flow, '\0', sizeof(flow_t));

	flow->timeout = FLOW_TIMEOUT;
	flow->flowIndex = flowIndex;
	flow->oppositeFlowIndex = HASHTABLE_ENTRY_NOT_FOUND;
	flow->firstSeen = packet->pcapHeader->ts;
	flow->lastSeen = flow->firstSeen;
#if ETH_ACTIVATE == 2
	flow->ethDS = ((ethernetHeader_t*)packet->layer2Header)->ethDS;
#endif
#if (IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0)
	flow->ethType = packet->layer2Type;
#endif
	flow->vlanID = packet->innerVLANID;
	flow->srcIP = packet->srcIP;
	flow->dstIP = packet->dstIP;
	flow->srcPort = packet->srcPort;
	flow->dstPort = packet->dstPort;
	flow->layer4Protocol = packet->layer4Type;
#if SCTP_ACTIVATE == 1
	flow->sctpStrm = hashHelper->sctpStrm;
#endif

	if (PACKET_IS_IPV6(packet)) {
		T2_SET_STATUS(flow, L2_IPV6);
	} else {
		flow->lastIPID = UINT32_MAX;
		T2_SET_STATUS(flow, L2_IPV4);
	}

	// append the flow at the head of the LRU list
	updateLRUList(flow);

	// check whether the reverse flow exists and link both flows
#if ETH_ACTIVATE == 2
	char a[ETH_ALEN];
	memcpy(a, &hashHelper->ethDS, ETH_ALEN);
	memcpy(&hashHelper->ethDS, flow->ethDS.ether_shost, ETH_ALEN);
	memcpy(hashHelper->ethDS.ether_shost, a, ETH_ALEN);
#endif // ETH_ACTIVATE == 2
	hashHelper->srcIP = hashHelper->dstIP; // set ipHeader because now: sip dm dip sm
	hashHelper->dstIP = packet->srcIP;
	hashHelper->srcPort = packet->dstPort;
	hashHelper->dstPort = packet->srcPort;

	const unsigned long reverseFlowIndex = hashTable_lookup(mainHashMap, (char*)&hashHelper->srcIP);
	if (UNLIKELY(reverseFlowIndex == flowIndex)) {
		T2_SET_STATUS(flow, LANDATTACK);
		flow->findex = ++totalfIndex;
		totalAFlows++;
	} else if (reverseFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
		// reverse flow is in the hashTable
		flow_t * const revflow = &flows[reverseFlowIndex];
		revflow->oppositeFlowIndex = flowIndex;
		flow->oppositeFlowIndex = reverseFlowIndex;
		flow->findex = revflow->findex;
		totalBFlows++;
		if (!(revflow->status & L3FLOWINVERT)) flow->status |= L3FLOWINVERT;
	} else {
#if SCTP_ACTIVATE == 1 && SCTP_STATFINDEX == 1
		if (packet->layer4Type == L3_SCTP) {
			const uint16_t i = hashHelper->sctpStrm;
			hashHelper->sctpStrm = 0;
			const unsigned long fidx = hashTable_lookup(mainHashMap, (char*)&hashHelper->srcIP);
			flow->sctpStrm = i;
			flow->sctpFindex = fidx;
			if (fidx == HASHTABLE_ENTRY_NOT_FOUND) {
				++totalfIndex;
			}
			flow->findex = totalfIndex;
		} else
#endif
			flow->findex = ++totalfIndex;

		totalAFlows++;

		// check flow direction
		if ((packet->srcPort < 1024 && packet->srcPort < packet->dstPort) ||
				(packet->layer4Type == L3_TCP && ((*((char*)packet->layer4Header + 13) & TH_SYN_ACK) == TH_SYN_ACK)))
		{
			flow->status |= L3FLOWINVERT;
		}
	}

	if (++maxNumFlows > maxNumFlowsPeak) maxNumFlowsPeak = maxNumFlows;

	FOREACH_PLUGIN_DO(onFlowGen, packet, flowIndex);

	return flowIndex;
}


inline void dissembleIPv6Packet(packet_t *packet) {
	uint16_t ip6HDLen = 40, ip6THDLen = 40;
	uint8_t nxtHdr;
#if IPV6_ACTIVATE > 0 || PACKETLENGTH <= 1
	int32_t packetLen;
#endif

#if IPV6_ACTIVATE > 0

#if FRAGMENTATION == 1 && FRAG_HLST_CRFT == 1
	uint64_t sw_fnohead = 0;
#endif

	flow_t *flow;
	unsigned long flowIndex;
#endif // IPV6_ACTIVATE > 0

#if SCTP_ACTIVATE == 1
	int32_t sctpL7Len = 0, sctpChnkLen = 0;
	sctpChunk_t *sctpChunkP = NULL;
	uint8_t *sctpL7P = NULL;
#endif

	ip6Header_t *ip6Header = (ip6Header_t*) packet->layer3Header;
	ip6FragHdr_t *ip6FragHdr = NULL;
	ip6OptHdr_t *ip6OptHdr = NULL;
	ip6RouteHdr_t *ip6RouteHdr = NULL;

	packet->layer2Type = ETHERTYPE_IPV6;
	packet->layer3Type = packet->layer2Type;
	globalWarn |= L2_IPV6;
	numV6Packets++;

#if IPVX_INTERPRET == 1
	if ((ip6Header->vtc_flw_lbl & 0xf0) != 0x60) {
		T2_PKTDESC_ADD_HDR(packet, ":ipvx");
		T2_SET_STATUS(packet, L3_IPVX);
	} else
#endif
		T2_PKTDESC_ADD_HDR(packet, ":ipv6");

	if (ip6Header->next_header == L3_FRAG6) {
		ip6FragHdr = (ip6FragHdr_t*)(ip6Header + 1);
#if FRAGMENTATION == 0
		// do not handle fragmented packets
		if (ip6FragHdr->frag_off & FRAG6ID_N) {
			T2_PKTDESC_ADD_HDR(packet, ":ipv6.fraghdr");
			globalWarn |= IPV4_FRAG;
			numFragV6Packets++;
			return;
		}
#endif // FRAGMENTATION
	}

	uint16_t i = (uint16_t)((uint8_t*) packet->layer3Header - (uint8_t*) packet->layer2Header); // L2,VLAN length
	packet->snapL3Length = packet->snapL2Length - i; // L3 Packet length
	packet->l2HdrLen = i;
	const uint16_t l3Len = ntohs(ip6Header->payload_len) + 40; // get IP packet length from IP header
	const uint16_t l2Len = l3Len + i;
	packet->packetL2Length = l2Len;
	bytesOnWire += l2Len; // estimate all Ethernet & IP bytes seen on wire

	// Layer3 snaplength too short or IP packet too short?
	if (packet->snapL3Length < l3Len) {
		packet->status |= L3SNAPLENGTH;
		if (!(globalWarn & L3SNAPLENGTH)) { // Snap length warning
			globalWarn |= L3SNAPLENGTH;
#if VERBOSE > 0
			T2_WRN("snapL2Length: %"PRIu32" - snapL3Length: %"PRIu32" - IP length in header: %d", packet->snapL2Length, packet->snapL3Length, l3Len);
#endif
		}
	} else if (packet->snapL3Length > l3Len) {
		packet->snapL2Length = l2Len;
		packet->snapL3Length = l3Len;
	}

#if IPV6_ACTIVATE > 0 || PACKETLENGTH <= 1
#if PACKETLENGTH == 0
	packetLen = l2Len;
#else // PACKETLENGTH != 0
	packetLen = l3Len;
#endif // PACKETLENGTH != 0
#endif // IPV6_ACTIVATE > 0 || PACKETLENGTH <= 1

	// -------------------- layer3 ------------------------

#if PACKETLENGTH <= 1
	packet->packetLength = packetLen;
#endif

	// set layer4Type already for global plugins such as protoStats
	nxtHdr = ip6Header->next_header;
	packet->layer4Type = nxtHdr;

#if GRE == 1
	uint32_t *grePPP, *greHD;
#endif

#if IPV6_ACTIVATE > 0 || SCTP_ACTIVATE == 1
	uint16_t l4HdrOff = 8;
#endif

	for (uint_fast32_t j = 0; j < MAXHDRCNT; j++) {
		packet->srcPort = 0;
		packet->dstPort = 0;
		packet->layer4Header = (l4Header_t*) ((uint8_t*)ip6Header + ip6HDLen); // adjust header to the beginning of the encapsulated protocol
		switch (nxtHdr) {
			case L3_IPIP4: { // IPv4 in IPv6
				numV6Packets--;
				const char *hp = (char*)packet->layer3Header;
				hp += ip6HDLen;
#if IPIP == 1 && (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
				packet->layer3Header = (l3Header_t*)hp;
				dissembleIPv4Packet(packet);
				return;
#else // IPIP == 0 || IPV6_ACTIVATE == 1
				T2_PKTDESC_ADD_HDR(packet, ":ipv4");
				T2_PKTDESC_ADD_PROTO(packet, ((ipHeader_t*)hp)->ip_p);
				j = MAXHDRCNT;
				l4HdrOff = 0;
				numV4Packets++;
				break;
#endif // IPV6_ACTIVATE == 1
			}

			case L3_HHOPT6: // options
				T2_PKTDESC_ADD_HDR(packet, ":ipv6.hopopts");
				ip6OptHdr = (ip6OptHdr_t*)packet->layer4Header;
				packet->ip6HHOptHdr = ip6OptHdr;
				goto dopt6p;

			case L3_DOPT6:
				T2_PKTDESC_ADD_HDR(packet, ":ipv6.dstopts");
				ip6OptHdr = (ip6OptHdr_t*)packet->layer4Header;
				packet->ip6DOptHdr = ip6OptHdr;

dopt6p:				nxtHdr = ip6OptHdr->next_header;
				i = (ip6OptHdr->len + 1) << 3;
				ip6HDLen += i;
				ip6THDLen += i;
				continue;

			case L3_ICMP6:
				T2_PKTDESC_ADD_HDR(packet, ":icmpv6");
#if IPV6_ACTIVATE > 0
				l4HdrOff = sizeof(icmpHeader_t);
#endif
				j = MAXHDRCNT;
				break;

			case L3_TCP:
				T2_PKTDESC_ADD_HDR(packet, ":tcp");
#if IPV6_ACTIVATE > 0
				l4HdrOff = packet->layer4Header->tcpHeader.doff << 2;
#endif
				if (l3Len < 40) {
					T2_SET_STATUS(packet, L4HDRSHRTLEN);
				} else {
					const uint16_t sport = ntohs(packet->layer4Header->tcpHeader.source);
					const uint16_t dport = ntohs(packet->layer4Header->tcpHeader.dest);
					packet->srcPort = sport;
					packet->dstPort = dport;
					if ((dport == UPNP_PORT && sport > 1024) ||
					    (sport == UPNP_PORT && dport > 1024))
					{
						T2_PKTDESC_ADD_HDR(packet, ":ssdp");
						T2_SET_STATUS(packet, L4_UPNP);
					}
				}
				j = MAXHDRCNT;
				break;

			case L3_UDPLITE:
			case L3_UDP:
				if (nxtHdr == L3_UDPLITE) {
					T2_PKTDESC_ADD_HDR(packet, ":udplite");
				} else {
					T2_PKTDESC_ADD_HDR(packet, ":udp");
				}
#if IPV6_ACTIVATE > 0
				l4HdrOff = 8;
#endif
				if (l3Len < 40) {
					T2_SET_STATUS(packet, L4HDRSHRTLEN);
				} else {
					const uint16_t sport = ntohs(packet->layer4Header->udpHeader.source);
					const uint16_t dport = ntohs(packet->layer4Header->udpHeader.dest);
					packet->srcPort = sport;
					packet->dstPort = dport;
#if L2TP == 1
					if (sport == L2TP_PORT || dport == L2TP_PORT) {
						T2_PKTDESC_ADD_HDR(packet, ":l2tp");
						T2_SET_STATUS(packet, L2_L2TP);
						packet->layer3Type = L2TP_V2;
						uint16_t *l2TPPP = (uint16_t*) packet->layer4Header;
						packet->l2tpLayer3Hdr = packet->layer3Header;
						l2TPPP += 4; // advance to L2TP
						const uint16_t * const l2TPH = l2TPPP;
						packet->l2TPHdr = l2TPH;
						if ((*l2TPH & (L2TP_TYP | L2TP_RES | L2TP_VER)) != L2TP_V2) return; // only data
						// advance to L3 header, later version: supply L2TP, PPP parameters for plugins
						l2TPPP++;
						if (*l2TPH & L2TP_LEN) l2TPPP++;
						l2TPPP += 2; // tunnel / session ID
						if (*l2TPH & L2TP_SQN) l2TPPP += 2;
						if (*l2TPH & L2TP_OFF) l2TPPP += (ntohs(*l2TPPP) >> 1) + 1;

						//if (*l2TPPP == PPP_ADD_CTL) { // HDLC PPP present 0xff03
							T2_SET_STATUS(packet, L2_PPP);
							T2_PKTDESC_ADD_HDR(packet, ":ppp");
							packet->pppHdr = (pppHu_t*)l2TPPP; // save PPP header
							l2TPPP++; // advance HDLC PPP header add field 0xff03, following HDLC PPP encapsulated prot code

							if (*l2TPPP == PPP_MPn) { // PPP multilink protocol
								T2_PKTDESC_ADD_HDR(packet, ":mp");
								l2TPPP += 3; // skip protocol and multilink header
							}

							if (*l2TPPP == PPP_IP6n) { // PPP IPv6 encapsulation only
								packet->layer2Type = L2TP_V2;
								packet->layer3Header = (l3Header_t*) (uint8_t*)(++l2TPPP);
								packet->layer3Type = ETHERTYPE_IPV6;
								ip6Header = (ip6Header_t*) packet->layer3Header;
							} else {
								T2_PKTDESC_ADD_PPPPROTO(packet, *l2TPPP);
								return;
							}
						//} else { // TODO: check for IPC etc
						//	return;
						//}
					}
#endif // L2TP == 1

					if ((dport == UPNP_PORT && sport > 1024) ||
					    (sport == UPNP_PORT && dport > 1024))
					{
						T2_PKTDESC_ADD_HDR(packet, ":ssdp");
						T2_SET_STATUS(packet, L4_UPNP);
					}

					if (sport == 9899 && dport == 9899) { // SCTP tunneling ports
#if SCTP_ACTIVATE == 1
						packet->layer4Header = (l4Header_t*) (((uint8_t*)(packet->layer4Header))+8);
						nxtHdr = L3_SCTP;
						goto sctp6;
#else // SCTP_ACTIVATE == 0
						//T2_SET_STATUS(packet, L2_SCTPTNL);
#endif // SCTP_ACTIVATE
					}
				}
				j = MAXHDRCNT;
				break;

			case L3_IPIP6: { // IPv6 encapsulation
				T2_PKTDESC_ADD_HDR(packet, ":ipv6");
				T2_SET_STATUS(packet, L3_IPIP);
#if IPIP == 0
				j = MAXHDRCNT;
				break;
#else // IPIP == 1
				char *hp = (char*)packet->layer3Header + 40;
				packet->layer3Header = (l3Header_t*)hp;
				ip6Header = (ip6Header_t*) packet->layer3Header;
				nxtHdr = ip6Header->next_header;
				ip6THDLen += 40;
				ip6HDLen = 40;
				continue;
#endif // IPIP == 1
			}

			case L3_ROUT6: // routing
				T2_PKTDESC_ADD_HDR(packet, ":ipv6.routing");
				ip6RouteHdr = (ip6RouteHdr_t*)packet->layer4Header;
				nxtHdr = ip6RouteHdr->next_header;
				i = (ip6RouteHdr->len + 1) << 3;
				ip6HDLen += i;
				ip6THDLen += i;
				continue;

			case L3_FRAG6: // fragmentation
				T2_PKTDESC_ADD_HDR(packet, ":ipv6.fraghdr");
				ip6FragHdr = (ip6FragHdr_t*)packet->layer4Header;
				numFragV6Packets++;
#if FRAGMENTATION == 0
				// do not handle fragmented packets
				if (ip6FragHdr->frag_off & FRAG6ID_N) {
					globalWarn |= IPV4_FRAG;
					return; // fragmentation switch off: ignore fragmented packets except the 1. protocol header
				}
#endif // FRAGMENTATION
				nxtHdr = ip6FragHdr->next_header;
				packet->ip6FragHdr = ip6FragHdr;
				ip6HDLen += 8;
				ip6THDLen += 8;
				if (ip6FragHdr->frag_off & FRAG6ID_N) { // 2nd++ fragmented packet
					j = MAXHDRCNT;
					break;
				}
				continue;

			case L3_GRE:
				T2_PKTDESC_ADD_HDR(packet, ":gre");
#if GRE == 1
				grePPP = (uint32_t*) packet->layer4Header;
				T2_SET_STATUS(packet, L2_GRE);
				numGREPackets++;
				greHD = grePPP++;
				packet->greHdr = (greHeader_t*)greHD;
				packet->greLayer3Hdr = packet->layer3Header;
				if (*greHD & GRE_CKSMn) grePPP++;
				if (*greHD & GRE_RTn) grePPP++;
				if (*greHD & GRE_KEYn) grePPP++;
				if (*greHD & GRE_SQn) grePPP++;
				if (*greHD & GRE_SSRn) grePPP++;
				if (*greHD & GRE_ACKn) grePPP++;
				if ((*greHD & GRE_PROTOn) == GRE_IP6n) {
					packet->layer3Header = (l3Header_t*)grePPP;
					packet->layer3Type = (uint16_t)(*greHD & GRE_PROTOn);
					ip6Header = (ip6Header_t*) packet->layer3Header;
					ip6THDLen += 40;
					ip6HDLen = 40;
					continue;
				} else if ((*greHD & GRE_PROTOn) == GRE_PPPn) {
					T2_PKTDESC_ADD_HDR(packet, ":ppp");
					T2_SET_STATUS(packet, L2_PPP);
					packet->pppHdr = (pppHu_t*)grePPP; // save PPP header
					if ((*grePPP & 0x000000ff) == GRE_PPP_CMPRSS) {
						// compressed, no readable header; info for later processing of flow
						T2_PKTDESC_ADD_HDR(packet, ":comp_data");
						T2_SET_STATUS(packet, (PPP_NRHD | STPDSCT));
						j = MAXHDRCNT;
						break;
					} else if (((pppHdr_t*)grePPP)->prot == PPP_IP6n) {
						packet->layer3Header = (l3Header_t*) (uint8_t*)(++grePPP);
						packet->layer3Type = ETHERTYPE_IPV6;
						ip6Header = (ip6Header_t*)packet->layer3Header;
						ip6THDLen += 40;
						ip6HDLen = 40;
						continue;
					} else {
						// Enhanced GRE (1) with payload length == 0
						if ((*greHD & GRE_Vn) == 0x100 && (*(uint16_t*)((uint16_t*)greHD + 2) == 0)) {
							packet->pppHdr = NULL; // reset PPP header (not present)
						} else {
							T2_PKTDESC_ADD_PPPPROTO(packet, ((pppHdr_t*)grePPP)->prot);
						}
						T2_SET_STATUS(packet, STPDSCT);
						j = MAXHDRCNT;
						break;
					}
				} else if ((*greHD & GRE_PROTOn) == GRE_TEBn) {
					const char *hp = (char*)grePPP + 12;
					packet->layer3Header = (l3Header_t*)(hp+2);
					ip6Header = (ip6Header_t*)packet->layer3Header;
					packet->layer3Type = ntohs(*(uint16_t*)hp);
					ip6THDLen += 40;
					ip6HDLen = 40;
					continue;
				} else {
					T2_PKTDESC_ADD_ETHPROTO(packet, ((*greHD & GRE_PROTOn) >> 16));
					T2_SET_STATUS(packet, STPDSCT);
					j = MAXHDRCNT;
					break;
				}

#else // GRE == 0
#if IPV6_ACTIVATE > 0
				if (!(*(uint16_t*)packet->layer4Header & 0x000080f0)) l4HdrOff = 8;
#endif
#endif // GRE == 0
				j = MAXHDRCNT;
				break;

			case L3_AH: { // authentication header
				T2_PKTDESC_ADD_HDR(packet, ":ah");
				const ip6AHHdr_t * const ip6AHHdr = (ip6AHHdr_t*)packet->layer4Header;
				T2_SET_STATUS(packet, L3_IPSEC_AH);
				nxtHdr = ip6AHHdr->next_header;
				i = (ip6AHHdr->len + 2) << 2;
				ip6HDLen = i;
				ip6THDLen += i;
				continue;
			}

#if ETHIP == 1
			case L3_ETHIP: { // ethernet within ipv6
				uint8_t *hp = (uint8_t*)packet->layer3Header + ip6HDLen;
				if ((*hp & 0xf0) < ETHIPVERN) return;
				const uint8_t * const hp1 = hp;
				T2_PKTDESC_ADD_HDR(packet, ":etherip");
				T2_PKTDESC_ADD_HDR(packet, ":eth");
				T2_SET_STATUS(packet, L3_ETHIPF);
				i = (uint16_t)(hp - (uint8_t*)packet->layer2Header) + 2; // L2,VLAN length
				packet->snapL2Length -= i;
				packet->layer2Header = (l2Header_t*)(hp+2);

				hp += 14;

				// check for 802.1Q/ad signature (VLANs)
				_8021Q_t *shape = (_8021Q_t*)hp;
				shape = t2_process_vlans(shape, packet);
				hp = (uint8_t*)shape + 2;
				if (shape->identifier == ETHERTYPE_IPV6n) {
					packet->layer3Header = (l3Header_t*)hp;
					T2_PKTDESC_ADD_HDR(packet, ":ipv6");
					ip6Header = (ip6Header_t*)hp;
					packet->layer3Type = ntohs(*(uint16_t*)(hp-2));
					ip6HDLen = 40;
					ip6THDLen += (40 + (uint16_t)(hp1 - hp));
					continue;
				} else if (shape->identifier == ETHERTYPE_IPn) {
					numV6Packets--;
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
					packet->layer3Header = (l3Header_t*)hp;
					dissembleIPv4Packet(packet);
					return;
#else // IPV6_ACTIVATE == 1
					T2_PKTDESC_ADD_HDR(packet, ":ipv4");
					numV4Packets++;
#endif // IPV6_ACTIVATE == 1
				} else {
					T2_PKTDESC_ADD_ETHPROTO(packet, shape->identifier);
				}
#if IPV6_ACTIVATE > 0
				l4HdrOff = 0;
#endif
				T2_SET_STATUS(packet, STPDSCT);
				j = MAXHDRCNT;
				break;
			}
#endif // ETHIP == 1

			case L3_OSPF:
				T2_PKTDESC_ADD_HDR(packet, ":ospf");
#if IPV6_ACTIVATE > 0
				l4HdrOff = 16;
#endif
				j = MAXHDRCNT;
				break;

			case L3_L2TP: // L2TPv3
				T2_PKTDESC_ADD_HDR(packet, ":l2tp");
				T2_SET_STATUS(packet, L2_L2TP);
				packet->layer3Type = L2TP_V3;
				j = MAXHDRCNT;
				break;

			case L3_SCTP:
#if SCTP_ACTIVATE == 1
sctp6:
#endif
				T2_PKTDESC_ADD_HDR(packet, ":sctp");
				T2_SET_STATUS(packet, L4_SCTP);
#if IPV6_ACTIVATE > 0 || SCTP_ACTIVATE == 1
				l4HdrOff = 12;
#endif
				if (l3Len < 36) {
					T2_SET_STATUS(packet, L4HDRSHRTLEN);
				} else {
					packet->srcPort = ntohs(packet->layer4Header->sctpHeader.source);
					packet->dstPort = ntohs(packet->layer4Header->sctpHeader.dest);
				}
#if SCTP_ACTIVATE == 1
				packet->layer7Header = (uint8_t*)packet->layer4Header + l4HdrOff;
				sctpL7P = (uint8_t*)packet->layer7Header;
				packet->layer7SCTPHeader = sctpL7P;
				sctpChunkP = (sctpChunk_t*)sctpL7P;
				sctpChnkLen = ntohs(sctpChunkP->len);
				sctpL7Len = packet->snapL7Length;
				if ((sctpChunkP->type & SCTP_C_TYPE) == 0) {
					packet->layer7Header += 16;
					if (sctpL7Len >= sctpChnkLen) {
						packet->snapSCTPL7Length = sctpChnkLen;
						packet->snapL7Length = sctpChnkLen - 16;
					} else {
						packet->snapSCTPL7Length = sctpL7Len;
						packet->snapL7Length = sctpL7Len - 16;
					}
					packet->packetL7Length = sctpChnkLen - 16;
					packet->packetLength = packet->packetL7Length;
				} else {
					packet->layer7Header += sctpChnkLen;
					packet->snapSCTPL7Length = sctpChnkLen;
					packet->snapL7Length = 0;
				}
#endif // SCTP_ACTIVATE == 1
				j = MAXHDRCNT;
				break;

			case L3_PIM: {
				T2_PKTDESC_ADD_HDR(packet, ":pim");
				const pimHeader_t * const pim = (pimHeader_t*)packet->layer4Header;
				if (pim->type == PIM_TYPE_REGISTER) {
					const uint8_t * const pktptr = ((uint8_t*)pim + PIM_REGISTER_LEN);
					if ((*pktptr & 0xf0) == 0x40) {
						numV6Packets--;
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
						packet->layer3Header = (l3Header_t*)pktptr;
						dissembleIPv4Packet(packet);
						return;
#else // IPV6_ACTIVATE == 1
						T2_PKTDESC_ADD_HDR(packet, ":ipv4");
						T2_PKTDESC_ADD_PROTO(packet, ((ipHeader_t*)pktptr)->ip_p);
						numV4Packets++;
#endif // IPV6_ACTIVATE == 1
					} else if ((*pktptr & 0xf0) == 0x60) {
#if IPV6_ACTIVATE > 0
						numV6Packets--;
						packet->layer3Header = (l3Header_t*)pktptr;
						dissembleIPv6Packet(packet);
						return;
#else // IPV6_ACTIVATE == 0
						T2_PKTDESC_ADD_HDR(packet, ":ipv6");
						T2_PKTDESC_ADD_PROTO(packet, ((ip6Header_t*)pktptr)->next_header);
#endif // IPV6_ACTIVATE == 0
					}
				}
				j = MAXHDRCNT;
				break;
			}

			case L3_NXTH6:
#if IPV6_ACTIVATE > 0
				l4HdrOff = 0;
#endif
				j = MAXHDRCNT;
				break;

			default: // all other protocols not implemented yet
				T2_PKTDESC_ADD_PROTO(packet, nxtHdr);
				j = MAXHDRCNT;
				break;
			}
		}

#if IPV6_ACTIVATE == 0
		return;
	}
#else // IPV6_ACTIVATE > 0

	packet->layer4Type = nxtHdr; // set layer4Type already for global plugins such as protoStats
	packet->l3HdrLen = ip6HDLen;

	// -------------------------------- layer 4 --------------------------------

	if (ip6FragHdr && (ip6FragHdr->frag_off & FRAG6ID_N)) l4HdrOff = 0; // 2nd++ fragmented packet

	packet->l4HdrLen = l4HdrOff;

#if PACKETLENGTH >= 2
	packetLen -= ip6THDLen;
#if PACKETLENGTH == 3 // subtract L4 header
	packetLen -= l4HdrOff;
#endif

	if (packetLen >= 0) {
		packet->packetLength = packetLen;
	} else {
		packet->packetLength = 0;
		T2_SET_STATUS(packet, L4HDRSHRTLEN);
	}
#endif // PACKETLENGTH >= 2

	// -------------------------------- layer 7 --------------------------------

	packet->packetL7Length = l3Len - packet->l3HdrLen - l4HdrOff;

	packet->layer7Header = (uint8_t*)packet->layer4Header + l4HdrOff;

	if (packet->snapL3Length >= l3Len) { // L3 length not snapped
		if (UNLIKELY(packet->snapL3Length < packet->l3HdrLen)) packet->snapL4Length = 0; // return or frag??? todo
		else packet->snapL4Length = l3Len - ip6THDLen; // Protocol L3/4 Hdr lengths are valid
		if (LIKELY(l4HdrOff < packet->snapL4Length)) packet->snapL7Length = packet->snapL4Length - l4HdrOff; // Protocol L3/4 Hdr lengths are valid
		else packet->snapL7Length = 0;
	} else { // L3 length snapped so calculate real hdr L7 length
		if (UNLIKELY(packet->snapL3Length < packet->l3HdrLen)) packet->snapL4Length = 0; // return or frag??? todo
		else packet->snapL4Length = packet->snapL3Length - ip6THDLen;
		packet->snapL7Length = (uint16_t)(packet->layer7Header - (uint8_t*)packet->layer3Header); // offset between L3 and L7
		if (UNLIKELY(packet->snapL3Length < packet->snapL7Length)) packet->snapL7Length = 0;
		else packet->snapL7Length = packet->snapL3Length - packet->snapL7Length; // real L7 length
	}

#if AGGREGATIONFLAG & SUBNET
	//if (subnet_table) {
	//	packet->srcID = subnet_testP(subnet_table, flow->srcIP.s_addr); // subnet test src ip
	//	packet->dstID = subnet_testP(subnet_table, flow->dstIP.s_addr); // subnet test dst ip
	//}
#else // AGGREGATIONFLAG & SUBNET == 0

#if (AGGREGATIONFLAG & SRCIP)
		//ip6Header->ip_src.IP128 &= (__uint128_t)SRCIP6MASKn;
		packet->srcIP.IPv6L[0] = ip6Header->ip_src.IPv6L[0] & be64toh(SRCIP6MSKH);
		packet->srcIP.IPv6L[1] = ip6Header->ip_src.IPv6L[1] & be64toh(SRCIP6MSKL);
#else // (AGGREGATIONFLAG & SRCIP) == 0
		packet->srcIP = ip6Header->ip_src;
#endif // AGGREGATIONFLAG & SRCIP

#if (AGGREGATIONFLAG & DSTIP)
		//ip6Header->ip_dst.IP128 &= (__uint128_t)DSTIP6MASKn;
		packet->dstIP.IPv6L[0] = ip6Header->ip_dst.IPv6L[0] & be64toh(DSTIP6MSKH);
		packet->dstIP.IPv6L[1] = ip6Header->ip_dst.IPv6L[1] & be64toh(DSTIP6MSKL);
#else // (AGGREGATIONFLAG & DSTIP) == 0
		packet->dstIP = ip6Header->ip_dst;
#endif // AGGREGATIONFLAG & DSTIP

#endif // AGGREGATIONFLAG & SUBNET

	flow_t hashHelper = {
#if ETH_ACTIVATE == 2
		.ethDS   = ((ethernetHeader_t*)packet->layer2Header)->ethDS,
#endif
#if (IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0)
		.ethType = packet->layer2Type,
#endif
		.vlanID  = packet->innerVLANID,
		.srcIP   = packet->srcIP,
		.dstIP   = packet->dstIP,
	};

#if FRAGMENTATION == 1
	unsigned long fragPendIndex;

	if (ip6FragHdr && (ip6FragHdr->frag_off & FRAG6ID_N)) { // 2nd++ fragmented packet

		hashHelper.fragID = ip6FragHdr->id;
		fragPendIndex = hashTable_lookup(fragPendMap, (char*)&hashHelper.srcIP);

		if (fragPendIndex == HASHTABLE_ENTRY_NOT_FOUND) { // probably missed 1. frag packet or packet mangling
			globalWarn |= (IPV4_FRAG | IPV4_FRAG_HDSEQ_ERR);
#if (VERBOSE > 0 && FRAG_ERROR_DUMP == 1)
			char srcIP[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &(hashHelper.srcIP), srcIP, INET6_ADDRSTRLEN);
			char dstIP[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &(hashHelper.dstIP), dstIP, INET6_ADDRSTRLEN);
			T2_PWRN("packetCapture", "1. frag not found @ %ld.%ld %d %s %d %s %d %d - 0x%08x 0x%04x",
					packet->pcapHeader->ts.tv_sec, (long int)packet->pcapHeader->ts.tv_usec, hashHelper.vlanID,
					srcIP, ntohs(packet->layer4Header->tcpHeader.source),
					dstIP, ntohs(packet->layer4Header->tcpHeader.dest),
					packet->layer4Type, ntohs(hashHelper.fragID), ntohs(ip6FragHdr->frag_off));
#endif // (VERBOSE > 0 && FRAG_ERROR_DUMP == 1)

#if FRAG_HLST_CRFT == 1
			sw_fnohead = IPV4_FRAG_HDSEQ_ERR;
			goto create_packetF6; // we dont know the flow, but create one anyway, because might be interesting crafted packet
#else // FRAG_HLST_CRFT == 0
			return; // we don't know the flow, so ignore packet
#endif // FRAG_HLST_CRFT == 0
		} else {
			numFragV6Packets++;
			flowIndex = fragPend[fragPendIndex];
			flow = &flows[flowIndex];
			if (!(ip6FragHdr->frag_off & MORE_FRAG6_N)) { // remove packet from frag queue when last fragment received
				if (hashTable_remove(fragPendMap, (char*) &hashHelper.srcIP) == HASHTABLE_ENTRY_NOT_FOUND) T2_PWRN("packetCapture", "fragPend remove failed");
				if (flow->status & IPV4_FRAG_PENDING) flow->status &= ~IPV4_FRAG_PENDING;
			}
		}

	} else { // not fragmented or 1. fragmented packet

#if FRAG_HLST_CRFT == 1
create_packetF6:
#endif

#endif // FRAGMENTATION == 1

		packet->status |= L2_IPV6;

#if AGGREGATIONFLAG & SRCPORT
		packet->srcPort = (packet->srcPort >= SRCPORTLW && packet->srcPort <= SRCPORTHW) ? 1 : 0;
#endif
		hashHelper.srcPort = packet->srcPort;

#if AGGREGATIONFLAG & DSTPORT
		packet->dstPort = (packet->dstPort >= DSTPORTLW && packet->dstPort <= DSTPORTHW) ? 1 : 0;
#endif
		hashHelper.dstPort = packet->dstPort;

#if AGGREGATIONFLAG & L4PROT
		packet->layer4Type = 0;
#endif
		hashHelper.layer4Protocol = packet->layer4Type;

#if (IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0)
		hashHelper.ethType = packet->layer2Type;
#endif

#if SCTP_ACTIVATE == 1
		if (sctpChunkP) hashHelper.sctpStrm = sctpChunkP->sis;
#endif

		flowIndex = hashTable_lookup(mainHashMap, (char*)&hashHelper.srcIP);
		if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) {
			flowIndex = flowCreate(packet, &hashHelper);
			flow = &flows[flowIndex];
		} else {
			flow = &flows[flowIndex];
			updateLRUList(flow);
		}

#if FRAGMENTATION >= 1
		if ((ip6FragHdr && (ip6FragHdr->frag_off & MORE_FRAG6_N) == MORE_FRAG6_N) // more flag set
#if FRAG_HLST_CRFT == 1
				|| sw_fnohead
#endif
		) { // if 1. fragmented packet or mangled fragment
#if FRAG_HLST_CRFT == 1
			if (sw_fnohead) {
				T2_SET_STATUS(flow, IPV4_FRAG_HDSEQ_ERR);
				//sw_fnohead = 0; // reset error state of fragmentation machine
			}
#endif // FRAG_HLST_CRFT == 1
			numFragV6Packets++;
			T2_SET_STATUS(flow, IPV4_FRAG);
#if ETH_ACTIVATE == 2
			hashHelper.ethDS = ((ethernetHeader_t*)packet->layer2Header)->ethDS;
#endif
			hashHelper.srcIP = packet->srcIP; // flowCreate looked into reverse flow
			hashHelper.dstIP = packet->dstIP; // so set orig flow again
			hashHelper.fragID = ip6FragHdr->id;
			fragPendIndex = HASHTABLE_ENTRY_NOT_FOUND; // no collision

			if (flow->status & IPV4_FRAG_PENDING) {
				hashHelper.fragID = flow->lastFragIPID;
				if (hashTable_remove(fragPendMap, (char*) &hashHelper.srcIP) == HASHTABLE_ENTRY_NOT_FOUND) {
#if VERBOSE > 2
					char srcIP[INET6_ADDRSTRLEN];
					inet_ntop(AF_INET6, &(hashHelper.srcIP), srcIP, INET6_ADDRSTRLEN);
					char dstIP[INET6_ADDRSTRLEN];
					inet_ntop(AF_INET6, &(hashHelper.dstIP), dstIP, INET6_ADDRSTRLEN);
					T2_PWRN("packetCapture", "IPv6 remove IPID notfound: "
							"findex: %"PRIu64", flowIndex: %lu, "
							"srcIP: %s, srcPort: %"PRIu16", "
							"dstIP: %s, dstPort: %"PRIu16", "
							"IPID: 0x%08"PRIx32", flowStat: 0x%016"PRIx64,
							flow->findex, flowIndex,
							srcIP, packet->srcPort,
							dstIP, packet->dstPort,
							ip6FragHdr->id, flow->status);
#endif // VERBOSE > 2
					T2_SET_STATUS(flow, IPV4_FRAG_ERR);
				} else if (flow->lastFragIPID != ip6FragHdr->id) {
					T2_SET_STATUS(flow, IPV4_FRAG_ERR);
				}
				// put back current IPID in hashHelper for the hashtable insert below
				hashHelper.fragID = ip6FragHdr->id;
			} else if ((fragPendIndex = hashTable_lookup(fragPendMap, (char*)&hashHelper.srcIP)) != HASHTABLE_ENTRY_NOT_FOUND) {
				// IPID hash collision between two flows
				flow_t* flow2 = &flows[fragPend[fragPendIndex]];
#if VERBOSE > 2
				T2_PWRN("packetCapture", "two IPv6 flows (%" PRIu64 " and %" PRIu64 ") with same IPID hash", flow2->findex, flow->findex);
				T2_PINF("packetCapture", "removing fragment of flow %" PRIu64, flow2->findex);
#endif
				flow2->status &= ~IPV4_FRAG_PENDING;
				// instead of removing fragment from hashmap here and adding the exact same
				// key below, we just check for collision before adding.
				fragPend[fragPendIndex] = flowIndex;
			}
			// if no collision, add new fragment to hashmap, on collision fragment is already in it.
			if (fragPendIndex == HASHTABLE_ENTRY_NOT_FOUND) {
				fragPendIndex = hashTable_insert(fragPendMap, (char*)&hashHelper.srcIP);
				if (UNLIKELY(fragPendIndex == HASHTABLE_ENTRY_NOT_FOUND)) { // Should not happen
					T2_PERR("packetCapture", "IPv6 frag insert failed: "
							"findex: %"PRIu64", flowIndex: %lu, "
							"srcPort: %"PRIu16", dstPort: %"PRIu16", "
							"IPID: 0x%08"PRIx32", flowStat: 0x%016"PRIx64,
							flow->findex, flowIndex,
							packet->srcPort, packet->dstPort,
							ip6FragHdr->id, flow->status);
					exit(3);
				}
				fragPend[fragPendIndex] = flowIndex;
			}
			flow->lastFragIPID = ip6FragHdr->id;
			flow->status |= IPV4_FRAG_PENDING;
		} else if (flow->status & IPV4_FRAG_PENDING) {
			T2_SET_STATUS(flow, IPV4_FRAG_ERR);
		}
	}
#endif // FRAGMENTATION

#if ETH_STAT_MODE == 1
	numPacketsL2[packet->outerL2Type]++;
	numBytesL2[packet->outerL2Type] += packet->snapLength;
#else // ETH_STAT_MODE == 0
	numPacketsL2[packet->layer2Type]++;
	numBytesL2[packet->layer2Type] += packet->snapLength;
#endif // ETH_STAT_MODE == 0

	numPacketsL3[packet->layer4Type]++;
	numBytesL3[packet->layer4Type] += packet->snapLength;

	// Layer 2
	FOREACH_PLUGIN_DO(claimL2Info, packet, HASHTABLE_ENTRY_NOT_FOUND);

	// Layer 3
	//FOREACH_PLUGIN_DO(claimL3Info, packet);

#if SCTP_ACTIVATE == 1
	while (1) {
#endif
		T2_SET_STATUS(flow, packet->status);
		flow->lastSeen = packet->pcapHeader->ts;

#if SPKTMD_PKTNO == 1
		if (sPktFile) fprintf(sPktFile, "%"PRIu64"\t", numPackets);
#endif

		// Layer 4
		FOREACH_PLUGIN_DO(claimL4Info, packet, flowIndex);

		if (sPktFile) t2_print_l7payload(sPktFile, packet);

#if SCTP_ACTIVATE == 1
		if (packet->layer4Type != L3_SCTP || sctpChnkLen < 1) break;
		sctpL7P += sctpChnkLen;
		sctpL7Len -= sctpChnkLen;
		if (sctpL7Len < 4) break;

#if ETH_ACTIVATE == 2
		hashHelper.ethDS = ((ethernetHeader_t*)packet->layer2Header)->ethDS;
#endif
		hashHelper.srcIP = packet->srcIP; // flowCreate looked into reverse flow
		hashHelper.dstIP = packet->dstIP; // so set orig flow again
		hashHelper.srcPort = packet->srcPort;
		hashHelper.dstPort = packet->dstPort;

		sctpChunkP = (sctpChunk_t*)sctpL7P;
		sctpChnkLen = ntohs(sctpChunkP->len);
		packet->layer7SCTPHeader = sctpL7P;
		if ((sctpChunkP->type & SCTP_C_TYPE) == 0) {
			hashHelper.sctpStrm = sctpChunkP->sis;
			packet->layer7Header += sctpChnkLen;
			if (sctpL7Len >= sctpChnkLen) {
				packet->snapSCTPL7Length = sctpChnkLen;
				packet->snapL7Length = sctpChnkLen - 16;
			} else {
				packet->snapSCTPL7Length = sctpL7Len;
				packet->snapL7Length = sctpL7Len - 16;
			}
			packet->packetL7Length = sctpChnkLen - 16;
			packet->packetLength = packet->packetL7Length;
		} else {
			hashHelper.sctpStrm = 0;
			packet->layer7Header += sctpChnkLen;
			packet->snapSCTPL7Length = sctpChnkLen;
			packet->snapL7Length = 0;
		}

		flowIndex = hashTable_lookup(mainHashMap, (char*)&hashHelper.srcIP);
		if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) {
			flowIndex = flowCreate(packet, &hashHelper);
			flow = &flows[flowIndex];
		} else {
			flow = &flows[flowIndex];
			updateLRUList(flow);
		}
	}
#endif // SCTP_ACTIVATE == 1

	if (flow->status & L3FLOWINVERT) {
		numBPackets++;
		numBBytes += packet->snapLength;
	} else {
		numAPackets++;
		numABytes += packet->snapLength;
	}
}
#endif // IPV6_ACTIVATE > 0


static inline void t2_dispatch_l2_packet(packet_t *packet) {
	// No flow could be created... flag the packet as L2_FLOW and create a L2 flow
	T2_SET_STATUS(packet, L2_FLOW);

#if ETH_STAT_MODE == 1
	numPacketsL2[packet->outerL2Type]++;
	numBytesL2[packet->outerL2Type] += packet->snapLength;
#else // ETH_STAT_MODE == 0
	numPacketsL2[packet->layer2Type]++;
	numBytesL2[packet->layer2Type] += packet->snapLength;
#endif // ETH_STAT_MODE == 0

#if ETH_ACTIVATE == 0
	FOREACH_PLUGIN_DO(claimL2Info, packet, HASHTABLE_ENTRY_NOT_FOUND);
	return;
#else // ETH_ACTIVATE > 0
	const uint32_t l2_hdrlen = (uint8_t*)packet->layer7Header - (uint8_t*)packet->layer2Header;
	packet->packetL7Length = packet->rawLength - l2_hdrlen;

#if PACKETLENGTH >= 1
	packet->packetLength = packet->packetL7Length;
#else // PACKETLENGTH == 0
	packet->packetLength = packet->rawLength;
#endif // PACKETLENGTH == 0

	packet->snapL3Length = packet->snapL2Length - l2_hdrlen;
	packet->snapL4Length = packet->snapL3Length;
	packet->snapL7Length = packet->snapL4Length;

	packet->l2HdrLen = l2_hdrlen;

	flow_t hashHelper = {
		.ethDS   = ((ethernetHeader_t*)packet->layer2Header)->ethDS,
		.ethType = packet->layer2Type,
		.vlanID  = packet->innerVLANID,
	};

	flow_t *flowP;
	unsigned long flowIndex = hashTable_lookup(mainHashMap, (char*)&hashHelper.srcIP);
	if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) {
		flowIndex = flowETHCreate(packet, &hashHelper);
		flowP = &flows[flowIndex];
	} else {
		flowP = &flows[flowIndex];
		updateLRUList(flowP);
	}

	flowP->lastSeen = packet->pcapHeader->ts;
	T2_SET_STATUS(flowP, packet->status);

#if SPKTMD_PKTNO == 1
	if (sPktFile) fprintf(sPktFile, "%"PRIu64"\t", numPackets);
#endif

	FOREACH_PLUGIN_DO(claimL2Info, packet, flowIndex);

	if (sPktFile) t2_print_l7payload(sPktFile, packet);

	if (flowP->status & L3FLOWINVERT) {
		numBPackets++;
		numBBytes += packet->snapLength;
	} else {
		numAPackets++;
		numABytes += packet->snapLength;
	}
#endif // ETH_ACTIVATE > 0
}


static inline void updateLRUList(flow_t *flow) {
#if FDURLIMIT > 0
	if (!(flow->status & RMFLOW)) {
		// Check whether the A or B flow should be timed-out
		bool rmflow = false;

		const unsigned long reverseFlowIndex = flow->oppositeFlowIndex;
		if (reverseFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
			flow_t * const revflow = &flows[reverseFlowIndex];
			if ((actTime.tv_sec - revflow->firstSeen.tv_sec) >= FDURLIMIT) {
				T2_SET_STATUS(revflow, RMFLOW);
				rmflow = true;
			}
		}

		if (rmflow || (actTime.tv_sec - flow->firstSeen.tv_sec) >= FDURLIMIT) {
			T2_SET_STATUS(flow, RMFLOW);
			rm_flows[num_rm_flows++] = flow; // TODO no need for an array, num_rm_flows is
			                                 // always 0 before entering this function
		}
	}
#endif // FDURLIMIT > 0

	if (lruHead.lruNextFlow != flow) {
		// we have work to do, move flow to the front (head)

		// remove flow from its current position
		if (flow->lruPrevFlow) flow->lruPrevFlow->lruNextFlow = flow->lruNextFlow;
		if (flow->lruNextFlow) flow->lruNextFlow->lruPrevFlow = flow->lruPrevFlow;

		// append it at the head of the LRU list
		flow->lruNextFlow = lruHead.lruNextFlow;
		lruHead.lruNextFlow->lruPrevFlow = flow;
		lruHead.lruNextFlow = flow;
		flow->lruPrevFlow = &lruHead;
	}
}


static inline void t2_print_l7payload(FILE *stream, packet_t *packet) {
#if SPKTMD_PCNTC == 0 && SPKTMD_PCNTH == 0
	t2_discard_trailing_char(stream, '\t');
#else // SPKTMD_PCNTC == 1 || SPKTMD_PCNTH == 1
	const uint8_t * const l7Hdr = packet->layer7Header;
	const uint_fast16_t snaplen = packet->snapL7Length;

	// Print L7 payload as hex
#if SPKTMD_PCNTH == 1
	if (snaplen > 0) {
		fprintf(stream, "0x%02x", l7Hdr[0]);
		for (uint_fast16_t i = 1; i < snaplen; i++) {
			fprintf(stream, " 0x%02x", l7Hdr[i]);
		}
	}
#endif

#if SPKTMD_PCNTC == 1 && SPKTMD_PCNTH == 1
	fputc('\t', stream); // only print a tab if hex content was displayed
#endif

	// Print L7 payload as char
#if SPKTMD_PCNTC == 1
	for (uint_fast16_t i = 0; i < snaplen; i++) {
		if (l7Hdr[i] >= 32 && l7Hdr[i] <= 126) fputc(l7Hdr[i], stream);
		else if (l7Hdr[i] == '\n') fputs("\\n", stream);
		else if (l7Hdr[i] == '\r') fputs("\\r", stream);
		else if (l7Hdr[i] == '\t') fputs("\\t", stream);
		else fputc('.', stream);
	}
#endif

#endif // SPKTMD_PCNTC == 1 || SPKTMD_PCNTH == 1

	fputc('\n', stream);
}
