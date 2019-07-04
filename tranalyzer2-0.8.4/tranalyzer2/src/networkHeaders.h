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

#ifndef __NETWORK_HEADERS_H__
#define __NETWORK_HEADERS_H__

// includes
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#ifdef __APPLE__
#include <sys/time.h>
#else // !__APPLE__
#include <time.h>
#endif // !__APPLE__

// local includes
#include "linktypes.h"


// Constant Definition

// user defines
#define IPV6_ACTIVATE   2 // 0: IPv4 only, 1: IPv6 only, 2: dual mode

#define ETH_ACTIVATE    1 // 0: No Ethernet flows,
                          // 1: Activate Ethernet flows,
                          // 2: Also use Ethernet addresses for IPv4/6 flows

#define SCTP_ACTIVATE   0 // 1: activate SCTP streams -> Flows
#define SCTP_STATFINDEX 1 // 0: findex increments
                          // 1: findex constant for all SCTP streams in a packet

#define MULTIPKTSUP     0 // multi-packet suppression

#define T2_PRI_HDRDESC    1 // 1: keep track of the headers traversed
#define T2_HDRDESC_AGGR   1 // 1: aggregate repetitive headers, e.g., vlan{2}
#define T2_HDRDESC_LEN  128 // max length of the headers description

// OS X fix
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

// Ether Type Defs host order
#define ETHERTYPE_PVSTP          0x010b // PVSTP+
#define ETHERTYPE_IP             0x0800
#define ETHERTYPE_ARP            0x0806
#define ETHERTYPE_CDP            0x2000 // Cisco Discovery Protocol
#define ETHERTYPE_RARP           0x8035
#define ETHERTYPE_VLAN           0x8100 // IEEE 802.1Q
#define ETHERTYPE_IPV6           0x86dd
#define ETHERTYPE_PPP            0x880b
#define ETHERTYPE_MPLS_UNICAST   0x8847
#define ETHERTYPE_MPLS_MULTICAST 0x8848
#define ETHERTYPE_PPPoE_D        0x8863
#define ETHERTYPE_PPPoE_S        0x8864
#define ETHERTYPE_JUMBO_LLC      0x8870
#define ETHERTYPE_EAPOL          0x888e // 802.1X Authentication
#define ETHERTYPE_QINQ           0x88a8 // IEEE 802.1ad
#define ETHERTYPE_LLDP           0x88cc
#define ETHERTYPE_LOOP           0x9000

// Ether Type Defs network order
#define ETHERTYPE_LLC_WLCCPn      0x0000 // WLCCP over LLC
#define ETHERTYPE_IDPn            0x0006 // Internetwork Datagram Protocol
#define ETHERTYPE_IPn             0x0008
#define ETHERTYPE_CDPn            0x0020 // Cisco Discovery Protocol / Foundry Discovery Protocol
#define ETHERTYPE_VLANn           0x0081 // IEEE 802.1Q
#define ETHERTYPE_LOOPn           0x0090
#define ETHERTYPE_NHRPn           0x0120 // Next Hop Resolution Protocol (NHRP)
#define ETHERTYPE_DEC_MOPn        0x0260 // DEC MOP Remote Console
#define ETHERTYPE_CFMn            0x0289 // IEEE 802.1ag Connectivity Fault Management (CFM) Protocol
#define ETHERTYPE_VTPn            0x0320 // VLAN Trunking Protocol
#define ETHERTYPE_DEC_DNAn        0x0360 // DEC DNA Routing Protocol
#define ETHERTYPE_PAGPn           0x0401 // Port Aggregation Protocol
#define ETHERTYPE_DTPn            0x0420 // Dynamic Trunk Protocol
#define ETHERTYPE_LATn            0x0460 // DEC Local Area Transfer (LAT)
#define ETHERTYPE_ARPn            0x0608
#define ETHERTYPE_FCoEn           0x0689 // Fibre Channel over Ethernet (FCoE)
#define ETHERTYPE_SLOWn           0x0988 // Slow Protocol
#define ETHERTYPE_PVSTPn          0x0b01 // PVSTP+
#define ETHERTYPE_PPPn            0x0b88
#define ETHERTYPE_TDLSn           0x0d89 // IEEE 802.11 data encapsulation / TDLS
#define ETHERTYPE_UDLDn           0x1101 // Unidirectional Link Detection
#define ETHERTYPE_IPCPn           0x2180 // PPP IP Control Protocol
#define ETHERTYPE_LCPn            0x21c0 // PPP Link Control Protocol
#define ETHERTYPE_CHAPn           0x23c2 // PPP Challenge Handshake Authentication Protocol (CHAP)
#define ETHERTYPE_CBCPn           0x29c0 // PPP Callback Control Protocol
#define ETHERTYPE_WLCCPn          0x2d87 // Cisco Wireless LAN Context Control Protocol (WLCCP)
#define ETHERTYPE_RARPn           0x3580
#define ETHERTYPE_IPXn            0x3781 // Netware IPX/SPX
#define ETHERTYPE_DEC_STPn        0x3880 // DEC Spanning Tree Protocol (STP)
#define ETHERTYPE_WCCPn           0x3e88 // Cisco Web Cache Communication Protocol (WCCP)
#define ETHERTYPE_MPLS_UNICASTn   0x4788
#define ETHERTYPE_MPLS_MULTICASTn 0x4888
#define ETHERTYPE_TEBn            0x5865 // Transparent Ethernet bridging
#define ETHERTYPE_PPPoE_Dn        0x6388
#define ETHERTYPE_PPPoE_Sn        0x6488
#define ETHERTYPE_MS_NLBn         0x6f88 // MS Network Load Balancing
#define ETHERTYPE_JUMBO_LLCn      0x7088
#define ETHERTYPE_EAPOLn          0x8e88 // 802.1X Authentication
#define ETHERTYPE_DDPn            0x9b80 // AppleTalk Datagram Delivery Protocol
#define ETHERTYPE_NDP_Fn          0xa101 // Nortel Discovery Protocol flatnet hello
#define ETHERTYPE_NDP_Sn          0xa201 // Nortel Discovery Protocol segment hello
#define ETHERTYPE_AOEn            0xa288 // ATA over Ethernet
#define ETHERTYPE_QINQn           0xa888 // IEEE 802.1ad
#define ETHERTYPE_VINES_IPn       0xad0b // Banyan Vines IP
#define ETHERTYPE_EDPn            0xbb00 // Extreme Discovery Protocol
#define ETHERTYPE_LWAPPn          0xbb88 // Lightweight Access Point Protocol (LWAPP)
#define ETHERTYPE_ERSPANn         0xbe88 // ERSPAN (encapsulated in GRE)
#define ETHERTYPE_LLDPn           0xcc88
#define ETHERTYPE_IPV6n           0xdd86
#define ETHERTYPE_AARPn           0xf380 // AppleTalk Address Resolution Protocol
#define ETHERTYPE_CCPn            0xfd80 // PPP Compression Control Protocol
#define ETHERTYPE_PTPn            0xf788 // Precision Time Protocol (PTP) over Ethernet (IEEE 1588)

// CISCO
#define ETHERTYPE_CISCO_CGMPn  0x0120 // Cisco Group Management Protocol
#define ETHERTYPE_CISCO_SLARPn 0x3580
#define ETHERTYPE_CISCO_OSIn   0xfefe

// LLC
#define LLC_DSAP_S  0x01
#define LLC_SSAP_CR 0x01
#define LLC_STP     0x42
#define LLC_SNAPC   0xfe
#define LLC_SNAPR   0xff

#define LLC_LEN    0x05dc
#define LLC_DCODE  0x00fe
#define LLC_DCODEn 0xfe00

// LLC SAP
#define LLC_SAP_NULL     0x00 // NULL SAP
#define LLC_SAP_LLC      0x02 // LLC Sublayer Management
#define LLC_SAP_SNA_PATH 0x04 // SNA Path Control
#define LLC_SAP_IP       0x06 // TCP/IP
#define LLC_SAP_SNA1     0x08 // SNA
#define LLC_SAP_SNA2     0x0c // SNA
#define LLC_SAP_PNM      0x0e // Proway Network Management
#define LLC_SAP_NETWARE1 0x10 // NetWare (unofficial?)
#define LLC_SAP_OSINL1   0x14 // ISO Network Layer (OSLAN 1)
#define LLC_SAP_TI       0x18 // Texas Instruments
#define LLC_SAP_OSINL2   0x20 // ISO Network Layer (unofficial?)
#define LLC_SAP_OSINL3   0x34 // ISO Network Layer (unofficial?)
#define LLC_SAP_SNA3     0x40 // SNA
#define LLC_SAP_BSPAN    0x42 // Bridge Spanning Tree Proto
#define LLC_SAP_MMS      0x4e // Manufacturing Message Srv
#define LLC_SAP_OSINL4   0x54 // ISO Network Layer (OSLAN 2)
#define LLC_SAP_8208     0x7e // ISO 8208
#define LLC_SAP_3COM     0x80 // 3COM
#define LLC_SAP_BACNET   0x82 // BACnet
#define LLC_SAP_NESTAR   0x86 // Nestar
#define LLC_SAP_PRO      0x8e // Proway Active Station List
#define LLC_SAP_ARP      0x98 // ARP
#define LLC_SAP_SNAP     0xaa // SNAP
#define LLC_SAP_HPJD     0xb4 // HP JetDirect Printer
#define LLC_SAP_VINES1   0xba // Banyan Vines
#define LLC_SAP_VINES2   0xbc // Banyan Vines
#define LLC_SAP_SNA4     0xc8 // SNA
#define LLC_SAP_LAR      0xdc // LAN Address Resolution
#define LLC_SAP_RM       0xd4 // Resource Management
#define LLC_SAP_IPX      0xe0 // IPX/SPX
#define LLC_SAP_NETBEUI  0xf0 // NetBEUI
#define LLC_SAP_LANMGR   0xf4 // LanManager
#define LLC_SAP_IMPL     0xf8 // IMPL
#define LLC_SAP_UB       0xfa // Ungermann-Bass
#define LLC_SAP_DISC     0xfc // Discovery
#define LLC_SAP_OSI      0xfe // OSI Network Layers
#define LLC_SAP_GLOBAL   0xff // Global SAP

// MPLS
#define BTM_MPLS_STKn16 0x0001
#define BTM_MPLS_STKn32 0x00010000

// L2TP
#define L2TP_V2  0x0200
#define L2TP_V3  0x0300
#define L2TP_RES 0xf000 // Reserved, MUST be 0
#define L2TP_VER 0x0f00
#define L2TP_FLG 0X00ff

#define L2TP_PRI 0x0001
#define L2TP_OFF 0x0002
#define L2TP_SQN 0x0008
#define L2TP_LEN 0x0040
#define L2TP_TYP 0x0080

#define L2TP_PORT   1701
#define L2TP_PORT_N 0xa506 // 1701

// Teredo
#define TRDO_PORT   3544
#define TRDO_PORT_N 0xd80d // 3544

// IPsec
#define UDPENCAP_PORT   4500
#define UDPENCAP_PORT_N 0x9411 // 4500

// SSDP/UPnP
#define UPNP_PORT   1900
#define UPNP_PORT_N 0x6c07 // 1900

// PPP
#define PPP_ADD_CTL     0x03ff // not numbered/listen to all

#define PPP_IP4n        0x2100 // IPv4
#define PPP_IPCPn       0x2180 // IP Control Protocol (IPCP)
#define PPP_LCPn        0x21c0 // Link Control Protocol (LCP)
#define PPP_OSIn        0x2300 // OSI Network Layer
#define PPP_PAPn        0x23c0 // Password Authentication Protocol (PAP)
#define PPP_CHAPn       0x23c2 // Challenge Handshake Authentication Protocol (CHAP)
#define PPP_MPn         0x3d00 // PPP Multilink Protocol
#define PPP_IP6n        0x5700 // IPv6
#define PPP_MPLS_UCASTn 0x8102 // MPLS Unicast
#define PPP_MPLS_MCASTn 0x8302 // MPLS Multicast
#define PPP_COMPRESSn   0xfd00 // PPP Compressed Datagram
#define PPP_CCPn        0xfd80 // Compression Control Protocol

// GRE
#define GRE_CKSMn 0x00000080 // Checksum
#define GRE_RTn   0x00000040 // Routing offset
#define GRE_KEYn  0x00000020 // Key
#define GRE_SQn   0x00000010 // Sequence Number
#define GRE_SSRn  0x00000008 // Strict Source Routing

#define GRE_RECURn 0x00000007 // Recursion control
#define GRE_ACKn   0x00008000 // Acknowledge Number
#define GRE_FLAGSn 0x00007800 // Flags
#define GRE_Vn     0x00000700 // Version

#define GRE_PROTOn 0xffff0000 // encapsulated protocols

// GRE protocols
#define GRE_PPPn        0x0b880000 // PPP
#define GRE_IP4n        0x00080000 // IPv4
#define GRE_WCCPn       0x3e880000 // WCCP
#define GRE_MPLS_UCASTn 0x47880000 // MPLS Unicast
#define GRE_ERSPANn     0xbe880000 // ERSPAN
#define GRE_IP6n        0xdd860000 // IPv6
#define GRE_TEBn        0x58650000 // Transparent Ethernet bridging

// GRE_PPP
#define GRE_PPP_CMPRSS 0xfd

// L4 codes in L3 header
#define L3_HHOPT6   0x00
#define L3_ICMP     0x01
#define L3_IGMP     0x02
#define L3_IPIP4    0x04
#define L3_ST       0x05 // Internet Stream Protocol
#define L3_TCP      0x06
#define L3_CBT      0x07
#define L3_EGP      0x08
#define L3_IGP      0x09
#define L3_UDP      0x11
#define L3_DCCP     0x21 // Datagram Congestion Control Protocol
#define L3_XTP      0x24 // Xpress Transport Protocol
#define L3_DDP      0x25 // Datagram Delivery Protocol
#define L3_IPIP6    0x29
#define L3_ROUT6    0x2b
#define L3_FRAG6    0x2c
#define L3_IDRP     0x2d // Inter-Domain Routing Protocol
#define L3_RSVP     0x2e
#define L3_GRE      0x2f // IPSEC
#define L3_DSR      0x30 // Dynamic Source Routing Protocol
#define L3_ESP      0x32 // IPSEC
#define L3_AH       0x33
#define L3_SWIPE    0x35 // SwIPe
#define L3_NHRP     0x36 // Next Hop Resolution Protocol
#define L3_ICMP6    0x3a
#define L3_NXTH6    0x3b // No next header
#define L3_DOPT6    0x3c
#define L3_OSI      0x50 // ISO Internet Protocol
#define L3_VINES    0x53
#define L3_EIGRP    0x58
#define L3_OSPF     0x59
#define L3_AX25     0x5d
#define L3_ETHIP    0x61
#define L3_PIM      0x67
#define L3_IPCOMP   0x6c // IP Payload Compression Protocol
#define L3_VRRP     0x70
#define L3_PGM      0x71 // PGM Reliable Transport Protocol
#define L3_L2TP     0x73
#define L3_PTP      0x7b
#define L3_SCTP     0x84
#define L3_RSVPE2EI 0x86 // Reservation Protocol (RSVP) End-to-End Ignore
#define L3_MOB6     0x87
#define L3_UDPLITE  0x88 // Lightweight User Datagram Protocol
#define L3_MPLSIP   0x89 // MPLS in IP
#define L3_HIP      0x8b // Host Identity Protocol
#define L3_SHIM6    0x8c

// L4 header definitions: TCP flags

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80

#define TH_SYN_ACK     0x12
#define TH_FIN_ACK     0x11
#define TH_RST_ACK     0x14
#define TH_SYN_FIN     0x03
#define TH_RST_FIN     0x05
#define TH_SYN_FIN_RST 0x07
#define TH_ARSF        0x17
#define TH_NULL        0x00
#define TH_XMAS        0x29
#define TH_ALL_FLAGS   0x3f

// SCTP

#define SCTP_C_TYPE 0x3f // Chunk type mask
#define SCTP_C_TACT 0xc0 // Chunk type action

// Ethernet over IP
#define ETHIPVERN 0x30 // Version

// Fragmentation
#define FRAGID_N    0xff1f
#define MORE_FRAG_N 0x0020
#define FRAGIDM_N   0xff3f
#define FRAGID_1P_N 0x0000

// IPv6 definitions
#define FRAG6ID_N    0xf8ff
#define MORE_FRAG6_N 0x0100
#define FRAG6IDM_N   0xf9ff
#define FRAG6ID_1P_N 0x0000

// structs

// IP address

typedef union {
	uint32_t IPv4x[4];
	struct in_addr  IPv4;  // IPv4 address
	struct in6_addr IPv6;  // IPv6 address
	uint64_t IPv6L[2];     // IPv6 address 2*64 bit max chunk for masking ops
} __attribute__((packed)) ipAddr_t;

typedef struct {
	uint8_t  ver;    // version
	ipAddr_t addr;
} ipVAddr_t;

typedef union {
    uint32_t IPv4x[1];
    struct in_addr IPv4;
} __attribute__((packed)) ip4Addr_t;

// MPLS

typedef struct {
	uint32_t TTL:8;
	uint32_t S:1;
	uint32_t Exp_ToS:3;
	uint32_t label:20;
} mplsHdrh_t;

// Ethernet header

typedef struct {
	uint8_t ether_dhost[ETH_ALEN]; // destination eth addr
	uint8_t ether_shost[ETH_ALEN]; // source ether addr
} __attribute__((packed)) ethDS_t;

typedef struct {
	ethDS_t  ethDS;
	uint16_t ether_type; // packet type ID field or length
	uint16_t data;
} __attribute__((packed)) ethernetHeader_t;

// ISL header

#define ISL_HEADER_LEN      26 // 26-bytes

#define ISL_TYPE_ETHER       0
#define ISL_TYPE_TOKEN_RING  1
#define ISL_TYPE_FDDI        2
#define ISL_TYPE_ATM         3

typedef struct {
	ethDS_t  ether_dhost[ETH_ALEN]; // DA (40 bits), Type (4 bits), User (4 bits)
	ethDS_t  ether_shost[ETH_ALEN];
	uint16_t len;
	uint16_t dssap;    // 0xaa
	uint8_t  control;  // 0x03
	uint8_t  hsa[3];   // High bits of Source Address
	uint16_t vlanID:15;
	uint16_t bpdu:1;
	uint16_t indx;
	uint16_t reserved;
} __attribute__((packed)) islHeader_t;

// LLC

typedef struct {
	uint16_t typ_len;   // ether type or length XXX this does NOT belong to the LLC header...
	uint16_t dssap;     // Destination & Source Service Access Point
	union {
		// command
		struct {
			uint32_t cntrl:8;
			uint32_t org:24;
			uint16_t type;
			uint16_t res;
		} cmd;
		// response
		struct {
			uint16_t cntrl;
			uint16_t org1;
			uint8_t  org2;
			uint16_t type;
			uint8_t  res;
		} res;
	};
} __attribute__((packed)) etherLLCHeader_t;

typedef struct {
	uint16_t typ_len; // ether type or length
	uint16_t dssap;   // Destination & source Service Access Point
	uint8_t  cFlags;
} ethLLCHdr_t;

typedef struct {
	ethLLCHdr_t ethLLCHdr;
	uint8_t  protID;
	uint8_t  verIP;
	uint8_t  bpduType;
	uint8_t  bpduFlags;
	uint64_t rootID;
	uint32_t rootPCost;
	uint64_t brdgID;
	uint16_t portID;
	uint16_t msgAge;
	uint16_t maxAge;
	uint16_t fwrdDel;
	uint8_t  ver1Len;
	uint16_t ver3Len;
} ethLLCMsg_t;

// IP header

typedef struct {
	uint8_t  ip_vhl;               // version, header length
#define IP_V(ip) (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip) ((ip)->ip_vhl & 0x0f)
	uint8_t  ip_tos;               // type of service
	uint16_t ip_len;               // total length
	uint16_t ip_id;                // identification
	uint16_t ip_off;               // fragment offset field
#define IP_DF 0x4000               // dont fragment flag
#define IP_MF 0x2000               // more fragments flag
#define IP_OFFMASK 0x1fff          // mask for fragmenting bits
	uint8_t  ip_ttl;               // time to live
	uint8_t  ip_p;                 // protocol
	uint16_t ip_sum;               // checksum
	struct in_addr ip_src, ip_dst; // source and dest address
} __attribute__((packed)) ipHeader_t;

// IPv6 headers

typedef struct {
	uint32_t vtc_flw_lbl;   // first word: ver, tcl, flow
	uint16_t payload_len;   // payload length
	uint8_t  next_header;   // next protocol
	union {
		uint8_t hop_limit;  // hop limit
		uint8_t ip_ttl;     // TTL
	};
	ipAddr_t ip_src;        // source address
	ipAddr_t ip_dst;        // destination address
} __attribute__((packed)) ip6Header_t;

typedef struct {
	uint8_t  next_header;
	uint8_t  len;
	uint16_t reserved;
	uint32_t spi; // security parameters index
	uint32_t seqnum;
	// Integrity Check Value (ICV): multiple of 32 bits
} ip6AHHdr_t;

typedef struct {
	uint8_t next_header;
	uint8_t len;
	uint8_t options;
} ip6OptHdr_t;

typedef struct {
	uint8_t  next_header;
	uint8_t  res;
	uint16_t frag_off;
	uint32_t id;
} ip6FragHdr_t;

typedef struct {
	uint8_t next_header;
	uint8_t len;
	uint8_t route_type;
	uint8_t seg_left;
} ip6RouteHdr_t;

// TCP header

typedef struct {
	uint16_t source;
	uint16_t dest;
	uint32_t seq;
	uint32_t ack_seq;
	uint16_t res1:4;
	uint16_t doff:4;
	uint16_t fin:1;
	uint16_t syn:1;
	uint16_t rst:1;
	uint16_t psh:1;
	uint16_t ack:1;
	uint16_t urg:1;
	uint16_t res2:2;
	uint16_t window;
	uint16_t check;
	uint16_t urg_ptr;
} __attribute__((packed)) tcpHeader_t;

// SCTP header

typedef struct {
	uint16_t source;
	uint16_t dest;
	uint32_t verTag;
	uint32_t chkSum;
	uint32_t data;
} __attribute__((packed)) sctpHeader_t;

// SCTP chunks

typedef struct {
	uint8_t  type;
	uint8_t  flags;
	uint16_t len;
	union {
		uint32_t tsn_it_cta;
		struct {
			uint16_t cc;
			uint16_t cl;
		};
	};
	union {
		uint32_t arwc;
		struct {
			uint16_t sis;
			uint16_t ssn;
		};
	};
	union {
		uint32_t ppi;
		struct {
			uint16_t nos;
			uint16_t nis;
		};
	};
	union {
		uint32_t itsn;
		struct {
			uint16_t gab;
			uint16_t ndtsn;
		};
		uint8_t a[4];
	};
	union {
		uint32_t data;
		uint8_t  d[4];
	};
} __attribute__((packed)) sctpChunk_t;

// UDP header

typedef struct {
	uint16_t source;
	uint16_t dest;
	uint16_t len;
	uint16_t check;
} __attribute__((packed)) udpHeader_t;

// UDP-Lite header

typedef struct {
	uint16_t source;
	uint16_t dest;
	uint16_t coverage; // checksum coverage
	uint16_t check;
} __attribute__((packed)) udpliteHeader_t;

// ICMP header

typedef struct {
	uint8_t  type;  // message type
	uint8_t  code;  // type sub-code
	uint16_t checksum;
	union {
		// echo datagram
		struct {
			uint16_t id;
			uint16_t sequence;
		} echo;
		// gateway address
		uint32_t gateway;
		// path mtu discovery
		struct {
			uint16_t unused;
			uint16_t mtu;
		} frag;
	} un;
} __attribute__((packed)) icmpHeader_t;

// IGMP header

#define IGMP_TYPE_DVMRP      0x13
#define IGMP_TYPE_PIM        0x14
// RGMP uses the destination address 224.0.0.25
#define IGMP_TYPE_RGMP_LEAVE 0xfc
#define IGMP_TYPE_RGMP_JOIN  0xfd
#define IGMP_TYPE_RGMP_BYE   0xfe
#define IGMP_TYPE_RGMP_HELLO 0xff

#define IGMP_RGMP_DADDRn 0x190000e0 // 224.0.0.25

typedef struct {
	uint8_t  type;
	uint8_t  code;
	uint16_t checksum;
	struct in_addr group; // group address
} __attribute__((packed)) igmpHeader_t;

// PIM header

#define PIM_REGISTER_LEN 8

#define PIM_TYPE_HELLO     0x00
#define PIM_TYPE_REGISTER  0x01
#define PIM_TYPE_REG_STOP  0x02 // Register-Stop
#define PIM_TYPE_JOIN      0x03 // Join/Prune
#define PIM_TYPE_BOOTSTRAP 0x04
#define PIM_TYPE_ASSERT    0x05
#define PIM_TYPE_GRAFT     0x06 // Graft (used in PIM-DM only)
#define PIM_TYPE_GRAFT_ACK 0x07 // Graft-Ack (used in PIM-DM only)
#define PIM_TYPE_CANDIDATE 0x08 // Candidate-RP-Advertisement

typedef struct {
    uint8_t  type:4;
    uint8_t  version:4;
    uint8_t  reserved;
    uint16_t checksum;
} __attribute__((packed)) pimHeader_t;

// VLAN tag, also used for MPLS header

typedef struct {
	uint16_t identifier;
	uint16_t vlanID;
} _8021Q_t;

// PPP header

typedef struct {
	uint16_t addctl;
	uint16_t prot;
} pppHdr_t;

// PPPoE header

typedef struct {
	uint8_t  ver_typ;
	uint8_t  code;
	uint16_t sessID;
	uint16_t len;
	uint16_t pppProt;
} __attribute__((packed)) pppoEH_t;

// GRE encapsulation v1,2

typedef struct {
	uint32_t hdrFlags:5;
	uint32_t recur:3;
	uint32_t ack:1;
	uint32_t flags:4;
	uint32_t ver:3;
	uint32_t proto:16;
	uint16_t plength;
	int16_t  CallID;
} greHeader_t;

// L2TP - Layer 2 Tunneling Protocol v2/3

typedef struct {
	uint16_t res3:4;  // reserved
	uint16_t ver:4;   // L2TP version
	uint16_t type:1;  // message type (0: Data, 1: Control)
	uint16_t len:1;   // message length present
	uint16_t res:2;   // reserved
	uint16_t seq:1;   // sequence numbers present
	uint16_t res2:1;  // reserved
	uint16_t off:1;   // offset number present
	uint16_t prio:1;  // priority (zero on Control messages)
	uint16_t length;  // length
	union {
		struct {
			uint16_t tID;  // tunnel ID, L2TPv2
			uint16_t sID;  // session ID, L2TPv2
		};
		uint32_t ccID;     // Control Connection ID, L2TPv3
	};
	uint16_t sN;      // sequence number
	uint16_t sNExp;   // sequence number expected
	union {
		// L2TPv2
		struct {
			uint16_t offSize; // offset size
			uint16_t offPad;  // offset pad
		};
		// L2TPv3
		uint8_t data[4];
	};
} l2tpv2Header_t;

// general Layer 2 - 4 headers

typedef union {
	mplsHdrh_t mplshs;
	uint32_t   mplshu;
} mplsh_t;

typedef union {
	pppHdr_t pppHdru;
	uint32_t pppHdrc;
} pppHu_t;

typedef union {
	ethernetHeader_t ethernetHeader;
	etherLLCHeader_t etherLLCHeader;
} l2Header_t;

typedef union {
	ipHeader_t  ipHeader;
	ip6Header_t ip6Header;
} __attribute__((packed)) l3Header_t;

typedef union {
	tcpHeader_t  tcpHeader;
	sctpHeader_t sctpHeader;
	udpHeader_t  udpHeader;
	icmpHeader_t icmpHeader;
	igmpHeader_t igmpHeader;
} __attribute__((packed)) l4Header_t;

// a common packet pointer, holds pointers to each layer's header

typedef struct {
#if T2_PRI_HDRDESC == 1
	char hdrDesc[T2_HDRDESC_LEN];                // header description, e.g., eth:ipv4:tcp
	uint16_t hdrDescPos;                         // header description position
	uint16_t numHdrDesc;                         // number of headers description
#endif // T2_PRI_HDRDESC == 1

	const u_char * const raw_packet;             // Pointer to the beginning of the packet
	const u_char * const end_packet;             // Pointer to the end of the packet

	const struct pcap_pkthdr * const pcapHeader; // Network order

	const l2Header_t *layer2Header;              // Network order
	const uint32_t *vlans;                       // Network order, ptr to vlans
	const etherLLCHeader_t *etherLLC;            // Ethernet header LLC part if present
	const uint32_t *mpls;                        // Network order, MPLS pointer

	const l3Header_t *layer3Header;
	const l4Header_t *layer4Header;

	const greHeader_t *greHdr;                   // Network order pointer to GRE v1,2 header
	const uint16_t *l2TPHdr;                     // Network order uint16 pointer to L2TPv2 header
	const l3Header_t *greLayer3Hdr;              // Network order
	const l3Header_t *l2tpLayer3Hdr;             // Network order

	const pppHu_t  *pppHdr;                      // Network order, pointer to PPP header
	const pppoEH_t *pppoEHdr;                    // Network order, pointer to PPPoE header

	const ip6OptHdr_t   *ip6HHOptHdr;
	const ip6OptHdr_t   *ip6DOptHdr;
	const ip6FragHdr_t  *ip6FragHdr;
	const ip6RouteHdr_t *ip6RouteHdr;

	const uint8_t *trdoOIHdr;
	const uint8_t *trdoAHdr;

	const uint8_t *layer7Header;     // pointer to payload

#if SCTP_ACTIVATE == 1
	const uint8_t *layer7SCTPHeader; // pointer to 1. SCTP payload
	uint16_t snapSCTPL7Length;       // Host order, only higher packet payload (layer 7),
	                                 // can be truncated due to limited snaplength
#endif // SCTP_ACTIVATE == 1

	uint16_t l2HdrLen;               // Host order
	uint16_t l3HdrLen;               // Host order
	uint16_t l4HdrLen;               // Host order

	const uint32_t rawLength;        // Host order, extracted from pcapHeader
	const uint32_t snapLength;       // Host order, extracted from pcapHeader

	uint32_t snapL2Length;           // Host order, includes layer2 header, can be truncated due to limited snaplength, will be processed by header dissection
	uint32_t snapL3Length;           // Host order, includes layer3 header, can be truncated due to limited snaplength, derived by header dissection

	uint32_t packetL2Length;         // Host order, derived from IP header length field + length of L2 header
	uint32_t packetLength;           // Host order, derived from IP header length field, defined by PACKETLENGTH in packetCapture.h
	                                 // (0: including L2-4 header, including L3-4 header, 2: including L4 header, 3: Only payload L7)
	uint16_t snapL4Length;           // Host order, includes layer4 header, can be truncated due to limited snaplength, derived by header dissection
	uint16_t snapL7Length;           // Host order, only higher packet payload (layer 7), can be truncated due to limited snaplength, derived by header dissection
	uint16_t packetL7Length;         // Layer7 Length

	uint16_t srcPort, dstPort;       // Host order

	uint16_t innerVLANID;

	uint16_t outerL2Type;            // Ethernet, ...
	uint16_t layer2Type;             // Ethernet, ...
	uint16_t layer3Type;             // IPv4, IPv6, ...

	uint64_t status;

#if IPV6_ACTIVATE > 0
	ipAddr_t srcIP;
	ipAddr_t dstIP;
#else // IPV6_ACTIVATE == 0
	ip4Addr_t srcIP;
	ip4Addr_t dstIP;
#endif // IPV6_ACTIVATE == 0

	uint8_t layer4Type;              // TCP, UDP, ICMP, IGMP, ...
	uint8_t vlanHdrCnt;
	uint8_t mplsHdrCnt;
} packet_t;

typedef struct flow_s {
	struct flow_s *lruNextFlow, *lruPrevFlow; // pointers to the next and previous flow in LRU list

	struct timeval lastSeen;                  // the earliest time we've seen this flow
	struct timeval firstSeen;                 // the first time we've seen this flow
	struct timeval duration;                  // lastSeen-firstSeen. NOTE: Not available before flow completely terminated

	// flow identification

#if IPV6_ACTIVATE > 0
	ipAddr_t srcIP, dstIP;
#else // IPV6_ACTIVATE == 0
	ip4Addr_t srcIP, dstIP;
#endif // IPV6_ACTIVATE == 0

#if ETH_ACTIVATE > 0
	ethDS_t ethDS;
#endif // ETH_ACTIVATE > 0

#if (IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0)
	uint16_t ethType;
#endif // (IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0)

	uint16_t vlanID;

	union {
		struct {
			uint16_t srcPort;
			uint16_t dstPort;
		};
		uint32_t fragID;
	};

#if SCTP_ACTIVATE == 1
	uint16_t sctpStrm;
#endif // SCTP_ACTIVATE == 1

	uint8_t layer4Protocol;

	// flow identification end

	uint64_t findex; // flow index

#if (SCTP_ACTIVATE == 1 && SCTP_STATFINDEX == 1)
	unsigned long sctpFindex;
#endif // (SCTP_ACTIVATE == 1 && SCTP_STATFINDEX == 1)

#if IPV6_ACTIVATE > 0
	uint32_t lastFragIPID; // for fragPend hash cleanup
#else // IPV6_ACTIVATE == 0
	uint16_t lastFragIPID; // for fragPend hash cleanup
#endif // IPV6_ACTIVATE == 0

	uint32_t lastIPID;     // for duplicate IP ID detection

	uint64_t status;                 // status of flow, e.g., fragmentation processing
	unsigned long flowIndex;
	unsigned long oppositeFlowIndex;
	float timeout;                   // the timeout of this flow in seconds
} __attribute__((packed)) flow_t;

#endif // __NETWORK_HEADERS_H__
