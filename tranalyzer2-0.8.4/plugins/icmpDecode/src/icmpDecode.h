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

#ifndef __ICMP_DECODE_H__
#define __ICMP_DECODE_H__

// user defines

#define ICMP_TC_MD     0 // Type code representation: 0: bitfield; 1: explicit array of type code;
                         // 2: type code statistics (not implemented)
#define ICMP_NUM      10 // Number of type and code info / flow (require ICMP_TC_MD == 1)
#define ICMP_FDCORR    1 // Flow direction correction
#define ICMP_PARENT    1 // Whether or not to resolve the parent flow
#define ICMP_STATFILE  1 // Whether or not to print global ICMP statistics in a file

#define ICMP_NOCODE "-"
#define ICMP_SUFFIX "_icmpStats.txt"

// includes

// local includes
#include "global.h"

// ICMP types
#define ICMP4_ECHOREPLY       0 // Echo Reply
#define ICMP4_DEST_UNREACH    3 // Destination Unreachable
#define ICMP4_SOURCE_QUENCH   4 // Source Quench
#define ICMP4_REDIRECT        5 // Redirect (change route)
#define ICMP4_ECHO            8 // Echo Request
#define ICMP4_TIME_EXCEEDED  11 // Time Exceeded
#define ICMP4_PARAMETERPROB  12 // Parameter Problem
#define ICMP4_TIMESTAMP      13 // Timestamp Request
#define ICMP4_TIMESTAMPREPLY 14 // Timestamp Reply
#define ICMP4_INFO_REQUEST   15 // Information Request
#define ICMP4_INFO_REPLY     16 // Information Reply
#define ICMP4_ADDRESS        17 // Address Mask Request
#define ICMP4_ADDRESSREPLY   18 // Address Mask Reply
#define ICMP4_TRACEROUTE     30

// Codes for UNREACH
#define ICMP4_NET_UNREACH     0 // Network Unreachable
#define ICMP4_HOST_UNREACH    1 // Host Unreachable
#define ICMP4_PROT_UNREACH    2 // Protocol Unreachable
#define ICMP4_PORT_UNREACH    3 // Port Unreachable
#define ICMP4_FRAG_NEEDED     4 // Fragmentation Needed/DF set
#define ICMP4_SR_FAILED       5 // Source Route failed
#define ICMP4_NET_UNKNOWN     6
#define ICMP4_HOST_UNKNOWN    7
#define ICMP4_HOST_ISOLATED   8
#define ICMP4_NET_ANO         9
#define ICMP4_HOST_ANO       10
#define ICMP4_NET_UNR_TOS    11
#define ICMP4_HOST_UNR_TOS   12
#define ICMP4_PKT_FILTERED   13 // Packet filtered
#define ICMP4_PREC_VIOLATION 14 // Precedence violation
#define ICMP4_PREC_CUTOFF    15 // Precedence cut off

// Codes for REDIRECT
#define ICMP4_REDIR_NET       0 // Redirect Net
#define ICMP4_REDIR_HOST      1 // Redirect Host
#define ICMP4_REDIR_NETTOS    2 // Redirect Net for TOS
#define ICMP4_REDIR_HOSTTOS   3 // Redirect Host for TOS

// Codes for TIME_EXCEEDED
#define ICMP4_EXC_TTL         0 // TTL count exceeded
#define ICMP4_EXC_FRAGTIME    1 // Fragment Reass time exceeded

// icmp4 bit field length
#define ICMP4_NTYPE          32 // if you change this value: %2 & change the datatype of 'type' if necessary
#define ICMP4_NCODE          16 // if you change this value: %2 & change the datatype of 'code' if necessary

// ICMPv6 types

// Error messages
#define ICMP6_DEST_UNREACH      1 // Destination Unreachable
#define ICMP6_PKT_TOO_BIG       2 // Packet Too Big
#define ICMP6_TIME_EXCEEDED     3 // Time Exceeded
#define ICMP6_PARAM_PROBLEM     4 // Parameter Problem

// Informational messages
#define ICMP6_ECHO            128 // Echo Request
#define ICMP6_ECHOREPLY       129 // Echo Reply

#define ICMP6_MCAST_QUERY     130 // Multicast Listener Query
#define ICMP6_MCAST_REP       131 // Multicast Listener Report
#define ICMP6_MCAST_DONE      132 // Multicast Listener Done
#define ICMP6_RTER_SOLICIT    133 // Router Solicitation
#define ICMP6_RTER_ADVERT     134 // Router Advertisement
#define ICMP6_NBOR_SOLICIT    135 // Neighbor Solicitation
#define ICMP6_NBOR_ADVERT     136 // Neighbor Advertisement
#define ICMP6_REDIRECT_MSG    137 // Redirect Message
#define ICMP6_RTER_RENUM      138 // Router Renumbering
#define ICMP6_NODE_INFO_QUERY 139 // ICMP Node Information Query
#define ICMP6_NODE_INFO_RESP  140 // ICMP Node Information Response
#define ICMP6_INV_NBOR_DSM    141 // Inverse Neighbor Discovery Solicitation Message
#define ICMP6_INV_NBOR_DAM    142 // Inverse Neighbor Discovery Advertisement Message
#define ICMP6_MLD2            143 // Version 2 Multicast Listener Report
#define ICMP6_ADDR_DISC_REQ   144 // Home Agent Address Discovery Request Message
#define ICMP6_ADDR_DISC_REP   145 // Home Agent Address Discovery Reply Message
#define ICMP6_MOB_PREF_SOL    146 // Mobile Prefix Solicitation
#define ICMP6_MOB_PREF_ADV    147 // Mobile Prefix Advertisement
#define ICMP6_CERT_PATH_SOL   148 // Certification Path Solicitation Message
#define ICMP6_CERT_PATH_ADV   149 // Certification Path Advertisement Message
#define ICMP6_EXP_MOBI        150 // Experimental mobility protocols
#define ICMP6_MRD_ADV         151 // Multicast Router Advertisement
#define ICMP6_MRD_SOL         152 // Multicast Router Solicitation
#define ICMP6_MRD_TERM        153 // Multicast Router Termination
#define ICMP6_FMIPV6          154 // FMIPv6 Messages
#define ICMP6_RPL_CTRL        155 // RPL Control Message
#define ICMP6_ILNP_LOC_UP     156 // ILNPv6 Locator Update Message
#define ICMP6_DUP_ADDR_REQ    157 // Duplicate Address Request
#define ICMP6_DUP_ADDR_CONF   158 // Duplicate Address Confirmation

// Codes for UNREACH
#define ICMP6_NO_ROUTE          0 // No route to destination
#define ICMP6_COMM_PROHIBIT     1 // Communication with destination administratively prohibited
#define ICMP6_BEYOND_SCOPE      2 // Beyond scope of source address
#define ICMP6_ADDR_UNREACH      3 // Address unreachable
#define ICMP6_PORT_UNREACH      4 // Port unreachable
#define ICMP6_SR_FAILED         5 // Source address failed ingress/egress policy
#define ICMP6_REJECT            6 // Reject source to destination
#define ICMP6_ERROR_HDR         7 // Error in Source Routing Header

// Codes for TIME_EXCEEDED
#define ICMP6_EXC_HOPS          0 // Hop limit exceeded
#define ICMP6_EXC_FRAGTIME      1 // Fragment Reass time exceeded

// Codes for PARAM_PROBLEM
#define ICMP6_ERR_HDR           0 // Erroneous header field
#define ICMP6_UNRECO_NEXT_HDR   1 // Unrecognized Next Header type
#define ICMP6_UNRECO_IP6_OPT    2 // Unrecognized IPv6 option

// Codes for ROUTER RENUMBERING
#define ICMP6_RR_CMD   0 // Router Renumbering Command
#define ICMP6_RR_RES   1 // Router Renumbering Result
#define ICMP6_RR_RST 255 // Sequence Number Reset

// Codes for ICMP NODE INFO QUERY
#define ICMP6_NIQ_IP6  0 // Data field contains an IPv6 address
#define ICMP6_NIQ_NAME 1 // Data field contains a name or is empty (NOOP)
#define ICMP6_NIQ_IP4  2 // Data field contains an IPv4 address

// Codes for ICMP NODE INFO RESP
#define ICMP6_NIR_SUCC   0 // Successful reply
#define ICMP6_NIR_DENIED 1 // Responder refuses to supply the answer
#define ICMP6_NIR_UNKN   2 // Qtype of the Query is unknown to the Responder

// ICMPv6 bit field length
#define ICMP6_NTYPE     32 // if you change this value: %2 & change the datatype of 'type' if necessary
#define ICMP6_NCODE     16 // if you change this value: %2 & change the datatype of 'code' if necessary

#if ICMP_PARENT == 1 && ETH_ACTIVATE != 2
#define SET_HAS_PARENT() (hasParent = 1)
#else // ICMP_PARENT == 0 || ETH_ACTIVATE == 2
#define SET_HAS_PARENT()
#endif // ICMP_PARENT == 0 || ETH_ACTIVATE == 2

// ICMP status
#define ICMP_STAT_ICMP 0x01 // Flow is ICMP
#define ICMP_STAT_WANG 0x10 // WANG2 Microsoft bandwidth test


// Plugin Structs

typedef struct {
#if ICMP_PARENT == 1 && ETH_ACTIVATE != 2
	uint64_t pfi; // parent flow index
#endif // ICMP_PARENT == 1 && ETH_ACTIVATE != 2
	uint32_t echoReq;
	uint32_t echoRep;
	uint32_t tmStmp;
#if ICMP_TC_MD == 0
	uint32_t type_bfieldH;
	uint32_t type_bfieldL;
	uint16_t code_bfield;
#elif ICMP_TC_MD == 1
	uint8_t type[ICMP_NUM];
	uint8_t code[ICMP_NUM];
//#elif ICMP_TC_MD == 2
//	uint8_t type[ICMP4_NTYPE];
//	uint8_t code[ICMP4_NCODE];
#endif // ICMP_TC_MD
	uint8_t numtc;
	uint8_t stat;
} icmpFlow_t;

extern icmpFlow_t *icmpFlows;

#endif //__ICMP_DECODE_H__
