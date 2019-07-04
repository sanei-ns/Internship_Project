/*
 * stunDecode.h
 *
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
 *     NAT Port Mapping Protocol (NAT-PMP)                     [RFC6886]
 *     Port Control Protocol (PCP)                             [RFC6887] // TODO
 *
 *     Session Traversal Utilities for NAT (STUN)              [RFC5389]
 *     Traversal Using Relays around NAT (TURN)                [RFC5766]
 *     Interactive Connectivity Establishment (ICE)            [RFC5245]
 *     NAT Behavior Discovery Using STUN                       [RFC5780]
 *     Explicit Congestion Notification (ECN) for RTP over UDP [RFC6679]
 *     TURN Extensions for TCP Allocations                     [RFC6062]
 *     TURN Extension for IPv6                                 [RFC6156]
 *
 *     [Microsoft Extensions]
 *     TURN Extensions                                         [MS-TURN]
 *     TURN Bandwidth Management Extensions                    [MS-TURNBW]
 *     ICE Extensions                                          [MS-ICE]
 *     ICE Extensions 2.0                                      [MS-ICE2]
 *
 *     TODO
 *      PCP, SSDP, uPNP, IGD (Apple)
 */

#ifndef __STUN_DECODE_H__
#define __STUN_DECODE_H__

// global includes

// local includes
#include "global.h"

// user defines
#define NAT_PMP       1 // whether or not to analyse NAT-PMP

// plugin defines

/* NAT PMP */
//#define NATPMP_STAT_PORT 5350 // Status port
#define NATPMP_PORT      5351 // UDP

// Opcodes
#define NATPMP_OP_EXTADDR_REQ    0 // External Address Request
#define NATPMP_OP_MAP_UDP_REQ    1 // Map UDP Request
#define NATPMP_OP_MAP_TCP_REQ    2 // Map TCP Request
#define NATPMP_OP_EXTADDR_RESP 128 // External Address Response
#define NATPMP_OP_MAP_UDP_RESP 129 // Map UDP Response
#define NATPMP_OP_MAP_TCP_RESP 130 // Map TCP Response

// Result codes
#define NATPMP_R_SUCCESS  0 // Success
#define NATPMP_R_UNSUP_V  1 // Unsupported version
#define NATPMP_R_REFUSED  2 // Not authorized/refused
#define NATPMP_R_NET_FAIL 3 // Network failure
#define NATPMP_R_OUT_RES  4 // Out of resources
#define NATPMP_R_UNSUP_OP 5 // Unsupported opcode

/* STUN/TURN */
#define STUN_PORT   3478
#define STUNS_PORT  5349

#define STUN_MAGIC_COOKIE 0x42a41221 // network order
#define TURN_MAGIC_COOKIE 0xc64bc672 // network order

#define STUN_HDR_LEN      20
#define STUN_ATTR_HDR_LEN  4

#define STUN_ATTR_STR_MAXLEN    127 // REALM, SERVER, reason_phrases and NONCE
#define STUN_USERNAME_MAXLEN    513
#define STUN_ATTR_SIP_ID_MAXLEN 256

// Since all STUN attributes are padded to a multiple of 4 bytes,
// the last two bits of the 'length' field are always zero.
#define STUN_LEN_IS_VALID(l) (((l) & 0x0300) == 0)

// message type: method, class
// m m m m m c m m m c m m m m

#define STUN_MT_CLASS_N 4
#define STUN_MT_METH_N  8

// class
#define STUN_MT_CLASS(m) ((ntohs(m) & 0x0110) >> 4)
#define STUN_MT_CLASS_TO_INT(m) ((((m) & 0x10) >> 3) | ((m) & 0x01))
#define STUN_C_REQ       0x00
#define STUN_C_INDIC     0x01
#define STUN_C_SUCC_RESP 0x10
#define STUN_C_ERR_RESP  0x11

// method
#define STUN_MT_METH(m) (ntohs(m) & 0x3eef)
#define STUN_M_BINDING         0x0001
#define STUN_M_SHARED_SECRET   0x0002
#define STUN_M_ALLOC           0x0003 // TURN
#define STUN_M_REFRESH         0x0004 // TURN
#define STUN_M_SEND            0x0006 // TURN
#define STUN_M_DATA            0x0007 // TURN
#define STUN_M_CREATE_PERM     0x0008 // TURN, Create Permission
#define STUN_M_CHANNEL_BIND    0x0009 // TURN
#define STUN_M_CONNECT         0x000A // RFC6062
#define STUN_M_CONNECT_BIND    0x000B // RFC6062
#define STUN_M_CONNECT_ATTEMPT 0x000C // RFC6062

// method+class
// Request
#define STUN_M_BINDING_REQ            0x0001
#define STUN_M_SHARED_SECRET_REQ      0x0002
#define STUN_M_ALLOC_REQ              0x0003 // TURN
#define STUN_M_REFRESH_REQ            0x0004 // TURN
#define STUN_M_CREATE_PERM_REQ        0x0008 // TURN, Create Permission
#define STUN_M_CHANNEL_BIND_REQ       0x0009 // TURN
// Indication
#define STUN_M_SEND_INDIC             0x0016 // TURN
#define STUN_M_DATA_INDIC             0x0017 // TURN
// Success Response
#define STUN_M_BINDING_RESP           0x0101
#define STUN_M_SHARED_SECRET_RESP     0x0102
#define STUN_M_ALLOC_RESP             0x0103 // TURN
#define STUN_M_REFRESH_RESP           0x0104 // TURN
#define STUN_M_CREATE_PERM_RESP       0x0108 // TURN, Create Permission
#define STUN_M_CHANNEL_BIND_RESP      0x0109 // TURN
// Error Response
#define STUN_M_BINDING_ERR_RESP       0x0111
#define STUN_M_SHARED_SECRET_ERR_RESP 0x0112
#define STUN_M_ALLOC_ERR_RESP         0x0113 // TURN
#define STUN_M_REFRESH_ERR_RESP       0x0114 // TURN
#define STUN_M_CREATE_PERM_ERR_RESP   0x0118 // TURN, Create Permission
#define STUN_M_CHANNEL_BIND_ERR_RESP  0x0119 // TURN

// attribute type
#define STUN_AT_MAPPED_ADDR          0x0001
#define STUN_AT_RESP_ADDR            0x0002 // Reserved (removed from RFC3489)
#define STUN_AT_CHANGE_ADDR          0x0003 // Reserved (removed from RFC3489), Change Request
#define STUN_AT_SOURCE_ADDR          0x0004 // Reserved (removed from RFC3489)
#define STUN_AT_CHANGED_ADDR         0x0005 // Reserved (removed from RFC3489)
#define STUN_AT_USERNAME             0x0006
#define STUN_AT_PASSWORD             0x0007 // Reserved (removed from RFC3489)
#define STUN_AT_MSG_INTEGRITY        0x0008
#define STUN_AT_ERR_CODE             0x0009
#define STUN_AT_UNKNOWN_ATTR         0x000A
#define STUN_AT_REFLECTED_FROM       0x000B // Reserved (removed from RFC3489)
#define STUN_AT_CHANNEL_NUMBER       0x000C // TURN
#define STUN_AT_LIFETIME             0x000D // TURN
#define STUN_AT_MAGIC_COOKIE         0x000F // TURN-08
#define STUN_AT_BANDWIDTH            0x0010 // TURN, Deprecated
#define STUN_AT_DEST_ADDR            0x0011 // TURN-08
#define STUN_AT_XOR_PEER_ADDR        0x0012 // TURN
#define STUN_AT_DATA                 0x0013 // TURN
#define STUN_AT_REALM                0x0014
#define STUN_AT_NONCE                0x0015
#define STUN_AT_XOR_RELAYED_ADDR     0x0016 // TURN
#define STUN_AT_REQ_ADDR_FAMILY      0x0017 // RFC6156, Requested Address Family
#define STUN_AT_EVEN_PORT            0x0018 // TURN
#define STUN_AT_REQ_TRANSPORT        0x0019 // TURN, Requested Transport
#define STUN_AT_DONT_FRAGMENT        0x001A // TURN
#define STUN_AT_XOR_MAPPED_ADDR      0x0020
#define STUN_AT_TIMER_VAL            0x0021 // TURN, Deprecated
#define STUN_AT_RESERVATION_TOKEN    0x0022 // TURN
#define STUN_AT_PRIORITY             0x0024 // ICE
#define STUN_AT_USE_CANDIDATE        0x0025 // ICE
#define STUN_AT_PADDING              0x0026 // RFC5780
#define STUN_AT_RESP_PORT            0x0027 // RFC5780
#define STUN_AT_MS_VERSION           0x8008 // MS-TURN, TURN protocol version
#define STUN_AT_MS_XOR_MAPPED_ADDR   0x8020 // MS-TURN
#define STUN_AT_SOFTWARE             0x8022
#define STUN_AT_ALT_SERVER           0x8023
#define STUN_AT_CACHE_TIMEOUT        0x8027 // RFC5780
#define STUN_AT_FINGERPRINT          0x8028
#define STUN_AT_ICE_CONTROLLED       0x8029 // ICE
#define STUN_AT_ICE_CONTROLLING      0x802A // ICE
#define STUN_AT_RESPONSE_ORIGIN      0x802B // RFC5780, Useful for detecting double NAT
#define STUN_AT_OTHER_ADDRESS        0x802C // RFC5780, Server second IP address
#define STUN_AT_ECN_CHECK_STUN       0x802D // RFC6679
#define STUN_AT_MS_SEQ_NUM           0x8050 // MS-TURN
#define STUN_AT_CANDIDATE_ID         0x8054 // MS-ICE2
#define STUN_AT_MS_SERVICE_QUALITY   0x8055 // MS-TURN
#define STUN_AT_BANDWIDTH_ACM        0x8056 // MS-TURNBWM, Bandwidth Admission Control Message
#define STUN_AT_BANDWIDTH_RSV_ID     0x8057 // MS-TURNBWM, Bandwidth Reservation Identifier
#define STUN_AT_BANDWIDTH_RSV_AMOUNT 0x8058 // MS-TURNBWM, Bandwidth Reservation Amount
#define STUN_AT_REMOTE_SITE_ADDR     0x8059 // MS-TURNBWM
#define STUN_AT_REMOTE_RELAY_SITE    0x805A // MS-TURNBWM
#define STUN_AT_LOCAL_SITE_ADDR      0x805B // MS-TURNBWM
#define STUN_AT_LOCAL_RELAY_SITE     0x805C // MS-TURNBWM
#define STUN_AT_REMOTE_SITE_ADDR_RP  0x805D // MS-TURNBWM
#define STUN_AT_REMOTE_RELAY_SITE_RP 0x805E // MS-TURNBWM
#define STUN_AT_LOCAL_SITE_ADDR_RP   0x805F // MS-TURNBWM
#define STUN_AT_LOCAL_RELAY_SITE_RP  0x8060 // MS-TURNBWM
#define STUN_AT_SIP_DIALOG_ID        0x8061 // MS-TURNBWM
#define STUN_AT_SIP_CALL_ID          0x8062 // MS-TURNBWM
#define STUN_AT_LOCATION_PROFILE     0x8068 // MS-TURNBWM
#define STUN_AT_IMPLEM_VER           0x8070 // MS-ICE2, Implementation Version
#define STUN_AT_MS_ALT_MAPPED_ADDR   0x8090 // MS-TURN

// MAPPED-ADDRESS Family
#define STUN_MA_FAMILY_IP4 0x01
#define STUN_MA_FAMILY_IP6 0x02

// XOR-MAPPED-ADDRESS
#define STUN_XMA_PORT(p) (htons(ntohs(p) ^ (ntohl(STUN_MAGIC_COOKIE) >> 16)))
#define STUN_XMA_ADDR4(a) (htonl(ntohl(a) ^ ntohl(STUN_MAGIC_COOKIE)))
// TODO If the IP address family is IPv6, X-Address is computed by
// taking the mapped IP address in host byte order, XOR'ing it with
// the concatenation of the magic cookie and the 96-bit transaction
// ID, and converting the result to network byte order
//#define STUN_XMA_ADDR6(a) (a)

#define STUN_ERR_CLASS(e) (ntohl(e) & 0x700)
#define STUN_ERR_NUM(e)   (ntohl(e) & 0x0ff)
#define STUN_ERR_CODE(e)  (ntohl(e) & 0x7ff)

// Error codes
#define STUN_ERR_TRY_ALT            0x300
#define STUN_ERR_BAD_REQ            0x400
#define STUN_ERR_UNAUTHORIZED       0x401
#define STUN_ERR_FORBIDDEN          0x403 // TURN
#define STUN_ERR_UNKN_ATTR          0x420
#define STUN_ERR_ALLOC_MISMATCH     0x437 // TURN, Allocation Mismatch
#define STUN_ERR_STALE_NONCE        0x438
#define STUN_ERR_FAMILY_NOT_SUP     0x440 // RFC6156, Address Family Not Supported
#define STUN_ERR_WRONG_CRED         0x441 // TURN, Wrong Credentials
#define STUN_ERR_UNSUP_PROTO        0x442 // TURN, Unsupported Transport Protocol
#define STUN_ERR_PA_FAMILY_MISMATCH 0x443 // RFC6156, Peer Address Family Mismatch
#define STUN_ERR_CONN_EXISTS        0x446 // RFC6062, Connection Already Exists
#define STUN_ERR_CONN_TIMEOUT       0x447 // RFC6062, Connection Timeout or Failure
#define STUN_ERR_ALLOC_QUOTA        0x486 // TURN, Allocation Quota Reached
#define STUN_ERR_ROLE_CONFLICT      0x487 // ICE
#define STUN_ERR_SERVER_ERR         0x500
#define STUN_ERR_INSUF_CAP          0x508 // TURN, Insufficient Capacity

// MS-TURNBW
#define TURN_BW_MIN_SEND 0
#define TURN_BW_MAX_SEND 1
#define TURN_BW_MIN_RCV  2
#define TURN_BW_MAX_RCV  3
#define TURN_BW_N        4

// Location Profile
#define TURN_LOC_PEER       0
#define TURN_LOC_SELF       1
#define TURN_LOC_FEDERATION 2
#define TURN_LOC_N          3

#define TURN_LOC_PROF_UNKNOWN  0x00
#define TURN_LOC_PROF_INTERNET 0x01
#define TURN_LOC_PROF_INTRANET 0x02

#define TURN_LOC_PROF_NO_FED     0x00 // No Federation
#define TURN_LOC_PROF_ENTERP_FED 0x01 // Enterprise Federation
#define TURN_LOC_PROF_PUBLIC_FED 0x02 // Public Cloud Federation

// NAT status
#define NAT_STAT_STUN          0x00000001
#define NAT_STAT_TURN          0x00000002
#define NAT_STAT_ICE           0x00000004
#define NAT_STAT_SIP           0x00000008
#define NAT_STAT_MS            0x00000010 // Microsoft Extension
#define NAT_STAT_EVEN_PORT     0x00000020
#define NAT_STAT_RES_NEXT_PORT 0x00000040
#define NAT_STAT_DF            0x00000080
#define NAT_STAT_NONCE         0x00000100
#define NAT_STAT_DEPRECATED    0x00002000
#define NAT_STAT_STUN_OVER_NSP 0x00004000 // STUN over non-standard port
#define NAT_STAT_MALFORMED     0x00008000
#define NAT_STAT_PMP           0x00010000 // Port Mapping Protocol
#define NAT_STAT_SNAPLEN       0x80000000 // packet snapped, analysis incomplete

// NAT type TODO need to analyse reverse flow
// Binding
//  A: CHANGE_REQUEST from IP x port p
//  B: (y,q) = (XOR_)MAPPED_ADDR: if ((y,q) == (x,p)) => NO NAT, done
//  A: CHANGE_REQUEST to IP alt_x port p
//  B: (z,r) = (XOR_)MAPPED_ADDR: if ((z,r) == (y,q)) => EIM_NAT, done
//  A: CHANGE_REQUEST to IP alt_x port alt_p
//  B: (w,s) = (XOR_)MAPPED_ADDR: if ((w,s) == (z,r)) => ADM_NAT, done
//  else ADPM_NAT
#define NAT_STAT_NO_NAT   0x1 // Type of nat mapping
#define NAT_STAT_EIM_NAT  0x2 // Endpoint-Independent Mapping NAT
#define NAT_STAT_ADM_NAT  0x4 // Address Dependent Mapping NAT
#define NAT_STAT_ADPM_NAT 0x8 // Address and Port Dependent Mapping NAT
// Filtering
//   A: CHANGE_REQUEST from IP x port p
//   B: RESPONSE: if (!OTHER_ADDRESS) test cannot be performed, done
//   A: CHANGE_REQUEST(change_ip=1, change_port=1)
//   B: if (RESPONSE) EIF_NAT, done
//   A: CHANGE_REQUEST(change_ip=0, change_port=1)
//   B: if (RESPONSE) ADF_NAT, done
//  else ADPF_NAT
#define NAT_STAT_NO_NAT   0x1 // Type of nat mapping
#define NAT_STAT_EIF_NAT  0x2 // Endpoint-Independent Filtering NAT
#define NAT_STAT_ADF_NAT  0x4 // Address Dependent Filtering NAT
#define NAT_STAT_ADPF_NAT 0x8 // Address and Port Dependent Filtering NAT

#define STUN_ERR_TO_BF(e, nf) do { \
    switch (e) { \
        case STUN_ERR_TRY_ALT: \
            nf->err |= 0x0001; \
            break; \
        case STUN_ERR_BAD_REQ: \
            nf->err |= 0x0002; \
            break; \
        case STUN_ERR_UNAUTHORIZED: \
            nf->err |= 0x0004; \
            break; \
        case STUN_ERR_FORBIDDEN: \
            nf->stat |= NAT_STAT_TURN; \
            nf->err |= 0x0008; \
            break; \
        case STUN_ERR_UNKN_ATTR: \
            nf->err |= 0x0010; \
            break; \
        case STUN_ERR_ALLOC_MISMATCH: \
            nf->stat |= NAT_STAT_TURN; \
            nf->err |= 0x0020; \
            break; \
        case STUN_ERR_STALE_NONCE: \
            nf->err |= 0x0040; \
            break; \
        case STUN_ERR_FAMILY_NOT_SUP: \
            nf->stat  |= NAT_STAT_TURN; \
            nf->err |= 0x0080; \
            break; \
        case STUN_ERR_WRONG_CRED: \
            nf->stat |= NAT_STAT_TURN; \
            nf->err |= 0x0100; \
            break; \
        case STUN_ERR_UNSUP_PROTO: \
            nf->stat |= NAT_STAT_TURN; \
            nf->err |= 0x0200; \
            break; \
        case STUN_ERR_PA_FAMILY_MISMATCH: \
            nf->stat |= NAT_STAT_TURN; \
            nf->err |= 0x0400; \
            break; \
        case STUN_ERR_CONN_EXISTS: \
            nf->stat |= NAT_STAT_TURN; \
            nf->err |= 0x0800; \
            break; \
        case STUN_ERR_CONN_TIMEOUT: \
            nf->stat |= NAT_STAT_TURN; \
            nf->err |= 0x1000; \
            break; \
        case STUN_ERR_ALLOC_QUOTA: \
            nf->stat |= NAT_STAT_TURN; \
            nf->err |= 0x2000; break; \
        case STUN_ERR_ROLE_CONFLICT: \
            nf->stat |= NAT_STAT_ICE; \
            nf->err |= 0x4000; \
            break; \
        case STUN_ERR_SERVER_ERR: \
            nf->err |= 0x8000; \
            break; \
        case STUN_ERR_INSUF_CAP: \
            nf->stat |= NAT_STAT_TURN; \
            nf->err |= 0x10000; \
            break; \
        default: \
            nf->err |= 0x80000000; \
            T2_PDBG("stunDecode", "Unhandled error %#04x\n", (e)); \
            break; \
    } \
} while (0)

// plugin structs

typedef struct {
    uint8_t version;
    uint8_t opcode;
} nat_pmp_t;

typedef struct {
    uint8_t version;
    uint8_t opcode;
    uint16_t result;
    uint32_t start; //  seconds since start of epoch
    uint32_t ext_ip;
} nat_pmp_resp_t;

typedef struct {
    uint8_t version;
    uint8_t opcode;    // 0: UDP, 1: TCP
    uint16_t reserved;
    uint16_t int_port;
    uint16_t ext_port; // suggested external port
    uint32_t lifetime; // requested port mapping lifetime (secs)
} nat_pmp_map_req_t;

typedef struct {
    uint8_t version;
    uint8_t opcode;
    uint16_t result;
    uint32_t start;
    uint16_t int_port;
    uint16_t ext_port;
    uint32_t lifetime; // port mapping lifetime (secs)
} nat_pmp_map_resp_t;

typedef struct {
    uint32_t min_send;
    uint32_t max_send;
    uint32_t min_rcv;
    uint32_t max_rcv;
} turn_bw_rsv_amount_t;

typedef struct {
  uint16_t ch_num;   // Channel number
  uint16_t reserved; // MUST be 0
} stun_chann_num_t;

typedef struct {
    uint32_t res_cl_num;    // reserved:21    // SHOULD be 0
                            // eclass:3;      // MUST be between 3 and 6
                            // number:8;      // MUST be between 0 and 99
    uint32_t reason_phrase; // variable length, UTF8
} stun_error_t;

typedef struct {
    uint8_t  zero;
    uint8_t  family;
    uint16_t port;
    union {
        uint32_t addr4;
        uint32_t addr6[4];
    };
} stun_mapped_addr_t;

typedef struct {
    uint16_t type;
    uint16_t len;  // without padding
    //uint8_t  data; // variable length, padded to end on 32-bit boundary
} stun_attr_t;

#define STUN_ATTR_DATA(p) ((p)+sizeof(stun_attr_t))

typedef struct {
    uint16_t type:14;
    uint16_t zero:2;
    uint16_t len;          // message length (without the 20 bytes header)
    uint32_t magic_cookie;
    uint8_t  tran_id[12];  // transaction ID
    //uint8_t data;        // variable length
} stun_header_t;

typedef struct {
    uint32_t natpmp_start;
    uint32_t natpmp_map_lifetime;
    uint32_t bandwidth;
    uint32_t lifetime;   // how long to keep the mapping in the NAT table
    uint32_t priority;
    uint32_t err;        // bitfield for errors
    uint32_t stat;

    uint32_t ms_bandwidth[TURN_BW_N];

    // address
    uint32_t mapped_addr;
    uint32_t xor_mapped_addr;
    uint32_t xor_peer_addr;
    uint32_t relayed_addr;
    uint32_t resp_orig_addr;
    uint32_t dest_addr;
    uint32_t alt_server_addr;
    uint32_t other_addr;
    //uint32_t remote_addr;       // MS, Remote Site Address
    //uint32_t remote_relay_addr; // MS, Remote Relay Site Address
    //uint32_t local_addr;        // MS, Local Site Address
    //uint32_t local_relay_addr;  // MS, Local Relay Site Address

    // port
    uint16_t mapped_port;
    uint16_t xor_mapped_port;
    uint16_t xor_peer_port;
    uint16_t relayed_port;
    uint16_t resp_orig_port;
    uint16_t dest_port;
    uint16_t alt_server_port;
    uint16_t other_port;
    //uint16_t remote_port;       // MS, Remote Site Address
    //uint16_t remote_relay_port; // MS, Remote Relay Site Address
    //uint16_t local_port;        // MS, Local Site Address
    //uint16_t local_relay_port;  // MS, Local Relay Site Address

    uint16_t location[TURN_LOC_N];
    uint16_t channel;
    uint16_t num_mt_class[STUN_MT_CLASS_N];
    uint16_t num_natpmp_op[6];

    // string
    char username[STUN_USERNAME_MAXLEN+1];
    char password[STUN_USERNAME_MAXLEN+1];
    char realm[STUN_ATTR_STR_MAXLEN+1];
    char software[STUN_ATTR_STR_MAXLEN+1];
    //char sip_dialog_id[STUN_ATTR_SIP_ID_MAXLEN];
    //char sip_call_id[STUN_ATTR_SIP_ID_MAXLEN];

    uint8_t req_proto;  // requested transport
    uint8_t req_family; // requested address family
} nat_flow_t;

extern nat_flow_t *nat_flows;

#endif // __STUN_DECODE_H__
