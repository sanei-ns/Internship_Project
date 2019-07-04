/*
 * radiusDecode.h
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
 * [RFC2865] Remote Authentication Dial In User Service (RADIUS)
 * [RFC2866] RADIUS Accounting
 * [RFC2867] RADIUS Accounting Modifications for Tunnel Protocol Support
 * [RFC2868] RADIUS Attributes for Tunnel Protocol Support
 * [RFC2869] RADIUS Extensions
 */

#ifndef __RADIUS_DECODE_H__
#define __RADIUS_DECODE_H__

// global includes

// local includes
#include "global.h"

// user defines
#define RADIUS_DEBUG  0 // whether or not to output debug messages
#define RADIUS_NAS    1 // whether or not to output NAS info
#define RADIUS_FRAMED 1 // whether or not to output framed info
#define RADIUS_TUNNEL 1 // whether or not to output tunnel info
#define RADIUS_ACCT   1 // whether or not to output accounting info

// plugin defines
#define RADIUS_AUTH_PORT     1812 // authentication and configuration
#define RADIUS_ACC_PORT      1813 // accounting
#define RADIUS_AUTH_OLD_PORT 1645 // authentication and configuration
#define RADIUS_ACC_OLD_PORT  1646 // accounting

#define RADIUS_LEN_MIN   20
#define RADIUS_LEN_MAX 4096

// RADIUS codes
#define RADIUS_C_AXS_REQ         1 // Access-Request
#define RADIUS_C_AXS_ACC         2 // Access-Accept
#define RADIUS_C_AXS_REJ         3 // Access-Reject
#define RADIUS_C_ACC_REQ         4 // Accounting-Request
#define RADIUS_C_ACC_RESP        5 // Accounting-Response
//#define RADIUS_C_ACC_STAT        6 // Accounting-Status (now Interim Accounting) [RFC3575]
//#define RADIUS_C_PASS_REQ        7 // Password-Request    [RFC3575]
//#define RADIUS_C_PASS_ACK        8 // Password-Ack        [RFC3575]
//#define RADIUS_C_PASS_REJ        9 // Password-Reject     [RFC3575]
//#define RADIUS_C_ACC_MSG        10 // Accounting-Message  [RFC3575]
#define RADIUS_C_AXS_CHAL       11 // Access-Challenge
//#define RADIUS_C_STAT_SRV       12 // Status-Server (experimental)
//#define RADIUS_C_STAT_CLI       13 // Status-Client (experimental)
//#define RADIUS_C_RES_FREE_REQ   21 // Resource-Free-Request   [RFC3575]
//#define RADIUS_C_RES_FREE_RESP  22 // Resource-Free-Response  [RFC3575]
//#define RADIUS_C_RES_QREQ       23 // Resource-Query-Request  [RFC3575]
//#define RADIUS_C_RES_QRESP      24 // Resource-Query-Response     [RFC3575]
//#define RADIUS_C_ALT_RES        25 // Alternate-Resource-Reclaim-Request  [RFC3575]
//#define RADIUS_C_NAS_RBOOT_REQ  26 // NAS-Reboot-Request  [RFC3575]
//#define RADIUS_C_NAS_RBOOT_RESP 27 // NAS-Reboot-Response     [RFC3575]
// 28 (Reserved)
//#define RADIUS_C_NEX   0.0T_PASS      29 // Next-Passcode   [RFC3575]
//#define RADIUS_C_NEW_PING       30 // New-Pin     [RFC3575]
//#define RADIUS_C_TERM_SESS      31 // Terminate-Session   [RFC3575]
//#define RADIUS_C_PASS_EXP       32 // Password-Expired    [RFC3575]
//#define RADIUS_C_EVT_REQ        33 // Event-Request   [RFC3575]
//#define RADIUS_C_EVT_RESP       34 // Event-Response  [RFC3575]
// 35-39 (Unassigned)
//#define RADIUS_C_DCONN_REQ      40 // Disconnect-Request  [RFC3575][RFC5176]
//#define RADIUS_C_DCONN_ACK      41 // Disconnect-ACK  [RFC3575][RFC5176]
//#define RADIUS_C_DCONN_NAK      42 // Disconnect-NAK  [RFC3575][RFC5176]
//#define RADIUS_C_COA_REQ        43 // CoA-Request     [RFC3575][RFC5176]
//#define RADIUS_C_COA_ACK        44 // CoA-ACK     [RFC3575][RFC5176]
//#define RADIUS_C_COA_NAK        45 // CoA-NAK     [RFC3575][RFC5176]
// 46-49 (Unassigned)
//#define RADIUS_C_IP_ALLOC       50 // IP-Address-Allocate     [RFC3575]
//#define RADIUS_C_IP_RELEASE     51 // IP-Address-Release  [RFC3575]

// RADIUS attribute types
#define RADIUS_AT_USER                  1 // User-Name
#define RADIUS_AT_PASS                  2 // User-Password
#define RADIUS_AT_CHAP                  3 // CHAP-Password
#define RADIUS_AT_NAS_IP                4 // NAS-IP-Address
#define RADIUS_AT_NAS_PORT              5 // NAS-Port
#define RADIUS_AT_SERVICE               6 // Service-Type
#define RADIUS_AT_FPROTO                7 // Framed-Protocol
#define RADIUS_AT_FR_IP                 8 // Framed-IP-Address
#define RADIUS_AT_FR_MASK               9 // Framed-IP-Netmask
#define RADIUS_AT_FR_ROUTING           10 // Framed-Routing
#define RADIUS_AT_FILTER               11 // Filter-Id
#define RADIUS_AT_FR_MTU               12 // Framed-MTU
#define RADIUS_AT_FR_COMPR             13 // Framed-Compression
#define RADIUS_AT_HOST                 14 // Login-IP-Host
#define RADIUS_AT_LSERV                15 // Login-Service
#define RADIUS_AT_TCP_PORT             16 // Login-TCP-Port
// 17 (unassigned)
#define RADIUS_AT_REPLY_MSG            18 // Reply-Message
#define RADIUS_AT_CBACK_NUM            19 // Callback-Number
#define RADIUS_AT_CBACK_ID             20 // Callback-Id
// 21 (unassigned)
#define RADIUS_AT_FR_RTE               22 // Framed-Route
#define RADIUS_AT_FR_IPX               23 // Framed-IPX-Network
#define RADIUS_AT_STATE                24 // State
#define RADIUS_AT_CLASS                25 // Class
#define RADIUS_AT_VENDOR               26 // Vendor-Specific
#define RADIUS_AT_TMOUT                27 // Session-Timeout
#define RADIUS_AT_IDLE                 28 // Idle-Timeout
#define RADIUS_AT_TERM                 29 // Termination-Action
#define RADIUS_AT_CALLED               30 // Called-Station-Id
#define RADIUS_AT_CALLING              31 // Calling-Station-Id
#define RADIUS_AT_NAS_ID               32 // NAS-Identifier
#define RADIUS_AT_PROXY                33 // Proxy-State
#define RADIUS_AT_LAT_SERV             34 // Login-LAT-Service
#define RADIUS_AT_LAT_NODE             35 // Login-LAT-Node
#define RADIUS_AT_LAT_GROUP            36 // Login-LAT-Group
#define RADIUS_AT_APPLE_LINK           37 // Framed-AppleTalk-Link
#define RADIUS_AT_APPLE_NET            38 // Framed-AppleTalk-Network
#define RADIUS_AT_APPLE_ZONE           39 // Framed-AppleTalk-Zone
// 40-59 (reserved for accounting) [rfc2869,rfc2866,rfc4675]
#define RADIUS_AT_ACC_STAT_T           40 // Acct-Status-Type
#define RADIUS_AT_ACC_DELAY            41 // Acct-Delay-Time
#define RADIUS_AT_ACC_INOCT            42 // Acct-Input-Octets
#define RADIUS_AT_ACC_OUTOCT           43 // Acct-Output-Octets
#define RADIUS_AT_ACC_SESSID           44 // Acct-Session-Id
#define RADIUS_AT_ACC_AUTH             45 // Acct-Authentic
#define RADIUS_AT_ACC_SESS_T           46 // Acct-Session-Time
#define RADIUS_AT_ACC_INPKTS           47 // Acct-Input-Packets
#define RADIUS_AT_ACC_OUTPKTS          48 // Acct-Output-Packets
#define RADIUS_AT_ACC_TERM             49 // Acct-Terminate-Cause
#define RADIUS_AT_ACC_MULT_SESS        50 // Acct-Multi-Session-Id
#define RADIUS_AT_ACC_LCOUNT           51 // Acct-Link-Count
#define RADIUS_AT_ACC_INGWORDS         52 // Acct-Input-Gigawords
#define RADIUS_AT_ACC_OUTGWORDS        53 // Acct-Output-Gigawords
// 54 (unassigned)
#define RADIUS_AT_EVT_TSTAMP           55 // Event-Timestamp
#define RADIUS_AT_EGRESS_VLANID        56 // Egress-VLANID
#define RADIUS_AT_INGRESS_FILTER       57 // Ingress-Filters
#define RADIUS_AT_EGRASS_VLANNAME      58 // Egress-VLAN-Name
#define RADIUS_AT_USR_PRI_TABLE        59 // User-Priority-Table
#define RADIUS_AT_CHAP_CHALL           60 // CHAP-Challenge
#define RADIUS_AT_NAS_PTYPE            61 // NAS-Port-Type
#define RADIUS_AT_PORT_LIMIT           62 // Port-Limit
#define RADIUS_AT_LAT_PORT             63 // Login-LAT-Port
#define RADIUS_AT_TUN_T                64 // Tunnel-Type [RFC2868]
#define RADIUS_AT_TUN_MED_T            65 // Tunnel-Medium-Type [RFC2868]
#define RADIUS_AT_TUN_CLI_EP           66 // Tunnel-Client-Endpoint [RFC2868]
#define RADIUS_AT_TUN_SRV_EP           67 // Tunnel-Server-Endpoint [RFC2868]
#define RADIUS_AT_ACC_TUN_CON          68 // Acct-Tunnel-Connection [RFC2867]
#define RADIUS_AT_TUN_PASS             69 // Tunnel-Password [RFC2868]
#define RADIUS_AT_ARAP_PASS            70 // ARAP-Password [RFC2869]
#define RADIUS_AT_ARAP_FEAT            71 // ARAP-Features [RFC2869]
#define RADIUS_AT_ARAP_ZONE            72 // ARAP-Zone-Access [RFC2869]
#define RADIUS_AT_ARAP_SEC             73 // ARAP-Security [RFC2869]
#define RADIUS_AT_ARAP_SECDAT          74 // ARAP-Security-Data [RFC2869]
#define RADIUS_AT_PASS_RTRY            75 // Password-Retry [RFC2869]
#define RADIUS_AT_PROMPT               76 // Prompt [RFC2869]
#define RADIUS_AT_CONN_INF             77 // Connect-Info [RFC2869]
#define RADIUS_AT_CONF_TOK             78 // Configuration-Token [RFC2869]
#define RADIUS_AT_EAP_MSG              79 // EAP-Message [RFC2869]
#define RADIUS_AT_MSG_AUTH             80 // Message-Authenticator [RFC2869]
#define RADIUS_AT_TUN_PRIV_GID         81 // Tunnel-Private-Group-ID [RFC2868]
#define RADIUS_AT_TUN_ASSIG_ID         82 // Tunnel-Assignment-ID [RFC2868]
#define RADIUS_AT_TUN_PREF             83 // Tunnel-Preference [RFC2868]
#define RADIUS_AT_ARAP_CHAL_RESP       84 // ARAP-Challenge-Response [RFC2869]
#define RADIUS_AT_ACC_INT_INT          85 // Acct-Interim-Interval [RFC2869]
#define RADIUS_AT_ACC_TUN_PKTLOS       86 // Acct-Tunnel-Packets-Lost [RFC2867]
#define RADIUS_AT_NAS_PORT_ID          87 // NAS-Port-Id [RFC2869]
#define RADIUS_AT_FRAMED_POOL          88 // Framed-Pool [RFC2869]
#define RADIUS_AT_CUI                  89 // CUI [RFC4372]
#define RADIUS_AT_TUN_CLI_AUTH         90 // Tunnel-Client-Auth-ID [RFC2868]
#define RADIUS_AT_TUN_SRV_AUTH         91 // Tunnel-Server-Auth-ID [RFC2868]
#define RADIUS_AT_NAS_FILTER           92 // NAS-Filter-Rule [RFC4849]
// 93 (Unassigned)
#define RADIUS_AT_ORIG_LINE_INF        94 // Originating-Line-Info [RFC7155]
#define RADIUS_AT_NAS_IP6              95 // NAS-IPv6-Address [RFC3162]
#define RADIUS_AT_FRAMED_IFACE         96 // Framed-Interface-Id [RFC3162]
#define RADIUS_AT_FRAMED_IP6_PREF      97 // Framed-IPv6-Prefix [RFC3162]
#define RADIUS_AT_LOG_IP6              98 // Login-IPv6-Host [RFC3162]
#define RADIUS_AT_FRAMED_IP6_RTE       99 // Framed-IPv6-Route [RFC3162]
#define RADIUS_AT_FRAMED_IP6_POOL     100 // Framed-IPv6-Pool [RFC3162]
#define RADIUS_AT_ERR_CAUSE           101 // Error-Cause Attribute [RFC3576]
#define RADIUS_AT_EAP_KEY_NAME        102 // EAP-Key-Name [RFC4072][RFC7268]
#define RADIUS_AT_DIGEST_RESP         103 // Digest-Response [RFC5090]
#define RADIUS_AT_DIGEST_REALM        104 // Digest-Realm [RFC5090]
#define RADIUS_AT_DIGEST_NONCE        105 // Digest-Nonce [RFC5090]
#define RADIUS_AT_DIGEST_RESP_AUTH    106 // Digest-Response-Auth [RFC5090]
#define RADIUS_AT_DIGEST_NEXTNONCE    107 // Digest-Nextnonce [RFC5090]
#define RADIUS_AT_DIGEST_METH         108 // Digest-Method [RFC5090]
#define RADIUS_AT_DIGEST_URI          109 // Digest-URI [RFC5090]
#define RADIUS_AT_DIGEST_QOP          110 // Digest-Qop [RFC5090]
#define RADIUS_AT_DIGEST_ALGO         111 // Digest-Algorithm [RFC5090]
#define RADIUS_AT_DIGEST_ENTITY       112 // Digest-Entity-Body-Hash [RFC5090]
#define RADIUS_AT_DIGEST_CNONCE       113 // Digest-CNonce [RFC5090]
#define RADIUS_AT_DIGEST_NONCE_CNT    114 // Digest-Nonce-Count [RFC5090]
#define RADIUS_AT_DIGEST_UNAME        115 // Digest-Username [RFC5090]
#define RADIUS_AT_DIGEST_OPAQUE       116 // Digest-Opaque [RFC5090]
#define RADIUS_AT_DIGEST_AUTH_PARAM   117 // Digest-Auth-Param [RFC5090]
#define RADIUS_AT_DIGEST_AKA_AUTS     118 // Digest-AKA-Auts [RFC5090]
#define RADIUS_AT_DIGEST_DOMAIN       119 // Digest-Domain [RFC5090]
#define RADIUS_AT_DIGEST_STALE        120 // Digest-Stale [RFC5090]
#define RADIUS_AT_DIGEST_HA1          121 // Digest-HA1 [RFC5090]
#define RADIUS_AT_SIP_AOR             122 // SIP-AOR [RFC5090]
#define RADIUS_AT_DELEG_IP6           123 // Delegated-IPv6-Prefix [RFC4818]
#define RADIUS_AT_MIP6_FEAT_VEC       124 // MIP6-Feature-Vector [RFC5447]
#define RADIUS_AT_MIP6_HOME_LNK       125 // MIP6-Home-Link-Prefix [RFC5447]
#define RADIUS_AT_OPNAME              126 // Operator-Name [RFC5580]
#define RADIUS_AT_LOCINF              127 // Location-Information [RFC5580]
#define RADIUS_AT_LOCDAT              128 // Location-Data [RFC5580]
#define RADIUS_AT_BASIC_LOC           129 // Basic-Location-Policy-Rules [RFC5580]
#define RADIUS_AT_EXT_LOC             130 // Extended-Location-Policy-Rules [RFC5580]
#define RADIUS_AT_LOC_CAP             131 // Location-Capable [RFC5580]
#define RADIUS_AT_REQ_LOCINF          132 // Requested-Location-Info [RFC5580]
#define RADIUS_AT_FRAMED_MGMT_PROT    133 // Framed-Management-Protocol [RFC5607]
#define RADIUS_AT_MGMT_PROTECT        134 // Management-Transport-Protection [RFC5607]
#define RADIUS_AT_MGMT_POLICY         135 // Management-Policy-Id [RFC5607]
#define RADIUS_AT_MGMT_PRIVIL         136 // Management-Privilege-Level [RFC5607]
#define RADIUS_AT_PKM_SS_CERT         137 // PKM-SS-Cert [RFC5904]
#define RADIUS_AT_PKM_CA_CERT         138 // PKM-CA-Cert [RFC5904]
#define RADIUS_AT_PKM_CONF            139 // PKM-Config-Settings [RFC5904]
#define RADIUS_AT_PKM_CRYPTOSUITE     140 // PKM-Cryptosuite-List [RFC5904]
#define RADIUS_AT_PKM_SAID            141 // PKM-SAID [RFC5904]
#define RADIUS_AT_PKM_SA_DESC         142 // PKM-SA-Descriptor [RFC5904]
#define RADIUS_AT_PKM_AUTH_KEY        143 // PKM-Auth-Key [RFC5904]
#define RADIUS_AT_DS_TUN_NAME         144 // DS-Lite-Tunnel-Name [RFC6519]
#define RADIUS_AT_MOBE_NODEID         145 // Mobile-Node-Identifier [RFC6572]
#define RADIUS_AT_SERV_SELECT         146 // Service-Selection [RFC6572]
#define RADIUS_AT_PMIP6_HOM_LMA_IP6   147 // PMIP6-Home-LMA-IPv6-Address [RFC6572]
#define RADIUS_AT_PMIP6_VIS_LMA_IP6   148 // PMIP6-Visited-LMA-IPv6-Address [RFC6572]
#define RADIUS_AT_PMIP6_HOM_LMA_IP4   149 // PMIP6-Home-LMA-IPv4-Address [RFC6572]
#define RADIUS_AT_PMIP6_VIS_LMA_IP4   150 // PMIP6-Visited-LMA-IPv4-Address [RFC6572]
#define RADIUS_AT_PMIP6_HOM_HN_PREF   151 // PMIP6-Home-HN-Prefix [RFC6572]
#define RADIUS_AT_PMIP6_VIS_HN_PREF   152 // PMIP6-Visited-HN-Prefix [RFC6572]
#define RADIUS_AT_PMIP6_HOM_IFACE     153 // PMIP6-Home-Interface-ID [RFC6572]
#define RADIUS_AT_PMIP6_VIS_IFACE     154 // PMIP6-Visited-Interface-ID [RFC6572]
#define RADIUS_AT_PMIP6_HOM_IP4_HOA   155 // PMIP6-Home-IPv4-HoA [RFC6572]
#define RADIUS_AT_PMIP6_VIS_IP4_HOA   156 // PMIP6-Visited-IPv4-HoA [RFC6572]
#define RADIUS_AT_PMIP6_HOM_DHCP4_SRV 157 // PMIP6-Home-DHCP4-Server-Address [RFC6572]
#define RADIUS_AT_PMIP6_VIS_DHCP4_SRV 158 // PMIP6-Visited-DHCP4-Server-Address [RFC6572]
#define RADIUS_AT_PMIP6_HOM_DHCP6_SRV 159 // PMIP6-Home-DHCP6-Server-Address [RFC6572]
#define RADIUS_AT_PMIP6_VIS_DHCP6_SRC 160 // PMIP6-Visited-DHCP6-Server-Address [RFC6572]
#define RADIUS_AT_PMIP6_HOM_IP4_GTWAY 161 // PMIP6-Home-IPv4-Gateway [RFC6572]
#define RADIUS_AT_PMIP6_VIS_IP4_GTWAY 162 // PMIP6-Visited-IPv4-Gateway [RFC6572]
#define RADIUS_AT_EAP_LOW_L           163 // EAP-Lower-Layer [RFC6677]
#define RADIUS_AT_GSS_SNAME           164 // GSS-Acceptor-Service-Name [RFC7055]
#define RADIUS_AT_GSS_HNAME           165 // GSS-Acceptor-Host-Name [RFC7055]
#define RADIUS_AT_GSS_SERVS           166 // GSS-Acceptor-Service-Specifics [RFC7055]
#define RADIUS_AT_GSS_REALM           167 // GSS-Acceptor-Realm-Name [RFC7055]
#define RADIUS_AT_FRAMED_IP6          168 // Framed-IPv6-Address [RFC6911]
#define RADIUS_AT_DNS_SRV_IP6         169 // DNS-Server-IPv6-Address [RFC6911]
#define RADIUS_AT_RTE_IP6             170 // Route-IPv6-Information [RFC6911]
#define RADIUS_AT_DELEG_IP6_POOL      171 // Delegated-IPv6-Prefix-Pool [RFC6911]
#define RADIUS_AT_STATEFUL_IP6        172 // Stateful-IPv6-Address-Pool [RFC6911]
#define RADIUS_AT_IP6_CONF            173 // IPv6-6rd-Configuration [RFC6930]
#define RADIUS_AT_ALLOW_CALLID        174 // Allowed-Called-Station-Id [RFC7268]
#define RADIUS_AT_EAP_PEERID          175 // EAP-Peer-Id [RFC7268]
#define RADIUS_AT_EAP_SRVID           176 // EAP-Server-Id [RFC7268]
#define RADIUS_AT_MOBIL_DOMAIN        177 // Mobility-Domain-Id [RFC7268]
#define RADIUS_AT_PREAUTH_TMOUT       178 // Preauth-Timeout [RFC7268]
#define RADIUS_AT_NETID               179 // Network-Id-Name [RFC7268]
#define RADIUS_AT_EAPOL_ANN           180 // EAPoL-Announcement [RFC7268]
#define RADIUS_AT_WLAN_HESSID         181 // WLAN-HESSID [RFC7268]
#define RADIUS_AT_WLAN_INF            182 // WLAN-Venue-Info [RFC7268]
#define RADIUS_AT_WLAN_LANG           183 // WLAN-Venue-Language [RFC7268]
#define RADIUS_AT_WLAN_NAME           184 // WLAN-Venue-Name [RFC7268]
#define RADIUS_AT_WLAN_REASON         185 // WLAN-Reason-Code [RFC7268]
#define RADIUS_AT_WLAN_PAIR_CIPHER    186 // WLAN-Pairwise-Cipher [RFC7268]
#define RADIUS_AT_WLAN_GRP_CIPHER     187 // WLAN-Group-Cipher [RFC7268]
#define RADIUS_AT_WLAN_AKM            188 // WLAN-AKM-Suite [RFC7268]
#define RADIUS_AT_WLAN_GRP_MGMT       189 // WLAN-Group-Mgmt-Cipher [RFC7268]
#define RADIUS_AT_WLAN_RF_BAND        190 // WLAN-RF-Band [RFC7268]

// RADIUS status
#define RADIUS_STAT_RADIUS    0x01 // flow is radius
#define RADIUS_STAT_AXS       0x02 // authentication and configuration traffic
#define RADIUS_STAT_ACC       0x04 // accounting traffic
//#define RADIUS_STAT_ACC_START 0x04 // Acct-Status-Type = start
//#define RADIUS_STAT_ACC_STOP  0x08 // Acct-Status-Type = stop
#define RADIUS_STAT_CONN_SUCC 0x10 // connection successful
#define RADIUS_STAT_CONN_FAIL 0x20 // connection failed
#define RADIUS_STAT_MALFORMED 0x80 // packet is malformed, e.g., invalid length

#if RADIUS_DEBUG == 1
#define RADIUS_DBG(format, args...) printf(format, ##args)
#else // RADIUS_DEBUG == 0
#define RADIUS_DBG(format, args...)
#endif // RADIUS_DEBUG


typedef struct {
    uint8_t  code;
    uint8_t  id;       // packet identifier
    uint16_t len;
    uint8_t  auth[16]; // authenticator
    // AVPs...
} __attribute__((packed)) radius_t;

typedef struct {
    uint8_t type;
    uint8_t len;
    // value (len bytes)
} __attribute__((packed)) radius_avp_t;

typedef struct {
    uint32_t serviceType;
    uint32_t logSer; // login-service
    uint32_t vendor;

    // Network Access Server (NAS)
    char nasid[256];
    char nasportid[256];
    uint32_t nasip;
    uint32_t nasport;
    uint32_t nasporttyp;

    // Framed
    uint32_t fip;
    uint32_t fmask;
    uint32_t fproto;
    uint32_t fcomp;
    uint32_t fmtu;

    // Tunnel
    uint32_t tunnel;     // type
    uint32_t tunnel_med; // medium
    uint32_t tunnelPref;
    char tunnelCli[128];
    char tunnelSrv[128];
    char tunnelCliAId[128];
    char tunnelSrvAId[128];

    // Accounting
    char acctSessId[128];
    uint32_t acctStatTyp;
    uint32_t acctTerm;
    uint32_t in_oct;
    uint32_t in_pkt;
    uint32_t in_gw;
    uint32_t out_oct;
    uint32_t out_pkt;
    uint32_t out_gw;

    uint32_t sessTime; // how many seconds the user has received servicce for
    //uint32_t acct_evt_ts;

    char connInfo[256]; // user's connection
    char filter[256];
    char callingid[256];
    char calledid[256];

    uint8_t stat;
    uint8_t code;
    uint16_t num_axs[4]; // number of Access-Request/Accept/Reject/Challenge
    uint16_t num_acc[2]; // number of Accounting-Request/Response
    uint16_t num_acc_start;
    uint16_t num_acc_stop;

    char user[256];
    char replymsg[256];
} radius_flow_t;

// plugin struct pointer for potential dependencies
extern radius_flow_t *radius_flows;

#endif // __RADIUS_DECODE_H__
