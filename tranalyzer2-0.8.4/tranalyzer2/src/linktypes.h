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

#ifndef __LINKTYPE_HEADERS_H__
#define __LINKTYPE_HEADERS_H__

// includes
#include <stdint.h>

#define LINKTYPE_JUNIPER 1 // Dissect PCAP with Juniper linktypes (Experimental)

/*----------------------*
 * Linux Cooked Capture *
 *----------------------*/

typedef struct {
	uint16_t pkt_type; // packet type
	uint16_t type;     // link-layer address type
	uint16_t len;      // link-layer address length
	uint8_t  addr[8];  // source address
	uint16_t proto;    // address_protocol
} linux_cooked_t;

/*------------------------*
 * Per-Packet Information *
 *------------------------*/

// https://www.cacetech.com/documents/PPI_Header_format_1.0.1.pdf

typedef struct {
	uint8_t  version; // MUST be 0
	uint8_t  flags;   // Flags (lsb(1): 1: 32-bit aligned, 0: non-aligned)
	                  // bits 1-7 MUST be 0
	uint16_t len;     // header length (including PPI fields)
	uint32_t dlt;     // Data Link Type of the catured packet data
} ppi_hdr_t;

// PPI field types
#define PPI_FT_80211_COMMON 2
#define PPI_FT_80211_MAC    3
#define PPI_FT_80211_MACPHY 4
#define PPI_FT_SPECTRUM     5 // radio freq spectrum info
#define PPI_FT_PROCINFO     6 // process information (uid, gid, ...)
#define PPI_FT_CAPINFO      7 // capture information (iface, drop, ...)

typedef struct ppi_fieldheader {
	uint16_t type;
	uint16_t datalen;
} ppi_field_hdr_t;

/*----------------------*
 * Prism Capture Header *
 *----------------------*/

#define PRISM_MSGCODE1     0x00000041

#define PRISMP_DID_HTIME1  0x00001041 // host time
#define PRISMP_DID_MTIME1  0x00002041 // MAC time
#define PRISMP_DID_CHAN1   0x00003041 // channel
#define PRISMP_DID_RSSI1   0x00004041 // RSSI
#define PRISMP_DID_SIGQ1   0x00005041 // signal quality
#define PRISMP_DID_SIG1    0x00006041 // signal
#define PRISMP_DID_NOISE1  0x00007041 // noise
#define PRISMP_DID_RATE1   0x00008041 // rate
#define PRISMP_DID_ISTX1   0x00009041 // transmitted frame indicator
#define PRISMP_DID_FRMLEN1 0x0000a041 // frame length

#define PRISM_MSGCODE2     0x00000044

#define PRISMP_DID_HTIME2  0x00010044 // host time
#define PRISMP_DID_MTIME2  0x00020044 // MAC time
#define PRISMP_DID_CHAN2   0x00030044 // channel
#define PRISMP_DID_RSSI2   0x00040044 // RSSI
#define PRISMP_DID_SIGQ2   0x00050044 // signal quality
#define PRISMP_DID_SIG2    0x00060044 // signal
#define PRISMP_DID_NOISE2  0x00070044 // noise
#define PRISMP_DID_RATE2   0x00080044 // rate
#define PRISMP_DID_ISTX2   0x00090044 // transmitted frame indicator
#define PRISMP_DID_FRMLEN2 0x000a0044 // frame length

#define PRISM_STAT_HAS_VAL 0
#define PRISM_STAT_NOVAL   1

#define PRISM_DEV_LEN  16 // device name length
#define PRISM_HDR_LEN 144 // Default Prism header length

typedef struct {
	uint32_t did;    // parameter ID
	uint16_t status; // 0: value supplied; 1: value not supplied
	uint16_t len;    // data length (number of bits bytes used)
	uint32_t data;
} __attribute__ ((packed)) prism_param_t;

typedef struct {
	uint32_t msgcode;        // 0x00000041 or 0x00000044
	uint32_t msglen;         // header length (always(?) PRISM_HDR_LEN (=144) octets)
	char dev[PRISM_DEV_LEN]; // name of the device that captured this packet
	// (Almost?) always 10 parameter?
	prism_param_t hosttime;  // measured in jiffies - I think
	prism_param_t mactime;   // truncated microsecond timer (lower 32 bits of a 64 bits value)
	prism_param_t channel;
	prism_param_t rssi;
	prism_param_t sq;        // signal quality
	prism_param_t signal;
	prism_param_t noise;
	prism_param_t rate;
	prism_param_t istx;      // transmitted frame indicator
	prism_param_t frmlen;
} __attribute__ ((packed)) prism_hdr_t;

/*-----------------*
 * Radiotap Header *
 *-----------------*/

typedef struct {
	uint8_t  version;     // 0
	uint8_t  pad;
	uint16_t len;
	uint32_t present;     // flags
} __attribute__((__packed__)) radiotap_hdr_t;

/*------------------------------*
 * Juniper *
 *------------------------------*/

#define JUNIPER_PCAP_MAGIC   0x4d4743 // Host order
#define JUNIPER_PCAP_MAGIC_N 0x43474d // Network order
#define JUNIPER_FLAG_NOL2    0x02     // L2 header stripped
#define JUNIPER_FLAG_EXT     0x80     // L2 header stripped

typedef struct {
	uint32_t magic:24;
	uint32_t flags:8;  // direction, l2 header present
	uint32_t cookie;
} __attribute__ ((__packed__)) juniper_atm_hdr_t;

typedef struct {
	uint32_t magic:24;
	uint32_t flags:8;  // direction, l2 header present
	uint16_t ext_len;  // Extension(s) total length
} __attribute__ ((__packed__)) juniper_eth_hdr_t;

typedef struct {
	uint32_t magic:24;
	uint32_t flags:8;  // direction, l2 header present
} __attribute__ ((__packed__)) juniper_pppoe_hdr_t;

/*------------------------------*
 * Symantec Enterprise Firewall *
 *------------------------------*/

#define SYMANTEC_FW_V2_LEN 44

typedef struct {
	uint32_t iface_ip; // IP of capture interface
	uint16_t zero1;
	uint16_t type;     // ethertype
	uint8_t  zero2[36];
} __attribute__ ((__packed__)) symantec_fw_v2_hdr_t;

#define SYMANTEC_FW_V3_LEN 56

typedef struct {
	uint32_t iface_ip; // IP of capture interface
	uint8_t  zero1[6];
	uint16_t type;     // ethertype
	uint8_t  zero2[44];
} __attribute__ ((__packed__)) symantec_fw_v3_hdr_t;

#endif // __LINKTYPE_HEADERS_H__
