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

#ifndef __DNSDECODE_H__
#define __DNSDECODE_H__

// local includes
#include "global.h"
#include "dnsType.h"

// user config
#define DNS_MODE         4 // 0: Only aggregated header info,
                           // 1: +Req Content Info,
                           // 2: +Answer Records,
                           // 3: +AUX records,
                           // 4: +Add records
#define DNS_HEXON        0 // 0: Hex Output flags off, 1: Hex output flags on
#define DNS_REQA         0 // 1: Request record aggregation mode
#define DNS_ANSA         0 // 1: Answer record aggregation mode
#define DNS_QRECMAX     15 // Max # of query records / flow
#define DNS_ARECMAX     20 // Max # of answer records / flow

#define MAL_TEST         0 // activate Malware domain test
#define MAL_TYPE         1 // 1: Type string; 0: Code

// dns record types bit field defs from dnsType.h
#define DNS_BF0 64
#define DNS_BF1 DNS_SPF
#define DNS_BF2 DNS_TKEY
#define DNS_BF3 DNS_TA

// local plugin defines
#define DNS_QRECMXI (DNS_QRECMAX - 1)
#define DNS_ARECMXI (DNS_ARECMAX - 1)

// Local defines

// DNS Status
#define DNS_PRTDT   0x0001 // DNS ports detected
#define DNS_NBIOS   0x0002 // Netbios dns
#define DNS_FRAGA   0x0004 // DNS TCP aggregate fragmented content
#define DNS_FRAGS   0x0008 // DNS TCP fragmented content state

#define DNS_FTRUNC  0x0010 // Warning: Name truncated
#define DNS_ANY     0x0020 // Warning: ANY: Zone all from a domain or cached server
#define DNS_IZTRANS 0x0040 // Warning: Incremental DNS zone transfer detected
#define DNS_ZTRANS  0x0080 // Warning: DNS zone transfer detected

#define DNS_WRNULN  0x0100 // Warning: DNS UDP Length exceeded
#define DNS_WRNIGN  0x0200 // Warning: following Records ignored
#define DNS_WRNDEX  0x0400 // Warning: Max DNS name records exceeded
#define DNS_WRNAEX  0x0800 // Warning: Max address records exceeded

#define DNS_ERRLEN  0x1000 // Error: DNS record length error
#define DNS_ERRPTR  0x2000 // Error: Wrong DNS PTR detected
#define DNS_WRNMLN  0x4000 // Warning: DNS length undercut
#define DNS_ERRCRPT 0x8000 // Error: UDP/TCP DNS Header corrupt or TCP packets missing

// DNS boundary conditions
#define DNS_MAXUDPLEN 65000 // Max DNS udp payload length
#define DNS_MAXTCPLEN 65443 // Max DNS tcp payload length
#define DNS_MINDNSLEN    17 // Minimal acceptable DNS record length
#define DNS_RSTART       12 // DNS record start in payload
#define DNS_MXNAME      253 // RFC maximal DNS name length
#define DNS_LEN_REJECT    4 // minimal L7 safety length of a DNS packet

#define DNS_HNLMAX      253 // Max name length in flow structure

// DNS Ports network order
#define DNSPORT    53  // dns
#define DNSNPORT  137  // dns netbios
#define DNSPORTM 5353  // dns Multicast
#define DNSPORTB 5355  // dns Broadcast

// DNS types
#define DNS_QR  0x8000
#define DNS_QRN 0x0080
#define DNS_AA  0x0400
#define DNS_TC  0x0200
#define DNS_RD  0x0100
#define DNS_RA  0x0080
#define DNS_BF  0x0780

#define DNS_OPC_MASKn 0x7000
#define DNS_RC_MASKn  0x000F

#define DNS_PTRN  0x00C0
#define DNS_PTRVN ~DNS_PTRN

// Type codes binary mask
#define DNS_HOST_B  0x0000000000000002
#define DNS_CNAME_B 0x0000000000000020
#define DNS_MX_B    0x0000000000008000
#define DNS_AAAA_B  0x0000000010000000

// local plugin structures
typedef struct {
	uint16_t rCode:4;
	uint16_t z:3;
	uint16_t aCode:4;
	uint16_t opCode:4;
	uint16_t qr:1;
} dnsHCode_t;

typedef union {
	dnsHCode_t dnsHCs;
	uint16_t dnsHCu;
} dnsHC_t;

typedef struct {
	//uint16_t len; // only TCP
	uint16_t id;
	dnsHC_t dnsHCode;
	uint16_t qdCount;
	uint16_t anCount;
	uint16_t nsCount;
	uint16_t arCount;
} dnsHeader_t;

typedef struct {
	uint16_t dtype;
	uint16_t dclass;
	uint32_t dttl;
	uint16_t eLen;
	uint8_t data;
} dnsRecHdr_t;

typedef struct {
	ipAddr_t dnsAadd[DNS_ARECMAX];
	uint64_t dnsTypeBF0;
	uint32_t dnsQALen;
	uint32_t dnsAALen;
	uint32_t seqT;
	uint32_t dnsAttl[DNS_ARECMAX];
	uint32_t dnsOptStat[DNS_ARECMAX];
	uint16_t dnsQType[DNS_ARECMAX];
	uint16_t dnsQClass[DNS_ARECMAX];
	uint16_t dnsType[DNS_ARECMAX];
	uint16_t dnsClass[DNS_ARECMAX];
	uint16_t dnsMXPref[DNS_ARECMAX];
	uint16_t srvPrio[DNS_ARECMAX];
	uint16_t srvWeight[DNS_ARECMAX];
	uint16_t srvPort[DNS_ARECMAX];
	uint16_t dnsQRNCnt;
	uint16_t dnsARNCnt;
	uint16_t dnsNRSCnt;
	uint16_t dnsARRCnt;
	uint16_t dnsQNACnt;
	uint16_t dnsANACnt;
	uint16_t dnsNSACnt;
	uint16_t dnsARACnt;
	uint16_t dnsQRNACnt;
	uint16_t dnsARNACnt;
	uint16_t dnsQNCnt;
	uint16_t dnsANCnt;
	uint16_t dnsNSCnt;
	uint16_t dnsARCnt;
	uint16_t dnsHdField;
	uint16_t dnsRCodeBfield;
	uint16_t dnsOpCodeBfield;
	uint16_t dnsTypeBF1;
	uint16_t dnsTypeBF2;
	uint16_t dnsTLen;
	uint16_t dnsStat;
	uint16_t dnsOpCode[DNS_ARECMAX];
	uint8_t dnsTypeBF3;
	uint8_t dnsStatBfield;
	char *dnsQname[DNS_QRECMAX];
	char *dnsAname[DNS_ARECMAX];
	char *dnsPname[DNS_ARECMAX];
//} __attribute__((packed)) dnsFlow_t;
} dnsFlow_t;

extern dnsFlow_t *dnsFlow;

#endif // __DNSDECODE_H__
