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

#ifndef __TCPFLAGS_H__
#define __TCPFLAGS_H__

// local includes
#include "global.h"

// local defines

// -s option
#define SPKTMD_SEQACKREL 0 // -s option SEQ/ACK Numbers 0: absolute, 1: relative

// tcp ops
#define RTT_ESTIMATE     1 // 1: Round trip time estimation
#define IPCHECKSUM       2 // 1: Calculation of L3 (IP) header checksum,
                           // 2: L3 + L4 (TCP,UDP) checksum
#define WINDOWSIZE       1 // 1: Calculation of TCP window size parameters
#define WINMIN		 1 // Minimal window size threshold defining a healthy communication, below packets are counted
#define SEQ_ACK_NUM      1 // 1: SEQ/ACK number feature analysis
#define FRAG_ANALYZE     1 // 1: Fragmentation analysis
#define NAT_BT_EST       1 // 1: NAT boot time estimation
#define SCAN_DETECTOR    1 // 1: Scan flow detector

// Local constants
#define IPFRAGPKTSZMIN      48
#define IPFRAGPKTSZMAX  0x1fff
#define PKTINTDISTOLL     0.01
#define RTTFILTERCONST     0.6 // round trip time filter constant
#define IP_ID_RLLOVR    0x2000 // IP ID roll-over threshold
#define TCPOPTTM    0x00000100

// scandetector
#define TCP_SCAN_PMAX   5   // maximal scan tries / flow

// tcpFStat
#define IP_INT_DISSTATE 0x0001 // 1. Packet no good for inter-distance assessment
#define TCP_SCAN_DET    0x0002 // scan detected in flow
#define TCP_SCAN_SU_DET 0x0004 // successful scan detected in flow
#define TCP_OPT_TM_DEC  0x0008 // timestamp option decreasing
#define TCP_OPT_INIT    0x0010 // TCP option init
#define TCP_ACK_PKTLOSS 0x0020 // ACK Packet loss state machine init
#define TCP_WIN_INIT    0x0040 // Window state-machine initialized
#define TCP_WIN_UP      0x0080 // Bit 7: Window state-machine count up
#define TCP_WIN_DWN     0x0000 // Bit 7: Window state-machine count down

#define L4CHKSUMC       0x0100 // L4 Checksum calculation if present
#define L4_CHKCOVERR    0x0200 // UDPLITE Checksum coverage error

// ipFlagsT
#define IP_OPT_CORRPT   0x0001 // IP options corrupt
#define IP_ID_OUT_ORDER 0x0002 // IPv4 packets out of order
#define IP_ID_ROLL_OVER 0x0004 // IPv4 ID roll over
#define IP_FRAG_BLW_MIN 0x0008 // IP fragment below minimum
#define IP_FRAG_OUT_RNG 0x0010 // IP fragment out of range
#define IP_FRAG_MF      0x0020 // More fragment bit
#define IP_FRAG_DF      0x0040 // IPv4: don't fragment bit, IPv6: reserve bit
#define IP_FRAG_RES     0x0080 // IPv4: reserve bit
#define IP_FRAG_NXTPPOS 0x0100 // fragmentation position error
#define IP_FRAG_SEQERR  0x0200 // fragmentation sequence error
#define IP_L3CHK_SUMERR 0x0400 // L3 chksum error
#define IP_L4CHK_SUMERR 0x0800 // L4 chksum error
#define IP_SNP_HLEN_WRN 0x1000 // L3 header length snapped
#define IP_PKT_INTDIS   0x2000 // pkt inter-distance = 0
#define IP_PKT_INTDISN  0x4000 // pkt inter-distance < 0
#define TCP_L7CNT       0x8000 // SYN flag with L7 content

#define IP_FRAG_BITS   (IP_FRAG_RES | IP_FRAG_DF | IP_FRAG_MF)

#define IP_FRAG_NO_HDR (IP_FRAG_SEQERR | IP_FRAG_OUT_RNG | IP_FRAG_NXTPPOS)

// tcpFlagsT
#define FIN 0x01
#define SYN 0x02
#define RST 0x04
#define PSH 0x08
#define ACK 0x10
#define URG 0x20
#define ECE 0x40
#define CWR 0x80

// tcpAnomaly
#define TCP_FIN_ACK     0x0001 // FIN-ACK flag
#define TCP_SYN_ACK     0x0002 // SYN-ACK flag
#define TCP_RST_ACK     0x0004 // RST-ACK flag
#define TCP_SYN_FIN     0x0008 // SYN-FIN flag, scan or malicious packet
#define TCP_SYN_FIN_RST 0x0010 // SYN-FIN-RST flag, potential malicious scan packet or malicious channel
#define TCP_RST_FIN     0x0020 // FIN-RST flag, abnormal flow termination
#define TCP_NULL        0x0040 // Null Flag, potential NULL scan packet, or malicious channel
#define TCP_XMAS        0x0080 // XMas Flag, potential Xmas scan packet, or malicious channel
#define TCP_L4OPTCORRPT 0x0100 // Warning: L4 Option field corrupt or not acquired
#define TCP_SYN_RETRY   0x0200 // SYN retransmission
#define TCP_SEQ_RETRY   0x0400 // Sequence Number retry
#define TCP_SEQ_OUTORDR 0x0800 // Sequence Number out of order
#define TCP_SEQ_PLSSMS  0x1000 // Sequence mess in flow order due to pcap packet loss
#define TCP_SEQ_JMP     0x2000 // Sequence number jump forward
#define TCP_ACK_OUTORDR 0x4000 // ACK number out of order
#define TCP_ACK_2       0x8000 // Duplicate ACK

#define TCP_SCAN_FLAGS  0x00fd

// round trip flags
#define TCP_RTT_NO_SYN  0x00 // RTT no SYN detected
#define TCP_RTT_SYN_ST  0x01 // RTT SYN state
#define TCP_RTT_SYN_ACK 0x02 // RTT SYN ACK state
#define TCP_RTT_ACK_A   0x04 // RTT ACK A flow
#define TCP_RTT_ACK_B   0x08 // RTT ACK B flow
#define TCP_RTT_FLTCST  0X10 // RTT filter ops ACK <--> ACK
#define TCP_RTT_STOP    0X80 // RTT machine stop


// structs

// pseudo header for checksum calculation (network order)

typedef struct {
	ipAddr_t ip_src;        // source address
	ipAddr_t ip_dst;        // dest address
	uint32_t l4_len;        // total L4 length
	uint32_t ip_p;          // high byte = protocol
} __attribute__((packed)) psyL3Header6_t;

typedef struct {
	struct in_addr ip_src;  // source address
	struct in_addr ip_dst;  // dest address
	uint16_t ip_p;          // high byte = protocol
	uint16_t l4_len;        // total L4 length
} __attribute__((packed)) psyL3Header4_t;

typedef struct {
    struct timeval lastPktTime;

#if NAT_BT_EST == 1
    struct timeval tmOptFrstPkt;
    struct timeval tmOptLstPkt;
#endif // NAT_BT_EST == 1

#if SEQ_ACK_NUM == 1
    int64_t tcpOpSeqPktLength;
    int64_t tcpOpAckPktLength;
    uint32_t tcpSeqT;
    uint32_t tcpAckT;
#endif // SEQ_ACK_NUM == 1

#if SPKTMD_SEQACKREL == 1
    uint32_t tcpSeqI;
    uint32_t tcpAckI;
#endif // SPKTMD_SEQACKREL == 1

#if IPV6_ACTIVATE > 0
    uint32_t ip6HHOptionsT;
    uint32_t ip6DOptionsT;
#endif // IPV6_ACTIVATE > 0
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    uint32_t ipOptionsT;
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    uint32_t tcpOptionsT;

#if NAT_BT_EST == 1
    uint32_t tcpTmS;
    uint32_t tcpTmER;
    uint32_t tcpTmSI;
    uint32_t tcpTmSLst;
#endif // NAT_BT_EST == 1

#if RTT_ESTIMATE == 1
    float tcpRTTtrip;
    float tcpRTTAckTripMin;
    float tcpRTTAckTripMax;
    float tcpRTTAckTripAve;
    float tcpRTTAckTripJitAve;
    float tcpPktCnt;
#endif // RTT_ESTIMATE == 1

#if WINDOWSIZE == 1
    float tcpWinAveT;
    uint32_t tcpWinMinCnt;
    uint32_t tcpPktvCnt;
    uint32_t tcpWinInitT;
    uint32_t tcpWinLastT;
    uint32_t tcpWinMinT;
    uint32_t tcpWinMaxT;
    uint16_t tcpWupCntT;
    uint16_t tcpWdwnCntT;
    uint16_t tcpWchgCntT;
#endif // WINDOWSIZE == 1

#if SEQ_ACK_NUM == 1
    uint16_t tcpPLstLen;
    uint16_t tcpPSeqCntT;
    uint16_t tcpSeqFaultCntT;
    uint16_t tcpPAckCntT;
    uint16_t tcpAckFaultCntT;
#endif // SEQ_ACK_NUM == 1

#if FRAGMENTATION == 1
    uint16_t l4CalChkSum;
    uint16_t l4HdrChkSum;
#endif // FRAGMENTATION == 1

    uint16_t stat;
    uint16_t tcpAnomaly;
    uint16_t tcpMssT;
    uint16_t tcpOptCntT;
    uint16_t tcpOptPktCntT;
    uint16_t ipIDT;
    uint16_t ipMinIDT;
    uint16_t ipMaxIDT;
    uint16_t ipFlagsT;
    uint16_t ipNxtFragBgnExp;
#if IPV6_ACTIVATE > 0
    uint16_t ip6HHOptCntT;
    uint16_t ip6DOptCntT;
#endif // IPV6_ACTIVATE > 0
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    uint16_t ipOptCntT;
//  uint16_t ipOptPktCntT;
    uint8_t ipCpClT;
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    uint8_t tcpWST;
    uint8_t tcpFlagsT;
    uint8_t ipTosT;
    uint8_t ipMinTTLT;
    uint8_t ipMaxTTLT;
    uint8_t ipTTLChgT;
    uint8_t ipTTLT;
    uint8_t tcpRTTFlag;

#if SCAN_DETECTOR == 1
    uint8_t pktCnt;
#endif // SCAN_DETECTOR == 1

//  uint8_t tcpRTTAggFlag;
} tcpFlagsFlow_t;

// Pointer for potential dependencies

extern tcpFlagsFlow_t *tcpFlagsFlows;

#endif // __TCPFLAGS_H__
