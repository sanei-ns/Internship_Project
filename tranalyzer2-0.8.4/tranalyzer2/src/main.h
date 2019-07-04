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

#ifndef __MAIN_H__
#define __MAIN_H__

// local includes

#include "global.h"

#include <wordexp.h>


// Packet mode (-s option)
#define SPKTMD_PKTNO    1 // Whether or not to print the packet number
#define SPKTMD_PCNTC    1 // Whether or not to print L7 content as characters
#define SPKTMD_PCNTH    0 // Whether or not to print L7 content as hex

// Monitoring mode
#define MONINTTHRD     1 // Monitoring: Threaded interrupt handling.
#define MONINTBLK      0 // Monitoring: Block interrupts in main loop during packet processing, disables MONINTTHRD.
#define MONINTPSYNC    1 // Monitoring: Synchronized print statistics.
#define MONINTTMPCP    0 // Monitoring: 1: pcap time base, 0: real time base.
#define MONINTTMPCP_ON 0 // Monitoring: Startup monitoring 1: on 0: off; if (MONINTTMPCP == 0)
#define MONINTV        1 // Monitoring: GI_ALRM: MONINTV >= 1 sec interval of monitoring output.

// Monitoring mode protocol stat
#define MONPROTMD 1 // Monitoring: 0: Protocol numbers; 1: Protocol names (L3 only)
#define MONPROTL3 L3_ICMP,L3_IGMP,L3_TCP,L3_UDP,L3_GRE,L3_ICMP6,L3_SCTP
#define MONPROTL2 0x0042,0x00fe,ETHERTYPE_ARP,ETHERTYPE_RARP,ETHERTYPE_IP,ETHERTYPE_IPV6
#define MONPROTFL "proto.txt"

// statistics summary min max
#define MIN_MAX_ESTIMATE 0 // min max bandwidth statistics


#if DIFF_REPORT == 1
#define REPTYPE 'D'
#else // DIFF_REPORT == 0
#define REPTYPE 'A'
#endif // DIFF_REPORT

#define REPORT_SECTION_L2 'B'
#define REPORT_SECTION_L3 'C'
#define REPORT_SECTION_PL 'P'

#define REPORT_HIST_HDR \
	"%repTyp\tstartTime\ttotFIndex\tnumFlows\tnumAFlows\t" \
	"numBFlows\tnumPkts\tnumAPkts\tnumBPkts\tnumV4Pkts\t" \
	"numV6Pkts\tnumVxPkts\tnumBytes\tnumABytes\tnumBBytes\t" \
	"numFrgV4Pkts\tnumFrgV6Pkts\tnumAlarms\tbytesOnWire\trawBytesOnWire\t" \
	"padBytesOnWire\tcorrReplFlows\ttotalRmFlows\tllcPKts\tgrePkts\t" \
	"teredoPkts\tayiyaPktS\tglobalWarn\n"

// global core defines

// globalInt
#define GI_DIE  0x0000
#define GI_EXIT 0x0001
#define GI_RUN  0x000f
#define GI_RPRT 0x0010
#define GI_USR1 0x0100
#define GI_USR2 0x0200
#define GI_ALRM 0x0400

#define GI_USR (GI_USR1 | GI_USR2)

#define GI_TERM_THRES (GI_EXIT + 2) // after n-times CTRL+C keystroke hit or remote SIGINT, kill the process
#define GI_INIT (GI_TERM_THRES & GI_RUN)

// internal pcap

#define PCAP_MAGIC_L   0xa1b2c3d4
#define PCAP_MAGIC_B   0xd4c3b2a1
#define PCAPNG         0x0a0d0d0a
#define PCAPNG_MAGIC_L 0x1a2b3c4d
#define PCAPNG_MAGIC_B 0x4d3c2b1a

// capture types 16 Bit
#define IFACE       0x0001 // -i option
#define CAPFILE     0x0002 // -r option
#define LISTFILE    0x0004 // -R option
#define DIRFILE     0x0008 // -D option
#define OFILELN     0x0010 // -W option
#define PKTFILE     0x0020 // -s option
#define LOGFILE     0x0040 // -l option
#define FILECNFLCT  0x0080 // Error: more than one input source provided
#define WSTDOUT     0x0100 // indicates that -w/-W option was '-' (stdout)
#define WFINDEX     0x1000 // -W option

// One of IFACE, CAPFILE, LISTFILE or DIRFILE is required
#define CAPTYPE_REQUIRED 0x000f

// Only one of IFACE, CAPFILE, LISTFILE or DIRFILE is allowed
#define CAPTYPE_ERROR(c, v) (((c) & CAPTYPE_REQUIRED) > (v))

// Macros

// 's' can be a pointer to the packet or flow structure
#define T2_SET_STATUS(s, flag) { \
	(s)->status |= (flag); \
	globalWarn |= (flag); \
}

#define BPFSET(captureDescriptor, bpfCommand) { \
	if (bpfCommand && strlen(bpfCommand) > 0) { \
		struct bpf_program bpfProgram; \
		if (pcap_compile(captureDescriptor, &bpfProgram, bpfCommand, ENABLE_BPF_OPTIMIZATION, 0) == -1) { \
			T2_ERR("pcap_compile failed: '%s' is not a valid BPF: %s", bpfCommand, pcap_geterr(captureDescriptor)); \
			if (capType & DIRFILE) T2_ERR("-D option requires \"\" for regex, RTFM"); \
			exit(-1); \
		} \
		if (pcap_setfilter(captureDescriptor, &bpfProgram) == -1) { \
			T2_ERR("pcap_setfilter failed: %s", pcap_geterr(captureDescriptor)); \
			exit(-1); \
		} \
	} \
}

// global thread variables
#if MONINTTHRD == 1
extern volatile sig_atomic_t globalInt; // global main/thread interrupt register
#else // MONINTTHRD == 0
extern volatile uint32_t globalInt;     // global interrupt register
#endif // MONINTTHRD

// core main variables
extern flow_t lruHead, lruTail; // front and tail lru flows. Are unused and don't contain values
extern pcap_t *captureDescriptor; // pcap handler

extern char *fileNumP, fileNumB[21];
extern uint32_t fileNum;      // -D option, incremental file ID
extern uint32_t fileNumE;     // -D option, final file ID
extern uint8_t numType;       // -D option, trailing 0?
extern int fNumLen, fNumLen0; // -D option, Number length
extern char *pDot;            // -D option, postion of '.'
extern char *globFName;       // -D

extern uint64_t captureFileSize;
extern uint64_t totalfIndex;

// monitoring statistics absolute mode

// If we're capturing traffic from a file, these are bytes already processed
extern uint64_t bytesProcessed, bytesProcessed0;
extern uint64_t bytesOnWire, bytesOnWire0;
extern uint64_t rawBytesOnWire, rawBytesOnWire0;
extern uint64_t padBytesOnWire, padBytesOnWire0;
extern uint64_t numFragV4Packets, numFragV4Packets0;
extern uint64_t numFragV6Packets, numFragV6Packets0;
extern uint64_t numLLCPackets, numLLCPackets0;
extern uint64_t numGREPackets, numGREPackets0;
extern uint64_t numTeredoPackets, numTeredoDOPackets0;
extern uint64_t numAYIYAPackets, numAYIYAPackets0;
extern uint64_t maxNumFlows; //, maxNumFlows0;
extern uint64_t maxNumFlowsPeak; //, maxNumFlowsPeak0;
extern uint64_t totalAFlows, totalAFlows0;
extern uint64_t totalBFlows, totalBFlows0;
extern uint64_t corrReplFlws, corrReplFlws0;

extern uint16_t maxHdrDesc, minHdrDesc;
extern float aveHdrDesc;

// endreport max min bandwidth info
#if MIN_MAX_ESTIMATE == 1
extern uint64_t rawBytesW0, maxBytesPs, minBytesPs, lagTm;
#endif // MIN_MAX_ESTIMATE == 1

#if FRAGMENTATION >= 1
extern hashMap_t *fragPendMap;
extern unsigned long *fragPend;
#endif // FRAGMENTATION >= 1

// vlan, mpls cnts
extern uint8_t vlanHdrCntMx, mplsHdrCntMx;

extern char *bpfCommand; // BPF filter command
extern uint32_t hashFactor;

typedef struct timeout_s {
	float timeout; // the timeout value in seconds
	flow_t flow;   // a sentinel flow
	struct timeout_s *next;
} timeout_t;

extern void cycleLRULists();

// Adds a new timeout handler to the main timeout manager
void timeout_handler_add(float timeout);

// -R option

typedef struct caplist_elem_s {
	uint64_t size;
	char *name;
	struct caplist_elem_s *next;
} caplist_elem_t;

typedef struct {
	uint64_t size;
	uint32_t num_files;
	caplist_elem_t *file_list;
} caplist_t;

extern caplist_t *caplist;
extern caplist_elem_t *caplist_elem;
extern uint32_t caplist_index;

bool ckpcaphdr(const char* pcapname);
void printGStats();

#if HASH_AUTOPILOT == 1
extern void lruRmLstFlow();
#endif

extern sigset_t t2_get_sigset();
extern void terminate() __attribute__((noreturn));

#endif // __MAIN_H__
