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

#ifndef __GLOBAL_H__
#define __GLOBAL_H__

// includes
#include <errno.h>
#include <float.h>
#include <libgen.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __APPLE__
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <netinet/if_ether.h>
#endif // __APPLE__

// local includes
#include "tranalyzer.h"
#include "packetCapture.h"
#include "bin2txt.h"
#include "hashTable.h"
#include "loadPlugins.h"
#include "ioBuffer.h"
#include "main.h"
#include "missing.h"
#include "fsutils.h"
#include "t2log.h"


// global defines

// globalStat, packet and flow status
#define L3FLOWINVERT        0x0000000000000001  // Inverted flow, did not initiate connection
#define L2_NO_ETH           0x0000000000000002  // No Ethernet header
#define L2_FLOW             0x0000000000000004  // Pure L2 Flow
#define L2_PPPoE_D          0x0000000000000008  // Point to Point Protocol over Ethernet Discovery (PPPoED)
#define L2_PPPoE_S          0x0000000000000010  // Point to Point Protocol over Ethernet Service (PPPoES)
#define L2_LLDP             0x0000000000000020  // Link Layer Discovery Protocol (LLDP)
#define L2_ARP              0x0000000000000040  // ARP present
#define L2_RARP             0x0000000000000080  // Reverse ARP present
#define L2_VLAN             0x0000000000000100  // VLANs present
#define L2_MPLS_UCAST       0x0000000000000200  // MPLS unicast present
#define L2_MPLS_MCAST       0x0000000000000400  // MPLS multicast present
#define L2_L2TP             0x0000000000000800  // L2TP v2/3 present
#define L2_GRE              0x0000000000001000  // GRE v1/2 present
#define L2_PPP              0x0000000000002000  // PPP header present after L2TP or GRE
#define L2_IPV4             0x0000000000004000  // IPv4 packets present
#define L2_IPV6             0x0000000000008000  // IPv6 packets present
#define L3_IPVX             0x0000000000010000  // IPvX bogus packets present
#define L3_IPIP             0x0000000000020000  // IPv4/6 in IPv4/6
#define L3_ETHIPF           0x0000000000040000  // Ethernet over IP
#define L3_TRDO             0x0000000000080000  // Teredo Tunnel
#define L3_AYIYA            0x0000000000100000  // Anything in Anything (AYIYA) Tunnel
#define L3_GTP              0x0000000000200000  // GPRS Tunneling Protocol (GTP)
#define L3_VXLAN            0x0000000000400000  // Virtual eXtensible Local Area Network (VXLAN)
#define L3_CAPWAP           0x0000000000800000  // Control And Provisioning of Wireless Access Points (CAPWAP),
                                                // Lightweight Access Point Protocol (LWAPP)
#define L4_SCTP             0x0000000001000000  // Stream Control Transmission Flows
#define L4_UPNP             0x0000000002000000  // SSDP/UPnP
#define L2_ERSPAN           0x0000000004000000  // Encapsulated Remote Switch Packet ANalysis (ERSPAN)
#define L2_WCCP             0x0000000008000000  // Cisco Web Cache Communication Protocol (WCCP)
#define L7_SIPRTP           0x0000000010000000  // SIP/RTP
#define L3_GENEVE           0x0000000020000000  // Generic Network Virtualization Encapsulation (GENEVE)
#define L3_IPSEC_AH         0x0000000040000000  // IPsec Authentication Header (AH)
#define L3_IPSEC_ESP        0x0000000080000000  // IPsec Encapsulating Security Payload (ESP)

// globalWarn, packet and flow warning
#define L2SNAPLENGTH        0x0000000100000000  // Acquired packet length < minimal L2 datagram
#define L3SNAPLENGTH        0x0000000200000000  // Acquired packet length < packet length in L3 header
#define L3HDRSHRTLEN        0x0000000400000000  // Acquired packet length < minimal L3 Header
#define L4HDRSHRTLEN        0x0000000800000000  // Acquired packet length < minimal L4 Header
#define IPV4_FRAG           0x0000001000000000  // IPv4 fragmentation present
#define IPV4_FRAG_ERR       0x0000002000000000  // IPv4 fragmentation Error (detailed err s. tcpFlags plugin)
#define IPV4_FRAG_HDSEQ_ERR 0x0000004000000000  // IPv4 1. fragment out of sequence or missing
#define IPV4_FRAG_PENDING   0x0000008000000000  // Packet fragmentation pending / fragmentation sequence not completed when flow timeouts
#define FLWTMOUT            0x0000010000000000  // Flow timeout instead of protocol termination
#define RMFLOW              0x0000020000000000  // Alarm mode: remove this flow instantly
#define RMFLOW_HFULL        0x0000040000000000  // Autopilot: Flow removed to free space in main hash map
#define STPDSCT             0x0000080000000000  // Stop dissecting
#define DUPIPID             0x0000100000000000  // Consequtive duplicate IP ID
#define PPP_NRHD            0x0000200000000000  // PPPL3 header not readable, compressed
#define HDOVRN              0x0001000000000000  // Header description overrun
#define FL_ALARM            0x0002000000000000  // pcapd and PD_ALARM=1: if set dumps the packets from this flow to a new pcap
#define LANDATTACK          0x0004000000000000  // Same src IP && dst IP and src port && dst port
#define TIMEJUMP            0x0008000000000000  // Time slip possibly due to NTP operations on the capture machine
#define LIVEXTR             0x0010000000000000  // Flow should be extracted by the liveXtr plugin
#define TORADD              0x0100000000000000  // Tor address detected
#define FS_VLAN0            0x0200000000000000  // A packet had a priority tag (VLAN tag with ID 0)
#define PCAPSNPD            0x8000000000000000  // PCAP packet length > MAX_MTU in ioBuffer.h, caplen reduced

#define SNAPLENGTH  (L2SNAPLENGTH | L3SNAPLENGTH)
#define L2_MPLS     (L2_MPLS_UCAST | L2_MPLS_MCAST)

// Global variables
//extern uint32_t globalProt; // global status and warning register
extern uint64_t globalWarn; // global status and warning register

#if ALARM_MODE == 1
extern unsigned char supOut; // suppress output
#define T2_REPORT_ALARMS(num) { \
    numAlarms += (num); \
    if (!ALARM_AND) { \
        if (num) supOut = 0; \
    } else { \
        if (!(num)) { \
            supOut = 1; \
            return; \
        } \
    } \
}
#else // ALARM_MODE == 0
#define T2_REPORT_ALARMS(num) numAlarms += (num) 
#endif // ALARM_MODE == 0

#if FORCE_MODE == 1
#define T2_RM_FLOW(flowP) { \
    (flowP)->status |= RMFLOW; \
    rm_flows[num_rm_flows++] = flowP; \
    numForced++; \
}
extern uint64_t numForced, numForced0;
#else // FORCE_MODE == 0
#define T2_RM_FLOW(flowP)
#endif // FORCE_MODE == 1

#if (FORCE_MODE == 1 || FDURLIMIT > 0)
extern unsigned long num_rm_flows;
//extern flow_t *rm_flows[HASHCHAINTABLE_BASE_SIZE];
extern flow_t *rm_flows[10];
#endif // (FORCE_MODE == 1 || FDURLIMIT > 0)

extern t2_plugin_array_t *t2_plugins;

extern binary_value_t *main_header_bv;
extern flow_t *flows;
extern hashMap_t *mainHashMap;
extern outputBuffer_t *main_output_buffer;

extern file_manager_t *t2_file_manager;

extern struct timeval actTime;

// counter and monitoring diff mode vars

extern struct timeval startTStamp, startTStamp0;

extern uint64_t numAlarms, numAlarms0;
extern uint64_t numPackets, numPackets0;
extern uint64_t numV4Packets, numV4Packets0;
extern uint64_t numV6Packets, numV6Packets0;
extern uint64_t numVxPackets, numVxPackets0;
extern uint64_t totalFlows, totalFlows0;
extern uint64_t numAPackets, numAPackets0;
extern uint64_t numBPackets, numBPackets0;
extern uint64_t numABytes, numABytes0;
extern uint64_t numBBytes, numBBytes0;

// global L3 protocols
extern uint64_t numBytesL3[256], numBytes0L3[256];
extern uint64_t numPacketsL3[256], numPackets0L3[256];

extern uint64_t numBytesL2[65536], numBytes0L2[65536];
extern uint64_t numPacketsL2[65536], numPackets0L2[65536];

// Parsing parameters

#if USE_PLLIST > 0
extern char *pluginList;    // -b option: plugin loading list
#endif // USE_PLLIST > 0
extern FILE *dooF;          // -l option: end report file
extern char *pluginFolder;  // -p option
extern FILE *sPktFile;      // -s option: packet file
extern uint32_t sensorID;   // -x option
extern double oFragFsz;     // -W option
extern uint64_t oFileNumB;  // -W option
extern char *capName;       // -D, -i, -r and -R option
extern uint16_t capType;    // -D, -i, -l, -r, -s and -W options
extern char *baseFileName;  // base file name for all generated files
extern char *esomFileName;  // for pcapd

extern char *cmdline;       // command line buffer

extern size_t baseFileName_len;
extern size_t pluginFolder_len;

#endif // __GLOBAL_H__
