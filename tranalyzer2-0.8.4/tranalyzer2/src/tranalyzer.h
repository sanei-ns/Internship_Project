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

#ifndef __TRANALYZER_H__
#define __TRANALYZER_H__

#include <limits.h>

#define T2_SENSORID 666

#define PLUGIN_FOLDER ".tranalyzer/plugins/"

// -D option parameters
#define RROP      0    // round robin operation
#define POLLTM    5    // poll timing in seconds for files
#define MFPTMOUT  0    // > 0: timeout for poll timing > POLLTM, 0: no poll timout
#define SCHR     'p'   // separating char for number (refer to the doc for examples)

// -W option parameters
#define OFRWFILELN 5E8 // default fragmented output file length (500MB)

// alive signal activation
#define REPSUP   0         // 1: activate alive mode
#define ALVPROG  "t2alive" // name of control program
#define REPCMDAS "a=`pgrep "ALVPROG"`; if [ $a ]; then kill -USR1 $a; fi" // alive and stall USR1 signal (no packets count)
#define REPCMDAW "a=`pgrep "ALVPROG"`; if [ $a ]; then kill -USR2 $a; fi" // alive and well USR2 signal (working)

// PID file
#define PID_FNM_ACT 0   // 1: enable PID -> file, 0: disable
#define PID_FNM "tranalyzer.pid"

#define MAX_FILENAME_LEN 1024 // should be enough for the wildest path- and filenames

// Suffixes for the generated files
#define PACKETS_SUFFIX "_packets.txt"
#define LOG_SUFFIX     "_log.txt"

/*
 *  The debug level:
 *  0: no debug output
 *  1: debug output which occurs only once or very seldom (i.e. initialize stuff, errors, ...)
 *  2: + debug output which occurs in special situations, but not regularly (i.e. border conditions, restructure works, ...)
 *  3: + debug output which occurs regularly (i.e. every packet)
 */
#define DEBUG 0

/*
 * The verbose level of final report:
 * 0: no output
 * 1: Basic pcap report
 * 2: + full traffic statistics
 * 3: + info about frag anomalies
 */
#define VERBOSE 2

/*
 * Enable memory debug of buffers on the heap (allocated with malloc or calloc):
 * 0: no memory debug
 * 1: memory debug: see utils/memdebug.h
 */
#define MEMORY_DEBUG 0

// timing ops
#define NO_PKTS_DELAY_US  1000 // if no packets are to be processed, sleep some time in us
#define NON_BLOCKING_MODE    1 // non blocking mode of pcap_dispatch is necessary when using the CTRL+C keystroke feature and complete flows are to be expected

// Flow output buffer
#define MAIN_OUTPUT_BUFFER_SIZE 1000000 // the size of the main output buffer

// pcap
#define SNAPLEN                 BUFSIZ
#define CAPTURE_TIMEOUT         1000
#define ENABLE_BPF_OPTIMIZATION 0
#define PACKETS_PER_BURST       1 // THIS VALUE SHOULD NOT BE CHANGED!!!
#define TSTAMP_PREC             0 // Timestamp precision: 0: microsecs, 1: nanosecs
#define TSTAMP_UTC              1 // Time representation: 0: localtime, 1: utc
#define TSTAMP_R_UTC            0 // Time report representation: 0: localtime, 1: utc

#if TSTAMP_PREC == 1
#define PTSPREC PCAP_TSTAMP_PRECISION_NANO
#else // TSTAMP_PREC == 0
#define PTSPREC PCAP_TSTAMP_PRECISION_MICRO
#endif // TSTAMP_PREC

// Tranalyzer User Operational modes

// Operation modes, Plugins which use these modes have to be recompiled

#define ALARM_MODE 0 // only flow output if an Alarm based plugin fires
#define ALARM_AND  0 // if (ALARM_MODE == 1) then 1: AND, 0: OR

#define FORCE_MODE 0 // netflow mode: parameter induced flow termination, implemented by plugins
#define BLOCK_BUF  0 // block unnecessary buffer output when non tranalyzer format event-based plugins are active: e.g. syslog, arcsight crap

#define USE_T2BUS  0 // XXX experimental (not implemented yet)

// End report / monitoring: USR1/2 interrupts
#define PLUGIN_REPORT    1 // enable plugins to contribute to the tranalyzer command line end report
#define DIFF_REPORT      0 // 1: differential, 0: Absolute tranalyzer command line USR1 report
#define MACHINE_REPORT   0 // 1: machine compliant; 0: human compliant

// state save mode: findex, report and statistical data
#define REPORT_HIST      0 // store statistical report history after shutdown and reload it when restarted
#define REPORT_HIST_FILE "stat_hist.txt" // statistical report history filename

// Esom dependency
#define ESOM_DEP        0 // allow the Classifier to globally access dependent plugin variables

// Protocol stack
#define AYIYA           1 // AYIYA processing on: 1, off: 0
#define GENEVE          1 // GENEVE processing on: 1, off: 0
#define TEREDO          1 // TEREDO processing on: 1, off: 0
#define L2TP            1 // L2TP processing on: 1, off: 0
#define GRE             1 // GRE processing on: 1, off: 0
#define GTP             1 // GTP processing on: 1, off: 0
#define VXLAN           1 // VXLAN processing on: 1, off: 0
#define IPIP            1 // IPv4/6 in IPv4/6 processing on: 1, off: 0
#define ETHIP           1 // Ethernet over IP on: 1, off: 0
#define CAPWAP          1 // CAPWAP processing on: 1, off: 0
#define LWAPP           1 // LWAPP processing on: 1, off: 0

// XXX Move to proto/capwap.h and proto/lwapp.h?
#define CAPWAP_SWAP_FC  1 // Swap frame control (required for Cisco)
#define LWAPP_SWAP_FC   1 // Swap frame control (required for Cisco)

#define FRAGMENTATION   1 // Fragmentation processing on: 1, off: 0
#define FRAG_HLST_CRFT  1 // if (FRAGMENTATION) then 1: Enables crafted packet processing (header missing, senseless flags etc); off: 0
#define FRAG_ERROR_DUMP 0 // if (FRAGMENTATION) then 1: Dumps flawed fragmented packet info on commandline for time-based identification ; WARNING: IF FRAG_HLST_CRFT != 0 THEN EVERY HEADERLESS FRAG PACKET IN A FLOW IS REPORTED!

#define IPVX_INTERPRET  0 // Interpret bogus IPvX packets and pack them into IPv4 or IPv6 flows

#define ETH_STAT_MODE   0 // Wether to use the innermost (0) or outermost (1) layer 2 type for the statistics

// Aggregation modes
#define L4PROT  0x01
#define DSTPORT 0x02
#define SRCPORT 0x04
#define DSTIP   0x08
#define SRCIP   0x10
#define VLANID  0x20
#define SUBNET  0x80

// Flow Agreggation
#define AGGREGATIONFLAG  0x00 // each bit: 1 : aggregation activated, def see aggregation mode local def above
#define SRCIP4CMSK 24  // src IPv4 aggregation CIDR mask
#define DSTIP4CMSK 24  // dst IPv4 aggregation CIDR mask

#define SRCIP6CMSK 120 // src IPv6 aggregation CIDR mask
#define DSTIP6CMSK 120 // dst IPv6 aggregation CIDR mask

#define SRCPORTLW 53  // src port lower bound
#define SRCPORTHW 53  // src port upper bound
#define DSTPORTLW 53  // dst port lower bound
#define DSTPORTHW 53  // dst port upper bound

// Calculation IPv4 flow aggregation network masks
#define SRCIP4MSK (0xffffffff << (32-SRCIP4CMSK))  // ipv6 network order 32 bit
#define DSTIP4MSK (0xffffffff << (32-DSTIP4CMSK))  // ipv6 network order 32 bit

// Calculation IPv6 flow aggregation network masks
#if SRCIP6CMSK > 64
#define SRCIP6MSKH 0xffffffffffffffff                       // ipv6 network order high 64 bit
#define SRCIP6MSKL (0xffffffffffffffff << (128-SRCIP6CMSK)) // ipv6 network order low 64 bit
#else // SRCIP6CMSK <= 64
#define SRCIP6MSKH (0xffffffffffffffff << (64-SRCIP6CMSK))  // ipv6 network order high 64 bit
#define SRCIP6MSKL 0x0 				            // ipv6 network order low 64 bit
#endif // SRCIP6CMSK < 64

#if DSTIP6CMSK > 64
#define DSTIP6MSKH 0xffffffffffffffff                        // ipv6 network order high 64 bit
#define DSTIP6MSKL ~(0xffffffffffffffff << (128-DSTIP6CMSK)) // ipv6 network order low 64 bit
#else // DSTIP6CMSK <= 64
#define DSTIP6MSKH (0xffffffffffffffff << (64-SRCIP6CMSK))   // ipv6 network order high 64 bit
#define DSTIP6MSKL 0x0				             // ipv6 network order low 64 bit
#endif // DSTIP6CMSK < 64

// Time mode
#define RELTIME 0 // 0: Absolute time, 1: Relative internal time

// Maximum lifetime of a flow
#define FDURLIMIT 0 // if > 0; forced flow life span of n +- 1 seconds

// The standard timeout for a flow in seconds
#define FLOW_TIMEOUT 182 // flow timeout after a packet is not seen after n seconds

// The sizes of the hash table
#define HASHFACTOR 1                       // default multiplication factor for HASHTABLE_BASE_SIZE and HASHCHAINTABLE_BASE_SIZE if no -f option
#define HASHTABLE_BASE_SIZE       524288UL // 2^19; HASHTABLE_BASE_SIZE >= HASHCHAINTABLE_BASE_SIZE * 2
#define HASHCHAINTABLE_BASE_SIZE  262144UL // 2^18

#define HASH_AUTOPILOT 1 // 1: avoids overrun of main hash, flushes oldest NUMFLWRM flow on flowInsert, 0: disable hash overun protection
#define NUMFLWRM       1 // number of flows to flush when main hash map is full

// Automatic adaptation to flow timeout if flow life span is limited by FDURLIMIT
#if FDURLIMIT > 0
#undef FLOW_TIMEOUT
#define FLOW_TIMEOUT 1
#endif // FDURLIMIT

#endif // __TRANALYZER_H__
