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

#ifndef _NETFLOW_V5_H
#define _NETFLOW_V5_H

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#define NETFLOW_V5_HEADER_LENGTH 24
#define NETFLOW_V5_RECORD_LENGTH 48
#define NETFLOW_V5_MAX_RECORDS   30

#define COLLECTORSERVER   "192.0.0.2"
#define COLLECTORPORTPORT 2055         // The port on which to send data
#define BUFLEN             512         // Max length of buffer

// plugin defs
#define MESSAGELEN   1500
#define MAX_LINE_LEN 1024

/* v5 structures */
typedef struct {
    uint16_t version;           // must be 5
    uint16_t flowcounter;       // number of exported flows (1-30)
    uint32_t SysUptime;         // Device Sysuptime. Applies only to routers and so. Therefore will be 0
    uint32_t unix_secs;         // Actual Time in Secinds since epoch
    uint32_t unix_nsecs;        // Residual nanaoseconds since epoch
    uint32_t flow_sequence;     // Sequencs Number of Flows actual seen. Maybe applicable. Else it will be zero. Maybe use Flow index L4
    uint16_t engine_tag;        // Type of Flow switching machine. Probably zero
    uint16_t engine_id;         // Slot Number. Will be zero
    uint16_t sampling_interval; // ??
} netflow_v5_header;
//netflow_v5_header_t;
//netflow_v5_header_t *netflow_v5_header;



typedef struct {
    uint32_t srcaddr;             // check
    uint32_t dstaddr;             // check
    uint32_t nexthop;             // Probable 0xffffffff;
    uint16_t snmpindexinput;      // snmp index of input interface
    uint16_t snmpindexoutput;
    uint32_t PktsInFlow;
    uint32_t BytesInOctets;       // Amount of bytes in the flow
    uint32_t FirstFlowSysuptime;
    uint32_t LastFlowSysuptime;
    uint16_t srcport;             // check
    uint16_t dstport;             // check
    uint8_t  pad1;                // set to zero bytes 0x00000000
    uint8_t  tcp_flags;
    uint8_t  prot;
    uint8_t  tos;                 // check
    uint16_t src_as;
    uint16_t dst_as;
    uint8_t  src_mask;
    uint8_t  dst_mask;
    uint16_t pad2;
} netflow_v5_record ;
//netflow_v5_record_t;
//netflow_v5_record_t *netflow_v5_record;


// prototypes
//int init_v5_input(void);

//void process_v5(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs);

//void init_v5_output(send_peer_t *peer);

//int add_v5_output_record(master_record_t *master_record, send_peer_t *peer);

/*
 * Extension map for v5/v7
 * Based on RFC 3176
 *
 * Required extensions:
 *
 *       4 byte byte counter
 *       | 4byte packet counter
 *       | | IPv4
 *       | | |
 * xxxx x0 0 0
 *
 * Optional extensions:
 *
 * 4: 2 byte input/output interface id
 * 6: 2 byte src/dst as
 * 8: srcmask/dst mask dst tos = 0, dir = 0
 * 9: IPv4 next hop
 */

#endif //_NETFLOW_V5_H
