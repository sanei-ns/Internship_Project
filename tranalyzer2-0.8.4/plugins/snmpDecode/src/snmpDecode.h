/*
 * snmpDecode.h
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

#ifndef __SNMP_DECODE_H__
#define __SNMP_DECODE_H__

// global includes

// local includes
#include "global.h"

// user defines
#define SNMP_STRLEN 64 // max length for string

// plugin defines
#define SNMP_PORT      161 // Server
#define SNMP_TRAP_PORT 162 // Traps

#define SNMP_MIN_HDRSIZE 5

#define SNMP_V1 0x0
#define SNMP_V2 0x1 // v2c
#define SNMP_V3 0x3

// SNMP data types
#define SNMP_T_INT             0x02 // Integer/Integer32
#define SNMP_T_BITSTR          0x03 // BitString
#define SNMP_T_OCTSTR          0x04 // OctetString
#define SNMP_T_NULL            0x05 // Null
#define SNMP_T_OID             0x06 // OID
#define SNMP_T_OID             0x06 // OID
#define SNMP_T_REAL            0x09 // Real
#define SNMP_T_ENUM            0x0a // Enumerated
#define SNMP_T_SEQ             0x30 // Sequence/Sequence Of/VarBind
#define SNMP_T_IP              0x40 // IpAddress
#define SNMP_T_CNT32           0x41 // Counter/Counter32
#define SNMP_T_GAUGE32         0x42 // Gauge/Gauge32
#define SNMP_T_TIMETICKS       0x43 // TimeTicks
#define SNMP_T_OPAQUE          0x44 // Opaque
#define SNMP_T_CNT64           0x46 // Counter64

// SNMP PDU types
#define SNMP_PDU_GET_REQ      0xa0 // GetRequest
#define SNMP_PDU_GET_NEXT_REQ 0xa1 // GetNextRequest
#define SNMP_PDU_GET_RESP     0xa2 // GetResponse
#define SNMP_PDU_SET_REQ      0xa3 // SetRequest
#define SNMP_PDU_TRAP         0xa4 // Trap (v1)
#define SNMP_PDU_GET_BULK_REQ 0xa5 // GetBulkRequest (v2c, v3)
#define SNMP_PDU_INFO_REQ     0xa6 // InformRequest
#define SNMP_PDU_TRAPv2       0xa7 // Trap (v2c, v3)
#define SNMP_PDU_REPORT       0xa8 // Report

#define SNMP_NUM_PDU_TYPES 9
#define SNMP_NPDU_BVTYPES \
    bt_uint_64, bt_uint_64, bt_uint_64, \
    bt_uint_64, bt_uint_64, bt_uint_64, \
    bt_uint_64, bt_uint_64, bt_uint_64

// SNMP error-status
#define SNMP_ERR_NONE      0x00 // No error occurred
#define SNMP_ERR_TOO_LARGE 0x01 // Response message too large to transport
#define SNMP_ERR_NOT_FOUND 0x02 // The name of the requested object was not found
#define SNMP_ERR_MISMATCH  0x03 // A data type in the request did not match the data type in the SNMP agent
#define SNMP_ERR_SET_RO    0x04 // The SNMP manager attempted to set a read-only parameter
#define SNMP_ERR_GENERAL   0x05 // General Error (some error other than the ones listed above)

// Status variable
#define SNMP_STAT_SNMP      0x01 // Flow is SNMP
#define SNMP_STAT_TRUNC     0x40 // String was truncated... increase SNMP_STRLEN
#define SNMP_STAT_MALFORMED 0x80 // Packet was malformed

typedef struct {
    uint64_t num_pkt[SNMP_NUM_PDU_TYPES];
    uint16_t msgT;
    uint8_t community[SNMP_STRLEN+1]; // SNMPv1-2
    uint8_t username[SNMP_STRLEN+1];  // SNMPv3
    uint8_t stat;
    uint8_t version;
} snmp_flow_t;

// plugin struct pointer for potential dependencies
extern snmp_flow_t *snmp_flows;

#endif // __SNMP_DECODE_H__
