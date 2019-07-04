/*
 * modbus.h
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

#ifndef __MODBUS_H__
#define __MODBUS_H__

// global includes

// local includes
#include "global.h"

// user defines
#define MB_DEBUG      0 // Whether or not to print debug messages
#define MB_FE_FRMT    0 // Function/Exception codes representation: 0: hex, 1: int
#define MB_NUM_FUNC   0 // Number of function codes to store (0 to hide modbusFC)
#define MB_UNIQ_FUNC  0 // Whether (1) or not (0) to aggregate multiply defined function codes
#define MB_NUM_FEX    0 // Number of function codes which caused exceptions to store (0 to hide modbusFEx)
#define MB_UNIQ_FEX   0 // Whether (1) or not (0) to aggregate multiply defined function codes which caused exceptions
#define MB_NUM_EX     0 // Number of exception codes to store (0 to hide modbusExC)
#define MB_UNIQ_EX    0 // Whether (1) or not (0) to aggregate multiply defined exception codes

// plugin defines
#if MB_FE_FRMT == 1
#define MB_FE_TYP bt_uint_8
#define MB_PRI_FE "%"PRIu8
#else // MB_FE_FRMT == 0
#define MB_FE_TYP bt_hex_8
#define MB_PRI_FE "0x%02"B2T_PRIX8
#endif // MB_FE_FRMT == 0

// Status
#define MB_STAT_MODBUS    0x0001 // flow is Modbus
#define MB_STAT_PROTO     0x0002 // non-modbus protocol identifier
#define MB_STAT_FUNC      0x0004 // unknown function code
#define MB_STAT_EX        0x0008 // unknown exception code
#define MB_STAT_UID       0x0010 // multiple unit identifiers
#define MB_STAT_NFUNC     0x0100 // list of function codes truncated... increase MB_NUM_FUNC
#define MB_STAT_NFEX      0x0200 // list of function codes which caused exceptions truncated... increase MB_NUM_FEX
#define MB_STAT_NEXCP     0x0400 // list of exception codes truncated... increase MB_NUM_EX
#define MB_STAT_SNAP      0x4000 // snapped packet
#define MB_STAT_MALFORMED 0x8000 // malformed packet

#define MODBUS_PROTO 0x0000
#define MODBUS_PORT  502 // TCP

// Function codes
#define MB_FC_READ_COILS  0x01 // Read Coils
#define MB_FC_READ_DINPT  0x02 // Read Discrete Inputs
#define MB_FC_READ_HREGS  0x03 // Read Multiple Holding Registers
#define MB_FC_READ_INREG  0x04 // Read Input Registers
#define MB_FC_WRITE_COIL  0x05 // Write Single Coil
#define MB_FC_WRITE_HREG  0x06 // Write Single Holding Register
#define MB_FC_READ_EXCEP  0x07 // Read Exception Status
#define MB_FC_DIAGNOSTIC  0x08 // Diagnostic
#define MB_FC_EVT_CNTER   0x0b // Get Com Event Counter
#define MB_FC_EVT_LOG     0x0c // Get Com Event Log
#define MB_FC_WRITE_COILS 0x0f // Write Multiple Coils
#define MB_FC_WRITE_MHREG 0x10 // Write Multiple Holding Registers
#define MB_FC_SLAVEID     0x11 // Report Slave ID
#define MB_FC_READ_FILE   0x14 // Read File Record
#define MB_FC_WRITE_FILE  0x15 // Write File Record
#define MB_FC_MASK_WREG   0x16 // Mask Write Register
#define MB_FC_RW_MREG     0x17 // Read/Write Multiple Registers
#define MB_FC_READ_FIFO   0x18 // Read FIFO Queue
#define MB_FC_DEVICEID    0x2b // Read Decide Identification
// Exceptions: response code + 128 (0x80)

// Exception numbers
#define MB_EX_ILLEGAL_FUNC 0x01 // Illegal function code
#define MB_EX_ILLEGAL_ADDR 0x02 // Illegal data address
#define MB_EX_ILLEGAL_VAL  0x03 // Illegal data value
#define MB_EX_SLAVE_FAIL   0x04 // Slave device failure
#define MB_EX_ACK          0x05 // Acknowledge
#define MB_EX_SLAVE_BUSY   0x06 // Slave device busy
#define MB_EX_NACK         0x07 // Negative acknowledge
#define MB_EX_MEMERR       0x08 // Memory parity error
#define MB_EX_GW_PATH      0x0a // Gateway path unavailable
#define MB_EX_GW_FAIL      0x0b // Gateway target device failed to respond

#if MB_DEBUG == 1
#define MB_DBG(format, args...) T2_PINF("modbus", format, ##args)
#else // MB_DEBUG == 0
#define MB_DBG(format, args...) /* do nothing */
#endif // MB_DEBUG == 0

typedef struct {
    uint16_t tid; // transaction identifier
    uint16_t pid; // protocol identifier (zero for Modbus/TCP)
    uint16_t len; // length
    uint8_t  uid; // unit identifier (255 if not used)
    uint8_t   fc; // function code
} modbus_hdr_t;

typedef struct {
    uint64_t fcbf;              // aggregated function codes
    uint64_t fexbf;             // aggregate functions which caused an exception
    uint32_t nmp;               // number of modbus packets
    uint16_t nex;               // number of exceptions
    uint16_t exbf;              // exceptions
    uint16_t  stat;             // status
#if MB_NUM_FEX > 0
    uint16_t  nfex;             // number of stored function codes
    uint8_t   fex[MB_NUM_FEX];  // list of function codes
#endif // MB_NUM_FEX > 0
#if MB_NUM_FUNC > 0
    uint16_t  nfc;              // number of stored function codes
    uint8_t   fc[MB_NUM_FUNC];  // list of function codes
#endif // MB_NUM_FUNC > 0
#if MB_NUM_EX > 0
    uint16_t  nsex;             // number of stored exceptions
    uint8_t   exc[MB_NUM_EX];   // list of exception numbers
#endif // MB_NUM_EX > 0
    uint8_t   uid;              // unit id
} modbus_flow_t;

// plugin struct pointer for potential dependencies
extern modbus_flow_t *modbus_flows;

#endif // __MODBUS_H__
