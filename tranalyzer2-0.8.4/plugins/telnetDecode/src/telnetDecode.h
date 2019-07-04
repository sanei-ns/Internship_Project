/*
 * telnetDecode.h
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

#ifndef TELNETDECODE_H_
#define TELNETDECODE_H_

// global includes
#include "global.h"

// user defines
#define TEL_SAVE     0 // Save content to TEL_F_PATH/TELFNAME
#define TEL_CMDC     0 // Output command codes
#define TEL_CMDS     1 // Output command human readable
#define TEL_OPTS     1 // Output options human readable
#define TEL_CMD_AGGR 1 // Aggregate commands
#define TEL_OPT_AGGR 1 // Aggregate options

#define TELCMDN 25 // Maximal command / flow
#define TELOPTN 25 // Maximal options / flow

#define TEL_F_PATH "/tmp/TELFILES/" // Path for extracted content
#define TELFNAME   "telwurst"       // file name

// def & Calculate name lengths
#define TEL_CNT_LEN  13 // max # of cnt digits attached to file name (currently not used).
#define TEL_FNDX_LEN 20 // string length of findex in decimal format
#define TEL_MXIMN_LEN (sizeof(TELFNAME) + TEL_CNT_LEN + TEL_FNDX_LEN)  // Standard name of fles without name: wurst_dir_findex_pkt_num

// plugin defines
#define TLNTPRT   23
#define CMDSTRT   0xf0
#define CMDEND    0xff
#define MINTELLEN 1
#define TELFLEN   20

#define TELCMD 0xff

// Command codes (actually start at 0xf0)
#define SE   0x00 // Subnegotiation End
#define NOP  0x01 // No Operation
#define DM   0x02 // Data Mark
#define BRK  0x03 // Break
#define IP   0x04 // Interrup Process
#define AO   0x05 // Abort Output
#define AYT  0x06 // Are You There
#define EC   0x07 // Erase Character
#define EL   0x08 // Erase Line
#define GA   0x09 // Go Ahead
#define SB   0x0a // Subnegotiation
#define WILL 0x0b // Will Perform
#define WONT 0x0c // Won't Perform
#define DO   0x0d // Do Perform
#define DONT 0x0e // Don't Perform
#define IAC  0x0f // Interpret As Command

// stat
#define TEL_INIT  0x01  // Telnet port found
//#define TEL_OVRN  0x10  // Command buffer overrun
#define TEL_OFERR 0x20  // File open error: TEL_SAVE=1

// flow plugin struct

typedef struct {
#if TEL_SAVE == 1
    file_object_t *fd;
    uint32_t seqInit;
#endif // TEL_SAVE == 1
    uint32_t optBF;
    uint32_t cmdBF;
    uint16_t cmdrCnt;
    uint16_t optrCnt;
#if (TEL_CMDC == 1 || TEL_CMDS == 1)
    uint16_t cmdCnt;
    uint8_t cmdCode[TELCMDN];
#endif // (TEL_CMDC == 1 || TEL_CMDS == 1)
#if TEL_OPTS == 1
    uint16_t optCnt;
    uint8_t optCode[TELOPTN];
#endif // TEL_OPTS == 1
    char nameF[TELFLEN];
    uint8_t stat;
} telFlow_t;

// plugin struct pointer for potential dependencies
extern telFlow_t *telFlows;

#endif // TELNETDECODE_H_
