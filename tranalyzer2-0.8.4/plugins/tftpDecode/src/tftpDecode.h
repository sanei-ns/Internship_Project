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

#ifndef __TFTP_DECODE_H__
#define __TFTP_DECODE_H__

// global includes

// local includes
#include "global.h"
#include "fsutils.h"

// user defines
#define TFTP_SAVE       0 // save content to FTP_F_PATH
#define TFTP_MXNMLN    15 // maximal name length
#define MAXCNM          4 // maximal length of command field

#define TFTP_F_PATH "/tmp/TFTPFILES/" // Path for files

#define TFTP_NON "knoedel" // no name file name

#define TFTP_CNT_LEN    13 // max # of cnt digits attached to file name (currently not used).
#define TFTP_FNDX_LEN   20 // string length of findex in decimal format

// def & Calculate name lengths
#define TFTP_MXPL TFTP_MXNMLN + TFTP_FNDX_LEN + 4
#define TFTP_NON_FILE_LEN (sizeof(TFTP_NON) + TFTP_CNT_LEN + TFTP_FNDX_LEN)  // Standard name of fles without name: wurst_dir_findex_pkt_num
#define TFTP_MXIMNM_LEN (sizeof(TFTP_F_PATH) + TFTP_NON_FILE_LEN + TFTP_MXNMLN + 1) // maximum file name length

// plugin defines
#define TFTPS_INIT	0x0001  // tftp flow found
#define TFTPS_DRD	0x0002  // tftp data read
#define TFTPS_DWR	0x0004  // tftp data write
#define TFTP_FERR       0x0008  // file open error
#define TFTPS_BSERR	0x0010  // error in block send sequence
#define TFTPS_BSAERR	0x0020  // error in block ack sequence
#define TFTPS_PERR	0x0040  // error, or tftp prot error or not tftp
#define TFTPS_OVFL	0x0080  // array overflow
#define TFTP_RW_PLNERR  0x0800  // crafted packet or tftp read/write parameter length error
#define TFTP_ACT	0x1000  // active
#define TFTP_PSV	0x2000  // passive

// RFC tftp op codes definition
#define RRQ	1
#define WRQ	2
#define DATA	3
#define ACK	4
#define ERR	5
#define OACK	6

// tfpt op code bit field: (code - 1)
#define TFTP_RRQ	0x01	// 1: Read request
#define TFTP_WRQ	0x02	// 2: Write request
#define TFTP_DATA	0x04	// 3: Read or write the next block of data
#define TFTP_ACK	0x08	// 4: Acknowledgment
#define TFTP_ERR	0x10	// 5: Error message
#define TFTP_OACK	0x20	// 6: Option acknowledgment

// tfpt error code bit field: (code - 1)
#define TFTP_NOERR	0x00	// 0: No Error
#define TFTP_FLNFND	0x01	// 1: File not found
#define TFTP_ACCVLT	0x02	// 2: Access violation
#define TFTP_DSKFLL	0x04	// 3: Disk full or allocation exceeded
#define TFTP_ILGLOP	0x08	// 4: Illegal TFTP operation
#define TFTP_UKWNID	0x10	// 5: Unknown transfer ID
#define TFTP_FLEXST	0x20	// 6: File already exists
#define TFTP_NOSUSR	0x40	// 7: No such user
#define TFTP_TRMOPN	0x80	// 8: Terminate transfer due to option negotiation

// sample plugin structures
typedef struct {
#if TFTP_SAVE == 1
	file_object_t *fd;
#endif // TFTP_SAVE == 1
	uint64_t pfi;
	uint16_t sndBlk;
	uint16_t lstBlk;
	uint16_t stat;
//	char prm[MAXCNM][TFTP_MXNMLN+1];
	char nameC[MAXCNM][TFTP_MXPL+1];
	uint8_t opCode[MAXCNM];
	uint8_t opCodeBF;
	uint8_t errCodeBF;
	uint8_t opCnt;
	uint8_t pCnt;
} tftpFlow_t;

// plugin struct pointer for potential dependencies
extern tftpFlow_t *tftpFlows;

#endif // __TFTP_DECODE_H__
