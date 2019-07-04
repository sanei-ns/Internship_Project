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

#ifndef __FTP_DECODE_H__
#define __FTP_DECODE_H__

// global includes

// local includes
#include "global.h"
#include "fsutils.h"

// user defines

#define FTP_SAVE       0 // save content to FTP_F_PATH
#define BITFIELD       0 // Bitfield coding of FTP commands

#define FTP_UXNMLN    10 // maximal USER length
#define FTP_PXNMLN    10 // maximal PW length
#define FTP_MXNMLN    50 // maximal name length
#define FTP_MAXCPFI   10 // Maximal number of pfi
#define MAXUNM         5 // Maximal number of users
#define MAXPNM         5 // Maximal number of passwords
#define MAXCNM        20 // Maximal number of parameters

#define FTP_F_PATH "/tmp/FTPFILES/" // Path for extracted content

#define FTP_NON "wurst" // no name file name

#define FTP_CNT_LEN    13 // max # of cnt digits attached to file name (currently not used).
#define FTP_FNDX_LEN   20 // string length of findex in decimal format

// def & Calculate name lengths
#define FTP_MXPL FTP_MXNMLN + FTP_FNDX_LEN + 4
#define FTP_NON_FILE_LEN (sizeof(FTP_NON) + FTP_CNT_LEN + FTP_FNDX_LEN)  // Standard name of fles without name: wurst_dir_findex_pkt_num
#define FTP_MXIMNM_LEN (sizeof(FTP_F_PATH) + FTP_NON_FILE_LEN + FTP_MXNMLN + 1) // maximum file name length

// plugin defines

// stat
#define FTP_INIT    0x01  // FTP port found
#define FTP_PPRNT   0x02  // FTP passive parent flow
#define FTP_PPWF    0x04  // FTP passive parent flow write finished
#define FTP_APRNT   0x08  // FTP active parent flow
#define FTP_HSHMFLL 0x10  // FTP Hash map full
#define FTP_PPWFERR 0x20  // File error, FTP_SAVE == 1
#define FTP_NDFLW   0x40  // Data flow not detected
#define FTP_OVFL    0x80  // array overflow

#define ABOR 0x524F4241
#define ACCT 0x54434341
#define ADAT 0x54414441
#define ALLO 0x4F4C4C41
#define APPE 0x45505041
#define AUTH 0x48545541
#define CCC  0x20434343
#define CDUP 0x50554443
#define CLNT 0x544E4C43
#define CONF 0x464E4F43
#define CWD  0x20445743
#define DELE 0x454C4544
#define ENC  0x20434E45
#define EPRT 0x54525045
#define EPSV 0x56535045
#define FEAT 0x54414546
#define HELP 0x504C4548
#define LANG 0x474E414C
#define LIST 0x5453494C
#define LPRT 0x5452504C
#define LPSV 0x5653504C
#define MDTM 0x4D54444D
#define MIC  0x2043494D
#define MKD  0x20444B4D
#define MLSD 0x44534C4D
#define MLST 0x54534C4D
#define MODE 0x45444F4D
#define NLST 0x54534C4E
#define NOOP 0x504F4F4E
#define OPTS 0x5354504F
#define PASS 0x53534150
#define PASV 0x56534150
#define PBSZ 0x5A534250
#define PORT 0x54524F50
#define PROT 0x544F5250
#define PWD  0x0D445750
#define QUIT 0x54495551
#define REIN 0x4E494552
#define REST 0x54534552
#define RETR 0x52544552
#define RMD  0x20444D52
#define RNFR 0x52464E52
#define RNTO 0x4F544E52
#define SITE 0x45544953
#define SIZE 0x455A4953
#define SMNT 0x544E4D53
#define STAT 0x54415453
#define STOR 0x524F5453
#define STOU 0x554F5453
#define STRU 0x55525453
#define SYST 0x54535953
#define TYPE 0x45505954
#define USER 0x52455355
#define XCUP 0x50554358
#define XMKD 0x444B4D58
#define XPWD 0x44575058
#define XRCP 0x50435258
#define XRMD 0x444D5258
#define XRSQ 0x51535258
#define XSEM 0x4D455358
#define XSEN 0x4E455358

#define FTP_ABOR 0x0000000000000001 // 0
#define FTP_ACCT 0x0000000000000002 // 1
#define FTP_ADAT 0x0000000000000004 // 2
#define FTP_ALLO 0x0000000000000008 // 3
#define FTP_APPE 0x0000000000000010 // 4
#define FTP_AUTH 0x0000000000000020 // 5
#define FTP_CCC  0x0000000000000040 // 6
#define FTP_CDUP 0x0000000000000080 // 7
#define FTP_CONF 0x0000000000000100 // 8
#define FTP_CWD  0x0000000000000200 // 9
#define FTP_DELE 0x0000000000000400 // 10
#define FTP_ENC  0x0000000000000800 // 11
#define FTP_EPRT 0x0000000000001000 // 12
#define FTP_EPSV 0x0000000000002000 // 13
#define FTP_FEAT 0x0000000000004000 // 14
#define FTP_HELP 0x0000000000008000 // 15
#define FTP_LANG 0x0000000000010000 // 16
#define FTP_LIST 0x0000000000020000 // 17
#define FTP_LPRT 0x0000000000040000 // 18
#define FTP_LPSV 0x0000000000080000 // 19
#define FTP_MDTM 0x0000000000100000 // 20
#define FTP_MIC  0x0000000000200000 // 21
#define FTP_MKD  0x0000000000400000 // 22
#define FTP_MLSD 0x0000000000800000 // 23
#define FTP_MLST 0x0000000001000000 // 24
#define FTP_MODE 0x0000000002000000 // 25
#define FTP_NLST 0x0000000004000000 // 26
#define FTP_NOOP 0x0000000008000000 // 27
#define FTP_OPTS 0x0000000010000000 // 28
#define FTP_PASS 0x0000000020000000 // 29
#define FTP_PASV 0x0000000040000000 // 30
#define FTP_PBSZ 0x0000000080000000 // 31
#define FTP_PORT 0x0000000100000000 // 32
#define FTP_PROT 0x0000000200000000 // 33
#define FTP_PWD  0x0000000400000000 // 34
#define FTP_QUIT 0x0000000800000000 // 35
#define FTP_REIN 0x0000001000000000 // 36
#define FTP_REST 0x0000002000000000 // 37
#define FTP_RETR 0x0000004000000000 // 38
#define FTP_RMD  0x0000008000000000 // 39
#define FTP_RNFR 0x0000010000000000 // 40
#define FTP_RNTO 0x0000020000000000 // 41
#define FTP_SITE 0x0000040000000000 // 42
#define FTP_SIZE 0x0000080000000000 // 43
#define FTP_SMNT 0x0000100000000000 // 44
#define FTP_STAT 0x0000200000000000 // 45
#define FTP_STOR 0x0000400000000000 // 46
#define FTP_STOU 0x0000800000000000 // 47
#define FTP_STRU 0x0001000000000000 // 48
#define FTP_SYST 0x0002000000000000 // 49
#define FTP_TYPE 0x0004000000000000 // 50
#define FTP_USER 0x0008000000000000 // 51
#define FTP_XCUP 0x0010000000000000 // 52
#define FTP_XMKD 0x0020000000000000 // 53
#define FTP_XPWD 0x0040000000000000 // 54
#define FTP_XRCP 0x0080000000000000 // 55
#define FTP_XRMD 0x0100000000000000 // 56
#define FTP_XRSQ 0x0200000000000000 // 57
#define FTP_XSEM 0x0400000000000000 // 58
#define FTP_XSEN 0x0800000000000000 // 59
#define FTP_CLNT 0x1000000000000000 // 60

const char ftpCom[61][5] = {"ABOR","ACCT","ADAT","ALLO","APPE","AUTH","CCC","CDUP","CONF","CWD","DELE","ENC","EPRT","EPSV","FEAT","HELP","LANG","LIST","LPRT","LPSV","MDTM","MIC","MKD","MLSD","MLST","MODE","NLST","NOOP","OPTS","PASS","PASV","PBSZ","PORT","PROT","PWD","QUIT","REIN","REST","RETR","RMD","RNFR","RNTO","SITE","SIZE","SMNT","STAT","STOR","STOU","STRU","SYST","TYPE","USER","XCUP","XMKD","XPWD","XRCP","XRMD","XRSQ","XSEM","XSEN","CLNT"};

// sample plugin structures

//typedef struct {
//#if IPV6_ACTIVATE == 1
//	uint64_t srcIP[2], dstIP[2];
//#else // IPV6_ACTIVATE == 0
//	uint32_t srcIP, dstIP;
//#endif // IPV6_ACTIVATE == 0
//	uint16_t sdPort, vlan;
//	uint8_t l4Proto;
//} __attribute__((packed)) ftpID_t;

typedef struct {
	uint64_t pfi[FTP_MAXCPFI];
	uint64_t sendCode;
	int64_t cLen;           // last declared ftp-Content-Length
#if FTP_SAVE == 1
	file_object_t *fd;      // file descriptor per flow
	int64_t dwLen;         	// Amount of data writtten
	uint32_t seqInit;
//	uint32_t seq;
#endif // FTP_SAVE == 1
	uint32_t pslAddr;
//	uint32_t tCode[MAXCNM];
	uint16_t pcrPort;	            // pasive mode: client rec port
	uint16_t recCode[MAXCNM];
	uint8_t tCode[MAXCNM];
	char nameU[MAXUNM][FTP_UXNMLN+1];
	char nameP[MAXPNM][FTP_PXNMLN+1];
	char nameC[MAXCNM][FTP_MXPL+1];
	uint8_t pfiCnt;
	uint8_t tCCnt;
	uint8_t rCCnt;
	uint8_t nameUCnt;
	uint8_t namePCnt;
	uint8_t nameCCnt;
	uint8_t stat;
} ftpFlow_t;

// plugin struct pointer for potential dependencies
extern ftpFlow_t *ftpFlows;

#endif // __FTP_DECODE_H__
