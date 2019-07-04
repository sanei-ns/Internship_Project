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

#include "ftpDecode.h"


// Global variables

ftpFlow_t *ftpFlows;


// Static variables

static hashMap_t *ftpHashMap;
static uint64_t *ftpFindex;
static uint64_t totFtpPktCnt, totFtpPktCnt0;
static uint8_t ftpAStat;


// Tranalyzer functions

T2_PLUGIN_INIT("ftpDecode", "0.8.4", 0, 8);


void initialize() {

#if FTP_SAVE == 1
	if (UNLIKELY(!rmrf(FTP_F_PATH))) {
		T2_PERR("ftpDecode", "Failed to remove directory '%s': %s", FTP_F_PATH, strerror(errno));
		exit(-1);
	}

	if (UNLIKELY(!mkpath(FTP_F_PATH, S_IRWXU))) {
		T2_PERR("ftpDeocde", "Failed to create directory '%s': %s", FTP_F_PATH, strerror(errno));
		exit(-1);
	}
#endif // FTP_SAVE == 1

	// allocate struct for all flows and initialise to 0
	if (UNLIKELY(!(ftpFlows = calloc(mainHashMap->hashChainTableSize, sizeof(*ftpFlows))))) {
		T2_PERR("ftpDecode", "failed to allocate memory for ftpFlows");
		exit(-1);
	}

	// initialize ftp data pair hash
	flow_t fF;
	ftpHashMap = hashTable_init(1.0f, ((char*) &fF.layer4Protocol - (char*) &fF.srcIP + sizeof(fF.layer4Protocol)), "ftp");

	// initialize the counter arrays
	if (UNLIKELY(!(ftpFindex = calloc(ftpHashMap->hashChainTableSize, sizeof(uint64_t))))) {
		T2_PERR("ftpDecode", "failed to allocate memory for ftpFindex");
		exit(-1);
	}
}


binary_value_t* printHeader() {
	binary_value_t *bv = NULL;
	bv = bv_append_bv(bv, bv_new_bv("FTP Status Bitfield", "ftpStat", 0, 1, bt_hex_8));
	bv = bv_append_bv(bv, bv_new_bv("FTP command/data findex link", "ftpCDFindex", 1, 1, bt_uint_64));
#if BITFIELD == 1
	bv = bv_append_bv(bv, bv_new_bv("FTP Command Bit Field", "ftpCBF", 0, 1, bt_hex_64));
//	bv = bv_append_bv(bv, bv_new_bv("FTP Response Bit Field", "ftpRBF", 0, 1, bt_hex_32));
#endif // BITFIELD == 1
	bv = bv_append_bv(bv, bv_new_bv("FTP Command Codes", "ftpCC", 1, 1, bt_string_class));
	bv = bv_append_bv(bv, bv_new_bv("FTP Response Codes", "ftpRC", 1, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("FTP Number of users", "ftpUsrNum", 0, 1, bt_uint_8));
	bv = bv_append_bv(bv, bv_new_bv("FTP Number of passwords", "ftpPwNum", 0, 1, bt_uint_8));
	bv = bv_append_bv(bv, bv_new_bv("FTP Number of parameters", "ftpCNum", 0, 1, bt_uint_8));
	bv = bv_append_bv(bv, bv_new_bv("FTP Users", "ftpUsr", 1, 1, bt_string));
	bv = bv_append_bv(bv, bv_new_bv("FTP Passwords", "ftpPw", 1, 1, bt_string));
	bv = bv_append_bv(bv, bv_new_bv("FTP Content", "ftpC", 1, 1, bt_string));
	return bv;
}


void onFlowGenerated(packet_t* packet __attribute__((unused)), unsigned long flowIndex) {
	ftpFlow_t *ftpFlowP = &ftpFlows[flowIndex];
	memset(ftpFlowP, '\0', sizeof(*ftpFlowP));

	// check also whether a passive ftp connection matches a port 21 connection using hash
	if (packet->layer4Type == L3_TCP || packet->layer4Type == L3_SCTP) {
		const flow_t * const flowP = &flows[flowIndex];
		if (flowP->dstPort == 21 || flowP->srcPort == 21) {
			ftpFlowP->stat = FTP_INIT;
		} else if (flowP->dstPort == 20 || flowP->dstPort > 1024 ||
		           flowP->srcPort == 20 || flowP->srcPort > 1024)
		{
			const flow_t client = {
				.vlanID = flowP->vlanID,
#if IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
				.ethType = flowP->ethType,
#endif // IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
#if SCTP_ACTIVATE == 1
				.sctpStrm = flowP->sctpStrm,
#endif // SCTP_ACTIVATE == 1
				.layer4Protocol = flowP->layer4Protocol,
				.srcIP = flowP->srcIP,
				.dstIP = flowP->dstIP,
				.dstPort = (flowP->oppositeFlowIndex == HASHTABLE_ENTRY_NOT_FOUND) ? flowP->dstPort : flowP->srcPort,
			};

			uint64_t pFindex = hashTable_lookup(ftpHashMap, (char*)&client.srcIP);
			if (pFindex == HASHTABLE_ENTRY_NOT_FOUND) {
				pFindex = hashTable_insert(ftpHashMap, (char*)&client.srcIP);
				if (pFindex == HASHTABLE_ENTRY_NOT_FOUND) {
					if (!(ftpAStat & FTP_HSHMFLL)) {
						ftpAStat |= FTP_HSHMFLL;
						T2_PWRN("ftpDecode", "%s HashMap full", ftpHashMap->name);
					}
					return;
				} else {
					if (ftpAStat & FTP_HSHMFLL) {
						T2_PWRN("ftpDecode", "%s HashMap free", ftpHashMap->name);
						ftpAStat &= ~FTP_HSHMFLL;
					}
				}
				ftpFindex[pFindex] = flowP->flowIndex;
			}
		}
	}
}


void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {
	ftpFlow_t *ftpFlowP = &ftpFlows[flowIndex];
	if (!ftpFlowP->stat) return;

#if FTP_SAVE == 1
	if (ftpFlowP->stat & FTP_PPWF) return;
#endif

	uint32_t i, j;
	int32_t l7Len = packet->snapL7Length;
	char *l7Hdr = (char*)packet->layer7Header, *s, *t;
	char fname[FTP_MXNMLN+1];
	uint8_t sC = 0;

	totFtpPktCnt++;

	if (l7Len < 4) return;

	const flow_t * const flowP = &flows[flowIndex];
	ftpFlow_t * const ftpFlowPO = (flowP->oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) ? &ftpFlows[flowP->oppositeFlowIndex] : NULL;

	if (ftpFlowP->stat & FTP_PPRNT) {
#if FTP_SAVE == 1
		const tcpHeader_t * const tcpHeader = (tcpHeader_t*)packet->layer4Header;
		uint32_t tcpSeq;
		if (packet->layer4Type == L3_TCP) tcpSeq = ntohl(tcpHeader->seq); // absolute / relative tcp sequence number
		if (!ftpFlowP->fd) {
			char imfname[FTP_MXIMNM_LEN];
			s = ftpFlowP->nameC[ftpFlowP->nameCCnt-1];
			j = strlen(s);
			for (i = 0; i < j; i++) if (s[i] == '/') s[i] = '_';
			memcpy(imfname, FTP_F_PATH, sizeof(FTP_F_PATH));
			i = sizeof(FTP_F_PATH) - 1;
			memcpy(imfname + i, s, j+1);
			i += j;
			//sprintf(imfname + i, "_%d_%"PRIu64"_%d", (flowP->status & L3FLOWINVERT), flowP->findex, ftpFlowP->pktCnt);
			sprintf(imfname + i, "_%d_%"PRIu64, (int)(flowP->status & L3FLOWINVERT), flowP->findex);
			if (ftpFlowP->stat & (FTP_APRNT | FTP_PPRNT)) memcpy(s, imfname + sizeof(FTP_F_PATH)-1, strlen(imfname)-sizeof(FTP_F_PATH)+1);// check nameC length exceeded

			ftpFlowP->fd = file_manager_open(t2_file_manager, imfname, "w+b");
			if (!ftpFlowP->fd) {
				T2_PERR("ftpDecode", "Failed to open file '%s': %s", imfname, strerror(errno));
				ftpFlowP->stat |= FTP_PPWFERR;
				return;
			}
			if (ftpFlowP->cLen) ftpFlowP->dwLen = ftpFlowP->cLen;
			else ftpFlowP->dwLen = l7Len;
			ftpFlowP->seqInit = tcpSeq;
		}
		if (ftpFlowP->dwLen > 0) {
			FILE *fp = file_manager_fp(t2_file_manager, ftpFlowP->fd);
			if (packet->layer4Type == L3_TCP) {
				i = tcpSeq - ftpFlowP->seqInit;
				fseek(fp, i, SEEK_SET);
			}
			fwrite(l7Hdr, 1, l7Len , fp);
			ftpFlowP->dwLen -= l7Len;
		}
		if (ftpFlowP->dwLen == 0) {
			file_manager_close(t2_file_manager, ftpFlowP->fd);
			ftpFlowP->fd = NULL;
			ftpFlowP->stat |= FTP_PPWF;
		}

#endif // FTP_SAVE == 1
		return;
	}

	uint32_t l7Hdr32 = *(uint32_t*)l7Hdr;
	if (flowP->status & L3FLOWINVERT) {
		if (ftpFlowP->rCCnt >= MAXCNM) {
			ftpFlowP->stat |= FTP_OVFL;
			return;
		}
		i = l7Hdr32 & 0xffffff;
		j = atoi((char*)&i);
		for (i = 0; i < ftpFlowP->rCCnt; i++) {
			if (ftpFlowP->recCode[i] == j) goto storinfo;
		}
		ftpFlowP->recCode[ftpFlowP->rCCnt++] = j;
		//ftpFlowP->recCode |= (1 << i);
storinfo:	switch (j) {
			case 213:
				if ((s = memchr(l7Hdr, '\r', l7Len)) != NULL) {
					ftpFlowP->cLen = atoll(l7Hdr+4);
				}
				break;
			case 215:
				if (ftpFlowP->nameCCnt >= MAXCNM) {
					ftpFlowP->stat |= FTP_OVFL;
					break;
				}
				if ((s = memchr(l7Hdr, '\r', l7Len)) != NULL) {
					i = s - l7Hdr;
					if (i > FTP_MXNMLN) i = FTP_MXNMLN;
					memcpy(ftpFlowP->nameC[ftpFlowP->nameCCnt++], l7Hdr, i);
				}
				break;
			case 227:
				if ((s = memchr(l7Hdr, '\r', l7Len)) != NULL) {
					if (!(s = memrchr(l7Hdr, ',', l7Len))) break;
					i = atoi(s+1);
					t = s;
					*s = 0;
					if (!(s = memrchr(l7Hdr, ',', strlen(l7Hdr)))) break;
					*t = ',';
					ftpFlowP->pcrPort = i + (atoi(s + 1) << 8);
				}
				break;
			case 125:
			case 150:
				t = memmem(l7Hdr, l7Len, "for", 3);
				if (t) t += 4;
				else {
					t = l7Hdr;
					ftpFlowP->stat |= FTP_NDFLW;
				}

				if ((s = memrchr(l7Hdr, '(', l7Len)) != NULL) {
					ftpFlowP->cLen = atoll(s+1);
					s--;
				} else {
					if (!(s = memchr(l7Hdr, '\r', l7Len))) break;
					ftpFlowP->cLen = 0;
				}

				const flow_t client = {
					.vlanID = flowP->vlanID,
#if IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
					.ethType = flowP->ethType,
#endif // IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
#if SCTP_ACTIVATE == 1
					.sctpStrm = flowP->sctpStrm,
#endif // SCTP_ACTIVATE == 1
					.layer4Protocol = flowP->layer4Protocol,
					.srcIP = flowP->dstIP,
					.dstIP = flowP->srcIP,
					.dstPort = (ftpFlowP->pcrPort) ? ftpFlowP->pcrPort : flowP->dstPort + 1,
				};

				const uint64_t pFindex = hashTable_lookup(ftpHashMap, (char*)&client.srcIP);
				if (pFindex == HASHTABLE_ENTRY_NOT_FOUND) {
					ftpFlowP->stat |= FTP_NDFLW;
				} else {
					uint64_t find = ftpFindex[pFindex];
					if (ftpFlowP->pfiCnt > FTP_MAXCPFI) ftpFlowP->pfiCnt = FTP_MAXCPFI;
					ftpFlowP->pfi[ftpFlowP->pfiCnt++] = flows[find].findex;

					ftpFlow_t *ftpFlowPC = &ftpFlows[find];
					if (ftpFlowPC->pfiCnt > FTP_MAXCPFI) ftpFlowPC->pfiCnt = FTP_MAXCPFI;
					ftpFlowPC->pfi[ftpFlowPC->pfiCnt++] = flowP->findex;

					j = (uint32_t)(s - t);
					if (j > FTP_MXNMLN) j = FTP_MXNMLN;
					find = flows[find].oppositeFlowIndex;
					if (find != HASHTABLE_ENTRY_NOT_FOUND) {
						ftpFlow_t *ftpFlowPCO = &ftpFlows[find];
						ftpFlowPCO->stat |= FTP_PPRNT;
						ftpFlowPCO->cLen = ftpFlowP->cLen;
						if (ftpFlowPCO->nameCCnt >= MAXCNM) {
							ftpFlowPCO->stat |= FTP_OVFL;
							break;
						}
						memcpy(ftpFlowPCO->nameC[ftpFlowPCO->nameCCnt], t, j);
						ftpFlowPCO->nameC[ftpFlowPCO->nameCCnt++][j] = 0x00;
					}

					if (ftpFlowP->nameCCnt >= MAXPNM) {
						ftpFlowP->stat |= FTP_OVFL;
						break;
					}
					memcpy(ftpFlowP->nameC[ftpFlowP->nameCCnt], t, j);
					ftpFlowP->nameC[ftpFlowP->nameCCnt++][j] = 0x00;
					memcpy(ftpFlowPC->nameC[ftpFlowPC->nameCCnt], t, j);
					ftpFlowPC->nameC[ftpFlowPC->nameCCnt++][j] = 0x00;
					ftpFlowPC->cLen = ftpFlowP->cLen;
					ftpFlowPC->stat |= FTP_PPRNT;
					//ftpFlowP->stat |= FTP_APRNT;
				}
				break;
			case 226:
#if FTP_SAVE == 1
				if (ftpFlowP->fd) {
					file_manager_close(t2_file_manager, ftpFlowP->fd);
					ftpFlowP->fd = NULL;
				}
#endif // FTP_SAVE == 1
				break;
			default:
				break;
		}

	} else {
		int pshft = 5;
		if (l7Hdr[0] > 0x60) l7Hdr32 -= 0x20202020;
		switch (l7Hdr32) {
			case ABOR:
				sC = 0;
				ftpFlowP->sendCode |= FTP_ABOR;
				break;
			case ACCT:
				sC = 1;
				ftpFlowP->sendCode |= FTP_ACCT;
				break;
			case ADAT:
				sC = 2;
				ftpFlowP->sendCode |= FTP_ADAT;
				break;
			case ALLO:
				sC = 3;
				ftpFlowP->sendCode |= FTP_ALLO;
				break;
			case APPE:
				sC = 4;
				ftpFlowP->sendCode |= FTP_APPE;
				break;
			case AUTH:
				sC = 5;
				ftpFlowP->sendCode |= FTP_AUTH;
				break;
			case CCC:
				sC = 6;
				ftpFlowP->sendCode |= FTP_CCC;
				break;
			case CDUP:
				sC = 7;
				ftpFlowP->sendCode |= FTP_CDUP;
				break;
			case CONF:
				sC = 8;
				ftpFlowP->sendCode |= FTP_CONF;
				break;
			case CWD:
				sC = 9;
				ftpFlowP->sendCode |= FTP_CWD;
				pshft = 4;
				goto ftpcc;
			case DELE:
				sC = 10;
				ftpFlowP->sendCode |= FTP_DELE;
				goto ftpcc;
			case ENC:
				sC = 11;
				ftpFlowP->sendCode |= FTP_ENC;
				break;
			case EPRT:
				sC = 12;
				ftpFlowP->sendCode |= FTP_EPRT;
				break;
			case EPSV:
				sC = 13;
				ftpFlowP->sendCode |= FTP_EPSV;
				break;
			case FEAT:
				sC = 14;
				ftpFlowP->sendCode |= FTP_FEAT;
				goto ftpcc;
			case HELP:
				sC = 15;
				ftpFlowP->sendCode |= FTP_HELP;
				break;
			case LANG:
				sC = 16;
				ftpFlowP->sendCode |= FTP_LANG;
				break;
			case LIST:
				sC = 17;
				ftpFlowP->sendCode |= FTP_LIST;
				break;
			case LPRT:
				sC = 18;
				ftpFlowP->sendCode |= FTP_LPRT;
				break;
			case LPSV:
				sC = 19;
				ftpFlowP->sendCode |= FTP_LPSV;
				break;
			case MDTM:
				sC = 20;
				ftpFlowP->sendCode |= FTP_MDTM;
				break;
			case MIC:
				sC = 21;
				ftpFlowP->sendCode |= FTP_MIC;
				break;
			case MKD:
				sC = 22;
				ftpFlowP->sendCode |= FTP_MKD;
				break;
			case MLSD:
				sC = 23;
				ftpFlowP->sendCode |= FTP_MLSD;
				break;
			case MLST:
				sC = 24;
				ftpFlowP->sendCode |= FTP_MLST;
				break;
			case MODE:
				sC = 25;
				ftpFlowP->sendCode |= FTP_MODE;
				break;
			case NLST:
				sC = 26;
				ftpFlowP->sendCode |= FTP_NLST;
				break;
			case NOOP:
				sC = 27;
				ftpFlowP->sendCode |= FTP_NOOP;
				break;
			case OPTS:
				sC = 28;
				ftpFlowP->sendCode |= FTP_OPTS;
				break;
			case PASS:
				sC = 29;
				if (ftpFlowP->namePCnt >= MAXPNM) {
					ftpFlowP->stat |= FTP_OVFL;
					break;
				}
				ftpFlowP->sendCode |= FTP_PASS;
				if (l7Len <= 7) break;
				l7Hdr += 5;
				l7Len -= 5;
				if ((s = memchr(l7Hdr, '\r', l7Len)) != NULL) {
					i = s - l7Hdr;
					if (i > FTP_MXNMLN) i = FTP_MXNMLN;
					memcpy(ftpFlowP->nameP[ftpFlowP->namePCnt++], l7Hdr, i);
				}
				break;
			case PASV:
				sC = 30;
				ftpFlowP->sendCode |= FTP_PASV;
				break;
			case PBSZ:
				sC = 31;
				ftpFlowP->sendCode |= FTP_PBSZ;
				break;
			case PORT:
				sC = 32;
				ftpFlowP->sendCode |= FTP_PORT;

				if ((s = memchr(l7Hdr, '\r', l7Len)) != NULL) {
					if (!(s = memchr(l7Hdr, ',', l7Len))) break;
					s++; // skip the comma
					j = ((atoi(l7Hdr + 5) << 8) + atoi(s)) << 8;
					if (!(s = memchr(s, ',', strlen(s)))) break;
					s++; // skip the comma
					j += atoi(s);
					j <<= 8;
					if (!(s = memchr(s, ',', strlen(s)))) break;
					s++; // skip the comma
					j += atoi(s);
					ftpFlowP->pslAddr = j;
					if (!(s = memchr(s, ',', strlen(s)))) break;
					s++; // skip the comma
					i = atoi(s) << 8;
					if (!(s = memchr(s, ',', strlen(s)))) break;
					s++; // skip the comma
					ftpFlowP->pcrPort = i + atoi(s);
					ftpFlowP->stat |= FTP_APRNT;
					if (ftpFlowPO) {
						ftpFlowPO->pcrPort = i + atoi(s);
						ftpFlowPO->stat |= FTP_APRNT;
					}
				}
				goto ftpcc;
			case PROT:
				sC = 33;
				ftpFlowP->sendCode |= FTP_PROT;
				break;
			case PWD:
				sC = 34;
				ftpFlowP->sendCode |= FTP_PWD;
				pshft = 4;
				goto ftpcc;
			case QUIT:
				sC = 35;
				ftpFlowP->sendCode |= FTP_QUIT;
				break;
			case REIN:
				sC = 36;
				ftpFlowP->sendCode |= FTP_REIN;
				break;
			case REST:
				sC = 37;
				ftpFlowP->sendCode |= FTP_REST;
				break;
			case RETR:
				sC = 38;
				ftpFlowP->sendCode |= FTP_RETR;
				goto ftpcc;
			case RMD:
				sC = 39;
				ftpFlowP->sendCode |= FTP_RMD;
				pshft = 4;
				goto ftpcc;
			case RNFR:
				sC = 40;
				ftpFlowP->sendCode |= FTP_RNFR;
ftpcc:				if (ftpFlowP->nameCCnt >= MAXCNM) {
					ftpFlowP->stat |= FTP_OVFL;
					break;
				}
				if (l7Len <= pshft+2) break;
				l7Hdr += pshft;
				l7Len -= pshft;
				if ((s = memchr(l7Hdr, '\r', l7Len)) != NULL) {
					i = s - l7Hdr;
					if (i > FTP_MXNMLN) i = FTP_MXNMLN;
					memcpy(fname, l7Hdr, i);
					for (j = 0; j < ftpFlowP->nameCCnt; j++) {
						if (!memcmp(ftpFlowP->nameC[j], fname, i)) goto strcd;
					}
					memcpy(ftpFlowP->nameC[j], fname, i);
					ftpFlowP->nameC[j][i] = 0x00;
					ftpFlowP->nameCCnt++;
				}
				break;
			case RNTO:
				sC = 41;
				ftpFlowP->sendCode |= FTP_RNTO;
				goto ftpcc;
			case SITE:
				sC = 42;
				ftpFlowP->sendCode |= FTP_SITE;
				break;
			case SIZE:
				sC = 43;
				ftpFlowP->sendCode |= FTP_SIZE;
				goto ftpcc;
			case SMNT:
				sC = 44;
				ftpFlowP->sendCode |= FTP_SMNT;
				break;
			case STAT:
				sC = 45;
				ftpFlowP->sendCode |= FTP_STAT;
				break;
			case STOR:
				sC = 46;
				ftpFlowP->sendCode |= FTP_STOR;
				goto ftpcc;
			case STOU:
				sC = 47;
				ftpFlowP->sendCode |= FTP_STOU;
				break;
			case STRU:
				sC = 48;
				ftpFlowP->sendCode |= FTP_STRU;
				break;
			case SYST:
				sC = 49;
				ftpFlowP->sendCode |= FTP_SYST;
				break;
			case TYPE:
				sC = 50;
				ftpFlowP->sendCode |= FTP_TYPE;
				goto ftpcc;
			case USER:
				sC = 51;
				if (ftpFlowP->nameUCnt >= MAXUNM) {
					ftpFlowP->stat |= FTP_OVFL;
					break;
				}
				ftpFlowP->sendCode |= FTP_USER;
				if (l7Len <= 7) break;
				l7Hdr += 5;
				l7Len -= 5;
				if ((s = memchr(l7Hdr, '\r', l7Len)) != NULL) {
					i = s - l7Hdr;
					if (i > FTP_MXNMLN) i = FTP_MXNMLN;
					memcpy(ftpFlowP->nameU[ftpFlowP->nameUCnt++], l7Hdr, i);
				}
				break;
			case XCUP:
				sC = 52;
				ftpFlowP->sendCode |= FTP_XCUP;
				break;
			case XMKD:
				sC = 53;
				ftpFlowP->sendCode |= FTP_XMKD;
				break;
			case XPWD:
				sC = 54;
				ftpFlowP->sendCode |= FTP_XPWD;
				break;
			case XRCP:
				sC = 55;
				ftpFlowP->sendCode |= FTP_XRCP;
				break;
			case XRMD:
				sC = 56;
				ftpFlowP->sendCode |= FTP_XRMD;
				break;
			case XRSQ:
				sC = 57;
				ftpFlowP->sendCode |= FTP_XRSQ;
				break;
			case XSEM:
				sC = 58;
				ftpFlowP->sendCode |= FTP_XSEM;
				break;
			case XSEN:
				sC = 59;
				ftpFlowP->sendCode |= FTP_XSEN;
				break;
			case CLNT:
				sC = 60;
				ftpFlowP->sendCode |= FTP_CLNT;
				break;
			default:
				return;
		}

strcd:		if (ftpFlowP->tCCnt >= MAXCNM) {
			ftpFlowP->stat |= FTP_OVFL;
			return;
		}

		for (j = 0; j < ftpFlowP->tCCnt; j++) {
			if (ftpFlowP->tCode[j] == sC) return;
		}

		ftpFlowP->tCode[ftpFlowP->tCCnt++] = sC;
	}
}


void onFlowTerminate(unsigned long flowIndex) {
	const flow_t * const flowP = &flows[flowIndex];

	flow_t client = {
		.vlanID = flowP->vlanID,
#if IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
		.ethType = flowP->ethType,
#endif // IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
#if SCTP_ACTIVATE == 1
		.sctpStrm = flowP->sctpStrm,
#endif // SCTP_ACTIVATE == 1
		.layer4Protocol = flowP->layer4Protocol,
		.srcIP = flowP->srcIP,
		.dstIP = flowP->dstIP,
		.dstPort = flowP->dstPort,
	};
	hashTable_remove(ftpHashMap, (char*)&client.srcIP);

	client.dstPort = flowP->srcPort;
	hashTable_remove(ftpHashMap, (char*)&client.srcIP);

	ftpFlow_t *ftpFlowP = &ftpFlows[flowIndex];

	ftpAStat |= ftpFlowP->stat;

#if FTP_SAVE == 1
	if (ftpFlowP->fd) {
		file_manager_close(t2_file_manager, ftpFlowP->fd);
		ftpFlowP->fd = NULL;
	}
#endif // FTP_SAVE == 1

#if BLOCK_BUF == 0
	ftpFlow_t *ftpFlowPO;
	if (flowP->oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) ftpFlowPO = &ftpFlows[flowP->oppositeFlowIndex];
	else ftpFlowPO = NULL;

	if (ftpFlowPO && (ftpFlowPO->stat & FTP_PPRNT)) ftpFlowP->stat |= FTP_PPRNT;

	outputBuffer_append(main_output_buffer, (char*) &ftpFlowP->stat, sizeof(uint8_t));

	uint_fast32_t i;

	uint32_t cnt = ftpFlowP->pfiCnt;
	if (cnt) {
		outputBuffer_append(main_output_buffer, (char*) &cnt, sizeof(uint32_t));
		for (i = 0; i < cnt; i++) {
			outputBuffer_append(main_output_buffer, (char*) &ftpFlowP->pfi[i], sizeof(uint64_t));
		}
	} else {
		cnt = ftpFlowPO ? ftpFlowPO->pfiCnt : 0;
		outputBuffer_append(main_output_buffer, (char*) &cnt, sizeof(uint32_t));
		for (i = 0; i < cnt; i++) {
			outputBuffer_append(main_output_buffer, (char*) &ftpFlowPO->pfi[i], sizeof(uint64_t));
		}
	}

#if BITFIELD == 1
	outputBuffer_append(main_output_buffer, (char*) &ftpFlowP->sendCode, sizeof(uint64_t));
	//outputBuffer_append(main_output_buffer, (char*) &ftpFlowP->recCode, sizeof(uint32_t));
#endif

	cnt = ftpFlowP->tCCnt;
	outputBuffer_append(main_output_buffer, (char*) &cnt, sizeof(uint32_t));
	for (i = 0; i < cnt; i++) {
		outputBuffer_append(main_output_buffer, ftpCom[ftpFlowP->tCode[i]], strlen(ftpCom[ftpFlowP->tCode[i]])+1);
	}

	cnt = ftpFlowP->rCCnt;
	outputBuffer_append(main_output_buffer, (char*) &cnt, sizeof(uint32_t));
	for (i = 0; i < cnt; i++) {
		outputBuffer_append(main_output_buffer, (char*)&ftpFlowP->recCode[i], sizeof(uint16_t));
	}

	outputBuffer_append(main_output_buffer, (char*) &ftpFlowP->nameUCnt, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*) &ftpFlowP->namePCnt, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*) &ftpFlowP->nameCCnt, sizeof(uint8_t));

	cnt = ftpFlowP->nameUCnt;
	outputBuffer_append(main_output_buffer, (char*) &cnt, sizeof(uint32_t));
	for (i = 0; i < cnt; i++) {
		outputBuffer_append(main_output_buffer, ftpFlowP->nameU[i], strlen(ftpFlowP->nameU[i])+1);
	}

	cnt = ftpFlowP->namePCnt;
	outputBuffer_append(main_output_buffer, (char*) &cnt, sizeof(uint32_t));
	for (i = 0; i < cnt; i++) {
		outputBuffer_append(main_output_buffer, ftpFlowP->nameP[i], strlen(ftpFlowP->nameP[i])+1);
	}

	cnt = ftpFlowP->nameCCnt;
	outputBuffer_append(main_output_buffer, (char*) &cnt, sizeof(uint32_t));
	for (i = 0; i < cnt; i++) {
		outputBuffer_append(main_output_buffer, ftpFlowP->nameC[i], strlen(ftpFlowP->nameC[i])+1);
	}
#endif // BLOCK_BUF == 0
}


void pluginReport(FILE *stream) {
	if (ftpAStat) T2_FPLOG(stream, "ftpDecode", "Anomaly flags: 0x%02"B2T_PRIX8, ftpAStat);
	T2_FPLOG_NUMP(stream, "ftpDecode", "Number of FTP packets", totFtpPktCnt, numPackets);
}


void monitoring(FILE *stream, uint8_t state) {

        switch (state) {

                case T2_MON_PRI_HDR:
                        fputs("ftpPkts\t", stream); // Note the trailing tab (\t)
                        return;

                case T2_MON_PRI_VAL:
                        fprintf(stream, "%"PRIu64"\t", totFtpPktCnt-totFtpPktCnt0);
                        break;

                case T2_MON_PRI_REPORT:
                        T2_PLOG_DIFFNUMP(stream, "ftpDecode", "Number of FTP packets", totFtpPktCnt, numPackets);
                        break;

                default:  // Invalid state, do nothing
                        return;
        }

#if DIFF_REPORT == 1
        totFtpPktCnt0 = totFtpPktCnt;
#endif // DIFF_REPORT == 1
}


void onApplicationTerminate() {
	hashTable_destroy(ftpHashMap);
	free(ftpFlows);
	free(ftpFindex);
}
