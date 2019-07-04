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

#include "popDecode.h"


// Global variables

popFlow_t *popFlows;


// Static variables

static uint64_t numPopPkts;

static const uint32_t popErrC[2] = { 0x204b4f2b, 0x5252452d };
//static const char popErr[2][5] ={ "+OK ", "-ERR" };
static const char popCom[17][5] = {
	"APOP", "AUTH", "CAPA", "DELE",
	"LIST", "NOOP", "PASS", "QUIT",
	"RETR", "RSET", "STAT", "STLS",
	"TOP ", "UIDL", "USER", "XTND",
	"-"
};


// Tranalyzer functions

T2_PLUGIN_INIT("popDecode", "0.8.4", 0, 8);


void initialize() {
	// allocate struct for all flows and initialise to 0
	if (UNLIKELY(!(popFlows = calloc(mainHashMap->hashChainTableSize, sizeof(*popFlows))))) {
		T2_PERR("popDecode", "failed to allocate memory for popFlows");
		exit(-1);
	}

#if POP_SAVE == 1
	if (UNLIKELY(!rmrf(POP_F_PATH))) {
		T2_PERR("popDecode", "Failed to remove directory '%s': %s", POP_F_PATH, strerror(errno));
		exit(-1);
	}

	if (UNLIKELY(!mkpath(POP_F_PATH, S_IRWXU))) {
		T2_PERR("popDeocde", "Failed to create directory '%s': %s", POP_F_PATH, strerror(errno));
		exit(-1);
	}
#endif // POP_SAVE == 1
}


binary_value_t* printHeader() {
	binary_value_t *bv = NULL;
	bv = bv_append_bv(bv, bv_new_bv("POP Status Bitfield", "popStat", 0, 1, bt_hex_8));
	bv = bv_append_bv(bv, bv_new_bv("POP Command Bit Field", "popCBF", 0, 1, bt_hex_16));
	bv = bv_append_bv(bv, bv_new_bv("POP Command Codes", "popCC", 1, 1, bt_string_class));
	bv = bv_append_bv(bv, bv_new_bv("POP Response #mail", "popRM", 1, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("POP Number of users", "popUsrNum", 0, 1, bt_uint_8));
	bv = bv_append_bv(bv, bv_new_bv("POP Number of passwords", "popPwNum", 0, 1, bt_uint_8));
	bv = bv_append_bv(bv, bv_new_bv("POP Number of parameters", "popCNum", 0, 1, bt_uint_8));
	bv = bv_append_bv(bv, bv_new_bv("POP Users", "popUsr", 1, 1, bt_string));
	bv = bv_append_bv(bv, bv_new_bv("POP Passwords", "popPw", 1, 1, bt_string));
	bv = bv_append_bv(bv, bv_new_bv("POP Content", "popC", 1, 1, bt_string));
	return bv;
}


void onFlowGenerated(packet_t* packet __attribute__((unused)), unsigned long flowIndex) {
	popFlow_t * const popFlowP = &popFlows[flowIndex];
	memset(popFlowP, '\0', sizeof(*popFlowP));

	const flow_t * const flowP = &flows[flowIndex];
	if (flowP->layer4Protocol != L3_TCP) return;

	const uint_fast16_t srcPort = flowP->srcPort;
	const uint_fast16_t dstPort = flowP->dstPort;

	if (dstPort == 110 || srcPort == 110) popFlowP->stat = POP3_INIT;
	else if (dstPort == 109 || srcPort == 109) popFlowP->stat = POP2_INIT;
}


void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {
	const flow_t * const flowP = &flows[flowIndex];

	popFlow_t * const popFlowP = &popFlows[flowIndex];
	if (popFlowP->stat == 0x00) return;

#if POP_SAVE == 1
	const tcpHeader_t * const tcpHeader = (tcpHeader_t*)packet->layer4Header; // the tcp-header
	const uint32_t tcpSeq = ntohl(tcpHeader->seq); // absolute / relative tcp sequence number
	popFlow_t *popFlowPO = NULL;
#endif // POP_SAVE == 1
	uint32_t l7Hdr32;
	uint32_t i, j;
	int32_t l7Len = packet->snapL7Length;
	char *l7Hdr = (char*)packet->layer7Header, *s;
	uint8_t sC = 0;

	if (l7Len < 4) return;

	numPopPkts++;

	l7Hdr32 = *(uint32_t*)l7Hdr;
	if (l7Hdr[0] > 0x60) l7Hdr32 -= 0x20202020;

	if (flowP->status & L3FLOWINVERT) {
		if (popFlowP->rCCnt >= MXCNM) {
			popFlowP->stat |= POP_OVFL;
			return;
		}
#if POP_SAVE == 1
		if (flowP->oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) popFlowPO = &popFlows[flowP->oppositeFlowIndex];
#endif // POP_SAVE == 1

		if (l7Hdr32 == popErrC[0]) {
			popFlowP->stat |= POP_ROK;
#if POP_SAVE == 1
			if (flowP->oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
				popFlowPO = &popFlows[flowP->oppositeFlowIndex];

				if ((popFlowPO->stat & POP_DTP) && !popFlowP->fd) {
					char imfname[POP_MXIMNM_LEN];
					s = popFlowPO->nameU[popFlowPO->nameUCnt-1];
					j = strlen(s);
					for (i = 0; i < j; i++) if (s[i] == '/') s[i] = '_';
					memcpy(imfname, POP_F_PATH, sizeof(POP_F_PATH));
					i = sizeof(POP_F_PATH) - 1;
					memcpy(imfname + i, s, j+1);
					i += j;
					//sprintf(imfname + i, "_%d_%"PRIu64"_%d", (flowP->status & L3FLOWINVERT), flowP->findex, popFlowP->pktCnt);
					sprintf(imfname + i, "_%d_%"PRIu64, (int)(flowP->status & L3FLOWINVERT), flowP->findex);
//					memcpy(s, imfname + sizeof(POP_F_PATH)-1, strlen(imfname)-sizeof(POP_F_PATH)));// check nameC length exceeded
//printf("%s	\n", imfname);
					popFlowP->fd = file_manager_open(t2_file_manager, imfname, "w+b");
					if (!popFlowP->fd) {
						T2_PERR("popDecode", "Failed to open file '%s': %s", imfname, strerror(errno));
						popFlowP->stat |= POP_RERR;
						return;
					}
					popFlowP->seqInit = tcpSeq + l7Len;
					popFlowPO->stat |= POP_DWF;
				}
			}
#endif // POP_SAVE == 1
		 	j = 4;
		} else if (l7Hdr32 == popErrC[1]) {
			popFlowP->stat |= POP_RERR;
			j = 5;
#if POP_SAVE == 1
			if (popFlowP->fd) {
				file_manager_close(t2_file_manager, popFlowP->fd);
				popFlowP->fd = NULL;
				popFlowPO->stat &= ~POP_DTP;
			}
#endif // POP_SAVE == 1
		} else {
			popFlowP->stat |= POP_RNVL;
#if POP_SAVE == 1
			if (popFlowPO && popFlowPO->stat & POP_DTP) {
				if (popFlowP->fd) {
					FILE *fp = file_manager_fp(t2_file_manager, popFlowP->fd);
					i = tcpSeq - popFlowP->seqInit;
					fseek(fp, i, SEEK_SET);
					fwrite(l7Hdr, 1, l7Len , fp);
				} else popFlowP->stat &= ~POP_DTP;
			} else if (popFlowP->fd) {
				file_manager_close(t2_file_manager, popFlowP->fd);
				popFlowP->fd = NULL;
				popFlowPO->stat &= ~POP_DTP;
			}
#endif // POP_SAVE == 1
			return;
		}

		if (popFlowP->nameCCnt >= MXPNM) {
			popFlowP->stat |= POP_OVFL;
			goto popaa;
		}

		l7Hdr += j;
		l7Len -= j;
		if ((s = memchr(l7Hdr, '\r', l7Len)) != NULL) {
			i = s - l7Hdr;
			if (i > MXNMLN) i = MXNMLN;
			memcpy(popFlowP->nameC[popFlowP->nameCCnt++], l7Hdr, i);
		}

	popaa:	j = atoi(l7Hdr);
		if (!j) return;
		for (i = 0; i < popFlowP->rCCnt; i++) {
			if (popFlowP->recCode[i] == j) return;
		}
		popFlowP->recCode[popFlowP->rCCnt++] = j;

	} else {
		switch (l7Hdr32) {
			case APOP:
				sC = 0;
				popFlowP->tCodeBF |= POP_APOP;
				break;
			case AUTH:
				sC = 1;
				popFlowP->tCodeBF |= POP_AUTH;
				break;
			case CAPA:
				sC = 2;
				popFlowP->tCodeBF |= POP_CAPA;
				break;
			case DELE:
				sC = 3;
				popFlowP->tCodeBF |= POP_DELE;
				break;
			case LIST:
				sC = 4;
				popFlowP->tCodeBF |= POP_LIST;
				break;
			case NOOP:
				sC = 5;
				popFlowP->tCodeBF |= POP_NOOP;
				break;
			case PASS:
				sC = 6;
				if (popFlowP->namePCnt >= MXPNM) {
					popFlowP->stat |= POP_OVFL;
					break;
				}
				popFlowP->tCodeBF |= POP_PASS;
				if (l7Len < 7) break;
				l7Hdr += 5;
				l7Len -= 5;
				if ((s = memchr(l7Hdr, '\r', l7Len)) != NULL) {
					i = s - l7Hdr;
					if (i > MXNMLN) i = MXNMLN;
					memcpy(popFlowP->nameP[popFlowP->namePCnt++], l7Hdr, i);
				}
				break;
			case QUIT:
				sC = 7;
				popFlowP->tCodeBF |= POP_QUIT;
#if POP_SAVE == 1
				if (popFlowP->fd) {
					file_manager_close(t2_file_manager, popFlowP->fd);
					popFlowP->fd = NULL;
					popFlowP->stat &= ~POP_DTP;
				}

#endif // POP_SAVE == 1
				break;
			case RETR:
				sC = 8;
				if (popFlowP->nameCCnt >= MXPNM) {
					popFlowP->stat |= POP_OVFL;
					break;
				}
				popFlowP->tCodeBF |= POP_RETR;
				popFlowP->stat |= POP_DTP;
				if (l7Len < 7) break;
				l7Hdr += 5;
				l7Len -= 5;
				if ((s = memchr(l7Hdr, '\r', l7Len)) != NULL) {
					i = s - l7Hdr;
					if (i > MXNMLN) i = MXNMLN;
					memcpy(popFlowP->nameC[popFlowP->nameCCnt++], l7Hdr, i);
				}
				break;
			case RSET:
				sC = 9;
				popFlowP->tCodeBF |= POP_RSET;
				break;
			case STAT:
				sC = 10;
				popFlowP->tCodeBF |= POP_STAT;
				break;
			case STLS:
				sC = 11;
				popFlowP->tCodeBF |= POP_STLS;
				break;
			case TOP:
				sC = 12;
				popFlowP->tCodeBF |= POP_TOP;
				break;
			case UIDL:
				sC = 13;
				popFlowP->tCodeBF |= POP_UIDL;
				break;
			case USER:
				sC = 14;
				if (popFlowP->nameUCnt >= MXUNM) {
					popFlowP->stat |= POP_OVFL;
					break;
				}
				popFlowP->tCodeBF |= POP_USER;
				if (l7Len < 7) break;
				l7Hdr += 5;
				l7Len -= 5;
				if ((s = memchr(l7Hdr, '\r', l7Len)) != NULL) {
					i = s - l7Hdr;
					if (i > MXNMLN) i = MXNMLN;
					memcpy(popFlowP->nameU[popFlowP->nameUCnt++], l7Hdr, i);
				}
				break;
			case XTND:
				sC = 15;
				popFlowP->tCodeBF |= POP_XTND;
				break;
			default:
				return;
		}

		if (popFlowP->tCCnt >= MXCNM) {
			popFlowP->stat |= POP_OVFL;
			return;
		}

		for (j = 0; j < popFlowP->tCCnt; j++) if (popFlowP->tCode[j] == sC) return;

		popFlowP->tCode[popFlowP->tCCnt++] = sC;
		popFlowP->tCodeBF |= (1 << sC);
	}
}


#if POP_SAVE == 1 || BLOCK_BUF == 0
void onFlowTerminate(unsigned long flowIndex) {
	popFlow_t * const popFlowP = &popFlows[flowIndex];

#if POP_SAVE == 1
	if (popFlowP->fd) {
		file_manager_close(t2_file_manager, popFlowP->fd);
		popFlowP->fd = NULL;
	}
#endif // POP_SAVE == 1

#if BLOCK_BUF == 0
	outputBuffer_append(main_output_buffer, (char*) &popFlowP->stat, sizeof(uint8_t));

	outputBuffer_append(main_output_buffer, (char*) &popFlowP->tCodeBF, sizeof(uint16_t));

	uint_fast32_t i;
	uint32_t j = popFlowP->tCCnt;
	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		if (popFlowP->tCode[i] < 17) outputBuffer_append(main_output_buffer, (char*)&popCom[popFlowP->tCode[i]], 5);
		else outputBuffer_append(main_output_buffer, (char*)&popCom[17], 2);
	}

	j = popFlowP->rCCnt;
	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) outputBuffer_append(main_output_buffer, (char*)&popFlowP->recCode[i], sizeof(uint16_t));

	outputBuffer_append(main_output_buffer, (char*) &popFlowP->nameUCnt, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*) &popFlowP->namePCnt, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*) &popFlowP->nameCCnt, sizeof(uint8_t));

	j = popFlowP->nameUCnt;
	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) outputBuffer_append(main_output_buffer, popFlowP->nameU[i], strlen(popFlowP->nameU[i])+1);

	j = popFlowP->namePCnt;
	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) outputBuffer_append(main_output_buffer, popFlowP->nameP[i], strlen(popFlowP->nameP[i])+1);

	j = popFlowP->nameCCnt;
	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		outputBuffer_append(main_output_buffer, popFlowP->nameC[i], strlen(popFlowP->nameC[i])+1);
	}
#endif // BLOCK_BUF == 0
}
#endif // POP_SAVE == 1 || BLOCK_BUF == 0


void pluginReport(FILE *stream) {
	T2_FPLOG_NUMP(stream, "popDecode", "Number of POP packets", numPopPkts, numPackets);
}


void onApplicationTerminate() {
	free(popFlows);
}
