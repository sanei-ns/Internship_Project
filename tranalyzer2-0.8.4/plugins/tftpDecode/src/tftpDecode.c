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

#include "tftpDecode.h"


// Global variables

tftpFlow_t *tftpFlows;


// Static variables

static uint64_t totTftpPktCnt;
static const char tftpCom[7][4] = {"---","RRQ","WRQ","DTA","ACK","ERR","OAK"};
//static const uint8_t tftpMode[3][9] = { "octet", "netascii", "mail" };


// Tranalyzer functions

T2_PLUGIN_INIT("tftpDecode", "0.8.4", 0, 8);


void initialize() {
	// allocate struct for all flows and initialise to 0
	if (UNLIKELY(!(tftpFlows = calloc(mainHashMap->hashChainTableSize, sizeof(*tftpFlows))))) {
		T2_PERR("tftpDecode", "failed to allocate memory for tftpFlows");
		exit(-1);
	}
#if TFTP_SAVE == 1
	if (!rmrf(TFTP_F_PATH)) {
		T2_PERR("tftpDecode", "Failed to remove directory '%s': %s", TFTP_F_PATH, strerror(errno));
		exit(-1);
	}

	if (!mkpath(TFTP_F_PATH, S_IRWXU)) {
		T2_PERR("tftpDeocde", "Failed to create directory '%s': %s", TFTP_F_PATH, strerror(errno));
		exit(-1);
	}
#endif // TFTP_SAVE == 1
}


binary_value_t* printHeader() {
	binary_value_t *bv = NULL;
	bv = bv_append_bv(bv, bv_new_bv("TFTP Status Bitfield", "tftpStat", 0, 1, bt_hex_16));
	bv = bv_append_bv(bv, bv_new_bv("TFTP Parent Flow", "tftPFlw", 0, 1, bt_uint_64));
	bv = bv_append_bv(bv, bv_new_bv("TFTP OP Code Bit Field", "tftpOpCBF", 0, 1, bt_hex_8));
	bv = bv_append_bv(bv, bv_new_bv("TFTP Error Code Bit Field", "tftpErrCBF", 0, 1, bt_hex_8));
	bv = bv_append_bv(bv, bv_new_bv("TFTP Number of OP Code", "tftOpCNum", 0, 1, bt_uint_8));
	bv = bv_append_bv(bv, bv_new_bv("TFTP Number of parameters", "tftpPNum", 0, 1, bt_uint_8));
	bv = bv_append_bv(bv, bv_new_bv("TFTP OP Codes", "tftpOpC", 1, 1, bt_string_class));
	bv = bv_append_bv(bv, bv_new_bv("TFTP Parameters", "tftpC", 1, 1, bt_string));
	return bv;
}


void onFlowGenerated(packet_t* packet, unsigned long flowIndex) {
	flow_t *flowP = &flows[flowIndex];
	tftpFlow_t *tftpFlowP = &tftpFlows[flowIndex];
	memset(tftpFlowP, '\0', sizeof(*tftpFlowP));

	if (flowP->layer4Protocol == L3_UDP) {
		if (*packet->layer7Header) return;
		if ( (flowP->srcPort == 69 && flowP->dstPort > 1024) || flowP->dstPort == 69 || flowP->dstPort == 1758 ) {
			tftpFlowP->stat = (TFTPS_INIT | TFTP_ACT);
		} else {
			unsigned long oFlowIndex = flowP->oppositeFlowIndex;
			if (oFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
				tftpFlow_t *otftpFlowP = &tftpFlows[oFlowIndex];
				if (otftpFlowP->stat & TFTPS_INIT) {
					tftpFlowP->pfi = otftpFlowP->pfi;
					tftpFlowP->stat = otftpFlowP->stat;
					tftpFlowP->sndBlk = 1;
					tftpFlowP->lstBlk = 1;
					return;
				}
			}
			flow_t parent = {
#if ETH_ACTIVATE == 2
				.ethDS = ((ethernetHeader_t*)packet->layer2Header)->ethDS,
#endif // ETH_ACTIVATE == 2
#if IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
				.ethType = packet->layer2Type,
#endif // IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
#if SCTP_ACTIVATE == 1
				.sctpStrm = flowP->sctpStrm,
#endif // SCTP_ACTIVATE == 1
				.layer4Protocol = flowP->layer4Protocol,
				.vlanID = flowP->vlanID,
				.srcIP = flowP->dstIP,
				.dstIP = flowP->srcIP,
				.srcPort = flowP->dstPort,
				.dstPort = 69,
			};
			char *pa = (char*)&parent.srcIP;
			unsigned long pIndex = hashTable_lookup(mainHashMap, pa);
			if (pIndex == HASHTABLE_ENTRY_NOT_FOUND) {
				parent.dstPort = 1758;
				pIndex = hashTable_lookup(mainHashMap, pa);
				if (pIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
			}
			tftpFlows[pIndex].pfi = flowP->findex;
			tftpFlowP->pfi = flows[pIndex].findex;
			tftpFlowP->stat = (TFTPS_INIT | TFTP_PSV);
			tftpFlows[pIndex].stat = (TFTPS_INIT | TFTP_PSV);
			tftpFlowP->sndBlk = 1;
			tftpFlowP->lstBlk = 1;
		}
	}
}


void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {
#if TFTP_SAVE == 1
	flow_t *flowP = &flows[flowIndex];
#endif // TFTP_SAVE == 1
	tftpFlow_t *tftpFlowP = &tftpFlows[flowIndex];
	if (tftpFlowP->stat == 0x00) return;

	int32_t l7Len = packet->snapL7Length;
	char *l7Hdr = (char*)packet->layer7Header;

	if (*l7Hdr || l7Len < 4) {
		tftpFlowP->stat = 0;
		return;
	}

	totTftpPktCnt++;

	uint16_t *l7Hdr16 = (uint16_t*)l7Hdr;
	if (tftpFlowP->opCnt >= MAXCNM) {
		tftpFlowP->stat |= TFTPS_OVFL;
		return;
	}

	uint32_t i;

	uint16_t j = ntohs(*l7Hdr16);
	for (i = 0; i < tftpFlowP->opCnt; i++) {
		if (tftpFlowP->opCode[i] == j) goto tftp;
	}
	tftpFlowP->opCode[tftpFlowP->opCnt++] = j;

	if (j) tftpFlowP->opCodeBF |= (1 << (j-1));

tftp:	switch (j) {
		case RRQ:
		case WRQ:
			if (tftpFlowP->pCnt >= MAXCNM) {
				tftpFlowP->stat |= TFTPS_OVFL;
				break;
			}
			l7Hdr += 2;
			l7Len -= 2;
			j = i = strlen(l7Hdr);
			if (i == 0 || l7Len < 1) {
				tftpFlowP->stat |= TFTP_RW_PLNERR;
				break;
			}
			if (i > TFTP_MXNMLN) i = TFTP_MXNMLN;
			if ((int32_t)i > l7Len) i = l7Len -1;
			memcpy(tftpFlowP->nameC[tftpFlowP->pCnt++], l7Hdr, i);
			l7Hdr += j+1;
			l7Len -= j+1;
			i = strlen(l7Hdr);
			if (i == 0 || l7Len < 1) {
				tftpFlowP->stat |= TFTP_RW_PLNERR;
				break;
			}
			if (i > TFTP_MXNMLN) i = TFTP_MXNMLN;
			if ((int32_t)i > l7Len) i = l7Len -1;
			memcpy(tftpFlowP->nameC[tftpFlowP->pCnt++], l7Hdr, i);
//			for (i = 0; i < 3; i++) if (*tftpMode[i] == *l7Hdr) tftpFlowP->mode |= (1<<(i+1));

#if TFTP_SAVE == 1
			char imfname[TFTP_MXIMNM_LEN], *s;
			s = tftpFlowP->nameC[tftpFlowP->pCnt-2];
			j = strlen(s);
			for (i = 0; i < j; i++) if (s[i] == '/') s[i] = '_';
			memcpy(imfname, TFTP_F_PATH, sizeof(TFTP_F_PATH));
			i = sizeof(TFTP_F_PATH) - 1;
			memcpy(imfname + i, s, j+1);
			i += j;
			//sprintf(imfname + i, "_%d_%"PRIu64"_%d", (flowP->status & L3FLOWINVERT), flowP->findex, ftpFlowP->pktCnt);
			sprintf(imfname + i, "_%d_%"PRIu64, (int)(flowP->status & L3FLOWINVERT), flowP->findex);
			memcpy(s, imfname + sizeof(TFTP_F_PATH)-1, strlen(imfname)-sizeof(TFTP_F_PATH)+1);// check nameC length exceeded
			tftpFlowP->fd = file_manager_open(t2_file_manager, imfname, "w+b");
			if (!tftpFlowP->fd) {
				T2_PERR("tftpDecode", "Failed to open file '%s': %s", imfname, strerror(errno));
				//exit(-1);
				tftpFlowP->stat |= TFTP_FERR;
				return;
			}
#endif // TFTP_SAVE == 1
			break;

		case DATA:
			j = ntohs(*(l7Hdr16+1));
			if (j != tftpFlowP->sndBlk) tftpFlowP->stat |= TFTPS_BSERR;
			tftpFlowP->sndBlk = j + 1;
#if TFTP_SAVE == 1
			tftpFlow_t *tftpFlowPO = NULL;
			if (tftpFlowP->stat & TFTP_ACT) {
				if (flowP->oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND ) tftpFlowPO = &tftpFlows[flowP->oppositeFlowIndex];
			} else {
				tftpFlowPO = &tftpFlows[tftpFlowP->pfi - 1];
			}
			if (tftpFlowPO && tftpFlowPO->fd) {
				FILE *fp = file_manager_fp(t2_file_manager, tftpFlowPO->fd);
				fseek(fp, (j-1)*512, SEEK_SET);
				i = l7Len - 4;
				fwrite(l7Hdr+4, 1, i , fp);
				if (i < 512) {
					file_manager_close(t2_file_manager, tftpFlowPO->fd);
					tftpFlowPO->fd = NULL;
				}
			}
#endif // TFTP_SAVE == 1
			break;

		case ACK:
			j = ntohs(*(l7Hdr16+1));
			if (j) {
				if (j != tftpFlowP->lstBlk) tftpFlowP->stat |= TFTPS_BSAERR;
				tftpFlowP->lstBlk = j + 1;
			}
			break;

		case ERR:
			j = ntohs(*(l7Hdr16+1)) - 1;
			tftpFlowP->errCodeBF |= (1 << j);
#if TFTP_SAVE == 1
			if (tftpFlowP->fd) {
				file_manager_close(t2_file_manager, tftpFlowP->fd);
				tftpFlowP->fd = NULL;
			}
#endif // TFTP_SAVE == 1
			break;

		case OACK:
			break;

		default:
			tftpFlowP->stat |= TFTPS_PERR;
			return;
	}
}


void onFlowTerminate(unsigned long flowIndex) {
#if TFTP_SAVE == 1 || BLOCK_BUF == 0
	tftpFlow_t *tftpFlowP = &tftpFlows[flowIndex];
#endif

#if TFTP_SAVE == 1
	if (tftpFlowP->fd) {
		file_manager_close(t2_file_manager, tftpFlowP->fd);
		tftpFlowP->fd = NULL;
	}
#endif

#if BLOCK_BUF == 0
	uint32_t i, cnt;

	outputBuffer_append(main_output_buffer, (char*) &tftpFlowP->stat, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*) &tftpFlowP->pfi, sizeof(uint64_t));

	outputBuffer_append(main_output_buffer, (char*) &tftpFlowP->opCodeBF, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*) &tftpFlowP->errCodeBF, sizeof(uint8_t));

	outputBuffer_append(main_output_buffer, (char*) &tftpFlowP->opCnt, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*) &tftpFlowP->pCnt, sizeof(uint8_t));

	cnt = tftpFlowP->opCnt;
	outputBuffer_append(main_output_buffer, (char*) &cnt, sizeof(uint32_t));
	for (i = 0; i < cnt; i++) {
		if (tftpFlowP->opCode[i] < 7) outputBuffer_append(main_output_buffer, (char*)&tftpCom[tftpFlowP->opCode[i]], 4);
		else outputBuffer_append(main_output_buffer, (char*)&tftpCom[0], 4);
	}

	cnt = tftpFlowP->pCnt;
	outputBuffer_append(main_output_buffer, (char*) &cnt, sizeof(uint32_t));
	for (i = 0; i < cnt; i++) {
		outputBuffer_append(main_output_buffer, tftpFlowP->nameC[i], strlen(tftpFlowP->nameC[i])+1);
	}
#endif // BLOCK_BUF == 0
}


void pluginReport(FILE *stream) {
	T2_FPLOG_NUMP(stream, "tftpDecode", "Number of TFTP packets", totTftpPktCnt, numPackets);
}


void onApplicationTerminate() {
	free(tftpFlows);
}
