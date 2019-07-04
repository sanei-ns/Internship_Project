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

#include "smtpDecode.h"


// Global variables

smtp_flow_t *smtp_flow;


// Static variables

static uint64_t totsmtpPktCnt;

// send commands
static const char smtpCom[17][5] = {
	"HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET",
	"SEND", "SOML", "SAML", "VRFY", "EXPN", "HELP",
	"NOOP", "QUIT", "TURN", "AUTH", "STLS"
};


// Tranalyzer plugin functions

T2_PLUGIN_INIT("smtpDecode", "0.8.4", 0, 8);


void initialize() {
	if (UNLIKELY(!(smtp_flow = calloc(mainHashMap->hashChainTableSize, sizeof(smtp_flow_t))))) {
		T2_PERR("smtpDecode", "failed to allocate memory for smtp_flow");
		exit(-1);
	}

#if SMTP_SAVE == 1
	if (!rmrf(SMTP_F_PATH)) {
		T2_PERR("smtpDecode", "Failed to remove directory '%s': %s", SMTP_F_PATH, strerror(errno));
		exit(-1);
	}

	if (!mkpath(SMTP_F_PATH, S_IRWXU)) {
		T2_PERR("smtpDeocde", "Failed to create directory '%s': %s", SMTP_F_PATH, strerror(errno));
		exit(-1);
	}
#endif // SMTP_SAVE == 1
}


binary_value_t* printHeader() {
	binary_value_t *bv = NULL;
	bv = bv_append_bv(bv, bv_new_bv("SMTP Status", "smtpStat", 0, 1, bt_hex_8));
#if SMTP_BTFLD == 1
	bv = bv_append_bv(bv, bv_new_bv("SMTP Command Bit Field", "smtpCBF", 0, 1, bt_hex_16));
	//bv = bv_append_bv(bv, bv_new_bv("SMTP Response Bit Field", "smtpRBF", 0, 1, bt_hex_32));
#endif // SMTP_BTFLD == 1
	bv = bv_append_bv(bv, bv_new_bv("SMTP Command Codes", "smtpCC", 1, 1, bt_string_class));
	bv = bv_append_bv(bv, bv_new_bv("SMTP Response Codes", "smtpRC", 1, 1, bt_int_16));
	bv = bv_append_bv(bv, bv_new_bv("SMTP Users", "smtpUsr", 1, 1, bt_string));
	bv = bv_append_bv(bv, bv_new_bv("SMTP Passwords", "smtpPW", 1, 1, bt_string));
	bv = bv_append_bv(bv, bv_new_bv("SMTP number of Server addresses", "smtpSANum", 0, 1, bt_int_8));
	bv = bv_append_bv(bv, bv_new_bv("SMTP number of Email sender addresses", "smtpESANum", 0, 1, bt_int_8));
	bv = bv_append_bv(bv, bv_new_bv("SMTP number of Email receiver addresses", "smtpERANum", 0, 1, bt_int_8));
	bv = bv_append_bv(bv, bv_new_bv("SMTP Server send addresses", "smtpSA", 1, 1, bt_string));
	bv = bv_append_bv(bv, bv_new_bv("SMTP Email send addresses", "smtpESA", 1, 1, bt_string));
	bv = bv_append_bv(bv, bv_new_bv("SMTP Email receive addresses", "smtpERA", 1, 1, bt_string));
	return bv;
}


void onFlowGenerated(packet_t* packet __attribute__((unused)), unsigned long flowIndex) {
	smtp_flow_t *smtpFlowP = &smtp_flow[flowIndex];
	memset(smtpFlowP, '\0', sizeof(smtp_flow_t));

	const flow_t * const flowP = &flows[flowIndex];

	const uint_fast16_t srcPort = flowP->srcPort;
	const uint_fast16_t dstPort = flowP->dstPort;

	if (flowP->layer4Protocol != L3_TCP) return;

	if (dstPort == 25 || dstPort == 465 || dstPort == 587 || dstPort == 2525 ||
	    srcPort == 25 || srcPort == 465 || srcPort == 587 || srcPort == 2525)
	{
		smtpFlowP->stat = SMTP_INIT;
	}
}


void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {
	smtp_flow_t *smtpFlowP = &smtp_flow[flowIndex];
	if (!smtpFlowP->stat) return;

#if SMTP_SAVE == 1
	const tcpHeader_t * const tcpHeader = (tcpHeader_t*)packet->layer4Header; // the tcp-header
	const uint32_t tcpSeq = ntohl(tcpHeader->seq); // absolute / relative tcp sequence number
#endif // SMTP_SAVE == 1

	uint32_t *l7Hdr32;
	uint32_t i, j;
	int pshft = 5;
	int32_t l7Len = packet->snapL7Length;
	char *l7Hdr = (char*)packet->layer7Header, *s;
	uint8_t sC = 0;

	totsmtpPktCnt++;

	if (l7Len < 4) return;

	const flow_t * const flowP = &flows[flowIndex];
	if (flowP->status & L3FLOWINVERT) {
#if SMTP_RCTXT == 1
		int32_t nameSLen = 0, k;
		char *t = smtpFlowP->nameS[smtpFlowP->nameSCnt];
smtpsnxt:
#endif // SMTP_RCTXT == 1
		l7Hdr32 = (uint32_t*)l7Hdr;
		if (smtpFlowP->rCCnt >= MAXCNM) {
			smtpFlowP->stat |= 0x80;
			return;
		}
		i = *l7Hdr32 & 0xffffff;
		j = atoi((char*)&i);
		if (!j) return;
		for (i = 0; i < smtpFlowP->rCCnt; i++) {
			if (smtpFlowP->recCode[i] == j)
#if SMTP_RCTXT == 1
				goto smtpsinfo;
#else // SMTP_RCTXT == 0
				return;
#endif // SMTP_RCTXT
		}
		smtpFlowP->recCode[smtpFlowP->rCCnt++] = j;
		//smtpFlowP->recCode |= (1 << i);
#if SMTP_RCTXT == 1
smtpsinfo:	if (j) {
			if (smtpFlowP->nameSCnt >= MAXSNM) {
				smtpFlowP->stat |= SMTP_OVFL;
				return;
			}
			if ((s = memchr(l7Hdr, '\r', l7Len)) != NULL) {
				pshft = s - l7Hdr;
				nameSLen += pshft;
				if (nameSLen > SMTP_MXNMLN) pshft = nameSLen - SMTP_MXNMLN;
				memcpy(t, l7Hdr, pshft);
				k = l7Len - pshft - 7;
				if (k > 0 && nameSLen < SMTP_MXNMLN-7) {
					t += pshft;
					*t = '_';
					t++;
					pshft += 2;
					l7Hdr += pshft;
					l7Len -= pshft;
					goto smtpsnxt;
				} else {
					smtpFlowP->nameSCnt++;
					return;
				}
			}
		}
#endif // SMTP_RCTXT == 1
	} else {
		if (smtpFlowP->stat & SMTP_AUTP) {
			if (smtpFlowP->namePCnt >= MAXPNM) {
				smtpFlowP->stat |= SMTP_OVFL;
				return;
			}
			s = memchr(l7Hdr, '\r', l7Len);
			if (s) {
				j = s - l7Hdr;
			} else {
				smtpFlowP->stat &= ~(PWSTATE | SMTP_AUTP);
				return;
			}

			if (smtpFlowP->stat & PWSTATE){
				if (j > SMTP_MXPNMLN) j = SMTP_MXUNMLN;
				s = smtpFlowP->nameP[smtpFlowP->namePCnt++];
				smtpFlowP->stat &= ~(PWSTATE | SMTP_AUTP);
			} else {
				if (j > SMTP_MXUNMLN) j = SMTP_MXUNMLN;
				s = smtpFlowP->nameU[smtpFlowP->nameUCnt++];
				smtpFlowP->stat |= PWSTATE;
			}
			memcpy(s, l7Hdr, j);
//			s[j] = 0x0;
			return;
#if SMTP_SAVE == 1
		} else if (smtpFlowP->stat & SMTP_DTP) {
			FILE *fp = file_manager_fp(t2_file_manager, smtpFlowP->fd);
			i = tcpSeq - smtpFlowP->seqInit;
			fseek(fp, i, SEEK_SET);
			fwrite(l7Hdr, 1, l7Len , fp);
#endif // SMTP_SAVE == 1
		}

		l7Hdr32 = (uint32_t*)l7Hdr;
		// case insensitive check of first 4 letters of SMTP command
		switch (l7Hdr[0] > 0x60 ? *l7Hdr32 - 0x20202020 : *l7Hdr32) {
			case HELO:
				sC = 0;
				smtpFlowP->sendCode |= SMTP_HELO;
				smtpFlowP->stat &= ~(PWSTATE | SMTP_AUTP);
				if (smtpFlowP->nameSCnt >= MAXSNM) {
					smtpFlowP->stat |= SMTP_OVFL;
					break;
				}
				goto smtpcc;
			case EHLO:
				sC = 1;
				smtpFlowP->sendCode |= SMTP_EHLO;
				smtpFlowP->stat &= ~(PWSTATE | SMTP_AUTP);
				if (smtpFlowP->nameSCnt >= MAXSNM) {
					smtpFlowP->stat |= SMTP_OVFL;
					break;
				}
smtpcc:
				if (l7Len <= 7) break;
				l7Hdr += 5;
				l7Len -= 5;
				if ((s = memchr(l7Hdr, '\r', l7Len)) != NULL) {
					pshft = s - l7Hdr;
					if (pshft > SMTP_MXNMLN) pshft = SMTP_MXNMLN;
					memcpy(smtpFlowP->nameS[smtpFlowP->nameSCnt++], l7Hdr, pshft);
				}
				break;
			case MAIL:
				sC = 2;
				smtpFlowP->sendCode |= SMTP_MAIL;
				smtpFlowP->stat &= ~(PWSTATE | SMTP_AUTP);
				if (smtpFlowP->nameTCnt >= MAXTNM) {
					smtpFlowP->stat |= SMTP_OVFL;
					break;
				}
				if (l7Len <= 13) break;
				l7Hdr += 10;
				l7Len -= 10;
				if ((s = memchr(l7Hdr, '<', l7Len)) != NULL) {
					l7Hdr = s + 1;
					l7Len--;
					if ((s = memchr(l7Hdr, '>', l7Len)) != NULL) pshft = s - l7Hdr;
					else pshft = l7Len;
					if (pshft > SMTP_MXNMLN) pshft = SMTP_MXNMLN;
					memcpy(smtpFlowP->nameT[smtpFlowP->nameTCnt++], l7Hdr, pshft);
				}
				break;
			case RCPT:
				sC = 3;
				smtpFlowP->sendCode |= SMTP_RCPT;
				smtpFlowP->stat &= ~(PWSTATE | SMTP_AUTP);
				if (smtpFlowP->nameRCnt >= MAXRNM) {
					smtpFlowP->stat |= SMTP_OVFL;
					break;
				}
				if (l7Len <= 11) break;
				l7Hdr += 8;
				l7Len -= 8;
				s = memchr(l7Hdr, '<', l7Len);
				if (s != NULL) {
					l7Hdr = s + 1;
					l7Len--;
					if ((s = memchr(l7Hdr, '>', l7Len)) != NULL) pshft = s - l7Hdr;
					else pshft = l7Len;
					if (pshft > SMTP_MXNMLN) pshft = SMTP_MXNMLN;
					memcpy(smtpFlowP->nameR[smtpFlowP->nameRCnt++], l7Hdr, pshft);
				}
				break;
			case DATA:
				sC = 4;
				smtpFlowP->sendCode |= SMTP_DATA;
#if SMTP_SAVE == 1
				if (!smtpFlowP->fd) {
					char imfname[SMTP_MXIMNM_LEN];
					s = smtpFlowP->nameT[smtpFlowP->nameTCnt-1];
					j = strlen(s);
					for (i = 0; i < j; i++) if (s[i] == '/') s[i] = '_';
					memcpy(imfname, SMTP_F_PATH, sizeof(SMTP_F_PATH));
					i = sizeof(SMTP_F_PATH) - 1;
					memcpy(imfname + i, s, j+1);
					i += j;
					//sprintf(imfname + i, "_%d_%"PRIu64"_%d", (flowP->status & L3FLOWINVERT), flowP->findex, ftpFlowP->pktCnt);
					sprintf(imfname + i, "_%d_%"PRIu64, (int)(flowP->status & L3FLOWINVERT), flowP->findex);
					memcpy(s, imfname + sizeof(SMTP_F_PATH)-1, strlen(imfname)-sizeof(SMTP_F_PATH)+1);// check nameC length exceeded

					smtpFlowP->fd = file_manager_open(t2_file_manager, imfname, "w+b");
					if (!smtpFlowP->fd) {
						T2_PERR("smtpDecode", "Failed to open file '%s': %s", imfname, strerror(errno));
						smtpFlowP->stat |= SMTP_FERR;
						return;
					}
					smtpFlowP->seqInit = tcpSeq + 6;
					smtpFlowP->stat |= SMTP_DTP;
				}
#endif // SMTP_SAVE == 1
				break;
			case RSET:
				sC = 5;
				smtpFlowP->sendCode |= SMTP_RSET;
				smtpFlowP->stat &= ~(PWSTATE | SMTP_AUTP);
				break;
			case SEND:
				sC = 6;
				smtpFlowP->sendCode |= SMTP_SEND;
				break;
			case SOML:
				sC = 7;
				smtpFlowP->sendCode |= SMTP_SOML;
				break;
			case SAML:
				sC = 8;
				smtpFlowP->sendCode |= SMTP_SAML;
				break;
			case VRFY:
				sC = 9;
				smtpFlowP->sendCode |= SMTP_VRFY;
				break;
			case EXPN:
				sC = 10;
				smtpFlowP->sendCode |= SMTP_EXPN;
				break;
			case HELP:
				sC = 11;
				smtpFlowP->sendCode |= SMTP_HELP;
				break;
			case NOOP:
				sC = 12;
				smtpFlowP->sendCode |= SMTP_NOOP;
				break;
			case QUIT:
				sC = 13;
				smtpFlowP->sendCode |= SMTP_QUIT;
				smtpFlowP->stat &= ~(PWSTATE | SMTP_AUTP);
#if SMTP_SAVE == 1
				if (smtpFlowP->fd) {
					file_manager_close(t2_file_manager, smtpFlowP->fd);
					smtpFlowP->fd = NULL;
					smtpFlowP->stat &= ~SMTP_DTP;
					smtpFlowP->stat |= SMTP_PWF;
				}
#endif // SMTP_SAVE == 1
				break;
			case TURN:
				sC = 14;
				smtpFlowP->sendCode |= SMTP_TURN;
				break;
			case AUTH:
				sC = 15;
				smtpFlowP->sendCode |= SMTP_AUTH;
				smtpFlowP->stat |= SMTP_AUTP;
				break;
			default:
				return;
		}

		if (smtpFlowP->tCCnt >= MAXCNM) {
			smtpFlowP->stat |= SMTP_OVFL;
			return;
		}

		for (j = 0; j < smtpFlowP->tCCnt; j++) {
			//if (smtpFlowP->tCode[i] == *l7Hdr32) return;
			if (smtpFlowP->tCode[j] == sC) return;
		}
		//smtpFlowP->tCode[smtpFlowP->tCCnt++] = *l7Hdr32;
		smtpFlowP->tCode[smtpFlowP->tCCnt++] = sC;
	}
}


#if SMTP_SAVE == 1 || BLOCK_BUF == 0
void onFlowTerminate(unsigned long flowIndex) {
	smtp_flow_t *smtpFlowP = &smtp_flow[flowIndex];

#if SMTP_SAVE == 1
	if (smtpFlowP->fd) {
		file_manager_close(t2_file_manager, smtpFlowP->fd);
		smtpFlowP->fd = NULL;
	}
#endif // SMTP_SAVE == 1

#if BLOCK_BUF == 0
	outputBuffer_append(main_output_buffer, (char*) &smtpFlowP->stat, sizeof(uint8_t));

#if SMTP_BTFLD == 1
	outputBuffer_append(main_output_buffer, (char*) &smtpFlowP->sendCode, sizeof(uint16_t));
	//outputBuffer_append(main_output_buffer, (char*) &smtpFlowP->recCode, sizeof(uint32_t));
#endif // SMTP_BTFLD == 1

	uint_fast32_t i;
	uint32_t j = smtpFlowP->tCCnt;
	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		outputBuffer_append(main_output_buffer, (char*)&smtpCom[smtpFlowP->tCode[i]], 5);
	}

	j = smtpFlowP->rCCnt;
	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		outputBuffer_append(main_output_buffer, (char*)&smtpFlowP->recCode[i], sizeof(uint16_t));
	}

	j = smtpFlowP->nameUCnt;
	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		outputBuffer_append(main_output_buffer, smtpFlowP->nameU[i], strlen(smtpFlowP->nameU[i])+1);
	}

	j = smtpFlowP->namePCnt;
	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		outputBuffer_append(main_output_buffer, smtpFlowP->nameP[i], strlen(smtpFlowP->nameP[i])+1);
	}

	outputBuffer_append(main_output_buffer, (char*) &smtpFlowP->nameSCnt, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*) &smtpFlowP->nameTCnt, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*) &smtpFlowP->nameRCnt, sizeof(uint8_t));

	j = smtpFlowP->nameSCnt;
	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		outputBuffer_append(main_output_buffer, smtpFlowP->nameS[i], strlen(smtpFlowP->nameS[i])+1);
	}

	j = smtpFlowP->nameTCnt;
	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		outputBuffer_append(main_output_buffer, smtpFlowP->nameT[i], strlen(smtpFlowP->nameT[i])+1);
	}

	j = smtpFlowP->nameRCnt;
	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		outputBuffer_append(main_output_buffer, smtpFlowP->nameR[i], strlen(smtpFlowP->nameR[i])+1);
	}
#endif // BLOCK_BUF == 0
}
#endif // SMTP_SAVE == 1 || BLOCK_BUF == 0


void pluginReport(FILE *stream) {
	T2_FPLOG_NUMP(stream, "smtpDecode", "Number of SMTP packets", totsmtpPktCnt, numPackets);
}


void onApplicationTerminate() {
	free(smtp_flow);
}
