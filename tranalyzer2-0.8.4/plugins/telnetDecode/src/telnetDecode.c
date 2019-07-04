/*
 * telnetDecode.c
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

#include "telnetDecode.h"


// plugin variables

telFlow_t *telFlows;


// Static variables
static uint64_t totTelPktCnt;

#if TEL_CMDS == 1
static const char *telCmdS[] = {
    "SE",   // 240 0xf0
    "NOP",  // 241
    "DM",   // 242
    "BRK",  // 243
    "IP",   // 244
    "AO",   // 245
    "AYT",  // 246
    "EC",   // 247
    "EL",   // 248
    "GA",   // 249
    "SB",   // 250
    "WILL", // 251
    "WONT", // 252
    "DO",   // 253
    "DONT", // 254
    "IAC",  // 255
};
#endif // TEL_CMDS == 1

#if TEL_OPTS == 1
static const char *telOpt[] = {
    "Bin Xmit",     // 0
    "Echo Data",    // 1
    "Reconn",
    "Suppr GA",
    "Msg Sz",
    "Opt Stat",
    "Timing Mark",
    "R/C XmtEcho",
    "Line Width",
    "Page Length",
    "CR Use",
    "Horiz Tabs",
    "Hor Tab Use",
    "FF Use",
    "Vert Tabs",
    "Ver Tab Use",
    "Lf Use",
    "Ext ASCII",
    "Logout",
    "Byte Macro",
    "Data Term",
    "SUPDUP",
    "SUPDUP Outp",
    "Send Locate",
    "Term Type",
    "End Record",
    "TACACS ID",
    "Output Mark",
    "Term Loc#",
    "3270 Regime",
    "X.3 PAD",
    "Window Size",
    "Term Speed",
    "Remote Flow",
    "Linemode",
    "X Disp loc",
    "Env",
    "Auth",
    "Encryp opt",
    "New Env",
    "TN3270E",
    "XAUTH",
    "CHARSET",
    "RSP",
    "Com Port ctl",
    "Supp Local Echo",
    "Start TLS",
    "KERMIT",
    "SEND",
    "FORWARD_X",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "PRAGMA LOGON",
    "SSPI LOGON",
    "PRAGMA HEARTBEAT",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "Extended", // 255
};
#endif // TEL_OPTS == 1


// Tranalyzer functions

T2_PLUGIN_INIT("telnetDecode", "0.8.4", 0, 8);


void initialize() {

#if TEL_SAVE == 1
	if (UNLIKELY(!rmrf(TEL_F_PATH))) {
		T2_PERR("telnetDecode", "Failed to remove directory '%s': %s", TEL_F_PATH, strerror(errno));
		exit(-1);
	}

	if (UNLIKELY(!mkpath(TEL_F_PATH, S_IRWXU))) {
		T2_PERR("telnetDeocde", "Failed to create directory '%s': %s", TEL_F_PATH, strerror(errno));
		exit(-1);
	}
#endif // TEL_SAVE == 1

	if (UNLIKELY(!(telFlows = calloc(mainHashMap->hashChainTableSize, sizeof(telFlow_t))))) {
		T2_PERR("telnetDecode", "Failed to allocate memory for telFlows");
		exit(-1);
	}
}


binary_value_t *printHeader() {
	binary_value_t *bv = NULL;
	bv = bv_append_bv(bv, bv_new_bv("Telnet status", "telStat", 0, 1, bt_hex_8));
	bv = bv_append_bv(bv, bv_new_bv("Telnet commands", "telCmdBF", 0, 1, bt_hex_16));
	bv = bv_append_bv(bv, bv_new_bv("Telnet options", "telOptBF", 0, 1, bt_hex_32));
	bv = bv_append_bv(bv, bv_new_bv("Telnet total command count", "telTCCnt", 0, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("Telnet total option count", "telTOCnt", 0, 1, bt_uint_16));

#if (TEL_CMDC == 1 || TEL_CMDS == 1)
	bv = bv_append_bv(bv, bv_new_bv("Telnet total Command Count", "telCCnt", 0, 1, bt_uint_16));
#endif // (TEL_CMDC == 1 || TEL_CMDS == 1)

#if TEL_CMDC == 1
	bv = bv_append_bv(bv, bv_new_bv("Telnet command codes ", "telCmdC", 1, 1, bt_hex_8));
#endif // TEL_CMDC == 1

#if TEL_CMDS == 1
	bv = bv_append_bv(bv, bv_new_bv("Telnet command string", "telCmdS", 1, 1, bt_string));
#endif // TEL_CMDS == 1

#if TEL_OPTS == 1
	bv = bv_append_bv(bv, bv_new_bv("Telnet total option count", "telOCnt", 0, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("Telnet option string", "telOptS", 1, 1, bt_string));
#endif // TEL_OPTS == 1

	return bv;
}


void onFlowGenerated(packet_t * packet, unsigned long flowIndex) {
	telFlow_t *telFlowP = &telFlows[flowIndex];
	memset(telFlowP, '\0', sizeof(*telFlowP));

	// check also whether a passive telnet connection matches a port 23 connection using hash
	if (packet->layer4Type == L3_TCP || packet->layer4Type == L3_SCTP) {
		const flow_t * const flowP = &flows[flowIndex];
		if (flowP->dstPort ==  TLNTPRT || flowP->srcPort == TLNTPRT) {
#if TEL_SAVE == 1
			if (flowP->oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
				telFlowP->fd = telFlows[flowP->oppositeFlowIndex].fd;
			} else {
				char imfname[TEL_MXIMN_LEN];
				sprintf(imfname, "%s%s_%d_%"PRIu64, TEL_F_PATH, TELFNAME, (int)(flowP->status & L3FLOWINVERT), flowP->findex);
				memcpy(telFlowP->nameF, imfname + sizeof(TEL_F_PATH)-1, strlen(imfname)-sizeof(TEL_F_PATH)+1);// check nameC length exceeded
				telFlowP->fd = file_manager_open(t2_file_manager, imfname, "w+b");
				if (UNLIKELY(!telFlowP->fd)) {
					T2_PERR("telnetDecode", "Failed to open file '%s': %s", imfname, strerror(errno));
					telFlowP->stat |= TEL_OFERR;
					return;
				}
			}

			const tcpHeader_t * const tcpHeader = (tcpHeader_t*)packet->layer4Header;
			uint32_t tcpSeq = 0;
			if (packet->layer4Type == L3_TCP) tcpSeq = ntohl(tcpHeader->seq); // absolute / relative tcp sequence number
			telFlowP->seqInit = tcpSeq;
#endif // TEL_SAVE == 1
			telFlowP->stat |= TEL_INIT;
		}
	}
}


void claimLayer4Information(packet_t * packet, unsigned long flowIndex) {
	telFlow_t *telFlowP = &telFlows[flowIndex];
	if (telFlowP->stat == 0x00) return;

	uint32_t i, j;
	const int32_t l7Len = packet->snapL7Length;
	uint8_t *l7Hdru = (uint8_t*)packet->layer7Header;

	totTelPktCnt++;

	if (l7Len < MINTELLEN) return;

	if (*l7Hdru == TELCMD) {
		while (*l7Hdru == TELCMD) {
			j = 0x0f & *(++l7Hdru);
#if (TEL_CMDC == 1 || TEL_CMDS == 1)
			if (telFlowP->cmdCnt < TELCMDN) {
#if TEL_CMD_AGGR == 1
				for (i = 0; i < telFlowP->cmdCnt; i++) if (telFlowP->cmdCode[i] == j) break;
				if (i == telFlowP->cmdCnt) {
#endif // TEL_CMD_AGGR == 1
					telFlowP->cmdCode[telFlowP->cmdCnt] = (uint8_t)j;
					telFlowP->cmdCnt++;
#if TEL_CMD_AGGR == 1
				}
#endif // TEL_CMD_AGGR == 1
			}
#endif // (TEL_CMDC == 1 || TEL_CMDS == 1)
			telFlowP->cmdrCnt++;

			telFlowP->cmdBF |= (1<<j);
			i = *(++l7Hdru);
			telFlowP->optBF |= (1<<i);
			switch (j) {
				case SE:
				case NOP:
				case DM:
				case BRK:
				case IP:
				case AO:
				case AYT:
				case EC:
				case EL:
				case GA:
				case SB:
					while (*l7Hdru != SE) l7Hdru++;
					break;
				case WILL:
				case WONT:
				case DO:
				case DONT:
#if TEL_OPTS == 1
					if (telFlowP->optCnt < TELOPTN) {
#if TEL_OPT_AGGR == 1
						for (i = 0; i < telFlowP->optCnt; i++) if (telFlowP->optCode[i] == *l7Hdru) break;
						if (i == telFlowP->optCnt) {
#endif // TEL_OPT_AGGR == 1
							telFlowP->optCode[telFlowP->optCnt] = *l7Hdru;
							telFlowP->optCnt++;
#if TEL_OPT_AGGR == 1
						}
#endif // TEL_OPT_AGGR == 1
					}
#endif // TEL_OPTS == 1
					telFlowP->optrCnt++;
					l7Hdru++;
					break;
				default:
					return;
			}
		}
		return;
#if TEL_SAVE == 1
	} else {
		if (!(telFlowP->stat & TEL_OFERR)) {
			FILE *fp = file_manager_fp(t2_file_manager, telFlowP->fd);
			const tcpHeader_t * const tcpHeader = (tcpHeader_t*)packet->layer4Header;
			if (packet->layer4Type == L3_TCP) {
				j = ntohl(tcpHeader->seq) - telFlowP->seqInit;
				fseek(fp, j, SEEK_SET);
			}
			fwrite(packet->layer7Header, 1, l7Len , fp);
		}
#endif // TEL_SAVE == 1
	}
}


void onFlowTerminate(unsigned long flowIndex) {
	telFlow_t *telFlowP = &telFlows[flowIndex];

#if TEL_CMDC == 1 || TEL_CMDS == 1 || TEL_OPTS == 1
	uint32_t i, cnt;
#endif // TEL_CMDC == 1 || TEL_CMDS == 1 || TEL_OPTS == 1

#if TEL_SAVE == 1
	if (telFlowP->fd) {
		file_manager_close(t2_file_manager, telFlowP->fd);
		telFlowP->fd = NULL;
	}
#endif // TEL_SAVE == 1

#if BLOCK_BUF == 0
	outputBuffer_append(main_output_buffer, (char*)&telFlowP->stat, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*)&telFlowP->cmdBF, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*)&telFlowP->optBF, sizeof(uint32_t));
	outputBuffer_append(main_output_buffer, (char*)&telFlowP->cmdrCnt, sizeof(uint16_t));
	outputBuffer_append(main_output_buffer, (char*)&telFlowP->optrCnt, sizeof(uint16_t));

#if (TEL_CMDC == 1 || TEL_CMDS == 1)
	cnt = telFlowP->cmdCnt;
	outputBuffer_append(main_output_buffer, (char*)&cnt, sizeof(uint16_t));
#endif // (TEL_CMDC == 1 || TEL_CMDS == 1)

#if TEL_CMDC == 1
	outputBuffer_append(main_output_buffer, (char*)&cnt, sizeof(uint32_t));
	uint8_t cmdCode;
	for (i = 0; i < cnt; i++) {
		cmdCode = telFlowP->cmdCode[i] | 0xf0; // cmdCode start at 0xf0
		outputBuffer_append(main_output_buffer, (char*)&cmdCode, sizeof(uint8_t));
	}
#endif // TEL_CMDC == 1

#if TEL_CMDS == 1
	outputBuffer_append(main_output_buffer, (char*)&cnt, sizeof(uint32_t));
	for (i = 0; i < cnt; i++) {
		outputBuffer_append(main_output_buffer, telCmdS[telFlowP->cmdCode[i]], strlen(telCmdS[telFlowP->cmdCode[i]])+1);
	}
#endif // TEL_CMDS == 1

#if TEL_OPTS == 1
	const uint16_t optCnt = telFlowP->optCnt;
	outputBuffer_append(main_output_buffer, (char*)&optCnt, sizeof(uint16_t));
	cnt = optCnt;
	outputBuffer_append(main_output_buffer, (char*)&cnt, sizeof(uint32_t));
	for (i = 0; i < cnt; i++) {
		outputBuffer_append(main_output_buffer, telOpt[telFlowP->optCode[i]], strlen(telOpt[telFlowP->optCode[i]])+1);
	}
#endif // TEL_OPTS == 1
#endif // BLOCK_BUF == 0
}


void pluginReport(FILE *stream) {
	T2_FPLOG_NUMP(stream, "telnetDecode", "Number of Telnet packets", totTelPktCnt, numPackets);
}


void onApplicationTerminate() {
	free(telFlows);
}
