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

#include "ircDecode.h"
#include "fsutils.h"


// Global variables

ircFlow_t *ircFlows;


// Static variables

static uint64_t ircPktCnt;
static const char ircCom[48][8] = {
	"ADMIN"  , "AWAY"    , "CONNECT", "DIE"   , "ERROR"  , "INFO"    ,
	"INVITE" , "ISON"    , "JOIN"   , "KICK"  , "KILL"   , "LINKS"   ,
	"LIST"   , "LUSERS"  , "MODE"   , "MOTD"  , "NAMES"  , "NICK"    ,
	"NJOIN"  , "NOTICE"  , "OPER"   , "PART"  , "PASS"   , "PING"    ,
	"PONG"   , "PRIVMSG" , "QUIT"   , "REHASH", "RESTART", "SERVER"  ,
	"SERVICE", "SERVLIST", "SQUERY" , "SQUIRT", "SQUIT"  , "STATS"   ,
	"SUMMON" , "TIME"    , "TOPIC"  , "TRACE" , "USER"   , "USERHOST",
	"USERS"  , "VERSION" , "WALLOPS", "WHO"   , "WHOIS"  , "WHOWAS"
};


// Tranalyzer functions

T2_PLUGIN_INIT("ircDecode", "0.8.4", 0, 8);


void initialize() {
	if (UNLIKELY(!(ircFlows = calloc(mainHashMap->hashChainTableSize, sizeof(*ircFlows))))) {
		T2_PERR("ircDecode", "failed to allocate memory for ircFlows");
		exit(-1);
	}

#if IRC_SAVE == 1
	if (!rmrf(IRC_F_PATH)) {
		T2_PERR("ircDecode", "Failed to remove directory '%s': %s", IRC_F_PATH, strerror(errno));
 		exit(-1);
	}

	if (!mkpath(IRC_F_PATH, S_IRWXU) && errno != EEXIST) {
		T2_PERR("ircDecode", "Failed to create directory '%s': %s", IRC_F_PATH, strerror(errno));
 		exit(-1);
	}
#endif // IRC_SAVE == 1
}


binary_value_t* printHeader() {
	binary_value_t *bv = NULL;
	bv = bv_append_bv(bv, bv_new_bv("IRC status", "ircStat", 0, 1, bt_hex_8));
#if IRC_BITFIELD == 1
	bv = bv_append_bv(bv, bv_new_bv("IRC commands", "ircCBF", 0, 1, bt_hex_64));
//	bv = bv_append_bv(bv, bv_new_bv("IRC Response Bit Field", "ircRBF", 0, 1, bt_hex_32));
#endif // IRC_BITFIELD == 1
	bv = bv_append_bv(bv, bv_new_bv("IRC command codes", "ircCC", 1, 1, bt_string_class));
	bv = bv_append_bv(bv, bv_new_bv("IRC response codes", "ircRC", 1, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("IRC number of users", "ircUsrNum", 0, 1, bt_uint_8));
	bv = bv_append_bv(bv, bv_new_bv("IRC number of passwords", "ircPwNum", 0, 1, bt_uint_8));
	bv = bv_append_bv(bv, bv_new_bv("IRC number of parameters", "ircCNum", 0, 1, bt_uint_8));
	bv = bv_append_bv(bv, bv_new_bv("IRC users", "ircUsr", 1, 1, bt_string));
	bv = bv_append_bv(bv, bv_new_bv("IRC passwords", "ircPw", 1, 1, bt_string));
	bv = bv_append_bv(bv, bv_new_bv("IRC content", "ircC", 1, 1, bt_string));
	return bv;
}


void onFlowGenerated(packet_t* packet __attribute__((unused)), unsigned long flowIndex) {
	ircFlow_t * const ircFlowP = &ircFlows[flowIndex];
	memset(ircFlowP, '\0', sizeof(*ircFlowP));

	const flow_t * const flowP = &flows[flowIndex];

	if (flowP->layer4Protocol != L3_TCP) return;

	const uint_fast16_t srcPort = flowP->srcPort;
	const uint_fast16_t dstPort = flowP->dstPort;
	if ((dstPort >= IRC_PORTMI && dstPort <= IRC_PORTMX) ||
	    (srcPort >= IRC_PORTMI && srcPort <= IRC_PORTMX))
	{
		ircFlowP->stat = IRC_INIT;
	}
}



void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {
	ircFlow_t *ircFlowP = &ircFlows[flowIndex];
	if (ircFlowP->stat == 0x00) return;

#if IRC_SAVE == 1
	if (ircFlowP->stat & IRC_PPWF) return;
#endif // IRC_SAVE == 1

	uint64_t l7Hdr64;
 	uint32_t i, j;
	int32_t l7Len = packet->snapL7Length;
	char *l7Hdr = (char*)packet->layer7Header, *s;
	//char fname[IRC_MXNMLN+1];
	uint8_t sC = 0;

	ircPktCnt++;

	if (l7Len < 4) return;

	const flow_t * const flowP = &flows[flowIndex];
	//ircFlow_t *ircFlowPO;
	//if (flowP->oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) ircFlowPO = &ircFlows[flowP->oppositeFlowIndex];
	//else ircFlowPO = NULL;

	if (ircFlowP->stat & IRC_PPRNT) {
#if IRC_SAVE == 1
		const tcpHeader_t * const tcpHeader = (tcpHeader_t*)packet->layer4Header;
		//ircFlowP->seq = tcpSeq = ntohl(tcpHeader->seq); // absolute / relative tcp sequence number
		const uint32_t tcpSeq = ntohl(tcpHeader->seq); // absolute / relative tcp sequence number
		if (ircFlowP->fd == NULL) {
			char imfname[IRC_MXIMNM_LEN];
			s = ircFlowP->nameC[ircFlowP->nameCCnt-1];
			j = strlen(s);
			for (i = 0; i < j; i++) if (s[i] == '/') s[i] = '_';
			memcpy(imfname, IRC_F_PATH, sizeof(IRC_F_PATH));
			i = sizeof(IRC_F_PATH) - 1;
			memcpy(imfname + i, s, j+1);
			i += j;
			//sprintf(imfname + i, "_%d_%"PRIu64"_%d", (flowP->status & L3FLOWINVERT), flowP->findex, ircFlowP->pktCnt);
			sprintf(imfname + i, "_%"PRIu64"_%"PRIu64, (flowP->status & L3FLOWINVERT), flowP->findex);
			if (ircFlowP->stat & (IRC_APRNT | IRC_PPRNT)) {
				memcpy(s, imfname + sizeof(IRC_F_PATH)-1, strlen(imfname)-sizeof(IRC_F_PATH)+1);// check nameC length exceeded
			}

			ircFlowP->fd = fopen(imfname, "w+");
			if (ircFlowP->fd == NULL) {
				T2_PERR("ircDecode", "Failed to open file '%s': %s", imfname, strerror(errno));
				ircFlowP->stat |= IRC_PPWFERR;
				return;
			}
			if (ircFlowP->cLen) ircFlowP->dwLen = ircFlowP->cLen;
			else ircFlowP->dwLen = l7Len;
			ircFlowP->seqInit = tcpSeq;
		}

		if (ircFlowP->dwLen > 0) {
			i = tcpSeq - ircFlowP->seqInit;
			fseek(ircFlowP->fd, i, SEEK_SET);
			fwrite(l7Hdr, 1, l7Len , ircFlowP->fd);
			ircFlowP->dwLen -= l7Len;
		}

		if (ircFlowP->dwLen == 0) {
			fclose(ircFlowP->fd);
			ircFlowP->fd = NULL;
			ircFlowP->stat |= IRC_PPWF;
		}
#endif // IRC_SAVE == 1
		return;
	}

	l7Hdr64 = *(uint64_t*)l7Hdr;
	if (flowP->status & L3FLOWINVERT) {
		if (ircFlowP->rCCnt >= IRC_MAXCNM) {
			ircFlowP->stat |= IRC_OVFL;
			return;
		}
		i = l7Hdr64 & 0xffffffffffffff;
		j = atoi((char*)&i);
		for (i = 0; i < ircFlowP->rCCnt; i++) {
			if (ircFlowP->recCode[i] == j) goto storinfo;
		}
		ircFlowP->recCode[ircFlowP->rCCnt++] = j;
		//ircFlowP->recCode |= (1 << i);
storinfo:
		switch (j) {
			case 311:
			default:
				break;
		}
	} else {
		switch (l7Hdr64 & 0xffffffff) {
			case I_ADMIN :
				sC = 0;
				ircFlowP->sendCode |= IRC_ADMIN;
				break;
			case I_AWAY :
				sC = 1;
				ircFlowP->sendCode |= IRC_AWAY;
				break;
			case I_CONNECT :
				sC = 2;
				ircFlowP->sendCode |= IRC_CONNECT;
				break;
			case I_DIE:
				sC = 3;
				ircFlowP->sendCode |= IRC_DIE;
				break;
			case I_ERROR:
				sC = 4;
				ircFlowP->sendCode |= IRC_ERROR;
				break;
			case I_INFO:
				sC = 5;
				ircFlowP->sendCode |= IRC_INFO;
				break;
			case I_INVITE:
				sC = 6;
				ircFlowP->sendCode |= IRC_INVITE;
				break;
			case I_ISON:
				sC = 7;
				ircFlowP->sendCode |= IRC_ISON;
				break;
			case I_JOIN:
				sC = 8;
				ircFlowP->sendCode |= IRC_JOIN;
				break;
			case I_KICK:
				sC = 9;
				ircFlowP->sendCode |= IRC_KICK;
				break;
			case I_KILL:
				sC = 10;
				ircFlowP->sendCode |= IRC_KILL;
				break;
			case I_LINKS:
				sC = 11;
				ircFlowP->sendCode |= IRC_LINKS;
				break;
			case I_LIST:
				sC = 12;
				ircFlowP->sendCode |= IRC_LIST;
				break;
			case I_LUSERS:
				sC = 13;
				ircFlowP->sendCode |= IRC_LUSERS;
				break;
			case I_MODE:
				sC = 14;
				ircFlowP->sendCode |= IRC_MODE;
				break;
			case I_MOTD:
				sC = 15;
				ircFlowP->sendCode |= IRC_MOTD;
				break;
			case I_NAMES:
				sC = 16;
				ircFlowP->sendCode |= IRC_NAMES;
				break;
			case I_NICK:
				sC = 17;
				if (ircFlowP->nameUCnt >= IRC_MAXUNM) {
					ircFlowP->stat |= IRC_OVFL;
					break;
				}
				ircFlowP->sendCode |= IRC_NICK;
				if (l7Len <= 7) break;
				l7Hdr += 5;
				l7Len -= 5;
				if ((s = memchr(l7Hdr, '\r', l7Len)) != NULL) {
					i = s - l7Hdr;
					if (i > IRC_MXNMLN) i = IRC_MXNMLN;
					memcpy(ircFlowP->nameU[ircFlowP->nameUCnt++], l7Hdr, i);
				}
				break;
			case I_NJOIN:
				sC = 18;
				ircFlowP->sendCode |= IRC_NJOIN;
				break;
			case I_NOTICE:
				sC = 19;
				ircFlowP->sendCode |= IRC_NOTICE;
				break;
			case I_OPER:
				sC = 20;
				ircFlowP->sendCode |= IRC_OPER;
				break;
			case I_PART:
				sC = 21;
				ircFlowP->sendCode |= IRC_PART;
				break;
			case I_PASS:
				sC = 22;
				if (ircFlowP->namePCnt >= IRC_MAXPNM) {
					ircFlowP->stat |= IRC_OVFL;
					break;
				}
				ircFlowP->sendCode |= IRC_PASS;
				if (l7Len <= 7) break;
				l7Hdr += 5;
				l7Len -= 5;
				if ((s = memchr(l7Hdr, '\r', l7Len)) != NULL) {
					i = s - l7Hdr;
					if (i > IRC_MXNMLN) i = IRC_MXNMLN;
					memcpy(ircFlowP->nameP[ircFlowP->namePCnt++], l7Hdr, i);
				}
				break;
			case I_PING:
				sC = 23;
				ircFlowP->sendCode |= IRC_PING;
				break;
			case I_PONG:
				sC = 24;
				ircFlowP->sendCode |= IRC_PONG;
				break;
			case I_PRIVMSG:
				sC = 25;
				ircFlowP->sendCode |= IRC_PRIVMSG;
				break;
			case I_QUIT:
				sC = 26;
				ircFlowP->sendCode |= IRC_QUIT;
				break;
			case I_REHASH:
				sC = 27;
				ircFlowP->sendCode |= IRC_REHASH;
				break;
			case I_RESTART:
				sC = 28;
				ircFlowP->sendCode |= IRC_RESTART;
				break;
			case I_SERVER:
				sC = 29;
				ircFlowP->sendCode |= IRC_SERVER;
				break;
			case I_SERVICE:
				sC = 30;
				ircFlowP->sendCode |= IRC_SERVICE;
				break;
			case I_SERVLIST:
				sC = 31;
				ircFlowP->sendCode |= IRC_SERVLIST;
				break;
			case I_SQUERY:
				sC = 32;
				ircFlowP->sendCode |= IRC_SQUERY;
				break;
			case I_SQUIRT:
				sC = 33;
				ircFlowP->sendCode |= IRC_SQUIRT;
				break;
			case I_SQUIT:
				sC = 34;
				ircFlowP->sendCode |= IRC_SQUIT;
				break;
			case I_STATS:
				sC = 35;
				ircFlowP->sendCode |= IRC_STATS;
				break;
			case I_SUMMON:
				sC = 36;
				ircFlowP->sendCode |= IRC_SUMMON;
				break;
			case I_TIME:
				sC = 37;
				ircFlowP->sendCode |= IRC_TIME;
				break;
			case I_TOPIC:
				sC = 38;
				ircFlowP->sendCode |= IRC_TOPIC;
				break;
			case I_TRACE:
				sC = 39;
				ircFlowP->sendCode |= IRC_TRACE;
				break;
			case I_USER:
				sC = 40;
				if (ircFlowP->nameUCnt >= IRC_MAXUNM) {
					ircFlowP->stat |= IRC_OVFL;
					break;
				}
				ircFlowP->sendCode |= IRC_USER;
				if (l7Len <= 7) break;
				l7Hdr += 5;
				l7Len -= 5;
				if ((s = memchr(l7Hdr, '\r', l7Len)) != NULL) {
					i = s - l7Hdr;
					if (i > IRC_MXNMLN) i = IRC_MXNMLN;
					memcpy(ircFlowP->nameU[ircFlowP->nameUCnt++], l7Hdr, i);
				}
				break;
			case I_USERHOST:
				sC = 41;
				ircFlowP->sendCode |= IRC_USERHOST;
				break;
			case I_USERS:
				sC = 42;
				ircFlowP->sendCode |= IRC_USERS;
				break;
			case I_VERSION:
				sC = 43;
				ircFlowP->sendCode |= IRC_VERSION;
				break;
			case I_WALLOPS:
				sC = 44;
				ircFlowP->sendCode |= IRC_WALLOPS;
				break;
			case I_WHO:
				sC = 45;
				ircFlowP->sendCode |= IRC_WHO;
				break;
			case I_WHOIS:
				sC = 46;
				ircFlowP->sendCode |= IRC_WHOIS;
				break;
			case I_WHOWAS:
				sC = 47;
				ircFlowP->sendCode |= IRC_WHOWAS;
				break;
			default:
				return;
		}

		if (ircFlowP->tCCnt >= IRC_MAXCNM) {
			ircFlowP->stat |= IRC_OVFL;
			return;
		}

		for (j = 0; j < ircFlowP->tCCnt; j++) {
			if (ircFlowP->tCode[j] == sC) return;
		}

		ircFlowP->tCode[ircFlowP->tCCnt++] = sC;
	}
}


#if IRC_SAVE == 1 || BLOCK_BUF == 0
void onFlowTerminate(unsigned long flowIndex) {
	ircFlow_t *ircFlowP = &ircFlows[flowIndex];

#if IRC_SAVE == 1
	if (ircFlowP->fd) {
		fseek(ircFlowP->fd, 0, SEEK_END);
		fclose(ircFlowP->fd);
		ircFlowP->fd = NULL;
	}
#endif // IRC_SAVE == 1

#if BLOCK_BUF == 0
	const flow_t * const flowP = &flows[flowIndex];
	if (flowP->oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
		const ircFlow_t * const ircFlowPO = &ircFlows[flowP->oppositeFlowIndex];
		if (ircFlowPO->stat & IRC_PPRNT) ircFlowP->stat |= IRC_PPRNT;
	}

	outputBuffer_append(main_output_buffer, (char*) &ircFlowP->stat, sizeof(uint8_t));

#if IRC_BITFIELD == 1
	outputBuffer_append(main_output_buffer, (char*) &ircFlowP->sendCode, sizeof(uint64_t));
	//outputBuffer_append(main_output_buffer, (char*) &ircFlowP->recCode, sizeof(uint32_t));
#endif // IRC_BITFIELD == 1

	uint_fast32_t i;

	uint32_t cnt = ircFlowP->tCCnt;
	outputBuffer_append(main_output_buffer, (char*) &cnt, sizeof(uint32_t));
	for (i = 0; i < cnt; i++) {
		outputBuffer_append(main_output_buffer, ircCom[ircFlowP->tCode[i]], strlen(ircCom[ircFlowP->tCode[i]])+1);
	}

	cnt = ircFlowP->rCCnt;
	outputBuffer_append(main_output_buffer, (char*) &cnt, sizeof(uint32_t));
	for (i = 0; i < cnt; i++) {
		outputBuffer_append(main_output_buffer, (char*)&ircFlowP->recCode[i], sizeof(uint16_t));
	}

	outputBuffer_append(main_output_buffer, (char*) &ircFlowP->nameUCnt, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*) &ircFlowP->namePCnt, sizeof(uint8_t));
	outputBuffer_append(main_output_buffer, (char*) &ircFlowP->nameCCnt, sizeof(uint8_t));

	cnt = ircFlowP->nameUCnt;
	outputBuffer_append(main_output_buffer, (char*) &cnt, sizeof(uint32_t));
	for (i = 0; i < cnt; i++) {
		outputBuffer_append(main_output_buffer, ircFlowP->nameU[i], strlen(ircFlowP->nameU[i])+1);
	}

	cnt = ircFlowP->namePCnt;
	outputBuffer_append(main_output_buffer, (char*) &cnt, sizeof(uint32_t));
	for (i = 0; i < cnt; i++) {
		outputBuffer_append(main_output_buffer, ircFlowP->nameP[i], strlen(ircFlowP->nameP[i])+1);
	}


	cnt = ircFlowP->nameCCnt;
	outputBuffer_append(main_output_buffer, (char*) &cnt, sizeof(uint32_t));
	for (i = 0; i < cnt; i++) {
		outputBuffer_append(main_output_buffer, ircFlowP->nameC[i], strlen(ircFlowP->nameC[i])+1);
	}
#endif // BLOCK_BUF == 0
}
#endif // IRC_SAVE == 1 || BLOCK_BUF == 0


void pluginReport(FILE *stream) {
	T2_FPLOG_NUMP(stream, "ircDecode", "Number of IRC packets", ircPktCnt, numPackets);
}


void onApplicationTerminate() {
	free(ircFlows);
}
