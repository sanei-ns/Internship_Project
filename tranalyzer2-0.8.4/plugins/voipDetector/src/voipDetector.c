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

#include "voipDetector.h"
//#include <bsd/string.h>


// Global variables

voip_flow_t *voip_flow;


// Static variables

static uint64_t totVoipPktCnt;
static uint16_t voipStat;

#if VOIP_V_SAVE == 1
static int32_t voipFdCnt, voipFdCntMax;
//static char vname[VOIP_FNLNMX+1];
#endif // VOIP_V_SAVE == 1


// Tranalyzer functions

T2_PLUGIN_INIT("voipDetector", "0.8.4", 0, 8);


void initialize() {

	if (UNLIKELY(!(voip_flow = calloc(mainHashMap->hashChainTableSize, sizeof(voip_flow_t))))) {
		T2_PERR("voipDetector", "Failed to allocate memory for voip_flow");
		exit(-1);
	}

#if VOIP_V_SAVE == 1
#if VOIP_RM_DIR == 1
	if (!rmrf(VOIP_V_PATH)) {
		T2_PERR("voipDetector", "Failed to remove directory '%s': %s", VOIP_V_PATH, strerror(errno));
		exit(-1);
	}
#endif // VOIP_RM_DIR == 1
	if (!mkpath(VOIP_V_PATH, S_IRWXU)) {
		T2_PERR("voipDetector", "Failed to create directory '%s': %s", VOIP_V_PATH, strerror(errno));
		exit(-1);
	}
#endif // VOIP_V_SAVE == 1
}


binary_value_t* printHeader() {
	binary_value_t *bv = NULL;
	BV_APPEND_H16(bv, "voipStat" , "VoIP stat");
	BV_APPEND_H32(bv, "voipID"   , "VoIP RTP/RTCP ID");
	BV_APPEND_U8(bv,  "voipSRCnt", "VoIP RTP SID/RTCP record count");
	BV_APPEND_U8(bv,  "voipTyp"  , "VoIP RTP/RTCP Type");
	BV_APPEND_U32(bv, "voipPMCnt", "VoIP RTP packet miss count");
	BV_APPEND_FLT(bv, "voipPMr"  , "VoIP RTP Packet miss ratio");

	BV_APPEND_U8(bv,    "voipSIPStatCnt", "VoIP SIP stat count");
	BV_APPEND_U8(bv,    "voipSIPReqCnt" , "VoIP SIP request count");
	BV_APPEND_STR(bv,   "voipSIPCID"    , "VoIP SIP Call ID");
	BV_APPEND_U16_R(bv, "voipSIPStat"   , "VoIP SIP stat");
	BV_APPEND_STR_R(bv, "voipSIPReq"    , "VoIP SIP request");

	BV_APPEND_U32(bv, "voipTPCnt" , "VoIP RTCP cumulated transmitter packet count");
	BV_APPEND_U32(bv, "voipTBCnt" , "VoIP RTCP cumulated transmitter byte count");
	BV_APPEND_U32(bv, "voipCPMCnt", "VoIP RTCP cumulated packet miss count");
	BV_APPEND_U32(bv, "voipMaxIAT", "VoIP RTCP max Inter Arrival Time");
	return bv;
}



void onFlowGenerated(packet_t* packet, unsigned long flowIndex) {
	voip_flow_t * const voipFP = &voip_flow[flowIndex];
	memset(voipFP, '\0', sizeof(voip_flow_t));

	const flow_t * const flowP = &flows[flowIndex];
	const uint_fast16_t sport = flowP->srcPort;
	const uint_fast16_t dport = flowP->dstPort;

	if (packet->layer4Type != L3_UDP || sport < 1024 || dport < 1024) return;

	uint8_t *dP8 = (uint8_t*)packet->layer7Header;

	uint64_t snaplen = packet->snapL7Length;
	if (sport == 3483 || dport == 3483) {
		if (snaplen <= 12) return;
		snaplen -= 10;
		dP8 += 2;
		if (snaplen - 10 == ntohs(*(uint16_t*)dP8)) {
			voipFP->stat = STUN;
			return;
		} else if (snaplen != ntohs(*(uint16_t*)dP8)) return;

		dP8 += 10;
		snaplen -= 2;
		voipFP->stat = STUN;
	}

	if (memmem(dP8, snaplen, VSIP, 4)) {
		voipFP->stat |= SIP;
		uint8_t *cp;
		if ((cp = memmem(dP8, snaplen, "To:", 3))) cp += 3;
		else cp = dP8;

		if ((cp = (uint8_t*)memmem(cp, snaplen, "sip:", 4))) cp += 4;
		else return;

		const uint8_t * const cpe = dP8 + packet->snapL7Length;
		const uint8_t * const cpa = cp--;
		snaplen = 0;
		while (++cp <= cpe) {
			if (*cp < 63 && (snaplen = ((uint64_t)1 << *cp) & SCMASK)) break;
		}

		if (snaplen) {
			snaplen = MIN(cp - cpa, SIPNMMAX);
			memcpy(voipFP->sipCID, cpa, snaplen);
			voipFP->sipCID[snaplen] = '\0';
		}

		return;
	}

	if (snaplen <= 12) return;

	const voip_rtcpH_t * const voipRtcpHP = (voip_rtcpH_t*)packet->layer7Header;
	if ((voipRtcpHP->vpr & RTPVERMASK) != RTPVER) return; // version 2 only

	voipFP->typ = voipRtcpHP->typ;
	if (voipFP->typ > 191) {
		if (voipFP->typ < 196 || (voipFP->typ > 199 && voipFP->typ < 210)) {
			voipFP->stat |= RTCP;
			voipFP->ssN = voipRtcpHP->ssrc;
			voipFP->rCnt = voipRtcpHP->vpr & 0x1f;
		}
	} else {
		voipFP->stat |= (RTP | (voipFP->typ & 0x80) | (voipRtcpHP->vpr & 0x10));
		voipFP->ssN = voipRtcpHP->id;
		voipFP->rtpSeqN = ntohs(voipRtcpHP->len) - 1;
		voipFP->rCnt = voipRtcpHP->vpr & 0x0f;
		voipFP->typ &= 0x7f;
	}
}


void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {
	voip_flow_t * const voipFP = &voip_flow[flowIndex];
	if (!voipFP->stat) return;

	uint64_t i;
	uint8_t *cp;
	uint8_t *dP8 = (uint8_t*)packet->layer7Header;
	voip_rtcpH_t *voipRtcpHP = (voip_rtcpH_t*)dP8;
	const uint16_t l7Len = packet->snapL7Length;

	if (voipFP->stat & STUN) {
		i = l7Len - 4;
		if (i <= 2 || i != ntohs(*(uint16_t*)(dP8+2))) return;
		dP8 += 4;

		if (voipFP->stat & SIP) goto procn;
		if (memmem(dP8, i, VSIP, 4)) {
			voipFP->stat |= SIP;
			if ((cp = memmem(dP8, i, "To:", 3))) cp += 3;
			else cp = dP8;

			if ((cp = (uint8_t*)memmem(cp, i, "sip:", 4))) cp += 4;
			else return;

			const uint8_t * const cpe = dP8 + l7Len;
			const uint8_t * const cpa = cp--;
			i = 0;
			while (++cp <= cpe) {
				if (*cp < 63 && (i = ((uint64_t)1 << *cp) & SCMASK)) break;
			}

			if (i) {
				i = MIN(cp - cpa, SIPNMMAX);
				memcpy(voipFP->sipCID, cpa, i);
				voipFP->sipCID[i] = '\0';
			}

			return;
		}

		if ((voipRtcpHP->vpr & RTPVERMASK) != RTPVER) {
			return; // version 2 only
		}

		if (voipFP->stat & RTPTCP) goto procn;
		voipFP->typ = voipRtcpHP->typ;
		if (voipFP->typ > 191) {
			if (voipFP->typ < 196 || (voipFP->typ > 199 && voipFP->typ < 210)) {
				voipFP->stat |= RTCP;
				voipFP->ssN = voipRtcpHP->ssrc;
				voipFP->rCnt = voipRtcpHP->vpr & 0x1f;
			}
		} else {
			voipFP->stat |= (RTP | (voipFP->typ & 0x80) | (voipRtcpHP->vpr & 0x10));
			voipFP->ssN = voipRtcpHP->id;
			voipFP->rtpSeqN = ntohs(voipRtcpHP->len) - 1;
			voipFP->rCnt = voipRtcpHP->vpr & 0x0f;
			voipFP->typ &= 0x7f;
		}
	}

	uint16_t *dP16;

procn:	dP16 = (uint16_t*)dP8;
	voipRtcpHP = (voip_rtcpH_t*)dP8;

	totVoipPktCnt++;
	if (voipFP->stat & SIP) {
		if (!memcmp(dP8, VSIP, 4)) {
			if ((cp = memchr(dP8 + 4, ' ', 4)) && voipFP->sipStatCnt < SIPSTATMAX) {
				voipFP->sipStat[voipFP->sipStatCnt++] = atoi((const char*)++cp);
			}
		} else if (voipFP->sipRqCnt < SIPSTATMAX) {
			if (*dP8 >= 65 && *dP8 <= 90) {
				memcpy(voipFP->sipRq[voipFP->sipRqCnt++], dP8, SIPCLMAX);
			}
		}

		return;
	}

	if ((dP8[0] & RTPVERMASK) != RTPVER) { // version 2
		voipFP->stat = 0x0;
		return;
	}

	voipFP->pktCnt++;

	if (voipFP->stat & RTP) {
		i = ntohs(dP16[1]) - voipFP->rtpSeqN - 1;

		if (!i) {
			voipFP->rtpScnt++;
		} else if (voipFP->rtpScnt < VOIPMINRPKTD) {
			voipFP->stat = 0x00;
			return;
		}

		voipFP->rtpSeqN = ntohs(dP16[1]);
		voipFP->stat |= (voipRtcpHP->vpr & (RTP_X | RTP_P));
		voipFP->stat |= (voipRtcpHP->typ & RTP_M);

#if VOIP_V_SAVE == 1
		if (voipFP->rtpScnt >= VOIPMINRPKTD) {
			FILE *fp;
			int len = l7Len;
			if (voipFP->fd == NULL) {
				const char *a;
				if (voipFP->typ < 35) a = voipRTPFEL[voipFP->typ];
				else if (voipFP->typ > 110) a = voipRTPFEH[voipFP->typ-111];
				else a = voipRTPFEL[35];
				const flow_t * const flowP = &flows[flowIndex];
				snprintf(voipFP->vname, VOIP_FNLNMX, "%s%s_%08"B2T_PRIX32"_%"PRIu64"_%1x_%s.raw", VOIP_V_PATH, VOIP_FNAME, ntohl(voipFP->ssN), flowP->findex, (int)(flowP->status & L3FLOWINVERT), a);

				voipFP->fd = file_manager_open(t2_file_manager, voipFP->vname, "w+b");
				if (!voipFP->fd) {
					T2_PERR("voipDetector", "failed to open file '%s' (%d) for writing: %s", voipFP->vname, voipFdCnt, strerror(errno));
					return;
				}

				if (++voipFdCnt > voipFdCntMax) voipFdCntMax = voipFdCnt;
				voipFP->stat |= WROP;

			}
			if (voipFP->stat & RTP_X) { // extended header
				dP16 += RTPDOFF/2 + 3; // get extended header length
				dP8 += (*dP16 * 4); // add extended header length to data pointer
			}
			if ((i = (voipRtcpHP->vpr & RTP_CC))) dP8 += i * 4; // skip ssrc info

			len -= ((dP8 - packet->layer7Header) + RTPDOFF + VOIP_PLDOFF);
			if (len > 0) {
				fp = file_manager_fp(t2_file_manager, voipFP->fd);
				fwrite(dP8+RTPDOFF+VOIP_PLDOFF, (size_t)len, 1, fp);
			}
		}
#endif // VOIP_V_SAVE == 1

		return;
	}

	if (voipFP->stat == RTCP) {

		if (voipFP->ssN != voipRtcpHP->ssrc) {
			if (voipFP->pktCnt < VOIPMINRPKTD + 1) {
				voipFP->stat = 0x00;
				return;
			}
		}
#if VOIP_ANALEN == 1
		const uint_fast32_t dLen = packet->packetL7Length/4;
		i = ntohs(voipRtcpHP->len) + 1;
		while (i < dLen) {
			i += ntohs(*(dP16 + i*2 + 1)) + 1;
		}

		if (i > dLen) {
			voipFP->stat = 0x00;
			return;
		}
#endif // VOIP_ANALEN == 1

		voipFP->ssN = voipRtcpHP->ssrc;
		i = voipRtcpHP->typ;

		if (i == 200) {
			voip_rtcp200_t *vr200P = (voip_rtcp200_t*)(&voipRtcpHP->id);
			voipFP->tPktCnt = ntohl(vr200P->tPktCnt);
			voipFP->tbytCnt = ntohl(vr200P->tbytCnt);
		} else if (i == 201) {
			voip_rtcp201_t *vr201P = (voip_rtcp201_t*)(&voipRtcpHP->id);
			voipFP->cumNpcktLst = ntohl(vr201P->cumNpcktLst);
			if (ntohl(vr201P->iatJit) > voipFP->iatJit) {
				voipFP->iatJit = ntohl(vr201P->iatJit);
			}
		}
	}
}


void onFlowTerminate(unsigned long flowIndex) {

	voip_flow_t *voipFP = &voip_flow[flowIndex];

#if VOIP_V_SAVE == 1
	if (voipFP->fd) {
		file_manager_close(t2_file_manager, voipFP->fd);
		voipFP->fd = NULL;
		voipFdCnt--;
		if (!(voipFP->stat & WROP)) remove(voipFP->vname);
	}
#endif // VOIP_V_SAVE == 1

	uint32_t i = 0;
	float f = 0.0;

	if (!(voipFP->stat & RTPTCP)) {
		voipFP->typ = voipFP->rCnt = 0;
		voipFP->tPktCnt = voipFP->tbytCnt = 0;
		voipFP->cumNpcktLst = voipFP->iatJit = 0;
	} else {
		if (voipFP->pktCnt < VOIPMINRPKTD) {
			memset(voipFP, 0x0, sizeof(voip_flow_t));
		}
		if (voipFP->stat & RTP) {
			i = voipFP->pktCnt - voipFP->rtpScnt;
			f = (float)i / voipFP->pktCnt;
			if (voipFP->pktCnt > voipFP->rtpScnt) voipFP->stat |= PKTLSS;
		}
	}

	if (voipFP->stat) {
		voipStat |= voipFP->stat;
		globalWarn |= L7_SIPRTP;
	}

	OUTBUF_APPEND_U16(main_output_buffer, voipFP->stat);

	uint32_t j = ntohl(voipFP->ssN);
	OUTBUF_APPEND_U32(main_output_buffer, j);
	OUTBUF_APPEND_U8(main_output_buffer, voipFP->rCnt);
	OUTBUF_APPEND_U8(main_output_buffer, voipFP->typ);

	OUTBUF_APPEND_U32(main_output_buffer, i);
	OUTBUF_APPEND_FLT(main_output_buffer, f);
	OUTBUF_APPEND_U8(main_output_buffer, voipFP->sipStatCnt);
	OUTBUF_APPEND_U8(main_output_buffer, voipFP->sipRqCnt);

	OUTBUF_APPEND_STR(main_output_buffer, (char*)voipFP->sipCID);

	j = voipFP->sipStatCnt;
	OUTBUF_APPEND_NUMREP(main_output_buffer, j);
	for (i = 0; i < j; i++) {
		OUTBUF_APPEND_U16(main_output_buffer, voipFP->sipStat[i]);
	}

	j = voipFP->sipRqCnt;
	OUTBUF_APPEND_NUMREP(main_output_buffer, j);
	for (i = 0; i < j; i++) {
		OUTBUF_APPEND_STR(main_output_buffer, (char*)voipFP->sipRq[i]);
	}

	OUTBUF_APPEND_U32(main_output_buffer, voipFP->tPktCnt);
	OUTBUF_APPEND_U32(main_output_buffer, voipFP->tbytCnt);
	OUTBUF_APPEND_U32(main_output_buffer, voipFP->cumNpcktLst);
	OUTBUF_APPEND_U32(main_output_buffer, voipFP->iatJit);
}


void pluginReport(FILE *stream) {
	if (voipStat) {
		T2_FPLOG(stream, "voipDetector", "Aggregated status: 0x%04"B2T_PRIX16, voipStat);
#if VOIP_V_SAVE == 1
		T2_FPLOG_NUM(stream, "voipDetector", "max fd count: ", voipFdCntMax);
#endif // VOIP_V_SAVE == 1
		T2_FPLOG_NUMP(stream, "voipDetector", "Number of SIP/RTP packets", totVoipPktCnt, numPackets);
	}
}


void onApplicationTerminate() {
	free(voip_flow);
}
