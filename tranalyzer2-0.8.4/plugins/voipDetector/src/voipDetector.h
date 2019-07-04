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

#ifndef VOIP_DETECTOR_H_
#define VOIP_DETECTOR_H_

// global includes
#include "global.h"
#include "fsutils.h"
//#include <zlib.h>

// user configs

#define VOIP_ANALEN  0 // chk report len against snap payload len
#define VOIP_RM_DIR  0 // rm dir
#define VOIP_V_SAVE  0 // save RTP content, requires PACKETLENGTH == 3
#define VOIP_PLDOFF  0 // if (VOIP_V_SAVE) offset for payload to be saved

#define SIPNMMAX    40 // maximal SIP caller name length

//#define VOIP_PATH "/tmp/"            // root path
#define VOIP_V_PATH "/tmp/TranVoIP/" // Path for raw voip
#define VOIP_FNAME  "eier"           // default content file name prefix

// plugin constants
#define VOIP_FNLNMX sizeof(VOIP_V_PATH) + sizeof(VOIP_FNAME) + 8 + 16 + 1 + 7

#define VSIP "SIP/"
#define RTPVER     0x80 // RTP version 2
#define RTPVERMASK 0xc0 // 2 upper bits for the version
#define RTPDOFF sizeof(voip_rtpH_t)
#define SIPSTATMAX   6
#define SIPCLMAX     3
#define VOIPMINRPKTD 2 // min number of rtp/rtcp packets for decision

#define SCMASK ((uint64_t)1 << '>' | (uint64_t)1 << ' ' | (uint64_t)1 << '\r' | (uint64_t)1 << ';' | (uint64_t)1 << ':')

// voip stat
#define RTP     0x0001
#define RTCP    0x0002
#define SIP     0x0004
#define STUN    0x0008

#define RTP_X   0x0010
#define RTP_P   0x0020
#define RTP_M   0x0080

#define WROP    0x0100

#define PKTLSS  0x1000
#define RTPNFRM 0x2000


#define RTPTCP (RTP | RTCP)
#define RTP_CC 0x0f

// protocol defs

const char * const voip_ioi[] = {
	"User-Agent: ",
	"Server: ",
	"username=",
	"Call-ID",
	"Contact:",
	"Register",
	"Via: ",
	"codec",
	"Authorization: ",
	"INVITE",
	"BYE",
	"ACK",
	"CANCEL",
	"OPTIONS",
	"REFER",
	"NOTIFY",
	"MESSAGE",
	"INFO",
	"PRACK",
	"UPDATE",
	"=audio",
	"=rtpmap"
};

// this is embedded into SIP so if SIP found -> check for SDP
// see RFC 4317, RFC 4566
const char * const voip_sdp[] = {
	"v=", // Proto-Version
	"o=", // Session ID
	"s=", // Session name
	"i=", // Session Info
	"u=", // URI
	"e=", // email-adr
	"p=", // phone no
	"c=", // connection info
	"b=", // bandwith info
	"z=", // Timezone info
	"k=", // enkrytion key
	"a=", // session attribute
	"t=", // time
	"r=", // call repetition
	"m=", // media type and formats
	"i="  // titel
};

// this is RTP payload type (PT) from 96-127 the assignement is dynamic
// see RFC 3550
const char * const voip_rtp[] = {
	"G711U",   // 0
	"1016",    // 1
	"G721",    // 2
	"GSM6.10", // 3
	"G723",    // 4
	"DVI4",    // 5
	"DVI4",    // 6
	"LPC",     // 7
	"G711A",   // 8
	"G722",    // 9
	"L16",     // 10
	"L16",     // 11
	"QCELP",   // 12
	"CN",      // 13
	"MPA",     // 14
	"G728",    // 15
	"DVI4",    // 16
	"DVI4",    // 17
	"G729",    // 18
	"CelB",    // 19
	"JPEG",    // 20
	"nv",      // 21
	"H261",    // 22
	"MPV",     // 23
	"MP2T",    // 24
	"H263",    // 25
	"JPEG",    // 26
	"una",     // 27
	"nv",      // 28
	"una",     // 29
	"una",     // 30
	"H261",    // 31
	"MPV",     // 32
	"MP2T",    // 33
	"H263",    // 34
	"una"      // 35
};

struct {
	uint16_t status;
	char interpretation[40];
} sip_status_codes[] = {
	{100, "Trying"},
	{180, "Ringing"},
	{181, "Call Is Being Forwarded"},
	{182, "Queued"},
	{183, "Session Progress"},
	{200, "OK"},
	{202, "Accepted"},
	{204, "No Notification"},
	{300, "Multiple Choices"},
	{301, "Moved Permanently"},
	{302, "Moved Temporarily"},
	{305, "Use Proxy"},
	{380, "Alternative Service"},
	{400, "Bad Request"},
	{401, "Unauthorized"},
	{402, "Payment Required"},
	{403, "Forbidden"},
	{404, "Not Found"},
	{405, "Method Not Allowed"},
	{406, "Not Acceptable"},
	{407, "Proxy Authentication Required"},
	{408, "Request Timeout"},
	{410, "Gone"},
	{412, "Conditional Request Failed"},
	{413, "Request Entity Too Large"},
	{414, "Request URI Too Long"},
	{415, "Unsupported Media Type"},
	{416, "Unsupported URI Scheme"},
	{417, "Unknown Resource-Priority"},
	{420, "Bad Extension"},
	{421, "Extension Required"},
	{422, "Session Interval Too Small"},
	{423, "Interval Too Brief"},
	{428, "Use Identity Header"},
	{429, "Provide Referrer Identity"},
	{430, "Flow Failed"},
	{433, "Anonymity Disallowed"},
	{436, "Bad Identity-Info"},
	{437, "Unsupported Certificate"},
	{438, "Invalid Identity Header"},
	{439, "First Hop Lacks Outbound Support"},
	{440, "Max-Breadth Exceeded"},
	{469, "Bad Info Package"},
	{470, "Consent Needed"},
	{480, "Temporarily Unavailable"},
	{481, "Call/Transaction Does Not Exist"},
	{482, "Loop Detected"},
	{483, "Too Many Hops"},
	{484, "Address Incomplete"},
	{485, "Ambiguous"},
	{486, "Busy Here"},
	{487, "Request Terminated"},
	{488, "Not Acceptable Here"},
	{489, "Bad Event"},
	{491, "Request Pending"},
	{493, "Undecipherable"},
	{494, "Security Agreement Required"},
	{500, "Server Internal Error"},
	{501, "Not Implemented"},
	{502, "Bad Gateway"},
	{503, "Service Unavailable"},
	{504, "Server Time-out"},
	{505, "Version Not Supported"},
	{513, "Message Too Large"},
	{580, "Precondition Failure"},
	{600, "Busy Everywhere"},
	{603, "Declined"},
	{604, "Does Not Exist Anywhere"},
	{606, "Not Acceptable"}
};

const char * const voipRTPFEL[] = {
	"G711u", // 0
	"1016",  // 1
	"G721",  // 2
	"GSM",   // 3
	"G723",  // 4
	"DVI4",  // 5
	"DVI4",  // 6
	"LPC",   // 7
	"G711a", // 8
	"G722",  // 9
	"L16",   // 10
	"L16",   // 11
	"QCELP", // 12
	"CN",    // 13
	"MPA",   // 14
	"G728",  // 15
	"DVI4",  // 16
	"DVI4",  // 17
	"G729",  // 18
	"CelB",  // 19
	"JPEG",  // 20
	"nv",    // 21
	"H261",  // 22
	"MPV",   // 23
	"MP2T",  // 24
	"H263",  // 25
	"JPEG",  // 26
	"una",   // 27
	"nv",    // 28
	"una",   // 29
	"una",   // 30
	"H261",  // 31
	"MPV",   // 32
	"MP2T",  // 33
	"H263",  // 34
	"nil"    // 35
};

const char * const voipRTPFEH[] = {
	"Siren",  // 111
	"G722.1", // 112
	"una",    // 113
	"RTAud",  // 114
	"RTAud",  // 115
	"G726",   // 116
	"G722",   // 117
	"CN",     // 118
	"PCMA",   // 119
	"una",    // 120
	"RTVid",  // 121
	"H264",   // 122
	"H264",   // 123
	"una",    // 124
	"una",    // 125
	"una",    // 126
	"xdata"   // 127
};

// plugin structs

typedef struct {
	uint8_t vpr;
	uint8_t typ;
	uint16_t len;
	uint32_t ssrc;
	uint32_t id;
} __attribute__((packed)) voip_rtcpH_t;

typedef struct {
	uint8_t vpec;
	uint8_t typ;
	uint16_t seq;
	uint32_t tS;
	uint32_t ssi;
} __attribute__((packed)) voip_rtpH_t;

typedef struct {
	uint64_t ntpTime;
	uint32_t rtpTime;
	uint32_t tPktCnt;
	uint32_t tbytCnt;
} __attribute__((packed)) voip_rtcp200_t;

typedef struct {
	uint32_t ssrcnS;
	uint32_t fracLst:8;
	uint32_t cumNpcktLst:24;
	uint16_t seqNCyclCnt;
	uint16_t hSeqNrec;
	uint32_t iatJit;
	uint32_t lsrTime;
	uint32_t dlsrTime;
} __attribute__((packed)) voip_rtcp201_t;

typedef struct {
#if VOIP_V_SAVE == 1
	file_object_t *fd;   // file descriptor per flow
#endif
	uint32_t ssN;
	uint32_t pktCnt;
	uint32_t tPktCnt;
	uint32_t tbytCnt;
	uint32_t iatJit;
	uint32_t cumNpcktLst;
	uint32_t rtpScnt;
	uint16_t rtpSeqN;
	uint16_t sipStat[SIPSTATMAX];
	uint16_t stat;
	uint8_t sipRq[SIPSTATMAX][SIPCLMAX+1];
	uint8_t sipCID[SIPNMMAX+1];
#if VOIP_V_SAVE == 1
	char vname[VOIP_FNLNMX+1];
#endif
	uint8_t sipStatCnt;
	uint8_t sipRqCnt;
	uint8_t typ;
	uint8_t rCnt;
} voip_flow_t;

extern voip_flow_t *voip_flow;

#endif // VOIP_DETECTOR_H_
