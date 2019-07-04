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

// local includes

#include "httpSniffer.h"
#include "memdebug.h"


// Append a repetitive string to the output buffer.
// Every repetition is freed once appended to the buffer.
#define HTTP_APPEND_REP_STR(field, count) \
	j = MIN(count, HTTP_DATA_C_MAX); \
	outputBuffer_append(main_output_buffer, (char*)&j, sizeof(uint32_t)); \
	for (i = 0; i < j; i++) { \
		outputBuffer_append(main_output_buffer, field[i], strlen(field[i])+1); \
		free(field[i]); \
	}

// Build a filename with flow/packet information
#define HTTP_BUILD_FILENAME(dest, str, count) { \
	if (!*str) { \
		dest = malloc(HTTP_NONAME_LEN + 1); \
		snprintf(dest, HTTP_NONAME_LEN, "%s_%"PRIu32"_%"PRIu64"_%"PRIu32"_%"PRIu16, HTTP_NONAME, dir, findex, httpFlowP->pktcnt, (count)); \
	} else { \
		const size_t len = strlen(str); \
		const size_t namelen = len + HTTP_CNT_LEN + HTTP_FINDEX_LEN; \
		dest = malloc(namelen + 1); \
		snprintf(dest, namelen, "%s_%"PRIu32"_%"PRIu64"_%"PRIu32"_%"PRIu16, str, dir, findex, httpFlowP->pktcnt, (count)); \
		/* replace all '/' with '_' */ \
		for (uint_fast32_t i = 0; i <= len; i++) { \
			if (dest[i] == '/' || dest[i] == '?') dest[i] = '_'; \
		} \
	} \
}

// Build a filepath from a directory and filename
#define HTTP_BUILD_FILEPATH(dest, dir, fname) \
	strncpy(dest, dir, HTTP_MXIMNM_LEN); \
	strncpy(dest + sizeof(dir) - 1, fname, HTTP_MXIMNM_LEN - sizeof(dir) + 1);


// Static variables

static http_flow_t *http_flow;
static uint64_t totalHttpPktCnt, totalHttpPktCnt0;
static uint64_t httpGetCnt, httpPstCnt;
static uint16_t sflgs, aflgs, cflgs, mflgs;
static uint32_t imageCnt, videoCnt, audioCnt, textCnt, msgCnt, applCnt, unkCnt;

#if HTTP_SAVE == 1
static int32_t http_fd_cnt, http_fd_max;

static const char *http_dirs[] = {
#if HTTP_SAVE_APPL == 1
	HTTP_APPL_PATH,
#endif // HTTP_SAVE_APPL == 1
#if HTTP_SAVE_AUDIO == 1
	HTTP_AUDIO_PATH,
#endif // HTTP_SAVE_AUDIO == 1
#if HTTP_SAVE_IMAGE == 1
	HTTP_IMAGE_PATH,
#endif // HTTP_SAVE_IMAGE == 1
#if HTTP_SAVE_MSG == 1
	HTTP_MSG_PATH,
#endif // HTTP_SAVE_MSG == 1
#if HTTP_SAVE_PUNK == 1
	HTTP_PUNK_PATH,
#endif // HTTP_SAVE_PUNK == 1
#if HTTP_SAVE_TEXT == 1
	HTTP_TEXT_PATH,
#endif // HTTP_SAVE_TEXT == 1
#if HTTP_SAVE_VIDEO == 1
	HTTP_VIDEO_PATH,
#endif // HTTP_SAVE_VIDEO == 1
	NULL
};
#endif // HTTP_SAVE == 1

typedef struct {
	const char    *name;
	const size_t   len;
	const uint8_t  hex;
} http_method_t;

static const http_method_t http_methods[] = {
	{ SGET    , sizeof(SGET)    , GET     },
	{ SPOST   , sizeof(SPOST)   , POST    },
	{ SOPTIONS, sizeof(SOPTIONS), OPTIONS },
	{ SDELETE , sizeof(SDELETE) , DELETE  },
	{ SPUT    , sizeof(SPUT)    , PUT     },
	{ SHEAD   , sizeof(SHEAD)   , HEAD    },
	{ SCONNECT, sizeof(SCONNECT), CONNECT },
	{ STRACE  , sizeof(STRACE)  , TRACE   },
	{ /* NULL */ }
};


// local function prototype declarations

/* Return size of http-header line
 * Arguments:
 *  - data         : the packet data
 *  - http_data_len: length of packet (data-field)
 */
static char* http_get_linesize(char *data, int32_t http_data_len);

/* Analyze http method
 * Arguments:
 *  - data     : the packet data
 *  - retmethod: the found method
 */
static http_mimetype http_read_mimetype(const char *data, size_t n);

/* Read header-field
 * Arguments:
 *  - data   : the packet data
 *  - header : the lookup-header field
 *  - retdata: return data of the specified header field in header
 */
static char* http_read_header_data(char* data, uint16_t data_len, const char *header, uint16_t header_len);


// Tranalyzer plugin functions

T2_PLUGIN_INIT("httpSniffer", "0.8.4", 0, 8);


void initialize() {
#if HTTP_SAVE == 1
	for (uint_fast8_t i = 0; http_dirs[i]; i++) {
#if HTTP_RM_PICDIR == 1
		if (UNLIKELY(!rmrf(http_dirs[i]))) {
			T2_PERR("httpSniffer", "Failed to remove directory '%s': %s", http_dirs[i], strerror(errno));
			exit(-1);
		}
#endif // HTTP_RM_PICDIR == 1
		if (UNLIKELY(!mkpath(http_dirs[i], S_IRWXU))) {
			T2_PERR("httpSniffer", "Failed to create directory '%s': %s", http_dirs[i], strerror(errno));
			exit(-1);
		}
	}
#endif // HTTP_SAVE == 1

	if (UNLIKELY(!(http_flow = calloc(mainHashMap->hashChainTableSize, sizeof(*http_flow))))) {
		T2_PERR("httpSniffer", "Failed to allocate memory for http_flow");
		exit(-1);
	}
}


binary_value_t *printHeader() {
	binary_value_t *bv = NULL;

	bv = bv_append_bv(bv, bv_new_bv("HTTP status", "httpStat", 0, 1, bt_hex_16));
	bv = bv_append_bv(bv, bv_new_bv("HTTP anomaly flags", "httpAFlags", 0, 1, bt_hex_16));
	bv = bv_append_bv(bv, bv_new_bv("HTTP methods in flow", "httpMethods", 0, 1, bt_hex_8));
	bv = bv_append_bv(bv, bv_new_bv("HTTP HEADMIME-TYPES in flow", "httpHeadMimes", 0, 1, bt_hex_16));
#if HTTP_BODY == 1
	bv = bv_append_bv(bv, bv_new_bv("HTTP content info in flow", "httpCFlags", 0, 1, bt_hex_16));
#endif // HTTP_BODY == 1
#if HTTP_MCNT == 1
	bv = bv_append_bv(bv, bv_new_bv("HTTP number of GET and POST requests", "httpGet_Post", 0, 2, bt_uint_16, bt_uint_16));
#endif // HTTP_MCNT == 1
#if HTTP_STAT == 1
	bv = bv_append_bv(bv, bv_new_bv("HTTP response status count", "httpRSCnt", 0, 1, bt_uint_16));
	bv = bv_append_bv(bv, bv_new_bv("HTTP response status code", "httpRSCode", 1, 1, bt_uint_16));
#endif // HTTP_STAT == 1
	bv = bv_append_bv(bv, bv_new_bv("HTTP number of URLs, Via, Location, Server, Powered By, User-Agent, X-Forwarded-For, Referer, Cookie and Mime-Type", "httpURL_Via_Loc_Srv_Pwr_UAg_XFr_Ref_Cky_Mim", 0, 10, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16));

	bv = bv_append_bv(bv, bv_new_bv("HTTP number of images, videos, audios, messages, texts, applications and unknown", "httpImg_Vid_Aud_Msg_Txt_App_Unk", 0, 7, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16));

#if HTTP_HOST == 1
	bv = bv_append_bv(bv, bv_new_bv("HTTP Host names", "httpHosts", 1, 1, bt_string));
#endif // HTTP_HOST == 1

#if HTTP_URL == 1
	bv = bv_append_bv(bv, bv_new_bv("HTTP URLs", "httpURL", 1, 1, bt_string));
#endif // HTTP_URL == 1

#if HTTP_MIME == 1
	bv = bv_append_bv(bv, bv_new_bv("HTTP MIME-types", "httpMimes", 1, 1, bt_string));
#endif // HTTP_MIME == 1

#if HTTP_COOKIE == 1
	bv = bv_append_bv(bv, bv_new_bv("HTTP cookies", "httpCookies", 1, 1, bt_string));
#endif // HTTP_COOKIE == 1

#if HTTP_IMAGE == 1
	bv = bv_append_bv(bv, bv_new_bv("HTTP images", "httpImages", 1, 1, bt_string));
#endif // HTTP_IMAGE == 1

#if HTTP_VIDEO == 1
	bv = bv_append_bv(bv, bv_new_bv("HTTP videos", "httpVideos", 1, 1, bt_string));
#endif // HTTP_VIDEO == 1

#if HTTP_AUDIO == 1
	bv = bv_append_bv(bv, bv_new_bv("HTTP audios", "httpAudios", 1, 1, bt_string));
#endif // HTTP_AUDIO == 1

#if HTTP_MSG == 1
	bv = bv_append_bv(bv, bv_new_bv("HTTP messages", "httpMsgs", 1, 1, bt_string));
#endif // HTTP_MSG == 1

#if HTTP_APPL == 1
	bv = bv_append_bv(bv, bv_new_bv("HTTP applications", "httpAppl", 1, 1, bt_string));
#endif // HTTP_APPL == 1

#if HTTP_TEXT == 1
	bv = bv_append_bv(bv, bv_new_bv("HTTP texts", "httpText", 1, 1, bt_string));
#endif // HTTP_TEXT == 1

#if HTTP_PUNK == 1
	bv = bv_append_bv(bv, bv_new_bv("HTTP punk", "httpPunk", 1, 1, bt_string));
#endif // HTTP_PUNK == 1

#if (HTTP_BODY == 1 && HTTP_BDURL == 1)
	bv = bv_append_bv(bv, bv_new_bv("HTTP body: Refresh, Set-Cookie URL", "httpBdyURL", 1, 1, bt_string));
#endif // (HTTP_BODY == 1 && HTTP_BDURL == 1)

#if HTTP_USRAG == 1
	bv = bv_append_bv(bv, bv_new_bv("HTTP User-Agent", "httpUsrAg", 1, 1, bt_string));
#endif // HTTP_USRAG

#if HTTP_XFRWD == 1
	bv = bv_append_bv(bv, bv_new_bv("HTTP X-Forwarded-For", "httpXFor", 1, 1, bt_string));
#endif // HTTP_XFRWD

#if HTTP_REFRR == 1
	bv = bv_append_bv(bv, bv_new_bv("HTTP Referer", "httpRefrr", 1, 1, bt_string));
#endif // HTTP_REFRR

#if HTTP_VIA == 1
	bv = bv_append_bv(bv, bv_new_bv("HTTP Via (Proxy)", "httpVia", 1, 1, bt_string));
#endif // HTTP_VIA

#if HTTP_LOC == 1
	bv = bv_append_bv(bv, bv_new_bv("HTTP Location (Redirection)", "httpLoc", 1, 1, bt_string));
#endif // HTTP_LOC

#if HTTP_SERV == 1
	bv = bv_append_bv(bv, bv_new_bv("HTTP Server", "httpServ", 1, 1, bt_string));
#endif // HTTP_SERV

#if HTTP_PWR == 1
	bv = bv_append_bv(bv, bv_new_bv("HTTP Powered By", "httpPwr", 1, 1, bt_string));
#endif // HTTP_PWR == 1

	return bv;
}


void onFlowGenerated(packet_t *packet, unsigned long flowIndex) {
	http_flow_t * const httpFlowP = &http_flow[flowIndex];
	memset(httpFlowP, '\0', sizeof(http_flow_t));

	httpFlowP->flags = HTTP_F_HTTP_HDR;

	const uint_fast8_t proto = packet->layer4Type;
	const flow_t * const flowP = &flows[flowIndex];

	if (proto == L3_TCP
#if SCTP_ACTIVATE == 1
		|| proto == L3_SCTP
#endif // SCTP_ACTIVATE == 1
		|| (proto == L3_UDP && (flowP->srcPort > 1024 || flowP->dstPort > 1024)))
	{
		httpFlowP->cFlags |= HTTP_PCNT;
	}
}


void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {
	http_flow_t * const httpFlowP = &http_flow[flowIndex];
	if (!(httpFlowP->cFlags & HTTP_PCNT)) return;

	uint16_t http_data_len = packet->snapL7Length; // length of http_data (if there is)
	if (http_data_len == 0) return;

	char *data_ptr = (char*)packet->layer7Header;
	if (!data_ptr) return;

	uint16_t line_size = 0; // size of current line (if 0 header is completely read)
	char *line_eptr = http_get_linesize(data_ptr, http_data_len); // size of current line (if 0 header is completely read)
	if (line_eptr) line_size = (uint16_t)(line_eptr - data_ptr);

	httpFlowP->pktcnt++;
	if (httpFlowP->flags & (HTTP_F_DETECT | HTTP_F_HTTP_HDR | HTTP_F_HTTP)) totalHttpPktCnt++;

	if ((httpFlowP->flags & HTTP_F_DETECT) && http_data_len >= 2 && *(uint16_t*)data_ptr == 0x5a4d) httpFlowP->aFlags |= HTTP_A_DEXE;

	if (!(httpFlowP->flags & HTTP_F_PLD_S) && !line_eptr) return;

	uint32_t i, k;
	int32_t j;
#if HTTP_STAT == 1
	uint_fast8_t stat_code_pos = 9; // Expected position of status code: HTTP/1.x 200 OK
#endif // HTTP_STAT == 1                                                          ^
	uint32_t namelen = 0; // file or image name length
	uint16_t linesz;
	char *http_header_data = NULL, *name_p = NULL, *p = NULL;
	char *dp;

#if HTTP_SAVE == 1
	char imfilename[HTTP_MXIMNM_LEN+1] = {};
#endif // HTTP_SAVE == 1

#if ((HTTP_BODY == 1 && HTTP_TEXT == 1) || HTTP_STAT == 1)
	char h[5];
#endif // ((HTTP_BODY == 1 && HTTP_TEXT == 1) || HTTP_STAT == 1)
#if (HTTP_BODY == 1 && HTTP_TEXT == 1)
	char *dp1, *dp2;
#endif // ((HTTP_BODY == 1 && HTTP_TEXT == 1) || HTTP_STAT == 1)

	const flow_t * const flowP = &flows[flowIndex];
	const uint_fast8_t dir = flowP->status & L3FLOWINVERT;
	const uint64_t findex = flowP->findex;

	// check whether opposite flow exists
	http_flow_t * const httpFlowPO = (flowP->oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) ? &(http_flow[flowP->oppositeFlowIndex]) : NULL;

	// HTTP-HEADER-Parsing
#if HTTP_SAVE == 1
hdrbgn:
#endif // HTTP_SAVE == 1
	if (line_size > 0 && httpFlowP->flags & HTTP_F_HTTP_HDR) {
		// first line: identify http-flow, e.g., HTTP/1.x 200 OK or SIP/x.x 200 OK or GET / HTTP/1.x, ...
		if (http_data_len >= sizeof(HTTP_ID)) { // Is there enough data for HTTP/1.x?
			http_header_data = memmem(data_ptr, http_data_len, HTTP_ID, sizeof(HTTP_ID)-1); // find end of url
			if (http_header_data) { // HTTP/1.x found
				if (http_header_data[7] == '0') httpFlowP->aFlags |= HTTP_A_1_0; // HTTP/1.0
			} else { // HTTP/1. not found... search for SIP (for simplicity, we assume the header contains one more character than SIP/1.x)
				http_header_data = memmem(data_ptr, http_data_len, SIP_ID, sizeof(SIP_ID)-1); // find end of url
				if (http_header_data) { // SIP/x.x found
					packet->status |= L7_SIPRTP;
					globalWarn |= L7_SIPRTP;
#if HTTP_STAT == 1
					stat_code_pos = 8;
#endif // HTTP_STAT == 1
				}
			}
		}
		if (!http_header_data || http_header_data - data_ptr >= http_data_len) { // HTTP or SIP not found
			// no HTTP or SIP header present
			if (!(httpFlowP->flags & HTTP_F_DETECT)) {
				httpFlowP->flags |= HTTP_F_HTTP_HDR;
			}
		} else { // HTTP or SIP found
			httpFlowP->flags &= ~HTTP_F_S;
			httpFlowP->flags |= (HTTP_F_DETECT | HTTP_F_HTTP_HDR | HTTP_F_HTTP);
#if HTTP_STAT == 1
			// HTTP status (response)
			// TODO make sure there is enough data to read
			if (http_header_data[stat_code_pos-1] == ' ') {
				memcpy(h, http_header_data + stat_code_pos, 3);
				h[3] = '\0';
				j = atoi(h);
				k = httpFlowP->stat_c;
#if HTTP_STATAGA == 1
				for (i = 0; i < k; i++) {
					// Status code already exists
					if (httpFlowP->stat[i] == j) break;
				}
				if (i == k) {
#endif // HTTP_STATAGA == 1
					if (k >= HTTP_DATA_C_MAX) {
						httpFlowP->flags |= HTTP_F_OVRFLW;
					} else {
						httpFlowP->stat[httpFlowP->stat_c] = (uint16_t)j;
					}
					httpFlowP->stat_c++;
#if HTTP_STATAGA == 1
				}
#endif // HTTP_STATAGA == 1
			}
#endif // HTTP_STAT == 1

			// look for HTTP methods
			uint_fast8_t method = 0;
			for (i = 0; http_methods[i].name; i++) {
				if (memcmp(data_ptr, http_methods[i].name, http_methods[i].len-1) == 0) {
					p = data_ptr + http_methods[i].len;
					method = http_methods[i].hex;
					httpFlowP->httpMethods |= method;
					if (method == GET) httpFlowP->getCnt++;
					else if (method == POST) httpFlowP->pstCnt++;
					break;
				}
			}

			httpFlowP->httpLastMeth = method;

			if (method) {
				// search for space after URL
				namelen = 0;
				while (namelen < http_data_len - (p - data_ptr) && p[namelen] != ' ') ++namelen;
				//if (!namelen) namelen = http_data_len;
				if (namelen > 0) {
#if HTTP_URL == 0
					httpFlowP->url_c++;
#else // HTTP_URL == 1
					k = httpFlowP->url_c;
					if (k >= HTTP_DATA_C_MAX) {
						httpFlowP->flags |= HTTP_F_OVRFLW;
					} else {
#if HTTP_URLAGA == 1
						for (i = 0; i < k; i++) {
							// URL already exists
							if (namelen == strlen(httpFlowP->url[i]) && memcmp(httpFlowP->url[i], p, namelen) == 0) break;
						}
						if (i == k) { // Not found
#endif // HTTP_URLAGA == 1
							name_p = httpFlowP->url[k] = malloc(namelen + 1);
							memcpy(name_p, p, namelen);
							name_p[namelen] = '\0';
							if (method == POST && !(httpFlowP->aFlags & HTTP_A_PST) && memchr(name_p, '?', namelen)) httpFlowP->aFlags |= HTTP_A_PST;
							httpFlowP->url_c++;
#if HTTP_URLAGA == 1
						}
#endif // HTTP_URLAGA == 1
					}
#endif // HTTP_URL == 1
					//if (method == GET) {
						if (namelen >= HTTP_MXFILE_LEN) {
							namelen = HTTP_MXFILE_LEN;
							httpFlowP->flags |= HTTP_F_FNM_LN;
						}

						// copy getfile
						memcpy(httpFlowP->getFile, p, namelen);
						httpFlowP->getFile[namelen] = '\0';

						httpFlowP->flags |= HTTP_F_GET; // finally set hasget-flag to true
					//}
				}
			}
		} // end if HTTP or SIP found
	}

	while (line_size > 0 && httpFlowP->flags & HTTP_F_HTTP_HDR && line_eptr) {
		// continue parsing http-header
		if (httpFlowP->flags & HTTP_F_HTTP_HDR) {

			if (httpFlowP->cFlags & HTTP_BOUND && !(httpFlowP->cFlags & HTTP_QUARA)) {
				if (memmem(data_ptr, http_data_len, QUARANTINE, sizeof(QUARANTINE)-1)) httpFlowP->cFlags |= HTTP_QUARA;
			}
			// Mime-Type-sniffing
			http_header_data = http_read_header_data(data_ptr, http_data_len, CONTENT_TYPE, sizeof(CONTENT_TYPE)-1);

			if (http_header_data) {
				// save mime type and boundary marker
#if HTTP_MIME == 1
				if (httpFlowP->mime_c >= HTTP_DATA_C_MAX) {
					httpFlowP->flags |= HTTP_F_OVRFLW;
				} else {
					linesz = (uint16_t)(line_eptr - http_header_data);
					for (i = 0; i < linesz; i++) {
						if (http_header_data[i] == ';') {
//							if (http_header_data[i+1] == '\r') {i += 2; k = }
							p = memmem(&http_header_data[i+1], linesz, BOUNDARY, sizeof(BOUNDARY)-1);
							if (p) {
/*								httpFlowP->bound = malloc(linesz + 1);
								k = (int)(line_eptr-p) - sizeof(BOUNDARY) -1;
								memcpy(httpFlowP->bound, p+sizeof(BOUNDARY)+1, k);
								httpFlowP->bound[k] = '\0';
*/								httpFlowP->cFlags |= HTTP_BOUND;
							}
							linesz = i;
							break;
						}
					}

#if HTTP_MIMEAGA == 1
					k = httpFlowP->mime_c;
					for (i = 0; i < k; i++) {
						if (!strncmp(httpFlowP->mime[i], http_header_data, linesz)) break;
					}
					if (i == k) {
#endif // HTTP_MIMEAGA == 1
						httpFlowP->mime[httpFlowP->mime_c] = malloc(linesz + 1); // malloc space for mime-type
						memcpy(httpFlowP->mime[httpFlowP->mime_c], http_header_data, linesz); // copy mime type..
						httpFlowP->mime[httpFlowP->mime_c++][linesz] = '\0';
						if (strlen(httpFlowP->mime[httpFlowP->mime_c-1]) == 0) httpFlowP->aFlags |= HTTP_A_HDR_WO_VAL;
#if HTTP_MIMEAGA == 1
					}
#endif // HTTP_MIMEAGA == 1
				}
#endif // HTTP_MIME == 1

				// do mimetype based actions
				const http_mimetype mimetype = http_read_mimetype(http_header_data, line_eptr - http_header_data);
				httpFlowP->mimeTypes |= mimetype; // add to seen mimetypes

				if (httpFlowPO && (httpFlowPO->flags & HTTP_F_GET)) {
					 //if (httpFlowPO->httpLastMeth == POST) goto dshdr;
					 p = httpFlowPO->getFile;
				} else p = httpFlowP->getFile;

				switch (mimetype) {
					case image:
#if (HTTP_IMAGE == 1 || HTTP_SAVE_IMAGE == 1)
						if (httpFlowP->image_c >= HTTP_DATA_C_MAX) {
							httpFlowP->flags |= HTTP_F_OVRFLW;
						} else {
							HTTP_BUILD_FILENAME(name_p, p, httpFlowP->image_c);
							httpFlowP->image[httpFlowP->image_c] = name_p;
#if HTTP_SAVE_IMAGE == 1
							remove(name_p);
							httpFlowP->flags |= HTTP_F_PLD_IMG_S; // start sniffing content..
#endif // HTTP_SAVE_IMAGE == 1
						}
#endif // (HTTP_IMAGE == 1 || HTTP_SAVE_IMAGE == 1)
						httpFlowP->image_c++;
						break;

					case message:
#if (HTTP_MSG == 1 || HTTP_SAVE_MSG == 1)
						if (httpFlowP->msg_c >= HTTP_DATA_C_MAX) {
							httpFlowP->flags |= HTTP_F_OVRFLW;
						} else {
							HTTP_BUILD_FILENAME(name_p, p, httpFlowP->msg_c);
							httpFlowP->msg[httpFlowP->msg_c] = name_p;
#if HTTP_SAVE_MSG == 1
							remove(name_p);
							httpFlowP->flags |= HTTP_F_PLD_MSG_S; // start sniffing content..
#endif // HTTP_SAVE_MSG == 1
						}
#endif // (HTTP_MSG == 1 || HTTP_SAVE_MSG == 1)
						httpFlowP->msg_c++;
						break;

					case text:
#if (HTTP_TEXT == 1 || HTTP_SAVE_TEXT == 1)
						if (httpFlowP->text_c >= HTTP_DATA_C_MAX) {
							httpFlowP->flags |= HTTP_F_OVRFLW;
						} else {
							HTTP_BUILD_FILENAME(name_p, p, httpFlowP->text_c);
							httpFlowP->text[httpFlowP->text_c] = name_p;
#if HTTP_SAVE_TEXT == 1
							remove(name_p);
							httpFlowP->flags |= HTTP_F_PLD_TXT_S; // start sniffing content..
#endif // HTTP_SAVE_TEXT == 1
						}
#endif // (HTTP_TEXT == 1 || HTTP_SAVE_TEXT == 1)
						httpFlowP->text_c++;
						break;

					case video:
#if (HTTP_VIDEO == 1 || HTTP_SAVE_VIDEO == 1)
						if (httpFlowP->cFlags & HTTP_STRM1) {
							httpFlowP->flags |= HTTP_F_PLD_VID_S; // start sniffing content..
							break;
						}

						if (httpFlowP->video_c >= HTTP_DATA_C_MAX) {
							httpFlowP->flags |= HTTP_F_OVRFLW;
						} else {
							HTTP_BUILD_FILENAME(name_p, p, httpFlowP->video_c);
							httpFlowP->video[httpFlowP->video_c] = name_p;
#if HTTP_SAVE_VIDEO == 1
							remove(name_p);
							httpFlowP->flags |= HTTP_F_PLD_VID_S; // start sniffing content..
#endif // HTTP_SAVE_VIDEO == 1
						}

						if (httpFlowP->cFlags & HTTP_STRM) httpFlowP->cFlags |= HTTP_STRM1;
#endif // (HTTP_VIDEO == 1 || HTTP_SAVE_VIDEO == 1)
						httpFlowP->video_c++;
						break;

					case audio:
#if (HTTP_AUDIO == 1 || HTTP_SAVE_AUDIO == 1)
						if (httpFlowP->audio_c >= HTTP_DATA_C_MAX) {
							httpFlowP->flags |= HTTP_F_OVRFLW;
						} else {
							HTTP_BUILD_FILENAME(name_p, p, httpFlowP->audio_c);
							httpFlowP->audio[httpFlowP->audio_c] = name_p;
#if HTTP_SAVE_AUDIO == 1
							remove(name_p);
							httpFlowP->flags |= HTTP_F_PLD_AUD_S; // start sniffing content..
#endif // HTTP_SAVE_AUDIO == 1
						}
#endif // (HTTP_AUDIO == 1 || HTTP_SAVE_AUDIO == 1)
						httpFlowP->audio_c++;
						break;

					case application:
#if (HTTP_APPL == 1 || HTTP_SAVE_APPL == 1)
						if (httpFlowP->appl_c >= HTTP_DATA_C_MAX) {
							httpFlowP->flags |= HTTP_F_OVRFLW;
						} else {
							HTTP_BUILD_FILENAME(name_p, p, httpFlowP->appl_c);
							httpFlowP->appl[httpFlowP->appl_c] = name_p;
#if HTTP_SAVE_APPL == 1
							remove(name_p);
							httpFlowP->flags |= HTTP_F_PLD_APP_S; // start sniffing content..
#endif // HTTP_SAVE_APPL == 1
						}
#endif // (HTTP_APPL == 1 || HTTP_SAVE_APPL == 1)
						httpFlowP->appl_c++;
						break;

					default:
#if (HTTP_PUNK == 1 || HTTP_SAVE_PUNK == 1)
						if (memmem(data_ptr, http_data_len, UPLOAD, sizeof(UPLOAD)-1)) httpFlowP->cFlags |= HTTP_QUARA;
						if (httpFlowP->unknwn_c >= HTTP_DATA_C_MAX) {
							httpFlowP->flags |= HTTP_F_OVRFLW;
						} else {
							HTTP_BUILD_FILENAME(name_p, p, httpFlowP->unknwn_c);
							httpFlowP->punk[httpFlowP->unknwn_c] = name_p;
#if HTTP_SAVE_PUNK == 1
							remove(name_p);
							httpFlowP->flags |= HTTP_F_PLD_PUNK_S; // start sniffing content..
#endif // HTTP_SAVE_PUNK == 1
						}
#endif // (HTTP_PUNK == 1 || HTTP_SAVE_PUNK == 1)
						httpFlowP->unknwn_c++;
						break;
				}
			}

//dshdr:
			// Content Dispositon
			http_header_data = http_read_header_data(data_ptr, http_data_len, CONTENT_DISP, sizeof(CONTENT_DISP)-1);
			if (http_header_data) {
				linesz = (uint16_t)(line_eptr - http_header_data);
				p = memmem(http_header_data, linesz, FILENAME, sizeof(FILENAME)-1);
				if (p) {
					k = linesz - sizeof(FILENAME);
					*line_eptr = 0x00;
					uint8_t *start = (uint8_t*)&p[sizeof(FILENAME)-1];
					// skip optional leading quote
					if (*start == '"') {
						start++;
						k--;
					}
					// Remove optional trailing quote
					bool requote = false;
					if (*(line_eptr-1) == '"') {
						requote = true;
						*(line_eptr-1) = 0x00;
						k--;
					}
					if (k >= HTTP_MXFILE_LEN) k = HTTP_MXFILE_LEN;
					memcpy(httpFlowP->getFile, start, k);
					httpFlowP->getFile[HTTP_MXFILE_LEN] = '\0';
					if (requote) *(line_eptr-1) = '"';
					*line_eptr = 0x0d;
					for (i = 0; i <= k; i++) if (httpFlowP->getFile[i] == '/' || httpFlowP->getFile[i] == '\\') httpFlowP->getFile[i] = '_';
				}
			}

			// Content-Length extraction
			http_header_data = http_read_header_data(data_ptr, http_data_len, CONTENT_LENGTH, sizeof(CONTENT_LENGTH)-1);
			if (http_header_data) {
				*line_eptr = 0x00;
				httpFlowP->contentLength = atoi(http_header_data);
				*line_eptr = 0x0d;
			}

			// Transfer-Encoding extraction
			http_header_data = http_read_header_data(data_ptr, http_data_len, TRANS_ENCODING, sizeof(TRANS_ENCODING)-1);
			if (http_header_data) {
				*line_eptr = 0x00;
				if (strstr(http_header_data, "chunked")) httpFlowP->flags |= HTTP_F_CHKD;
				*line_eptr = 0x0d;
			}

			// host extraction
			if (httpFlowP->host_c >= HTTP_DATA_C_MAX) { // host limit?
				httpFlowP->flags |= HTTP_F_OVRFLW;
			} else {
				http_header_data = http_read_header_data(data_ptr, http_data_len, HOST, sizeof(HOST)-1);
				if (http_header_data) {
#if HTTP_HOST == 1 || HTTP_SAVE_PUNK == 1
					linesz = (uint16_t)(line_eptr - http_header_data);
#endif // HTTP_HOST == 1 || HTTP_SAVE_PUNK == 1
#if HTTP_HOST == 0
					httpFlowP->host_c++;
#else // HTTP_HOST == 1

					k = httpFlowP->host_c;
#if HTTP_HOSTAGA == 1
					for (i = 0; i < k; i++) {
						if (!strncmp(httpFlowP->host[i], http_header_data, linesz)) break;
					}
					if (i == k) {
#endif // HTTP_HOSTAGA == 1
						httpFlowP->host[k] = malloc(linesz + 1);
						memcpy(httpFlowP->host[k], http_header_data, linesz);
						httpFlowP->host[k][linesz] = '\0';

						struct sockaddr_in s;
						if (!(httpFlowP->aFlags & HTTP_A_HNUM) && inet_pton(AF_INET, httpFlowP->host[k], &(s.sin_addr))) {
							httpFlowP->aFlags |= HTTP_A_HNUM;
						}
						httpFlowP->host_c++;
#if HTTP_HOSTAGA == 1
					}
#endif // HTTP_HOSTAGA == 1
#endif // HTTP_HOST == 1
				}
			}

			// location extraction
			if (httpFlowP->loc_c >= HTTP_DATA_C_MAX) { // location limit?
				httpFlowP->flags |= HTTP_F_OVRFLW;
			} else {
				http_header_data = http_read_header_data(data_ptr, http_data_len, LOC, sizeof(LOC)-1);
				if (http_header_data) {
#if HTTP_LOC == 0
					httpFlowP->loc_c++;
#else // HTTP_LOC == 1
					linesz = (uint16_t)(line_eptr - http_header_data);
					k = httpFlowP->loc_c;
#if HTTP_LOCA == 1
					for (i = 0; i < k; i++) {
						if (!strncmp(httpFlowP->loc[i], http_header_data, linesz)) break;
					}
					if (i == k) {
#endif // HTTP_LOCA == 1
						httpFlowP->loc[k] = malloc(linesz + 1);
						memcpy(httpFlowP->loc[k], http_header_data, linesz);
						httpFlowP->loc[k][linesz] = '\0';
						httpFlowP->loc_c++;
#if HTTP_LOCA == 1
					}
#endif // HTTP_LOCA == 1
#endif // HTTP_LOC == 1
				}
			}

			// via extraction
			if (httpFlowP->via_c >= HTTP_DATA_C_MAX) { // via limit?
				httpFlowP->flags |= HTTP_F_OVRFLW;
			} else {
				http_header_data = http_read_header_data(data_ptr, http_data_len, VIA, sizeof(VIA)-1);
				if (http_header_data) {
#if HTTP_VIA == 0
					httpFlowP->via_c++;
#else // HTTP_VIA == 1
					linesz = (uint16_t)(line_eptr - http_header_data);
					k = httpFlowP->via_c;
#if HTTP_VIAA == 1
					for (i = 0; i < k; i++) {
						if (!strncmp(httpFlowP->via[i], http_header_data, linesz)) break;
					}
					if (i == k) {
#endif // HTTP_VIAA == 1
						httpFlowP->via[k] = malloc(linesz + 1);
						memcpy(httpFlowP->via[k], http_header_data, linesz);
						httpFlowP->via[k][linesz] = '\0';
						httpFlowP->via_c++;
#if HTTP_VIAA == 1
					}
#endif // HTTP_VIAA == 1
#endif // HTTP_VIA == 1
				}
			}

			// serv extraction
			if (httpFlowP->serv_c >= HTTP_DATA_C_MAX) { // serv limit?
				httpFlowP->flags |= HTTP_F_OVRFLW;
			} else {
				http_header_data = http_read_header_data(data_ptr, http_data_len, SERVER, sizeof(SERVER)-1);
				if (http_header_data) {
#if HTTP_SERV == 0
					httpFlowP->serv_c++;
#else // HTTP_SERV == 1
					linesz = (uint16_t)(line_eptr - http_header_data);
					k = httpFlowP->serv_c;
#if HTTP_SERVA == 1
					for (i = 0; i < k; i++) {
						if (!strncmp(httpFlowP->serv[i], http_header_data, linesz)) break;
					}
					if (i == k) {
#endif // HTTP_SERVA == 1
						httpFlowP->serv[k] = malloc(linesz + 1);
						memcpy(httpFlowP->serv[k], http_header_data, linesz);
						httpFlowP->serv[k][linesz] = '\0';
						httpFlowP->serv_c++;
#if HTTP_SERVA == 1
					}
#endif // HTTP_SERVA == 1
#endif // HTTP_SERV == 1
				}
			}

			// poweredby extraction
			if (httpFlowP->pwr_c >= HTTP_DATA_C_MAX) { // poweredby limit?
				httpFlowP->flags |= HTTP_F_OVRFLW;
			} else {
				http_header_data = http_read_header_data(data_ptr, http_data_len, POWERED, sizeof(POWERED)-1);
				if (http_header_data) {
#if HTTP_PWR == 0
					httpFlowP->pwr_c++;
#else // HTTP_PWR == 1
					linesz = (uint16_t)(line_eptr - http_header_data);
					k = httpFlowP->pwr_c;
#if HTTP_PWRA == 1
					for (i = 0; i < k; i++) {
						if (!strncmp(httpFlowP->pwr[i], http_header_data, linesz)) break;
					}
					if (i == k) {
#endif // HTTP_PWRA == 1
						httpFlowP->pwr[k] = malloc(linesz + 1);
						memcpy(httpFlowP->pwr[k], http_header_data, linesz);
						httpFlowP->pwr[k][linesz] = '\0';
						httpFlowP->pwr_c++;
#if HTTP_PWRA == 1
					}
#endif // HTTP_PWRA == 1
#endif // HTTP_PWR == 1
				}
			}

			// referer extraction
			if (httpFlowP->refrr_c >= HTTP_DATA_C_MAX) { // referer limit?
				httpFlowP->flags |= HTTP_F_OVRFLW;
			} else {
				http_header_data = http_read_header_data(data_ptr, http_data_len, REFERER, sizeof(REFERER)-1);
				if (http_header_data) {
#if HTTP_REFRR == 0
					httpFlowP->refrr_c++;
#else // HTTP_REFRR == 1
					linesz = (uint16_t)(line_eptr - http_header_data);
					k = httpFlowP->refrr_c;
#if HTTP_REFRRA == 1
					for (i = 0; i < k; i++) {
						if (!strncmp(httpFlowP->refrr[i], http_header_data, linesz)) break;
					}
					if (i == k) {
#endif // HTTP_REFRRA == 1
						httpFlowP->refrr[k] = malloc(linesz + 1);
						memcpy(httpFlowP->refrr[k], http_header_data, linesz);
						httpFlowP->refrr[k][linesz] = '\0';
						httpFlowP->refrr_c++;
#if HTTP_REFRRA == 1
					}
#endif // HTTP_REFRRA == 1
#endif // HTTP_REFRR == 1
				}
			}

			// X-Site Scripting protection
			http_header_data = http_read_header_data(data_ptr, http_data_len, XXSSPROT, sizeof(XXSSPROT)-1);
			if (http_header_data) httpFlowP->aFlags |= HTTP_A_XSSP;

			// Content Security Policy
			http_header_data = http_read_header_data(data_ptr, http_data_len, CONTSECPOL, sizeof(CONTSECPOL)-1);
			if (http_header_data) httpFlowP->aFlags |= HTTP_A_CSP;

			// Do not track
			http_header_data = http_read_header_data(data_ptr, http_data_len, DNT, sizeof(DNT)-1);
			if (http_header_data) httpFlowP->aFlags |= HTTP_A_DNT;

		//} // if (httpFlowP->flags & HTTP_F_HTTP_HDR)

		// Cookie sniffing
		http_header_data = http_read_header_data(data_ptr, http_data_len, SET_COOKIE, sizeof(SET_COOKIE)-1);
		if (http_header_data) {
#if HTTP_COOKIE == 1
			// save cookie
			if (httpFlowP->cookie_c >= HTTP_DATA_C_MAX) { // cookie limit?
				httpFlowP->flags |= HTTP_F_OVRFLW;
			} else {
				linesz = (uint16_t)(line_eptr - http_header_data);
				httpFlowP->cookie[httpFlowP->cookie_c] = malloc(linesz + 1);
				memcpy(httpFlowP->cookie[httpFlowP->cookie_c], http_header_data, linesz);
				httpFlowP->cookie[httpFlowP->cookie_c][linesz] = '\0';
#endif // HTTP_COOKIE = 1
				httpFlowP->cookie_c++;
#if HTTP_COOKIE == 1
			}
#endif // HTTP_COOKIE = 1
		}

		// User Agent
		http_header_data = http_read_header_data(data_ptr, http_data_len, USER_AGENT, sizeof(USER_AGENT)-1);
		if (http_header_data) {
#if HTTP_USRAG == 0
			httpFlowP->usrAg_c++;
#else // HTTP_USRAG == 1
			if (httpFlowP->usrAg_c >= HTTP_DATA_C_MAX) {
				httpFlowP->flags |= HTTP_F_OVRFLW;
			} else {
				linesz = MIN((uint16_t)(line_eptr - http_header_data), HTTP_MXUA_LEN);
				k = httpFlowP->usrAg_c;
#if HTTP_USRAGA == 1
				for (i = 0; i < k; i++) {
					if (!strncmp(httpFlowP->usrAg[i], http_header_data, linesz)) break;
				}
				if (i == k) {
#endif // HTTP_USRAGA == 1
					httpFlowP->usrAg[k] = malloc(linesz + 1);
					memcpy(httpFlowP->usrAg[k], http_header_data, linesz);
					httpFlowP->usrAg[k][linesz] = '\0';
					httpFlowP->usrAg_c++;
#if HTTP_USRAGA == 1
				}
#endif // HTTP_USRAGA == 1
			}
#endif // HTTP_USRAG == 1
		}

		// x-forward-for
		http_header_data = http_read_header_data(data_ptr, http_data_len, X_FORWRD_FOR, sizeof(X_FORWRD_FOR)-1);
		if (http_header_data) {
#if HTTP_XFRWD == 0
			httpFlowP->xFor_c++;
#else // HTTP_XFRWD == 1
			if (httpFlowP->xFor_c >= HTTP_DATA_C_MAX) {
				httpFlowP->flags |= HTTP_F_OVRFLW;
			} else {
				linesz = MIN((uint16_t)(line_eptr - http_header_data), HTTP_MXXF_LEN);
				k = httpFlowP->xFor_c;
#if HTTP_XFRWDA == 1
				for (i = 0; i < k; i++) {
					if (!strncmp(httpFlowP->xFor[i], http_header_data, linesz)) break;
				}
				if (i == k) {
#endif // HTTP_XFRWDA == 1
					httpFlowP->xFor[k] = malloc(linesz + 1);
					memcpy(httpFlowP->xFor[k], http_header_data, linesz);
					httpFlowP->xFor[k][linesz] = '\0';
					httpFlowP->xFor_c++;
#if HTTP_XFRWDA == 1
				}
#endif // HTTP_XFRWDA == 1
			}
#endif // HTTP_XFRWD == 1
		}

		} // if (httpFlowP->flags & HTTP_F_HTTP_HDR)

		// go to next line
		if (httpFlowP->flags & HTTP_F_HTTP_HDR) {
			data_ptr += (line_size + 2); // +2 skip line ending \r\n
			http_data_len -= (line_size + 2);

			// Get new linesize
			line_eptr = http_get_linesize(data_ptr, http_data_len);
			if (line_eptr) line_size = (uint16_t)(line_eptr - data_ptr); // size of current line (if 0 header is completely read)
			else line_size = 0;
		}
	} // end while

	// skip \r\n at end of http-header
	if (httpFlowP->flags & HTTP_F_HTTP_HDR) { // was in HTTP-Header
		if (http_data_len == 0 || line_eptr == NULL) return;
		if (http_data_len >= 2) {
			data_ptr += 2; // skip \r\n
			http_data_len -= 2; // length of all body payload to come
		} else httpFlowP->aFlags |= HTTP_F_PRS_ERR; // Parse Error


#if HTTP_SAVE == 1
		if (httpFlowP->fd) {
			file_manager_close(t2_file_manager, httpFlowP->fd);
			httpFlowP->fd = NULL;
			http_fd_cnt--;
		}

		if (httpFlowPO && httpFlowPO->httpLastMeth == HEAD) goto chkbdy;

		if (httpFlowP->flags & HTTP_F_CHKD) {
			line_eptr = http_get_linesize(data_ptr, http_data_len); // size of current line (if 0 header is completely read)
			if (line_eptr) line_size = (uint16_t)(line_eptr - data_ptr); // size of current line (if 0 header is completely read)
			else line_size = 0;
			if (line_eptr) {
				*line_eptr = 0x00;
				sscanf(data_ptr, "%x", &(httpFlowP->contentLength));
				*line_eptr = 0x0d;
				data_ptr += (line_size + 2); // +2 skip line ending \r\n
				http_data_len -= (line_size + 2); // +2 skip line ending \r\n
			}
		}

		httpFlowP->sniffedContent = 0;

		sflgs |= httpFlowP->flags; // temp fix

		//if (httpFlowP->flags & HTTP_F_PLD_S && http_data_len <= (httpFlowP->contentLength - httpFlowP->sniffedContent)) {
		if (httpFlowP->flags & HTTP_F_PLD_S) {
			switch (httpFlowP->flags & HTTP_F_PLD_S) {
#if HTTP_SAVE_IMAGE == 1
				case HTTP_F_PLD_IMG_S:
					if (httpFlowP->image_c > HTTP_DATA_C_MAX) return;
					HTTP_BUILD_FILEPATH(imfilename, HTTP_IMAGE_PATH, httpFlowP->image[httpFlowP->image_c-1]);
					break;
#endif // HTTP_SAVE_IMAGE == 1
#if HTTP_SAVE_VIDEO == 1
				case HTTP_F_PLD_VID_S:
					if (httpFlowP->video_c > HTTP_DATA_C_MAX) return;
					HTTP_BUILD_FILEPATH(imfilename, HTTP_VIDEO_PATH, httpFlowP->video[httpFlowP->video_c-1]);
					break;
#endif // HTTP_SAVE_VIDEO == 1
#if HTTP_SAVE_AUDIO == 1
				case HTTP_F_PLD_AUD_S:
					if (httpFlowP->audio_c > HTTP_DATA_C_MAX) return;
					HTTP_BUILD_FILEPATH(imfilename, HTTP_AUDIO_PATH, httpFlowP->audio[httpFlowP->audio_c-1]);
					break;
#endif // HTTP_SAVE_AUDIO == 1
#if HTTP_SAVE_MSG == 1
				case HTTP_F_PLD_MSG_S:
					if (httpFlowP->msg_c > HTTP_DATA_C_MAX) return;
					HTTP_BUILD_FILEPATH(imfilename, HTTP_MSG_PATH, httpFlowP->msg[httpFlowP->msg_c-1]);
					break;
#endif // HTTP_SAVE_MSG == 1
#if HTTP_SAVE_TEXT == 1
				case HTTP_F_PLD_TXT_S:
					if (httpFlowP->text_c > HTTP_DATA_C_MAX) return;
					HTTP_BUILD_FILEPATH(imfilename, HTTP_TEXT_PATH, httpFlowP->text[httpFlowP->text_c-1]);
					break;
#endif // HTTP_SAVE_TEXT == 1
#if HTTP_SAVE_APPL == 1
				case HTTP_F_PLD_APP_S:
					if (httpFlowP->appl_c > HTTP_DATA_C_MAX) return;
					HTTP_BUILD_FILEPATH(imfilename, HTTP_APPL_PATH, httpFlowP->appl[httpFlowP->appl_c-1]);
					break;
#endif // HTTP_SAVE_APPL == 1
#if HTTP_SAVE_PUNK == 1
				case HTTP_F_PLD_PUNK_S:
					if (httpFlowP->unknwn_c > HTTP_DATA_C_MAX) return;
					HTTP_BUILD_FILEPATH(imfilename, HTTP_PUNK_PATH, httpFlowP->punk[httpFlowP->unknwn_c-1]);
					break;
#endif // HTTP_SAVE_PUNK == 1

				default:
					httpFlowP->flags &= ~HTTP_F_PLD_S;
					goto chkbdy;
			}

			if (httpFlowP->cFlags & HTTP_STRM1) {
				if ((httpFlowP->fd = file_manager_open(t2_file_manager, imfilename, "r+b")) == NULL) {
					httpFlowP->fd = file_manager_open(t2_file_manager, imfilename, "w+b");
				}
			} else {
				httpFlowP->fd = file_manager_open(t2_file_manager, imfilename, "w+b");
			}

			if (httpFlowP->fd == NULL) {
				static uint8_t svStat = 0;
				if (!svStat) {
					T2_PERR("httpSniffer", "Failed to open file '%s': %s", imfilename, strerror(errno));
					svStat = 1;
				}
				//terminate();
				return;
			}
			httpFlowP->flags |= HTTP_F_SEQ_INIT;
			if (http_data_len) httpFlowP->flags |= HTTP_F_SHFT;
			httpFlowP->flags &= ~HTTP_F_HTTP_HDR;

			if (++http_fd_cnt > http_fd_max) http_fd_max = http_fd_cnt;
		}
#endif // HTTP_SAVE == 1
	}

#if HTTP_SAVE == 1
chkbdy:
#endif // HTTP_SAVE == 1

#if (HTTP_BODY == 1 && HTTP_TEXT == 1)
	if ((httpFlowP->mimeTypes & HTTP_C_TEXT)
#if HTTP_BDURL == 1
		&& (httpFlowP->refURL_c < HTTP_DATA_C_MAX)
#endif // HTTP_BDURL == 1
	) { // text
		if ((dp = strnstr(data_ptr, "\"Refresh\"", http_data_len))) {
			for (i = 9; i < http_data_len - (dp - data_ptr); i++) {
				if (dp[i] == '>') {
					if ((dp1 = strnstr(dp + 9, "URL", i - 9))) {
						httpFlowP->cFlags |= HTTP_REFRESH;
#if HTTP_BDURL == 1
						if ((dp2 = memchr(dp1 + 4, '"', dp + i - dp1 - 4))) {
							j = dp2 - dp1 - 4;
							if (j > 0) {
								name_p = malloc(j + 1);
								memcpy(name_p, dp1 + 4, j);
								name_p[j] = '\0';
								httpFlowP->refURL[httpFlowP->refURL_c++] = name_p;
							}
						}
#endif // HTTP_BDURL == 1
					}
					break;
				}
			}
		}
	}
#endif // (HTTP_BODY == 1 && HTTP_TEXT == 1)

	if (httpFlowP->flags & HTTP_F_DETECT) {
		if (http_data_len >= 2 && *(uint16_t*)data_ptr == 0x5a4d) httpFlowP->aFlags |= HTTP_A_DEXE;
		if (http_data_len >= 4 && *(uint32_t*)data_ptr == 0x464c4547) httpFlowP->aFlags |= HTTP_A_DELF;
		if ((dp = strnstr(data_ptr, STREAM_INF, http_data_len))) {
			httpFlowP->cFlags |= HTTP_STRM;
			if (httpFlowPO) httpFlowPO->cFlags |= HTTP_STRM;
		}
	}

	if (httpFlowPO && httpFlowPO->httpLastMeth == HEAD) return;

#if HTTP_SAVE == 1

	// if Http-Flow do analyze data
	if ((httpFlowP->flags & HTTP_F_PLD_S) && http_data_len > 0) {
		int64_t tcpSeqDiff = 0;
		uint32_t tcpSeq = 0; // absolute / relative TSN
		const uint32_t * const hdp = (uint32_t*)data_ptr;
		uint16_t http_data_len_chkd;

#if SCTP_ACTIVATE == 1
		if (packet->layer4Type == L3_SCTP) {
			const sctpChunk_t * const sctpChunk = (sctpChunk_t*)packet->layer7SCTPHeader; // the sctp chunk header
			tcpSeq = ntohl(sctpChunk->tsn_it_cta); // absolute / relative TSN
		} else
#endif // SCTP_ACTIVATE == 1
		if (packet->layer4Type == L3_TCP) {
			const tcpHeader_t * const tcpHeader = (tcpHeader_t*)packet->layer4Header; // the tcp-header
			tcpSeq = ntohl(tcpHeader->seq); // absolute / relative tcp sequence number
		} else if (!(httpFlowP->flags & HTTP_F_SEQ_INIT)) tcpSeq = httpFlowP->sniffedContent;

		if (*hdp == HTTP_IDN) {
			if (httpFlowP->fd) {
				file_manager_close(t2_file_manager, httpFlowP->fd);
				httpFlowP->fd = NULL;
				http_fd_cnt--;
			}
			httpFlowP->flags &= ~HTTP_F_S; // content processing finished
			httpFlowP->flags |= HTTP_F_HTTP_HDR;
			httpFlowP->aggContLen += httpFlowP->contentLength;
			httpFlowP->sniffedContent = 0;
			httpFlowP->contentLength = 0;
			httpFlowP->tcpSeqInit = 0;
			httpFlowP->hdr_len = 0;
			goto hdrbgn;
		}

		if (http_data_len > (httpFlowP->contentLength - httpFlowP->sniffedContent)) http_data_len_chkd = httpFlowP->contentLength - httpFlowP->sniffedContent;
		else http_data_len_chkd = http_data_len;

		if (httpFlowP->flags & HTTP_F_SEQ_INIT) {
			httpFlowP->tcpSeqInit = tcpSeq;
			if (packet->layer4Type == L3_SCTP) httpFlowP->seq = http_data_len_chkd;
			httpFlowP->hdr_len = packet->snapL7Length - http_data_len_chkd;
			httpFlowP->flags &= ~HTTP_F_SEQ_INIT;
		} else if (httpFlowP->flags & HTTP_F_CHKD) {
			line_eptr = http_get_linesize(data_ptr, http_data_len_chkd); // size of current line (if 0 header is completely read)
			if (line_eptr) {
				line_size = (uint16_t)(line_eptr - data_ptr); // size of current line (if 0 header is completely read)
				if (line_eptr[2] == 0x0d) {
					p = memchr(line_eptr+4, '\r', http_data_len_chkd - line_size);
					if (p) {
						*p = 0x00;
						sscanf(line_eptr, "%x", &i);
						*p = 0x0d;
					}
				} else {
					*line_eptr = 0x00;
					sscanf(data_ptr, "%x", &i);
					*line_eptr = 0x0d;
				}
				if (i) {
					data_ptr += (line_size + 2); // +2 skip line ending \r\n
					http_data_len_chkd = i;
					httpFlowP->contentLength = i;
				}
			}
		}

		if (packet->layer4Type == L3_SCTP) tcpSeqDiff = (tcpSeq - httpFlowP->tcpSeqInit) * httpFlowP->seq;
		else tcpSeqDiff = tcpSeq - httpFlowP->tcpSeqInit;

		j = tcpSeqDiff - httpFlowP->sniffedContent;
		if (tcpSeqDiff && httpFlowP->flags & HTTP_F_SHFT) j -= httpFlowP->hdr_len; // remove header part

		if (packet->layer4Type == L3_UDP) j = 0;

		FILE *fp = file_manager_fp(t2_file_manager, httpFlowP->fd);

		if (!(httpFlowP->flags & HTTP_F_CHKD)) {
			if (j) { // appropriate transmission j == 0
				httpFlowP->aFlags |= HTTP_F_SQ_NM;
				if (httpFlowP->cFlags & HTTP_STRM1) {
					fseek(fp, httpFlowP->aggContLen + tcpSeqDiff - httpFlowP->hdr_len, SEEK_SET);
				} else {
					fseek(fp, tcpSeqDiff - httpFlowP->hdr_len, SEEK_SET);
				}
			} else if (httpFlowP->cFlags & HTTP_STRM1) fseek(fp, 0, SEEK_END);
			else fseek(fp, tcpSeqDiff - httpFlowP->hdr_len, SEEK_SET);
		}

		if (UNLIKELY(http_data_len_chkd != fwrite(data_ptr, 1, http_data_len_chkd, fp))) {
			T2_PERR("httpSniffer", "Failed to write to file '%s': %s", imfilename, strerror(errno));
			file_manager_close(t2_file_manager, httpFlowP->fd);
			terminate();
		}

		if (j >= 0) httpFlowP->sniffedContent += http_data_len_chkd; // more sniffed content

		if (packet->layer4Type == L3_SCTP) httpFlowP->seq = http_data_len_chkd;
		else httpFlowP->seq = tcpSeq;

		if (httpFlowP->contentLength <= httpFlowP->sniffedContent) {
			if (httpFlowP->flags & HTTP_F_CHKD) {
				do {
					i = http_data_len_chkd + 2;
					data_ptr += i;
					line_eptr = http_get_linesize(data_ptr, http_data_len - i); // size of current line (if 0 header is completely read)
					if (!line_eptr) {
						httpFlowP->contentLength = 0;
						return;
					}
					line_size = (uint16_t)(line_eptr - data_ptr);

					*line_eptr = 0x00;
					sscanf(data_ptr, "%x", &(httpFlowP->contentLength));
					*line_eptr = 0x0d;
					if (httpFlowP->contentLength == 0) break;
					i = line_size + 2; // +2 skip line ending \r\n
					data_ptr += i;
					http_data_len -= (http_data_len_chkd + i);
					fwrite(data_ptr, 1, http_data_len, fp);
					httpFlowP->sniffedContent += http_data_len_chkd; // more sniffed content
				} while (httpFlowP->contentLength < httpFlowP->sniffedContent);

				if (httpFlowP->contentLength) {
					httpFlowP->flags &= ~HTTP_F_SHFT;
					httpFlowP->sniffedContent = http_data_len;
					httpFlowP->tcpSeqInit = tcpSeq;
					return;
				}
			}

			if (httpFlowP->fd) {
				file_manager_close(t2_file_manager, httpFlowP->fd);
				httpFlowP->fd = NULL;
				http_fd_cnt--;
			}
			httpFlowP->flags &= ~HTTP_F_S; // content processing finished
			httpFlowP->flags |= HTTP_F_HTTP_HDR;
			httpFlowP->aggContLen += httpFlowP->contentLength;
			httpFlowP->sniffedContent = 0;
			httpFlowP->contentLength = 0;
			httpFlowP->tcpSeqInit = 0;
			httpFlowP->hdr_len = 0;
			http_data_len = 0;
		}
	}
#endif // HTTP_SAVE == 1
}


void onFlowTerminate(unsigned long flowIndex) {
	uint32_t j;
	uint_fast32_t i;
	http_flow_t * const httpFlowP = &(http_flow[flowIndex]);

#if HTTP_SAVE == 1
	if (httpFlowP->fd) {
		file_manager_close(t2_file_manager, httpFlowP->fd);
		httpFlowP->fd = NULL;
		http_fd_cnt--;
	}
#endif // HTTP_SAVE == 1

	if (!(httpFlowP->flags & HTTP_F_HTTP)) httpFlowP->flags = 0;

	sflgs |= httpFlowP->flags;
	mflgs |= httpFlowP->mimeTypes;
	aflgs |= httpFlowP->aFlags;
	cflgs |= httpFlowP->cFlags;

	imageCnt += httpFlowP->image_c;
	videoCnt += httpFlowP->video_c;
	audioCnt += httpFlowP->audio_c;
	textCnt += httpFlowP->text_c;
	msgCnt += httpFlowP->msg_c;
	applCnt += httpFlowP->appl_c;
	unkCnt += httpFlowP->unknwn_c;

	httpGetCnt += httpFlowP->getCnt;
	httpPstCnt += httpFlowP->pstCnt;

	outputBuffer_append(main_output_buffer, (char*) &(httpFlowP->flags), sizeof(uint16_t));      // Flags
	outputBuffer_append(main_output_buffer, (char*) &(httpFlowP->aFlags), sizeof(uint16_t));     // aFlags
	outputBuffer_append(main_output_buffer, (char*) &(httpFlowP->httpMethods), sizeof(uint8_t)); // Methods
	outputBuffer_append(main_output_buffer, (char*) &(httpFlowP->mimeTypes), sizeof(uint16_t));  // Mime Types
#if HTTP_BODY == 1
	outputBuffer_append(main_output_buffer, (char*) &(httpFlowP->cFlags), sizeof(uint16_t)); // Content flags
#endif // HTTP_BODY
#if HTTP_MCNT == 1
	outputBuffer_append(main_output_buffer, (char*) &(httpFlowP->getCnt), 2 * sizeof(uint16_t));
#endif // HTTP_MCNT == 1

#if HTTP_STAT == 1
	// print http status in flow file
	outputBuffer_append(main_output_buffer, (char*) &(httpFlowP->stat_c), sizeof(uint16_t)); // ++ counts

	j = MIN(httpFlowP->stat_c, HTTP_DATA_C_MAX);
	outputBuffer_append(main_output_buffer, (char*) &j, sizeof(uint32_t));
	for (i = 0; i < j; i++) {
		outputBuffer_append(main_output_buffer, (char*)(&httpFlowP->stat[i]), sizeof(uint16_t));
	}
#endif // HTTP_STAT == 1

	outputBuffer_append(main_output_buffer, (char*) &(httpFlowP->url_c), 17 * sizeof(uint16_t)); // ++ counts

#if HTTP_HOST == 1
	HTTP_APPEND_REP_STR(httpFlowP->host, httpFlowP->host_c);
#endif // HTTP_HOST == 1

#if HTTP_URL == 1
	HTTP_APPEND_REP_STR(httpFlowP->url, httpFlowP->url_c);
#endif // HTTP_URL == 1

#if HTTP_MIME == 1
	HTTP_APPEND_REP_STR(httpFlowP->mime, httpFlowP->mime_c);
#endif // HTTP_MINE == 1

#if HTTP_COOKIE == 1
	HTTP_APPEND_REP_STR(httpFlowP->cookie, httpFlowP->cookie_c);
#endif // HTTP_COOKIE == 1

#if HTTP_IMAGE == 1
	HTTP_APPEND_REP_STR(httpFlowP->image, httpFlowP->image_c);
#endif // HTTP_IMAGE == 1

#if HTTP_VIDEO == 1
	HTTP_APPEND_REP_STR(httpFlowP->video, httpFlowP->video_c);
#endif // HTTP_VIDEO == 1

#if HTTP_AUDIO == 1
	HTTP_APPEND_REP_STR(httpFlowP->audio, httpFlowP->audio_c);
#endif // HTTP_AUDIO == 1

#if HTTP_MSG == 1
	HTTP_APPEND_REP_STR(httpFlowP->msg, httpFlowP->msg_c);
#endif // HTTP_MSG == 1

#if HTTP_APPL == 1
	HTTP_APPEND_REP_STR(httpFlowP->appl, httpFlowP->appl_c);
#endif // HTTP_APPL == 1

#if HTTP_TEXT == 1
	HTTP_APPEND_REP_STR(httpFlowP->text, httpFlowP->text_c);
#endif // HTTP_TEXT == 1

#if HTTP_PUNK == 1
	HTTP_APPEND_REP_STR(httpFlowP->punk, httpFlowP->unknwn_c);
#endif // HTTP_PUNK == 1

#if (HTTP_BODY == 1 && HTTP_BDURL == 1)
	// print body set-cookie, refresh URL in flow file
	HTTP_APPEND_REP_STR(httpFlowP->refURL, httpFlowP->refURL_c);
#endif // (HTTP_BODY == 1 && HTTP_BDURL == 1)

#if HTTP_USRAG == 1
	HTTP_APPEND_REP_STR(httpFlowP->usrAg, httpFlowP->usrAg_c);
#endif // HTTP_USRAG == 1

#if HTTP_XFRWD == 1
	HTTP_APPEND_REP_STR(httpFlowP->xFor, httpFlowP->xFor_c);
#endif // HTTP_XFRWD == 1

#if HTTP_REFRR == 1
	HTTP_APPEND_REP_STR(httpFlowP->refrr, httpFlowP->refrr_c);
#endif // HTTP_REFRR == 1

#if HTTP_VIA == 1
	HTTP_APPEND_REP_STR(httpFlowP->via, httpFlowP->via_c);
#endif // HTTP_VIA == 1

#if HTTP_LOC == 1
	HTTP_APPEND_REP_STR(httpFlowP->loc, httpFlowP->loc_c);
#endif // HTTP_LOC == 1

#if HTTP_SERV == 1
	HTTP_APPEND_REP_STR(httpFlowP->serv, httpFlowP->serv_c);
#endif // HTTP_SERV == 1

#if HTTP_PWR == 1
	HTTP_APPEND_REP_STR(httpFlowP->pwr, httpFlowP->pwr_c);
#endif // HTTP_PWR == 1
}


void pluginReport(FILE *stream) {
	if (totalHttpPktCnt) {
#if HTTP_SAVE == 1
		T2_FPLOG_NUM(stream, "httpSniffer", "Max number of file handles", http_fd_max);
#endif // HTTP_SAVE == 1
		T2_FPLOG_NUMP(stream, "httpSniffer", "Number of HTTP packets", totalHttpPktCnt, numPackets);
		T2_FPLOG_NUMP(stream, "httpSniffer", "Number of HTTP GET  requests", httpGetCnt, totalHttpPktCnt);
		if (httpPstCnt) {
			T2_FPLOG_NUMP0(stream, "httpSniffer", "Number of HTTP POST requests", httpPstCnt, totalHttpPktCnt);
			T2_FPLOG(stream, "httpSniffer", "HTTP GET/POST ratio: %.2f", httpGetCnt/(double)httpPstCnt);
		}
		const uint16_t sflags = (uint16_t)(sflgs & ~HTTP_F_HTTP_HDR);
		if (sflags) T2_FPLOG(stream, "httpSniffer", "Aggregated status flags : 0x%04"B2T_PRIX16, sflags);
		if (aflgs) T2_FPLOG(stream, "httpSniffer", "Aggregated anomaly flags: 0x%04"B2T_PRIX16, aflgs);
#if HTTP_BODY == 1
		if (cflgs) T2_FPLOG(stream, "httpSniffer", "Aggregated content flags: 0x%04"B2T_PRIX16, cflgs);
#endif
		if (mflgs) T2_FPLOG(stream, "httpSniffer", "Aggregated mime type    : 0x%04"B2T_PRIX16, mflgs);

		const bool has_cnt = (imageCnt || videoCnt || audioCnt || textCnt || msgCnt || applCnt || unkCnt);
		if (has_cnt) {
			T2_FPLOG(stream, "httpSniffer", "Aggregated Cnts img_vid_aud_txt_msg_app_unk: "
					"%"PRIu32"_%"PRIu32"_%"PRIu32"_%"PRIu32"_%"PRIu32"_%"PRIu32"_%"PRIu32,
					imageCnt, videoCnt, audioCnt, textCnt, msgCnt, applCnt, unkCnt);
		}
	}
}


void monitoring(FILE *stream, uint8_t state) {

	switch (state) {

		case T2_MON_PRI_HDR:
			fputs("httpPkts\t", stream); // Note the trailing tab (\t)
			return;

		case T2_MON_PRI_VAL:
			fprintf(stream, "%"PRIu64"\t", totalHttpPktCnt); // Note the trailing tab (\t)
			break;

		case T2_MON_PRI_REPORT:
			T2_FPLOG_DIFFNUMP(stream, "httpSniffer", "Number of HTTP packets", totalHttpPktCnt, numPackets);
			break;

		default:  // Invalid state, do nothing
			return;
	}

#if DIFF_REPORT == 1
	totalHttpPktCnt0 = totalHttpPktCnt;
#endif // DIFF_REPORT == 1
}


void onApplicationTerminate() {
	free(http_flow);
}


static inline char* http_read_header_data(char* data, uint16_t data_len, const char *header, uint16_t header_len) {
	if (strncasecmp(data, header, header_len) != 0) return 0; // data not found..

	while (header_len < data_len && data[header_len] == ' ') header_len++;

	return &data[header_len];
}


static inline char* http_get_linesize(char *data, int32_t http_data_len) {
	if (http_data_len < 2) return NULL;
	return memmem(data, http_data_len, HTTP_HEADER_CRLF, sizeof(HTTP_HEADER_CRLF)-1);
}


static inline http_mimetype http_read_mimetype(const char *data, size_t n) {
	size_t mime_size = 0;
	while (mime_size < n && data[mime_size] != '/') ++mime_size;

	if (strncmp(data, "application", mime_size) == 0) return application;
	else if (strncmp(data, "audio", mime_size) == 0) return audio;
	else if (strncmp(data, "image", mime_size) == 0) return image;
	else if (strncmp(data, "message", mime_size) == 0) return message;
	else if (strncmp(data, "model", mime_size) == 0) return model;
	else if (strncmp(data, "multipart", mime_size) == 0) return multipart;
	else if (strncmp(data, "text", mime_size) == 0) return text;
	else if (strncmp(data, "video", mime_size) == 0) return video;
	else if (strncmp(data, "vnd", mime_size) == 0) return vnd;
	else if (strncmp(data, "x-pkcs", mime_size) == 0) return xpkcs;
	else if (strncmp(data, "x", mime_size) == 0) return x;

	return allelse;
}
