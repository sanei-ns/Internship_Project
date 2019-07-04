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

#ifndef _HTTP_SNIFFER_H
#define _HTTP_SNIFFER_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif // _GNU_SOURCE

// local includes
#include "global.h"
#include "fsutils.h"

// User defined output switches
#define HTTP_MIME      1 // 1: print mime type in flow file; 0: print # of mime types only
#define HTTP_STAT      1 // 1: print response status code in flow file; 0: print # of status codes only
#define HTTP_MCNT      1 // 1: method counts: get,post
#define HTTP_HOST      1 // 1: print hosts in flow file; 0: print # of hosts only
#define HTTP_URL       1 // 1: print url in flow file; 0: print # of hosts only
#define HTTP_COOKIE    1 // 1: print cookies in flow file; 0: print # of cookies only
#define HTTP_IMAGE     1 // 1: print image name in flow file; 0: print # of images only
#define HTTP_VIDEO     1 // 1: print video name in flow file; 0: print # of videos only
#define HTTP_AUDIO     1 // 1: print audio name in flow file; 0: print # of audios only
#define HTTP_MSG       1 // 1: print pdf name in flow file; 0: print # of pdf only
#define HTTP_APPL      1 // 1: print application name in flow file; 0: print # of applications only
#define HTTP_TEXT      1 // 1: print text name in flow file; 0: print # of texts only
#define HTTP_PUNK      1 // 1: print post/unknown and all else name in flow file; 0: print # of post/unknown/else only
#define HTTP_BODY      1 // 1: content body exam, print anomaly bits in flow file; 0: none
#define HTTP_BDURL     1 // 1: print body url name in flow file; 0: none
#define HTTP_USRAG     1 // 1: print user agents in flow file; 0: none
#define HTTP_XFRWD     1 // 1: print x-forward-for in flow file; 0: none
#define HTTP_REFRR     1 // 1: print Referer in flow file; 0: none
#define HTTP_VIA       1 // 1: print Via in flow file; 0: none
#define HTTP_LOC       1 // 1: print Location in flow file; 0: none
#define HTTP_SERV      1 // 1: print Server in flow file; 0: none
#define HTTP_PWR       1 // 1: print Powered by in flow file; 0: none

#define HTTP_STATAGA   1 // 1: aggregate Stat reponse in flow file; 0: dont
#define HTTP_MIMEAGA   1 // 1: aggregate Mime reponse in flow file; 0: dont
#define HTTP_HOSTAGA   1 // 1: aggregate Host in flow file; 0: dont
#define HTTP_URLAGA    1 // 1: aggregate URL in flow file; 0: dont
#define HTTP_USRAGA    1 // 1: aggregate User agents in flow file; 0: dont
#define HTTP_XFRWDA    1 // 1: aggregate X-forward-for in flow file; 0: dont
#define HTTP_REFRRA    1 // 1: aggregate Referer in flow file; 0: dont
#define HTTP_VIAA      1 // 1: aggregate Via in flow file; 0: dont
#define HTTP_LOCA      1 // 1: aggregate Location in flow file; 0: dont
#define HTTP_SERVA     1 // 1: aggregate Server in flow file; 0: dont
#define HTTP_PWRA      1 // 1: aggregate Powered by in flow file; 0: dont

//#define HTTP_ENT  0    // entropy calculation, not implemented yet

// data carving modes
#define HTTP_SAVE_IMAGE   0 // 1: Save images in files under HTTP_IMAGE_PATH; 0: Dont save images
#define HTTP_SAVE_VIDEO   0 // 1: Save videos in files under HTTP_VIDEO_PATH; 0: Dont save videos
#define HTTP_SAVE_AUDIO   0 // 1: Save audios in files under HTTP_TEXT_PATH; 0: Dont save audios
#define HTTP_SAVE_MSG     0 // 1: Save messages in files under HTTP_MSG_PATH; 0: Dont save pdfs
#define HTTP_SAVE_TEXT    0 // 1: Save texts in files under HTTP_TEXT_PATH; 0: Dont save text
#define HTTP_SAVE_APPL    0 // 1: Save applications in files under HTTP_TEXT_PATH; 0: Dont save applications
#define HTTP_SAVE_PUNK    0 // 1: Save put/else content in files under HTTP_PUNK_PATH; 0: Dont save put content
#define HTTP_RM_PICDIR    1 // if HTTP_SAVE == 1 then remove pic dir in order to prevent appending to existing files

#define HTTP_SAVE (HTTP_SAVE_IMAGE | HTTP_SAVE_VIDEO | HTTP_SAVE_AUDIO | HTTP_SAVE_MSG | HTTP_SAVE_TEXT | HTTP_SAVE_APPL | HTTP_SAVE_PUNK)
// User defined storage boundary conditions
#define HTTP_PATH "/tmp/" // root path

#define HTTP_IMAGE_PATH HTTP_PATH"httpPicture/" // Path for pictures
#define HTTP_VIDEO_PATH HTTP_PATH"httpVideo/"   // Path for videos
#define HTTP_AUDIO_PATH HTTP_PATH"httpAudio/"   // Path for audios
#define HTTP_MSG_PATH   HTTP_PATH"httpMSG/"     // Path for messages
#define HTTP_TEXT_PATH  HTTP_PATH"httpText/"    // Path for texts
#define HTTP_APPL_PATH  HTTP_PATH"httpAppl/"    // Path for applications
#define HTTP_PUNK_PATH  HTTP_PATH"httpPunk/"    // Path for Post / else / unknown content

#define HTTP_NONAME "nudel" // name of files without name

#define HTTP_DATA_C_MAX  40 // maximum dimension of storage arrays per flow
#define HTTP_CNT_LEN     13 // max # of cnt digits attached to file name.
#define HTTP_FINDEX_LEN  20 // string length of findex in decimal format
#define HTTP_MXFILE_LEN  80 // maximum storage name length
#define HTTP_MXUA_LEN   400 // user agent name
#define HTTP_MXXF_LEN    80 // xforwrd length
//#define HTTP_MXCK_LEN   150 // maximum cookie

#define HTTP_MAXPBIN (1 << 8)

// def & Calculate name lengths
#define HTTP_NONAME_LEN (sizeof(HTTP_NONAME) + HTTP_CNT_LEN + HTTP_FINDEX_LEN) // Standard name of files without name: name_findex_pkt_num
#define HTTP_MXIMNM_LEN (sizeof(HTTP_IMAGE_PATH) + HTTP_NONAME_LEN + HTTP_MXFILE_LEN + 1) // maximum name length

// http_status_flags
#define HTTP_F_OVRFLW     0x0001 // More Data in Flow than HTTP_DATA_C_MAX can save
#define HTTP_F_FNM_LN     0x0002 // Filename larger than HTTP_MXIMNM_LEN or Linux def
#define HTTP_F_GET        0x0004 // Internal State: pending url name
#define HTTP_F_HTTP       0x0008 // HTTP Flow
#define HTTP_F_CHKD       0x0010 // Internal State: Chunked transfer
#define HTTP_F_DETECT     0x0020 // Internal State: HTTP Flow detected
#define HTTP_F_HTTP_HDR   0x0040 // Internal State: http hdr in process
#define HTTP_F_SEQ_INIT   0x0080 // Internal State: sequence number init
#define HTTP_F_SHFT       0x0100 // Internal State: header shift
#define HTTP_F_PLD_PUNK_S 0x0200 // Internal State: PUT payload sniffing
#define HTTP_F_PLD_IMG_S  0x0400 // Internal State: Image payload sniffing
#define HTTP_F_PLD_VID_S  0x0800 // Internal State: video payload sniffing
#define HTTP_F_PLD_AUD_S  0x1000 // Internal State: audio payload sniffing
#define HTTP_F_PLD_MSG_S  0x2000 // Internal State: message payload sniffing
#define HTTP_F_PLD_TXT_S  0x4000 // Internal State: text payload sniffing
#define HTTP_F_PLD_APP_S  0x8000 // Internal State: application payload sniffing

#define HTTP_F_PLD_S      0xfe00 // Internal states mask: Payload sniffing
#define HTTP_F_S          0xfff0 // Internal states mask: Internal State

// http anomaly
#define HTTP_A_PST        0x0001 // POST | ? anomaly
#define HTTP_A_HNUM       0x0002 // host is ipv4
#define HTTP_A_DGA        0x0004 // Possible DGA
#define HTTP_A_MCTYP      0x0008 // Mismatched content-type
#define HTTP_F_SQ_NM      0x0010 // Sequence number violation
#define HTTP_F_PRS_ERR    0x0020 // Parse Error
#define HTTP_A_HDR_WO_VAL 0x0040 // header without value, e.g., Content-Type: [missing] (TODO currently only implemented for content-type)
#define HTTP_A_XSSP       0x0100 // X-Site Scripting protection
#define HTTP_A_CSP        0x0200 // Content Security Policy
#define HTTP_A_DNT        0x0400 // Do not track
#define HTTP_A_DEXE       0x1000 // EXE download
#define HTTP_A_DELF       0x2000 // ELF download
#define HTTP_A_1_0        0x4000 // HTTP 1.0

// http content flags
#define HTTP_STCOOKIE  0x0001 // http set cookie
#define HTTP_REFRESH   0x0002 // http refresh
#define HTTP_HOSTNME   0x0004 // host name
#define HTTP_BOUND     0x0008 // Boundary
#define HTTP_PCNT      0x0010 // potential http content
#define HTTP_STRM      0x0020 // Stream
#define HTTP_QUARA     0x0040 // Quarantine virus upload
#define HTTP_STRM1     0x8000 // Stream1

// content Types
#define HTTP_C_APPL   0x0001  // Application
#define HTTP_C_AUDIO  0x0002  // Audio
#define HTTP_C_IMAGE  0x0004  // Image
#define HTTP_C_MSG    0x0008  // Message
#define HTTP_C_MODEL  0x0010
#define HTTP_C_MLTPRT 0x0020
#define HTTP_C_TEXT   0x0040
#define HTTP_C_VIDEO  0x0080
#define HTTP_C_VND    0x0100
#define HTTP_C_X      0x0200
#define HTTP_C_XPKCS  0x0400
#define HTTP_C_PDF    0x1000
#define HTTP_C_JAVA   0x2000

#define HTTP_IDN 0x50545448
#define HTTP_ID "HTTP/1." // detect all HTTP/1.* - protocols
#define SIP_ID  "SIP/"    // detect all SIP/ - protocols

#define HTTP_HEADER_LINEEND { '\r', '\n' }
#define HTTP_HEADER_CRLF "\r\n"
#define HTTP_COOKIE_VALSEPARATOR_C 2
#define HTTP_COOKIE_VALSEPARATOR ";"
#define HTTP_COOKIE_SEPARATOR '='

// definition of content types
#define CONTENT_TYPE     "Content-type:"
#define CONTENT_DISP     "Content-Disposition:"
#define CONTENT_LENGTH   "Content-Length:"
#define CONTENT_ENCODING "Content-Encoding:"
#define TRANS_ENCODING   "Transfer-Encoding:"
#define SET_COOKIE       "Cookie:"
#define USER_AGENT       "User-Agent:"
#define HOST             "Host:"
#define X_FORWRD_FOR     "X-Forwarded-For:"
#define REFERER          "Referer:"
#define VIA              "Via:"
#define LOC              "Location:"
#define SERVER           "Server:"
#define CONTTRNSECDG     "Content-Transfer-Encoding:"
#define POWERED          "X-Powered-By:"
#define XXSSPROT         "X-XSS-Protection:"
#define CONTSECPOL       "Content-Security-Policy:"
#define FILENAME         "filename="
#define BOUNDARY         "boundary="
#define QUARANTINE       "quarantine"
#define UPLOAD           "upload"
#define STREAM           "#EXTM3U"
#define DNT              "DNT: 1"
#define STREAM_INF       "#EXT-X-STREAM-INF:"

// methods
#define RESPONSE 0x00
#define OPTIONS  0x01
#define GET      0x02
#define HEAD     0x04
#define POST     0x08
#define PUT      0x10
#define DELETE   0x20
#define TRACE    0x40
#define CONNECT  0x80

#define SRESPONSE "RESPONSE"
#define SOPTIONS  "OPTIONS"
#define SGET      "GET"
#define SHEAD     "HEAD"
#define SPOST     "POST"
#define SPUT      "PUT"
#define SDELETE   "DELETE"
#define STRACE    "TRACE"
#define SCONNECT  "CONNECT"

// mime type
typedef enum {
    application = 0x0001,
    audio       = 0x0002,
    image       = 0x0004,
    message     = 0x0008,
    model       = 0x0010,
    multipart   = 0x0020,
    text        = 0x0040,
    video       = 0x0080,
    vnd         = 0x0100,
    x           = 0x0200,
    xpkcs       = 0x0400,
    allelse     = 0x8000,
} http_mimetype;

// plugin structs
typedef struct {
#if HTTP_SAVE == 1
    file_object_t *fd;       // file descriptor per flow
#endif // HTTP_SAVE == 1
    uint64_t aggContLen;
    uint32_t pktcnt;         // packet count for stored info
    uint32_t tcpSeqInit;     // initial Tcp Sequence number if in sniff-content
    uint32_t seq;            // last Tcp Sequence number if in sniff-content
    uint32_t contentLength;  // The last Http-Content-Length field
    uint32_t sniffedContent; // Amount of sniffed content
    uint32_t hdr_len;        // header length
    uint16_t mimeTypes;      // mime types in flow
    uint16_t getCnt;
    uint16_t pstCnt;
    uint16_t host_c;         // # of host names in Flow
    uint16_t stat_c;         // # of status codes in Flow
    uint16_t url_c;          // # of url names in Flow
    uint16_t via_c;          // # of via proxies in Flow
    uint16_t loc_c;          // # of location in Flow
    uint16_t serv_c;         // # of server in Flow
    uint16_t pwr_c;          // # of powered by in Flow
    uint16_t usrAg_c;        // # of user agent info in flow
    uint16_t xFor_c;         // # of xFor in Flow
    uint16_t refrr_c;        // # of referer in Flow
    uint16_t cookie_c;       // # of cookies in flow
    uint16_t mime_c;         // # of mime types in Flow
    uint16_t image_c;        // # of images in flow
    uint16_t video_c;        // # of videos in flow
    uint16_t audio_c;        // # of audios in flow
    uint16_t msg_c;          // # of msgs in flow
    uint16_t text_c;         // # of texts in flow
    uint16_t appl_c;         // # of applications in flow
    uint16_t unknwn_c;       // # of unknown in flow
#if HTTP_BDURL == 1
    uint16_t refURL_c;
#endif // HTTP_BDURL == 1
    uint16_t flags;          // Http-Flags (see above)
    uint16_t aFlags;         // anomaly flags (see above)
    uint16_t cFlags;         // http Content Anomalies
#if HTTP_STAT == 1
    uint16_t stat[HTTP_DATA_C_MAX]; // http status
#endif // HTTP_STAT == 1
#if HTTP_HOST == 1
    char *host[HTTP_DATA_C_MAX];    // http host names
#endif // HTTP_HOST == 1
#if HTTP_URL == 1
    char *url[HTTP_DATA_C_MAX];     // http url names
#endif // HTTP_URL == 1
#if HTTP_MIME == 1
    char *mime[HTTP_DATA_C_MAX];    // http Mimetypes
#endif // HTTP_MIME == 1
#if HTTP_COOKIE == 1
    char *cookie[HTTP_DATA_C_MAX];  // http cookie names
#endif // HTTP_COOKIES == 1
#if (HTTP_IMAGE == 1 || HTTP_SAVE_IMAGE == 1)
    char *image[HTTP_DATA_C_MAX];   // http image names
#endif // (HTTP_IMAGES == 1 || HTTP_SAVE_IMAGES == 1)
#if (HTTP_VIDEO == 1 || HTTP_SAVE_VIDEO == 1)
    char *video[HTTP_DATA_C_MAX];   // http video names
#endif // (HTTP_VIDEO == 1 || HTTP_SAVE_VIDEO == 1)
#if (HTTP_AUDIO == 1 || HTTP_SAVE_AUDIO == 1)
    char *audio[HTTP_DATA_C_MAX];   // http audio names
#endif // (HTTP_AUDIO == 1 || HTTP_SAVE_AUDIO == 1)
#if (HTTP_MSG == 1 || HTTP_SAVE_MSG == 1)
    char *msg[HTTP_DATA_C_MAX];     // http message names
#endif // (HTTP_MSG == 1 || HTTP_SAVE_MSG == 1)
#if (HTTP_TEXT == 1 || HTTP_SAVE_TEXT == 1)
    char *text[HTTP_DATA_C_MAX];    // http text names
#endif // (HTTP_TEXT == 1 || HTTP_SAVE_TEXT == 1)
#if (HTTP_APPL == 1 || HTTP_SAVE_APPL == 1)
    char *appl[HTTP_DATA_C_MAX];    // http application names
#endif // (HTTP_APPL == 1 || HTTP_SAVE_APPL == 1)
#if (HTTP_PUNK == 1 || HTTP_SAVE_PUNK == 1)
    char *punk[HTTP_DATA_C_MAX];    // http application names
#endif // (HTTP_PUNK == 1 || HTTP_SAVE_PUNK == 1)
#if HTTP_BDURL == 1
    char *refURL[HTTP_DATA_C_MAX];  // http reference url names
#endif // HTTP_BDURL == 1
#if HTTP_USRAG == 1
    char *usrAg[HTTP_DATA_C_MAX];   // http user agent names
#endif // HTTP_USRAG == 1
#if HTTP_XFRWD == 1
    char *xFor[HTTP_DATA_C_MAX];    // http x-Forwarded-For names
#endif // HTTP_XFRWD == 1
#if HTTP_REFRR == 1
    char *refrr[HTTP_DATA_C_MAX];   // http Referer names
#endif // HTTP_REFRR == 1
#if HTTP_VIA == 1
    char *via[HTTP_DATA_C_MAX];     // http via proxy names
#endif // HTTP_VIA == 1
#if HTTP_LOC == 1
    char *loc[HTTP_DATA_C_MAX];     // http location names
#endif // HTTP_LOC == 1
#if HTTP_SERV == 1
    char *serv[HTTP_DATA_C_MAX];    // http server names
#endif // HTTP_SERV == 1
#if HTTP_PWR == 1
    char *pwr[HTTP_DATA_C_MAX];     // http powered by application
#endif // HTTP_PWR == 1
#if HTTP_ENT == 1
//    uint8_t eBinCnt[HTTP_MAXPBIN];
#endif // HTTP_ENT == 1
    char getFile[HTTP_MXIMNM_LEN+1];  // File requested by http-GET
    char *bound;
    uint8_t httpMethods;            // Bitfield Seen Http-Methods in that Flow
    uint8_t httpLastMeth;           // Last Http-Method in that Flow
} http_flow_t;

#endif // _HTTPSNIFFER_H
