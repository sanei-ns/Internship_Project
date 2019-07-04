/*
 * smbDecode.h
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

/*
 * References:
 *   [MS-SMB2]: Server Message Block (SMB) Protocol Versions 2 and 3
 *      http://download.microsoft.com/download/9/5/E/95EF66AF-9026-4BB0-A41D-A4F81802D92C/[MS-SMB2].pdf
 */

#ifndef __SMB_DECODE_H__
#define __SMB_DECODE_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif // _GNU_SOURCE

// global includes
#include <string.h>

// local includes
#include "global.h"

// user defines

#define SMB1_DECODE     1 // whether or not to decode SMB1 (experimental)
#define SMB_SECBLOB     1 // whether or not to decode security blob (experimental)

#define SMB2_NUM_DIALECT  3 // number of SMB2 dialects to store
#define SMB2_NUM_STAT    18 // number of unique SMB2 header status to store

#if SMB1_DECODE == 1
#define SMB1_NUM_DIALECT 20 // number of SMB1 dialects to store
#define SMB1_DIAL_MAXLEN 32 // maximum length for SMB1 dialects
#endif // SMB1_DECODE == 1

#define SMB_NUM_FNAME      5 // number of unique filenames to store in the flow file

#define SMB_NATIVE_NAME_LEN 64 // Max length for Native OS and LAN Manager

#define SMB2_SAVE_DATA    0 // whether or not to save files
#if SMB1_DECODE == 1
#define SMB1_SAVE_DATA    0 // whether or not to save files (SMB1, experimental)
#endif // SMB1_DECODE == 1

#define SMB_SAVE_AUTH     0 // whether or not to save NTLM authentications
#define SMB_AUTH_FILE     "smb_auth.txt" // stores NTLM authentications

#define SMB_SAVE_DIR      "/tmp/TranSMB/"         // folder for saved data
#if SMB2_SAVE_DATA == 1 || SMB1_SAVE_DATA == 1
#define SMB_MAP_FILE   "smb_filenames.txt" // stores the mapping between file ID and filename
#define SMB_RM_DATADIR      1 // whether or not to remove SMB_SAVE_DIR before starting
//#define SMB_USE_FILTER      0 // 0: save all files, 1: use whitelist, 2: use blacklist
//#if SMB_USE_FILTER > 0
//#define SMB_SAVE_FMT        "spoolss" // only save files with/without those extensions/filenames
//#endif // SMB_USE_FILTER
#endif //  SMB2_SAVE_DATA == 1 || SMB1_SAVE_DATA == 1

//#define SMB_NUM_FILE 10
#define SMB_FNAME_LEN 512

// plugin defines
#define SMB_FILE_ID "File_Id_" // used to name saved files

#define SMB_SAVE_DATA (SMB1_SAVE_DATA == 1 || SMB2_SAVE_DATA == 1)

#define NB_SESSION_PORT 139  // NetBIOS session service
#define SMB_DIRECT_PORT 445
#define NB_SS_HDR_LEN     4  // NetBIOS session server length (also used for SMB_DIRECT_PORT)
                             // 0x00, len(3 bytes)

#define SMB_READ_U16_STR(dst,src,len) \
    for (i = 0; i < (len); i++) { \
        (dst)[i] = *(src); \
        src += 2; \
    } \
    (dst)[i] = '\0';

#define SMB1_MAGIC_HDR 0x424d53ff // 0xff 'S' 'M' 'B' in network order
#define SMB2_MAGIC_HDR 0x424d53fe // 0xfe 'S' 'M' 'B' in network order
#define SMB3_MAGIC_HDR 0x424d53fd // 0xfd 'S' 'M' 'B' in network order

#define SMB1_HDR_LEN 32
#define SMB2_HDR_LEN 64
#define SMB2_SIG_LEN 16 // signature length

// SMB1 Commands
#define SMB1_CMD_OPEN_ANDX          0x2d
#define SMB1_CMD_READ_ANDX          0x2e
#define SMB1_CMD_WRITE_ANDX         0x2f
#define SMB1_CMD_TREE_CONNECT       0x70
#define SMB1_CMD_TREE_DISCONNECT    0x71
#define SMB1_CMD_NEGOTIATE          0x72
#define SMB1_CMD_SESSION_SETUP_ANDX 0x73
#define SMB1_CMD_LOGOFF             0x74
#define SMB1_CMD_TREE_CONNECT_ANDX  0x75
#define SMB1_CMD_CREATE_ANDX        0xa2

// SMB1 Flags
#define SMB1_FLAGS_REPLY        0x80 // 1: response, 0: request

// SMB1 Flags2
#define SMB1_FLAGS2_UNICODE 0x8000 // strings are encode in 16-bit unicode

// SMB1 WriteMode
#define SMB1_WM_WTHRU_MOD 0x0001 // Write-through mode
#define SMB1_WM_RB_AVAIL  0x0002 // Read bytes available
#define SMB1_WM_RAW_MODE  0x0004 // named pipe MUST be written to in raw mode (no translation)
#define SMB1_WM_MSG_START 0x0008 // start of a message (named pipes only)

// SMB2 Opcodes
#define SMB2_OP_NEGOTIATE       0x00 // Protocol negotiation
#define SMB2_OP_SESSION_SETUP   0x01 // User authentication
#define SMB2_OP_LOGOFF          0x02 // User authentication
#define SMB2_OP_TREE_CONNECT    0x03 // Share access
#define SMB2_OP_TREE_DISCONNECT 0x04 // Share access
#define SMB2_OP_CREATE          0x05 // File access
#define SMB2_OP_CLOSE           0x06 // File access
#define SMB2_OP_FLUSH           0x07 // File access
#define SMB2_OP_READ            0x08 // File access
#define SMB2_OP_WRITE           0x09 // File access
#define SMB2_OP_LOCK            0x0a // File access
#define SMB2_OP_IOCTL           0x0b // File access, Hash Retrieval (SMB 2.1)
#define SMB2_OP_CANCEL          0x0c // File access
#define SMB2_OP_ECHO            0x0d // Simple messaging
#define SMB2_OP_QUERY_DIR       0x0e // Directory access
#define SMB2_OP_CHANGE_NOTIFY   0x0f // Directory access
#define SMB2_OP_QUERY_INFO      0x10 // File/Volume access
#define SMB2_OP_SET_INFO        0x11 // File/Volume access
#define SMB2_OP_OPLOCK_BREAK    0x12 // Cache coherency
#define SMB2_OP_N               0x13 // Number of Opcodes (19)

// SMB2 Flags
#define SMB2_FLAGS_SERVER_TO_REDIR(f)    ((f) & 0x00000001) // 1: response, 0: request
#define SMB2_FLAGS_ASYNC_COMMAND(f)      ((f) & 0x00000002) // header type
#define SMB2_FLAGS_RELATED_OPERATIONS(f) ((f) & 0x00000004)
#define SMB2_FLAGS_SIGNED(f)             ((f) & 0x00000008)
#define SMB2_FLAGS_DFS_OPERATIONS(f)     ((f) & 0x10000000)
#define SMB2_FLAGS_REPLAY_OPERATION(f)   ((f) & 0x20000000) // SMB 3.x

// Use this on the SMB header, to differentiate between request/response
#define SMB2_IS_REQUEST(h) (SMB2_FLAGS_SERVER_TO_REDIR((h)->flags) == 0)

// GSS-API/SPNEGO
#define KRB5_OID   "1.2.840.113554.1.2.2"
#define NTLM_OID    0x0a02023782010404062b  // "1.3.6.1.4.1.311.2.2.10"
#define SPNEGO_OID  0x02050501062b0606      // "1.3.6.1.5.5.2"
//#define NTLMSSP     0x4e544c4d53535000      // NTLMSSP\0
#define NTLMSSP_LEN 8

// NTLMSSP Message Type
#define NTLMSSP_MT_NEGOTIATE 0x00000001
#define NTLMSSP_MT_CHALLENGE 0x00000002
#define NTLMSSP_MT_AUTH      0x00000003

// Status
#define SMB_STAT_SMB       0x0001
#define SMB_STAT_SMB2STAT  0x0002 // SMB2 header status list truncated... increase SMB2_NUM_STAT
#define SMB_STAT_DIALNAME  0x0004 // Dialect name truncated... increase SMB1_DIAL_MAXLEN
#define SMB_STAT_DIAL1L    0x0008 // SMB1 dialects list truncated... increase SMB1_NUM_DIALECT
#define SMB_STAT_DIAL2L    0x0010 // SMB2 dialects list truncated... increase SMB2_NUM_DIALECT
#define SMB_STAT_FNAMEL    0x0020 // List of accessed files truncated... increase SMB_NUM_FNAME
#define SMB_STAT_DIAL_OOB  0x0040 // selected dialect index out of bound... increase SMB1_NUM_DIALECT
#define SMB_STAT_INV_DIAL  0x0080 // selected dialect index out of bound... error (or A flow not seen)!
#define SMB_STAT_NAMETRUNC 0x0100 // Filename truncated... increase SMB_FNAME_LEN
#define SMB_STAT_AUTH      0x1000 // Authentication information extracted
#define SMB_STAT_MALFORMED 0x8000

// plugin structs

typedef struct {
    uint64_t magic;           // NTLMSSP\0
    uint32_t type;            // 0x00000001
    uint32_t flags;
    uint16_t dom_len;         // NT domain name length
    uint16_t dom_max_len;     // NT domain name max length
    uint32_t dom_off;         // NT domain name offset
    uint16_t host_len;        // local workstation name length
    uint16_t host_max_len;    // local workstation name max length
    uint32_t host_off;        // local workstation offset
} ntlmssp_negotiate_t;

typedef struct {
    uint64_t magic;         // NTLMSSP\0
    uint32_t type;          // 0x00000002
    uint16_t domlen;        // NT domain name length
    uint16_t dommaxlen;     // NT domain name max length
    uint32_t domoff;        // NT domain name offset (always 0x0030)
    uint32_t flags;
    uint8_t nonce[8];       // nonce
    uint8_t zero[8];
    uint16_t data_len;      // length of data following domain
    uint16_t data_max_len;  // length of data following domain
    uint32_t data_off;      // offset of data following domain
    //uint8_t domain[domlen]; // NT domain name
    // The following piece occurs multiple times
    //uint16_t type;        // Type of this data item
    //                      // 0x01: WINS name of server
    //                      // 0x02: NT domain name
    //                      // 0x03: DNS name of server
    //                      // 0x04: Window 2000 domain name
    //uint16_t length;      // Length in bytes of this data item
    //uint8_t data[length]; // Data
} ntlmssp_challenge_t;

typedef struct {
    uint64_t magic;           // NTLMSSP\0
    uint32_t type;            // 0x00000003

    uint16_t lm_resp_len;     // LanManager response length (always 0x18)
    uint16_t lm_resp_max_len; // LanManager response max length
    uint32_t lm_resp_off;     // LanManager response offset

    uint16_t nt_resp_len;     // NT response length (always 0x18)
    uint16_t nt_resp_max_len; // NT response max length
    uint32_t nt_resp_off;     // NT response offset

    uint16_t dom_len;         // NT domain name length
    uint16_t dom_max_len;     // NT domain name max length
    uint32_t dom_off;         // NT domain name offset (always 0x0040)

    uint16_t user_len;        // username length
    uint16_t user_max_len;    // username max length
    uint32_t user_off;        // username offset

    uint16_t host_len;        // local workstation name length
    uint16_t host_max_len;    // local workstation name max length
    uint32_t host_off;        // local workstation name offset

    uint16_t session_len;     // session key length
    uint16_t session_max_len; // session key max length
    uint32_t session_off;     // session key offset

    uint32_t flags;           // 0x00008201
    //uint8_t domain[];        // NT domain name (UCS-16LE)
    //uint8_t user[];          // username (UCS-16LE)
    //uint8_t host[];          // local workstation name (UCS-16LE)
    //uint8_t lm_resp[];       // LanManager response
    //uint8_t nt_resp[];       // NT response
} ntlmssp_auth_t;

typedef struct {
    uint8_t atag;   // 0x60
    uint8_t toklen; // token length octets
    uint8_t otag;   // 0x06: object id;
    uint8_t oidlen;
    // uint8_t OID[oidlen]
} gssapi_t;

// SMB2

typedef struct {
    uint32_t d1;
    uint16_t d2;
    uint16_t d3;
    uint8_t d4[8]; // opaque
} smb_guid_t;

typedef struct {
    uint16_t ssize;  // structure size (24)
    uint16_t flags;
    uint32_t reserved;
    smb_guid_t fid;
} smb2_close_req_t;

typedef struct {
    uint16_t ssize;     // structure size (60)
    uint16_t flags;
    uint32_t reserved;
    uint64_t ctime;     // creation time
    uint64_t atime;     // last access time
    uint64_t wtime;     // last write time
    uint64_t chgtime;   // change time
    uint64_t allocSize; // allocation size
    uint64_t eof;       // end of file
    uint32_t fattr;     // file attributes
} smb2_close_resp_t;

typedef struct {
    uint16_t ssize;         // structure size (57)
    uint8_t  secflags;      // 0
    uint8_t  oplock;        // 0,1,8,9,0xff
    uint32_t impersonation; // 0,1,2,3
    uint64_t cflags;        // create flags (should be 0)
    uint64_t reserved;      // 0
    uint32_t amask;         // desired access
    uint32_t fatt;          // file attributes
    uint32_t shacc;         // share access (1,2,4)
    uint32_t cdisp;         // create disposition (0,1,2,3,4,5)
    uint32_t copt;          // create options
    uint16_t fnameoff;      // name offset
    uint16_t fnamelen;      // name length (0: open root of the share)
    uint32_t cctxoff;       // create contexts offset
    uint32_t cctxlen;       // create contexts length
    // buffer (variable length)
} smb2_create_req_t;

typedef struct {
    uint16_t ssize;       // structure size (89)
    uint8_t  oplock;      // 0,1,8,9,0xff
    uint8_t  flags;       // SMB3
    uint32_t cact;        // create action
    uint64_t ctime;       // creation time
    uint64_t atime;       // last access time
    uint64_t wtime;       // last write time
    uint64_t chgtime;     // change time
    uint64_t allocsize;   // allocation size
    uint64_t eof;         // end of file (size of the file in bytes)
    uint32_t fatt;        // file attributes
    uint32_t resvd;       // reserved
    smb_guid_t fid;       // file id
    uint32_t cctxoff;     // create contexts offset
    uint32_t cctxlen;     // create contexts length
    // buffer (variable length)
} smb2_create_resp_t;

typedef struct {
    uint16_t ssize;    // structure size (49)
    uint8_t  padding;
    uint8_t  flags;
    uint32_t len;
    uint64_t off;      // offset
    smb_guid_t fid;    // file id
    uint32_t mincnt;   // minimum count
    uint32_t channel;
    uint32_t rembyt;   // remaining bytes
    uint32_t chInfOff; // read channel info offset
    uint32_t chInfLen; // read channel info length
    // buffer (variable length)
} smb2_read_req_t;

typedef struct {
    uint16_t ssize;    // structure size (17)
    uint8_t  doff;     // data offset
    uint8_t  resvd;    // reserved
    uint32_t dlen;     // data length
    uint32_t drem;     // data remaining
    uint32_t resvd2;   // reserved
    // buffer (variable length)
} smb2_read_resp_t;

typedef struct {
    uint16_t ssize;       // structure size (request: 49, response: 17)
    uint16_t dataoff;     // data offset (request), reserved (response)
    uint32_t datalen;     // date length (request), written bytes count (response)
    uint64_t fileoff;     // offset in destination file
    smb_guid_t fid;       // file id
    uint32_t channel;     // SMB3
    uint32_t remBytes;    // remaining bytes
    uint16_t wchanInfOff; // write channel info offset (SMB3)
    uint16_t wchanInfLen; // write channel info length (SMB3)
    uint32_t flags;
    // buffer (variable length)
} smb2_write_t;

typedef struct {
    uint16_t ssize;   // structure size (9)
    uint16_t resvd;   // flags/reserved
    uint16_t pathoff; // path offset
    uint16_t pathlen; // path length
    // buffer (variable length)
} smb2_tree_connect_req_t;

typedef struct {
    uint16_t ssize;      // structure size (16)
    uint8_t  sharetype;  // DISK, PIPE, PRINT
    uint8_t  resvd;      // reserved
    uint32_t shareflags;
    uint32_t caps;       // capabilities
    uint32_t maxacc;     // maximal access
} smb2_tree_connect_resp_t;

// Logoff, tree disconnect, echo, cancel
typedef struct {
    uint16_t ssize; // structure size (4)
    uint16_t resvd; // reserved
} smb2_logoff_t;

typedef struct {
    uint16_t ssize;      // structure size (25)
    uint8_t  flags;      // SMB3
    uint8_t  secmod;     // security mode
    uint32_t caps;       // capabilities
    uint32_t channel;
    uint16_t secbufoff;  // security buffer offset
    uint16_t secbuflen;  // security buffer length
    uint64_t prevsessid; // previous session id
    // buffer (variable length)
} smb2_session_setup_req_t;

typedef struct {
    uint16_t ssize;     // structure size (9)
    uint8_t  sflags;    // session flags (GUEST, NULL, ENCRYPT (SMB3))
    uint16_t secbufoff; // security buffer offset
    uint16_t secbuflen; // security buffer length
    // buffer (variable length)
} smb2_session_setup_resp_t;

typedef struct {
    uint16_t ssize;      // structure size (36)
    uint16_t dcnt;       // dialect count
    uint16_t secmod;     // security mode: 0x1 signing enabled, 0x2 signing required
    uint16_t resvd;      // reserved
    uint32_t caps;       // capabilities (SMB3)
    smb_guid_t guid;
    uint64_t dialdep;    // dialect dependent
    //uint16_t dialects; // array of one or more dialects: 0x202, 0x210, 0x300, 0x302, 0x311
    // padding (8 byte aligned)
} smb2_negotiate_req_t;

typedef struct {
    uint16_t ssize;     // structure size (65)
    uint16_t secmod;    // security mode: 0x1 signing enabled, 0x2 signing required
    uint16_t drev;      // dialect revision
    uint16_t resvd;     // reserved
    smb_guid_t guid;
    uint32_t caps;      // capabilities (SMB3)
    uint32_t maxTSize;  // Max transaction size
    uint32_t maxRSize;  // Max read size
    uint32_t maxWSize;  // Max write size
    uint64_t systime;   // system time
    uint64_t srvStartT; // server start time
    uint16_t secbufoff; // security buffer offset
    uint16_t secbuflen; // security buffer length
    // buffer (variable)
    // padding (variable)
    // negotiate context list (variable)
} smb2_negotiate_resp_t;

typedef struct {
    uint32_t proto_id;                // 0xfe,'S','M','B'
    uint16_t len;                     // header length (including proto_id)
    uint16_t credit_charge;
    uint32_t status;
    uint16_t opcode;                  // command being issued
    uint16_t credit;                  // Credit Request/Response
    uint32_t flags;
    uint32_t next_cmd;
    uint64_t msg_id;
    union {
        uint64_t async_id;            // if SMB2_FLAGS_ASYNC_COMMAND == 1
        struct {                      // if SMB2_FLAGS_ASYNC_COMMAND == 0
            uint32_t reserved;
            uint32_t tree_id;
        };
    };
    uint64_t session_id;
    uint8_t  signature[SMB2_SIG_LEN]; // MUST be 0 if SMB2_FLAGS_SIGNED == 0
} smb2_header_t;

// SMB1
typedef struct {
    uint8_t  wc;         // word count
    // Words
    uint8_t  AndXCommand;
    uint8_t  AndXReserved;
    uint16_t AndXOffset;
    uint8_t  Reserved;
    uint16_t NameLength;
    uint32_t Flags;
    uint32_t RootDirectoryFID;
    uint32_t DesiredAccess;
    uint64_t AllocationSize;
    uint32_t ExtFileAttributes;
    uint32_t ShareAccess;
    uint32_t CreateDisposition;
    uint32_t CreateOptions;
    uint32_t ImpersonationLevel;
    uint8_t  SecurityFlags;
    // Data
    uint16_t ByteCount;
    uint8_t  Pad;
    //uint8_t FileName[NameLength];
} __attribute__((packed)) smb1_create_andx_req_t;

typedef struct {
    uint8_t  wc;         // word count
    // Words
    uint8_t  AndXCommand;
    uint8_t  AndXReserved;
    uint16_t AndXOffset;
    uint8_t  OpLockLevel;
    uint16_t fid;
    uint32_t CreateDisposition;
    uint64_t CreateTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t LastChangeTime;
    uint32_t ExtFileAttributes;
    uint64_t AllocationSize;
    uint64_t EndOfFile;
    uint16_t ResourceType;
    uint16_t NMPipeStatus;
    uint8_t  Directory;
} __attribute__((packed)) smb1_create_andx_resp_t;

typedef struct {
    uint8_t  wc;         // word count
    uint8_t  cmd;
    uint8_t  reserved;
    uint16_t andxoff;
    uint16_t fid;
    uint32_t offset;
    uint32_t timeout;
    uint16_t wmode;      // write mode
    uint16_t remaining;
    uint16_t reserved2;
    uint16_t dlen;       // data length
    uint16_t doff;       // data offset
    uint32_t offsetHigh; // optional
    uint16_t bc;         // byte count
    uint8_t  pad;
    // uint8_t data[dlen]; (variable)
} __attribute__((packed)) smb1_write_andx_req_t;

typedef struct {
    uint8_t  wc;        // word count
    // Words
    uint8_t  AndXCommand;
    uint8_t  AndXReserved;
    uint16_t AndXOffset;
    uint16_t MaxBuffSize;
    uint16_t maxMpxCnt; // maximum number of pending requests
    uint16_t numvc;     // number of virtual circuits
    uint32_t skey;      // session key;
    // Variable
} __attribute__((packed)) smb1_session_setup_andx_req_t;

typedef struct {
    //smb1_session_setup_andx_req_t r;
    uint8_t  wc;   // word count
    // Words
    uint8_t  AndXCommand;
    uint8_t  AndXReserved;
    uint16_t AndXOffset;
    uint16_t MaxBuffSize;
    uint16_t maxMpxCnt; // maximum number of pending requests
    uint16_t numvc;     // number of virtual circuits
    uint32_t skey;      // session key;
    //// wc=10
    //uint16_t pwlen;
    //uint32_t reserved;
    // wc=12
    uint16_t secbloblen; // security blob length
    uint32_t reserved;
    uint32_t caps; // Capabilities
    //// wc=13
    //uint16_t oempwlen;
    //uint16_t unicodepwlen;
    //uint32_t reserved;
    //uint32_t caps; // Capabilities
    ////
    //// Data
    uint16_t bc; // byte count
    // Bytes
    //uint8_t secblob[secbloblen];
    //uint8_t NativeOS[];
    //uint8_t NativeLanMan[];
} __attribute__((packed)) smb1_session_setup_andx_req12_t;

typedef struct {
    uint8_t wc; // word count
    // Words
    uint8_t  AndXCommand;
    uint8_t  AndXReserved;
    uint16_t AndXOffset;
    uint16_t action;
    // wc=4
    ///uint16_t secbloblen; // security blob length
    // Data
    uint16_t bc; // byte count (security blob length if wc==4)
    // Bytes
    //uint8_t secblob[secbloblen];
    //uint8_t NativeOS[];
    //uint8_t NativeLanMan[];
    // wc=3||4
    //uint8_t PrimaryDomain[];
} __attribute__((packed)) smb1_session_setup_andx_resp_t;

typedef struct {
    uint8_t  wc; // word count
    uint16_t bc; // byte count
    // array of dialects
} __attribute__((packed)) smb1_negotiate_req_t;

typedef struct {
    uint8_t  wc;  // word count
    uint16_t sdi; // selected dialect index
    // dialect dependent...
} __attribute__((packed)) smb1_negotiate_resp_t;

typedef struct {
    uint32_t proto_id;  // 0xff,'S','M','B'
    uint8_t  cmd;
    uint32_t status;
    uint8_t  flags;
    uint16_t flags2;
    uint16_t pidhigh;   // process ID (high)
    uint64_t secfeat;   // security features
    uint16_t reserved;
    uint16_t tid;       // tree ID
    uint16_t pidlow;    // process ID (low)
    uint16_t uid;       // user ID
    uint16_t mid;       // multiplex ID
} __attribute__((packed)) smb1_header_t;

// NetBIOS session message

typedef struct {
    uint32_t zero:8;
    uint32_t reserved:7;
    uint32_t len:17; // length (network order) of the enclosed SMB2 message
} nb_session_t;

typedef struct {
    uint32_t zero:8;
    uint32_t len:24; // length (network order) of the enclosed SMB2 message
} smb_direct_tcp_t;

// SMB header status (used for reassembly)
#define SMB_HDRSTAT_NB     0x1 // incomplete NetBIOS header
#define SMB_HDRSTAT_SMB    0x2 // incomplete SMB header (version unknown)
#define SMB2_HDRSTAT_SMB2  0x3 // incomplete SMB2 header
#define SMB2_HDRSTAT_WRITE 0x4 // incomplete SMB2 write header
#define SMB2_HDRSTAT_DATA  0x5 // incomplete SMB2 data
#define SMB2_HDRSTAT_READ  0x6 // incomplete SMB2 read header
#define SMB2_HDRSTAT_RDATA 0x7 // incomplete SMB2 data (read)
#define SMB1_HDRSTAT_SMB1  0x8 // incomplete SMB1 header
#define SMB1_HDRSTAT_WRITE 0x9 // incomplete SMB1 writeAndX header
#define SMB1_HDRSTAT_DATA  0xa // incomplete SMB1 data

typedef struct {
    uint64_t msg_id; // last message id to associate request/response (SMB2)
#if SMB2_NUM_STAT > 0
    uint32_t numstat;
    uint32_t smbstat[SMB2_NUM_STAT];
#endif // SMB2_NUM_STAT > 0
    uint32_t opcodes;
    //uint32_t numPkts;
    uint32_t nopcode[SMB2_OP_N+1];

    uint16_t  stat;

    // Negotiate
    char guid[37];     // Client/Server GUID
    uint32_t maxTSize; // Max transaction size
    uint32_t maxRSize; // Max read size
    uint32_t maxWSize; // Max write size
    uint16_t sflags;   // session flags
    uint8_t  secmod;
    uint32_t caps;
#if SMB2_NUM_DIALECT > 0
    uint32_t ndialect;
    uint16_t dialect[SMB2_NUM_DIALECT];  // there could be more than one (in the request)
#endif // SMB2_NUM_DIALECT
    uint64_t bootTime;

    // Session setup
    uint64_t prevsessid; // previous session id

#if SMB1_NUM_DIALECT > 0
    // SMB1
    uint32_t ndialect1;
    char dialect1[SMB1_NUM_DIALECT][SMB1_DIAL_MAXLEN];  // there could be more than one (in the request)
#endif// SMB1_NUM_DIALECT

    char nativeos[SMB_NATIVE_NAME_LEN];
    char nativelanman[SMB_NATIVE_NAME_LEN];
    char primarydomain[SMB_NATIVE_NAME_LEN];

    // GSS-API/NTLMSSP
    char target_name[SMB_NATIVE_NAME_LEN];
    char domain_name[SMB_NATIVE_NAME_LEN];
    char user_name[SMB_NATIVE_NAME_LEN];
    char host_name[SMB_NATIVE_NAME_LEN];
    // NTLM Authentication
    char ntlmserverchallenge[16+1];
    char ntproof[32+1];
    char sessionkey[32+1]; // always 16?
#if SMB_SAVE_AUTH == 1 || SMB_SECBLOB == 1
    char ntlmclientchallenge[512]; // XXX max size???
#endif // SMB_SAVE_AUTH == 1 || SMB_SECBLOB == 1

    uint32_t numSFile;
    char sname[SMB_NUM_FNAME][SMB_FNAME_LEN];

    // Tree Connect
    char path[SMB_FNAME_LEN];
    uint8_t  sharetype;
    uint32_t shareflags;
    uint32_t sharecaps;
    uint32_t shareaccess;

    // Read
    char rname[SMB_FNAME_LEN]; // there could be more than one
    uint64_t roff;
    uint32_t rleft;

    // Write
    char fname[SMB_FNAME_LEN]; // there could be more than one
    uint64_t off;
    uint32_t left;

    // TCP reassembly
    uint8_t  hdrstat;
    uint8_t  hdroff;
    uint8_t  hdr[SMB2_HDR_LEN];
    uint32_t tcpseq;
} smb_flow_t;

#endif // __SMB_DECODE_H__
