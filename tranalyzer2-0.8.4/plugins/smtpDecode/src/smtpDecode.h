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

#ifndef SMTP_DECODE_H_
#define SMTP_DECODE_H_

// global includes

// local includes
#include "global.h"
#include "fsutils.h"

// user defines
#define SMTP_SAVE      0 // save content to SMTP_F_PATH
#define SMTP_BTFLD     0 // Bitfield coding of smtp commands
#define SMTP_RCTXT     1 // 1: print response code text
#define SMTP_MXNMLN   70 // maximal name length
#define SMTP_MXUNMLN  25 // maximal user length
#define SMTP_MXPNMLN  15 // maximal PW length
#define MAXCNM         8 // maximal number of rec,trans codes
#define MAXUNM         5 // maximal number of Users
#define MAXPNM         5 // maximal number of PWs
#define MAXSNM         8 // maximal number of server addresses
#define MAXRNM         8 // maximal number of rec EMail addresses
#define MAXTNM         8 // maximal number of trans EMail addresses

#define SMTP_CNT_LEN  13 // max # of cnt digits attached to file name (currently not used).
#define SMTP_FNDX_LEN 20 // string length of findex in decimal format

//#define SMTP_PATH "/tmp/"             // root path
#define SMTP_F_PATH "/tmp/SMTPFILES/" // Path for emails
#define SMTP_NON    "wurst"           // no name file name

// def & Calculate name lengths
#define SMTP_MXPL (SMTP_MXNMLN + SMTP_FNDX_LEN + 4)
#define SMTP_NON_FILE_LEN (sizeof(SMTP_NON) + SMTP_CNT_LEN + SMTP_FNDX_LEN) // Standard name of fles without name: wurst_dir_findex_pkt_num
#define SMTP_MXIMNM_LEN (sizeof(SMTP_F_PATH) + SMTP_NON_FILE_LEN + SMTP_MXNMLN + 1) // maximum file name length

// Plugin defines
// stat
#define SMTP_INIT 0x01 // smtp port found
#define SMTP_AUTP 0x02 // Authentication pending
#define SMTP_DTP  0x04 // data download pending
#define PWSTATE   0x08 // User PW pending
#define SMTP_PWF  0x10 // flow write finished
#define SMTP_FERR 0x40 // File error, SMTP_SAVE == 1
#define SMTP_OVFL 0x80 // array overflow

// Definition of command fields for client
#define CONN 0x4E4E4F43
#define HELO 0x4F4C4548
#define EHLO 0x4F4C4845
#define MAIL 0x4C49414D
#define RCPT 0x54504352
#define DATA 0x41544144
#define RSET 0x54455352
#define SEND 0x444E4553
#define SOML 0x4C4D4F53
#define SAML 0x4C4D4153
#define VRFY 0x59465256
#define EXPN 0x4E505845
#define HELP 0x504C4548
#define NOOP 0x504F4F4E
#define QUIT 0x54495551
#define TURN 0x4E525554
#define AUTH 0x48545541
#define STAR 0x52415453

#define SMTP_HELO 0x0001
#define SMTP_EHLO 0x0002
#define SMTP_MAIL 0x0004
#define SMTP_RCPT 0x0008
#define SMTP_DATA 0x0010
#define SMTP_RSET 0x0020
#define SMTP_SEND 0x0040
#define SMTP_SOML 0x0080
#define SMTP_SAML 0x0100
#define SMTP_VRFY 0x0200
#define SMTP_EXPN 0x0400
#define SMTP_HELP 0x0800
#define SMTP_NOOP 0x1000
#define SMTP_QUIT 0x2000
#define SMTP_TURN 0x4000
#define SMTP_AUTH 0x8000

// All chars not allowed in an eMail address.
// See RFC 822, section 3.3 and 6.1
#define SMTP_MAIL_ADDRESS_DELIMETERS "()<>,;:\\\"[] \a\b\f\n\r\t\v"

// receive codes
/*
const uint16_t smtpRec[44] = {
101,    // The server is unable to connect.
111,    // Connection refused or inability to open an SMTP stream
200,    // nonstandard success response, see rfc876
211,    // System status, or system help reply
214,    // Help message
220,    // <domain> Service ready
221,    // <domain> Service closing transmission channel
250,    // Requested mail action okay, completed
251,    // User not local; will forward to <forward-path>
252,    // Cannot VRFY user, but will accept message and attempt delivery
354,    // Start mail input; end with <CRLF>.<CRLF>
421,    // <domain> Service not available, closing transmission channel
422,    // The recipient's mailbox has exceeded its storage limit
431,    // Not enough space on the disk, or an "out of memory" condition due to a file overload
432,    // Typical side-message: "The recipient's Exchange Server incoming mail queue has been stopped"
441,    // The recipient's server is not responding
442,    // The connection was dropped during the transmission
446,    // The maximum hop count was exceeded for the message: an internal loop has occurred
447,    // Your outgoing message timed out because of issues concerning the incoming server
449,    // A routing error
450,    // Requested mail action not taken: mailbox unavailable
451,    // Requested action aborted: local error in processing
452,    // Requested action not taken: insufficient system storage
471,    // An error of your mail server, often due to an issue of the local anti-spam filter.
500,    // Syntax error, command unrecognised
501,    // Syntax error in parameters or arguments
502,    // Command not implemented
503,    // Bad sequence of commands
504,    // Command parameter not implemented
505,    // Your domain has not DNS/MX entries
510,    // Bad email address
511,    // Bad email address
512,    // A DNS error: the host server for the recipient's domain name cannot be found
513,    // Address type is incorrect": another problem concerning address misspelling. In few cases, however, it's related to an authentication issue
521,    // <domain> does not accept mail (see rfc1846)
523,    // The total size of your mailing exceeds the recipient server's limits
530,    // Normally, an authentication problem. But sometimes it's about the recipient's server blacklisting yours, or an invalid email address.
541,    // The recipient address rejected your message: normally, it's an error caused by an anti-spam filter.
550,    // Requested action not taken: mailbox unavailable
551,    // User not local; please try <forward-path>
552,    // Requested mail action aborted: exceeded storage allocation
553,    // Requested action not taken: mailbox name not allowed
554,    // Transaction failed
557,    // Access denied
}
*/

// output structs:
typedef struct {
#if SMTP_SAVE == 1
    file_object_t *fd;     // file descriptor per flow
    uint32_t seqInit;
#endif // SMTP_SAVE == 1
//  uint32_t tCode[MAXCNM];
    uint16_t sendCode;
    uint16_t recCode[MAXCNM];
    uint8_t tCode[MAXCNM];
    char nameU[MAXUNM][SMTP_MXUNMLN+1];
    char nameP[MAXPNM][SMTP_MXPNMLN+1];
    char nameS[MAXSNM][SMTP_MXNMLN+1];
    char nameR[MAXRNM][SMTP_MXNMLN+1];
    char nameT[MAXTNM][SMTP_MXPL+1];
    uint8_t tCCnt;
    uint8_t rCCnt;
    uint8_t nameUCnt;
    uint8_t namePCnt;
    uint8_t nameSCnt;
    uint8_t nameRCnt;
    uint8_t nameTCnt;
    uint8_t stat;
} smtp_flow_t;

// global pointer in case of dependency export
extern smtp_flow_t *smtp_flow;

#endif // SMTP_DECODE_H_
