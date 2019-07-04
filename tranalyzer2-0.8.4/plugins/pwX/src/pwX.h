/*
 * pwX.h
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

#ifndef PASSWORD_EXTRACTOR_H_
#define PASSWORD_EXTRACTOR_H_

// includes
#include <stdint.h>

// plugin defines
#define PWX_USERNAME   1 // Output the username
#define PWX_PASSWORD   1 // Output the password

#define PWX_FTP        1 // Extract FTP authentication
#define PWX_POP3       1 // Extract POP3 authentication
#define PWX_IMAP       1 // Extract IMAP authentication
#define PWX_SMTP       1 // Extract SMTP authentication
#define PWX_HTTP_BASIC 1 // Extract HTTP Basic Authorization
#define PWX_HTTP_PROXY 1 // Extract HTTP Proxy Authorization
#define PWX_HTTP_GET   1 // Extract HTTP GET authentication
#define PWX_HTTP_POST  1 // Extract HTTP POST authentication
#define PWX_IRC        1 // Extract IRC authentication
#define PWX_TELNET     1 // Extract Telnet authentication
#define PWX_LDAP       1 // Extract LDAP bind request authentication
#define PWX_PAP        1 // Extract PAP authentication

#define PWX_STATUS     1 // Extract authentication status (success, error, ...)

#define PWX_DEBUG      0 // whether or not to activate debug output


// ------------------------- DO NOT EDIT BELOW HERE -------------------------


#define PE_BUFFER_SIZE        256

// utils defines (do not edit them)
#define PWX_HTTP ((PWX_HTTP_BASIC | PWX_HTTP_PROXY | PWX_HTTP_GET | PWX_HTTP_POST))

// list of protocols for which passwords are extracted
typedef enum {
    UNDEFINED,         // flow protocol has not been defined yet (default value after memset)
    NOT_EXTRACTABLE,   // flow protocol is one for which there is no password to extract
    ALREADY_EXTRACTED, // password was already extracted
    FTP,
    POP3,
    IMAP,
    SMTP,
    HTTP,
    IRC,
    TELNET,
    TELNET_B,
    LDAP,
    PAP,
    // check status types for opposite flow
    CHECK_FTP,
    CHECK_POP3,
    CHECK_IMAP,
    CHECK_SMTP,
    CHECK_HTTP, // basic and proxy auth
    CHECK_IRC_FREENODE,
    //CHECK_IRC_PASS,
    //CHECK_IRC_NS,
    CHECK_TELNET,
    CHECK_LDAP,
    CHECK_PAP,
} PasswordProtocol;

// values for the authentication type column
typedef enum {
    NO_AUTH,
    FTP_AUTH,
    POP3_AUTH,
    IMAP_AUTH,
    SMTP_AUTH,
    HTTP_BASIC_AUTH,
    HTTP_PROXY_AUTH,
    HTTP_GET_AUTH,
    HTTP_POST_AUTH,
    IRC_AUTH,
    TELNET_AUTH,
    LDAP_AUTH,
    PAP_AUTH,
} AuthType;

// value for the authentication status column
typedef enum {
    UNKNOWN,
    SUCCESS,
    FAILED,
} AuthStatus;

// password extractor plugin structures
typedef struct pwX_flow_s {
    char* password;
    char* username;
    PasswordProtocol proto;
    AuthType auth_type;
#if PWX_STATUS != 0
    AuthStatus status;
#endif // PWX_STATUS != 0
#if PWX_SMTP != 0 || PWX_TELNET != 0
    uint32_t next_seq;
#endif // PWX_SMTP != 0 || PWX_TELNET != 0
#if PWX_SMTP != 0
    uint8_t smtp_plain_state;
    uint8_t smtp_login_state;
#endif // PWX_SMTP != 0
#if PWX_TELNET != 0
    uint8_t telnet_state;
#endif // PWX_TELNET != 0
} pwX_flow_t;

// plugin struct pointer for potential dependencies
pwX_flow_t *pwX_flows;

#endif // PASSWORD_EXTRACTOR_H_
