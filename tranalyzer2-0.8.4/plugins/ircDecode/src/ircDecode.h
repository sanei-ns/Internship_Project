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

#ifndef __IRC_DECODE_H__
#define __IRC_DECODE_H__

// global includes

// local includes
#include "global.h"

// user defines

#define IRC_SAVE       0 // save content to IRC_F_PATH
#define IRC_BITFIELD   0 // Bitfield coding of IRC commands

#define IRC_UXNMLN    10 // maximal USER length
#define IRC_PXNMLN    10 // maximal PW length
#define IRC_MXNMLN    50 // maximal name length
#define IRC_MAXUNM     5 // Maximal number of users
#define IRC_MAXPNM     5 // Maximal number of passwords
#define IRC_MAXCNM    20 // Maximal number of parameters

#define IRC_PATH "/tmp/" // root path
#define IRC_F_PATH IRC_PATH"IRCFILES/" // Path for pictures

#define IRC_NON "wurst" // no name file name

#define IRC_CNT_LEN    13 // max # of cnt digits attached to file name (currently not used).
#define IRC_FNDX_LEN   20 // string length of findex in decimal format

// def & Calculate name lengths
#define IRC_MXPL (IRC_MXNMLN + IRC_FNDX_LEN + 4)
#define IRC_NON_FILE_LEN ((sizeof(IRC_NON) + IRC_CNT_LEN + IRC_FNDX_LEN)) // Standard name of files without name: wurst_dir_findex_pkt_num
#define IRC_MXIMNM_LEN (sizeof(IRC_F_PATH) + IRC_NON_FILE_LEN + IRC_MXNMLN + 1) // maximum file name length

#define IRC_PORTS  6667
#define IRC_PORTMI 6665
#define IRC_PORTMX 6669

// plugin defines

// stat
#define IRC_INIT    0x01 // IRC port found
#define IRC_PPRNT   0x02 // IRC passive parent flow
#define IRC_PPWF    0x04 // IRC passive parent flow write finished
#define IRC_APRNT   0x08 // IRC active parent flow
#define IRC_PPWFERR 0x20 // File error, IRC_SAVE == 1
#define IRC_OVFL    0x80 // array overflow

#define I_ADMIN    0x0000004e494d4441 // Get information about the administrator of a server.
#define I_AWAY     0x0000000059415741 // Set an automatic reply string for any PRIVMSG commands.
#define I_CONNECT  0x005443454e4e4f43 // Request a new connection to another server immediately.
#define I_DIE      0x0000000020454944 // Shutdown the server.
#define I_ERROR    0x000000524f525245 // Report a serious or fatal error to a peer.
#define I_INFO     0x000000004f464e49 // Get information describing a server.
#define I_INVITE   0x0000455449564e49 // Invite a user to a channel.
#define I_ISON     0x000000004e4f5349 // Determine if a nickname is currently on IRC.
#define I_JOIN     0x000000004e494f4a // Join a channel.
#define I_KICK     0x000000004b43494b // Request the forced removal of a user from a channel.
#define I_KILL     0x000000004c4c494b // Close a client-server connection by the server which has the actual connection.
#define I_LINKS    0x000000534b4e494c // List all server names which are known by the server answering the query.
#define I_LIST     0x000000005453494c // List channels and their topics.
#define I_LUSERS   0x000053524553554c // Get statistics about the size of the IRC network.
#define I_MODE     0x0000000045444f4d // User mode.
#define I_MOTD     0x0000000044544f4d // Get the Message of the Day.
#define I_NAMES    0x00000053454d414e // List all visible nicknames.
#define I_NICK     0x000000004b43494e // Define a nickname.
#define I_NJOIN    0x0000004e494f4a4e // Exchange the list of channel members for each channel between servers.
#define I_NOTICE   0x0000454349544f4e
#define I_OPER     0x000000005245504f // Obtain operator privileges.
#define I_PART     0x0000000054524150 // Leave a channel.
#define I_PASS     0x0000000053534150 // Set a connection password.
#define I_PING     0x00000000474e4950 // Test for the presence of an active client or server.
#define I_PONG     0x00000000474e4f50 // Reply to a PING message.
#define I_PRIVMSG  0x0047534d56495250 // Send private messages between users, as well as to send messages to channels.
#define I_QUIT     0x0000000054495551 // Terminate the client session.
#define I_REHASH   0x0000485341484552 // Force the server to re-read and process its configuration file.
#define I_RESTART  0x0054524154534552 // Force the server to restart itself.
#define I_SERVER   0x0000524556524553 // Register a new server.
#define I_SERVICE  0x0045434956524553 // Register a new service.
#define I_SERVLIST 0x5453494c56524553 // List services currently connected to the network.
#define I_SQUERY   0x0000595245555153
#define I_SQUIRT   0x0000545249555153 // Disconnect a server link.
#define I_SQUIT    0x0000005449555153 // Break a local or remote server link.
#define I_STATS    0x0000005354415453 // Get server statistics.
#define I_SUMMON   0x00004e4f4d4d5553 // Ask a user to join IRC.
#define I_TIME     0x00000000454d4954 // Get the local time from the specified server.
#define I_TOPIC    0x0000004349504f54 // Change or view the topic of a channel.
#define I_TRACE    0x0000004543415254 // Find the route to a server and information about it's peers.
#define I_USER     0x0000000052455355 // Specify the username, hostname and realname of a new user.
#define I_USERHOST 0x54534f4852455355 // Get a list of information about up to 5 nicknames.
#define I_USERS    0x0000005352455355 // Get a list of users logged into the server.
#define I_VERSION  0x004e4f4953524556 // Get the version of the server program.
#define I_WALLOPS  0x0053504f4c4c4157 // Send a message to all currently connected users who have set the 'w' user mode.
#define I_WHO      0x00000000204f4857 // List a set of users.
#define I_WHOIS    0x00000053494f4857 // Get information about a specific user.
#define I_WHOWAS   0x00005341574f4857 // Get information about a nickname which no longer exists.

#define IRC_ADMIN    0x0000000000000001 // 1 Get information about the administrator of a server.
#define IRC_AWAY     0x0000000000000002 // 2 Set an automatic reply string for any PRIVMSG commands.
#define IRC_CONNECT  0x0000000000000004 // 3 Request a new connection to another server immediately.
#define IRC_DIE      0x0000000000000008 // 4 Shutdown the server.
#define IRC_ERROR    0x0000000000000010 // 5 Report a serious or fatal error to a peer.
#define IRC_INFO     0x0000000000000020 // 6 Get information describing a server.
#define IRC_INVITE   0x0000000000000040 // 7 Invite a user to a channel.
#define IRC_ISON     0x0000000000000080 // 8 Determine if a nickname is currently on IRC.
#define IRC_JOIN     0x0000000000000100 // 9 Join a channel.
#define IRC_KICK     0x0000000000000200 // 10 Request the forced removal of a user from a channel.
#define IRC_KILL     0x0000000000000400 // 11 Close a client-server connection by the server which has the actual connection.
#define IRC_LINKS    0x0000000000000800 // 12 List all server names which are known by the server answering the query.
#define IRC_LIST     0x0000000000001000 // 13 List channels and their topics.
#define IRC_LUSERS   0x0000000000002000 // 14 Get statistics about the size of the IRC network.
#define IRC_MODE     0x0000000000004000 // 15 User mode.
#define IRC_MOTD     0x0000000000008000 // 16 Get the Message of the Day.
#define IRC_NAMES    0x0000000000010000 // 17 List all visible nicknames.
#define IRC_NICK     0x0000000000020000 // 18 Define a nickname.
#define IRC_NJOIN    0x0000000000040000 // 19 Exchange the list of channel members for each channel between servers.
#define IRC_NOTICE   0x0000000000080000 // 20
#define IRC_OPER     0x0000000000100000 // 21 Obtain operator privileges.
#define IRC_PART     0x0000000000200000 // 22 Leave a channel.
#define IRC_PASS     0x0000000000400000 // 23 Set a connection password.
#define IRC_PING     0x0000000000800000 // 24 Test for the presence of an active client or server.
#define IRC_PONG     0x0000000001000000 // 25 Reply to a PING message.
#define IRC_PRIVMSG  0x0000000002000000 // 26 Send private messages between users, as well as to send messages to channels.
#define IRC_QUIT     0x0000000004000000 // 27 Terminate the client session.
#define IRC_REHASH   0x0000000008000000 // 28 Force the server to re-read and process its configuration file.
#define IRC_RESTART  0x0000000010000000 // 29 Force the server to restart itself.
#define IRC_SERVER   0x0000000020000000 // 30 Register a new server.
#define IRC_SERVICE  0x0000000040000000 // 31 Register a new service.
#define IRC_SERVLIST 0x0000000080000000 // 32 List services currently connected to the network.
#define IRC_SQUERY   0x0000000100000000 // 33
#define IRC_SQUIRT   0x0000000200000000 // 34 Disconnect a server link.
#define IRC_SQUIT    0x0000000400000000 // 35 Break a local or remote server link.
#define IRC_STATS    0x0000000800000000 // 36 Get server statistics.
#define IRC_SUMMON   0x0000001000000000 // 37 Ask a user to join IRC.
#define IRC_TIME     0x0000002000000000 // 38 Get the local time from the specified server.
#define IRC_TOPIC    0x0000004000000000 // 39 Change or view the topic of a channel.
#define IRC_TRACE    0x0000008000000000 // 40 Find the route to a server and information about it's peers.
#define IRC_USER     0x0000010000000000 // 41 Specify the username, hostname and realname of a new user.
#define IRC_USERHOST 0x0000020000000000 // 42 Get a list of information about up to 5 nicknames.
#define IRC_USERS    0x0000040000000000 // 43 Get a list of users logged into the server.
#define IRC_VERSION  0x0000080000000000 // 44 Get the version of the server program.
#define IRC_WALLOPS  0x0000100000000000 // 45 Send a message to all currently connected users who have set the 'w' user mode.
#define IRC_WHO      0x0000200000000000 // 46 List a set of users.
#define IRC_WHOIS    0x0000400000000000 // 47 Get information about a specific user.
#define IRC_WHOWAS   0x0000800000000000 // 48 Get information about a nickname which no longer exists.

typedef struct {
	uint64_t sendCode;
	int64_t cLen;               // last declared IRC-Content-Length
#if IRC_SAVE == 1
	FILE *fd;                   // file descriptor per flow
	int64_t dwLen;              // Amount of data written
	uint32_t seqInit;
	//uint32_t seq;
#endif // IRC_SAVE == 1
	//uint32_t tCode[IRC_MAXCNM];
	uint16_t recCode[IRC_MAXCNM];
	uint8_t tCode[IRC_MAXCNM];
	char nameU[IRC_MAXUNM][IRC_UXNMLN+1];
	char nameP[IRC_MAXPNM][IRC_PXNMLN+1];
	char nameC[IRC_MAXCNM][IRC_MXPL+1];
	uint8_t tCCnt;
	uint8_t rCCnt;
	uint8_t nameUCnt;
	uint8_t namePCnt;
	uint8_t nameCCnt;
	uint8_t stat;
} ircFlow_t;

// plugin struct pointer for potential dependencies
extern ircFlow_t *ircFlows;

#endif // __IRC_DECODE_H__
