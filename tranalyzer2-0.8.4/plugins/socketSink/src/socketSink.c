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

#include "socketSink.h"

#if GZ_COMPRESS == 1
#include "gz2txt.h"
#else // GZ_COMPRESS == 0
#include "bin2txt.h"
#endif // GZ_COMPRESS == 0

#if BUF_DATA_SHFT > 1
#include "chksum.h"
#endif // BUF_DATA_SHFT > 1

#if GZ_COMPRESS == 1
#include <zlib.h>
#endif // GZ_COMPRESS == 1


#if BLOCK_BUF == 0

// Static variables

#if GZ_COMPRESS == 1
static gzFile gzfd;
#endif // GZ_COMPRESS == 1
static int sfd;
static struct sockaddr_in server;
static struct hostent *host;
static char *bH;
#if CONTENT_TYPE > 0
static FILE *sBuf;
static size_t sBufSize;
#endif // CONTENT_TYPE > 0


// Function prototypes

#if HOST_INFO == 1 && CONTENT_TYPE == 0
static int gethostinfo(char *buf);
#endif // HOST_INFO == 1 && CONTENT_TYPE == 0

#endif // BLOCK_BUF == 0


// Tranalyzer functions

T2_PLUGIN_INIT("socketSink", "0.8.4", 0, 8);


void initialize() {
#if BLOCK_BUF == 1
    T2_PWRN("socketSink", "BLOCK_BUF is set in 'tranalyzer.h', no output will be produced");
#else // BLOCK_BUF == 0

#if GZ_COMPRESS == 1
	GZ2TXT_TEST_ZLIB_VERSION("socketSink");
#endif // GZ_COMPRESS == 1

#if SOCKTYPE == 1
	if (!(sfd = socket(AF_INET, SOCK_STREAM, 0))) {
#else // SOCKTYPE == 0
	if (!(sfd = socket(AF_INET, SOCK_DGRAM, 0))) {
#endif // SOCKTYPE
		T2_PERR("socketSink", "Could not create socket: %s", strerror(errno));
		exit(-1);
	}

	//int optval = 1;
	//setsockopt(sfd, IPPROTO_IP, IP_DONTFRAG, &optval, sizeof(optval));

	memset(&server, '\0', sizeof(server));
	host = gethostbyname(SERVADD);
	if (UNLIKELY(!host)) {
		T2_PERR("socketSink", "gethostbyname() failed for '%s'", SERVADD);
		if (sfd) close(sfd);
		exit(1);
	}

	server.sin_addr = *(struct in_addr*)host->h_addr;
	server.sin_family = AF_INET;
	server.sin_port = htons(DPORT);

#if GZ_COMPRESS == 1
	if (UNLIKELY(!(gzfd = gzdopen(sfd, "w")))) {
		T2_PERR("socketSink", "Could not create compressed stream: %s", strerror(errno));
		exit(-1);
	}
#endif // GZ_COMPRESS == 1

#if SOCKTYPE == 1
	if (connect(sfd, (struct sockaddr*)&server, sizeof(server)) < 0) {
		T2_PERR("socketSink", "Could not connect to socket: %s, check whether the server side is listening at %s on port %d", strerror(errno), SERVADD, DPORT);
		exit(-1);
	}
#endif // SOCKTYPE == 1

#if CONTENT_TYPE == 2
	sBuf = open_memstream(&bH, &sBufSize);
	return;
#endif // CONTENT_TYPE == 2

	uint32_t i, written = 0;
	int32_t act_written;

#if CONTENT_TYPE == 1
	sBuf = open_memstream(&bH, &sBufSize);
	parse_binary_header2text(main_header_bv, sBuf, b2t_funcs);
	fflush(sBuf);
	i = sBufSize;
#else // CONTENT_TYPE == 0
	// build first packet info about host and sent it to the appropriate socket
	uint32_t *wP;
	bH = malloc(MAXBHBUF + 1);
#if HOST_INFO == 1
	wP = (uint32_t*)bH;
	bH += SOCK_BUFSHFT;
	i = gethostinfo(bH) + SOCK_BUFSHFT; // "lo(MAC_IP),eth0(MAC1_IP1,MAC2_IP2)..."
#if BUF_DATA_SHFT > 0
	wP[0] = i;
#if BUF_DATA_SHFT > 1
	wP[1] = 0;
	wP[1] = Checksum32(wP, i);
#endif // BUF_DATA_SHFT > 1
#endif // BUF_DATA_SHFT > 0

	while (written < i) {
#if GZ_COMPRESS == 1
		act_written = gzwrite(gzfd, (char*)wP + written, i - written);
#elif SOCKTYPE == 1 // && GZ_COMPRESS == 0
		act_written = write(sfd, (char*)wP + written, i - written);
#else // SOCKTYPE == 0 && GZ_COMPRESS == 0
		act_written = sendto(sfd, (char*)wP + written, i - written, 0, (struct sockaddr*)&server, sizeof(server));
#endif // SOCKTYPE == 0 && GZ_COMPRESS == 0
		if (UNLIKELY(act_written <= 0)) {
			T2_PERR("socketSink", "Could not send message to socket: %s", strerror(errno));
			exit(-1);
		}
		written += act_written;
	}
#endif // HOST_INFO == 1

	// build binary header and sent it to the appropriate socket
	binary_header_t *header = build_header(main_header_bv);

	wP = header->header;
	i = header->length << 2;

	bH = (char*)wP;
#if BUF_DATA_SHFT > 0
	wP[0] = i;
#if BUF_DATA_SHFT > 1
	wP[1] = 0;
	wP[1] = Checksum32(wP, i);
#endif // BUF_DATA_SHFT > 1
#endif // BUF_DATA_SHFT > 0

#endif // CONTENT_TYPE == 0

	written = 0;
	while (written < i) {
#if GZ_COMPRESS == 1
		act_written = gzwrite(gzfd, bH + written, i - written);
#elif SOCKTYPE == 1 // && GZ_COMPRESS == 0
		act_written = write(sfd, bH + written, i - written);
#else // SOCKTYPE == 0 && GZ_COMPRESS == 0
		act_written = sendto(sfd, bH + written, i - written, 0, (struct sockaddr*)&server, sizeof(server));
#endif // SOCKTYPE == 0 && GZ_COMPRESS == 0
		if (UNLIKELY(act_written <= 0)) {
			T2_PERR("socketSink", "Could not send message to socket: %s", strerror(errno));
			exit(-1);
		}
		written += act_written;
	}

#if CONTENT_TYPE == 0
	free(header);
#endif // CONTENT_TYPE == 0

#endif // BLOCK_BUF == 0
}


// If BLOCK_BUF == 1, the plugin does not produce any output.
// All the code below is therefore not activated.


#if BLOCK_BUF == 0


#if CONTENT_TYPE == 0
void bufferToSink(outputBuffer_t *buffer) {
#else // CONTENT_TYPE != 0
void bufferToSink(outputBuffer_t *buffer __attribute__((unused))) {
#endif // CONTENT_TYPE != 0

	uint32_t i;
	char *bP;

#if CONTENT_TYPE > 0
	fseek(sBuf, 0, SEEK_SET);
#if CONTENT_TYPE == 2
	if (UNLIKELY(!parse_buffer_bin2json(main_output_buffer, main_header_bv, sBuf, b2t_funcs))) {
#else // CONTENT_TYPE == 1
	if (UNLIKELY(!parse_buffer_bin2txt(main_output_buffer, main_header_bv, sBuf, b2t_funcs))) {
#endif // CONTENT_TYPE == 1
		// ignore this flow
		return;
	}
	fflush(sBuf);
	i = sBufSize;
	bP = bH;
#else // CONTENT_TYPE == 0
	bP = buffer->buffer - SOCK_BUFSHFT;
	i = buffer->pos + SOCK_BUFSHFT;

#if BUF_DATA_SHFT > 0
	uint32_t *ubP = (uint32_t*)bP;
	ubP[0] = buffer->pos;
#if BUF_DATA_SHFT > 1
	ubP[1] = 0;
	ubP[1] = Checksum32(ubP, i);
#endif // BUF_DATA_SHFT > 1
#endif // BUF_DATA_SHFT > 0

#endif // CONTENT_TYPE == 0

	uint32_t written = 0;
	int32_t act_written;

	while (written < i) {
#if GZ_COMPRESS == 1
		act_written = gzwrite(gzfd, bP + written, i - written);
#elif SOCKTYPE == 1 // && GZ_COMPRESS == 0
		act_written = write(sfd, bP + written, i - written);
#else // SOCKTYPE == 0 && GZ_COMPRESS == 0
		act_written = sendto(sfd, bP + written, i - written, 0, (struct sockaddr*)&server, sizeof(server));
#endif // SOCKTYPE == 0 && GZ_COMPRESS == 0
		if (UNLIKELY(act_written <= 0)) {
			T2_PERR("socketSink", "Could not send message to socket: %s", strerror(errno));
			if (sfd) close(sfd);
#if CONTENT_TYPE > 0
			if (sBuf) fclose(sBuf);
#endif // CONTENT_TYPE > 0
			exit(-1);
		}
		written += act_written;
	}
}


void onApplicationTerminate() {
#if GZ_COMPRESS == 1
	gzclose(gzfd);
#endif // GZ_COMPRESS == 1
	if (sfd) close(sfd);
#if CONTENT_TYPE > 0
	if (sBuf) fclose(sBuf);
#endif // CONTENT_TYPE > 0
	free(bH);
}


#if HOST_INFO == 1 && CONTENT_TYPE == 0
int gethostinfo(char* ht) {

	struct ifaddrs *ifaddr;
	if (UNLIKELY(getifaddrs(&ifaddr) == -1)) {
		exit(-1);
	}

	struct timeval t;
	gettimeofday(&t, NULL);

	*ht = 0x0;
	uint32_t *p = (uint32_t*)ht;
	uint64_t *m = (uint64_t*)(p+1);

	p[0] = T2_SENSORID;
	m[0] = (uint64_t)t.tv_sec;
	p[3] = (uint32_t)t.tv_usec;

	char *h = ht + 16;

	struct utsname buf;
	uname(&buf);
	sprintf(h, "%s;%s;%s;%s;%s;", buf.nodename, buf.sysname, buf.release, buf.version, buf.machine);
	h += strlen(h);

	uint64_t k1;
	uint32_t j, k, l;
	int family;

	for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) continue;
		family = ifa->ifa_addr->sa_family;
		sprintf(h, "%s(", ifa->ifa_name);
		h += strlen(h);
		if (family == AF_INET) {
			j = *(uint32_t*)&((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr;
			for (k = ~ntohl(j), l = 0; k & 1; k >>= 1, l++);
			getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), h, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			sprintf(h, "%s/%d", h, 32-l);
			h += strlen(h);
		} else if (family == AF_INET6) {
			m = (uint64_t*)&((struct sockaddr_in6 *)ifa->ifa_netmask)->sin6_addr;
			for (k1 = ~m[0], l = 0; k1 & 1; k1 >>= 1, l++);
			for (k1 = ~m[1]; k1 & 1; k1 >>= 1, l++);
			getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6), h, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			sprintf(h, "%s/%d", strtok(ht, "%"), 128-l);
			h += strlen(h);
#ifndef __APPLE__
		} else if (family == AF_PACKET) {
			const uint8_t * const mac = ((struct sockaddr_ll*)ifa->ifa_addr)->sll_addr;
			// TODO use t2_mac_to_str
			sprintf(h, "%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s"
			           "%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s%02"B2T_PRIX8,
			           mac[0], MAC_SEP, mac[1], MAC_SEP, mac[2], MAC_SEP,
			           mac[3], MAC_SEP, mac[4], MAC_SEP, mac[5]);
			h += strlen(h);
#endif // __APPLE__
		}
		sprintf(h, ")");
		h++;
	}

	freeifaddrs(ifaddr);

	return (strlen(ht+16)+16);
}
#endif // HOST_INFO == 1 && CONTENT_TYPE == 0

#endif // BLOCK_BUF == 0
