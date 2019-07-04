/*
 * txtSink.c
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

#include "txtSink.h"
#include "../../tranalyzer2/config.h"

#if GZ_COMPRESS == 1
#include "gz2txt.h"
#else // GZ_COMPRESS == 0
#include "bin2txt.h"
#endif // GZ_COMPRESS == 0

#include <ifaddrs.h>
#include <netdb.h>
#include <sys/utsname.h>

#ifdef __APPLE__
#include <net/if_dl.h>
#else
#include <netpacket/packet.h>
#endif //__APPLE__


#if BLOCK_BUF == 0
// Static variables
static b2t_func_t funcs;

#if GZ_COMPRESS == 1
static gzFile txt_file;
#else // GZ_COMPRESS == 0
static FILE *txt_file;
#endif // GZ_COMPRESS == 1

static char txt_filename[MAX_FILENAME_LEN+1]; // filename of the flow file

#if TFS_SPLIT == 1
// -W option
static uint64_t oFileNum, oFileLn;
static uint64_t txtfIndex;
static char *oFileNumP;
#endif // TFS_SPLIT == 1
#endif // BLOCK_BUF == 0


// Function prototypes

#if TFS_HDR_FILE == 1
static void print_hdr_file();
static void getIinfo(char *buf);
#endif // TFS_HDR_FILE


// Tranalyzer plugin functions

T2_PLUGIN_INIT("txtSink", "0.8.4", 0, 8);


void initialize() {
#if BLOCK_BUF == 1
    T2_PWRN("txtSink", "BLOCK_BUF is set in 'tranalyzer.h', no flow file will be produced");
#else // BLOCK_BUF == 0

#if GZ_COMPRESS == 1
	GZ2TXT_TEST_ZLIB_VERSION("txtSink");
	funcs = b2t_funcs_gz;
#else // GZ_COMPRESS == 0
	funcs = b2t_funcs;
#endif // GZ_COMPRESS == 1

	// setup output file names
	if (capType & WSTDOUT) {
#if GZ_COMPRESS == 1
		if (UNLIKELY((txt_file = gzdopen(fileno(stdout), "w")) == NULL)) {
			T2_PERR("txtSink", "Could not create compressed stream: %s", strerror(errno));
			exit(-1);
		}
#else // GZ_COMPRESS == 0
		txt_file = stdout;
#endif // GZ_COMPRESS == 0
	} else {
		strncpy(txt_filename, baseFileName, MAX_FILENAME_LEN);
		strncat(txt_filename, FLOWS_TXT_SUFFIX, MAX_FILENAME_LEN-baseFileName_len);
#if GZ_COMPRESS == 1
		strncat(txt_filename, GZ_SUFFIX, MAX_FILENAME_LEN-baseFileName_len-sizeof(FLOWS_TXT_SUFFIX));
#endif // GZ_COMPRESS == 1

#if TFS_SPLIT == 1
		if (capType & OFILELN) {
			txtfIndex = 0;
			oFileLn = (uint64_t)oFragFsz;
			oFileNumP = txt_filename + strlen(txt_filename);
			oFileNum = oFileNumB;
			sprintf(oFileNumP, "%"PRIu64, oFileNum);
		}
#endif // TFS_SPLIT == 1

		// open flow output file
		if (UNLIKELY(!((txt_file = funcs.fopen(txt_filename, "w"))))) {
			T2_PERR("txtSink", "Failed to open file '%s' for writing: %s", txt_filename, strerror(errno));
			exit(-1);
		}
	}

#if TFS_PRI_HDR == 1
	// write header in flow file
	parse_binary_header2text(main_header_bv, txt_file, funcs);
#endif // TFS_PRI_HDR == 1

#endif // BLOCK_BUF == 0

#if TFS_HDR_FILE == 1
	print_hdr_file();
#endif // TFS_HDR_FILE == 1
}


#if BLOCK_BUF == 0
void bufferToSink(outputBuffer_t* buffer __attribute__((unused))) {

	if (UNLIKELY(!parse_buffer_bin2txt(main_output_buffer, main_header_bv, txt_file, funcs))) {
		exit(EXIT_FAILURE);
	}

#if TFS_SPLIT == 1
	if (capType & OFILELN) {
		const uint64_t offset = ((capType & WFINDEX) ? ++txtfIndex : (uint64_t)funcs.ftell(txt_file));
		if (offset >= oFileLn) {
			funcs.fclose(txt_file);

			oFileNum++;
			sprintf(oFileNumP, "%"PRIu64, oFileNum);

			if (UNLIKELY(!((txt_file = funcs.fopen(txt_filename, "w"))))) {
				T2_PERR("txtSink", "Failed to open file '%s' for writing: %s", txt_filename, strerror(errno));
				exit(-1);
			}
#if (TFS_PRI_HDR == 1 && TFS_PRI_HDR_FW == 1)
			parse_binary_header2text(main_header_bv, txt_file, funcs);
#endif // (TFS_PRI_HDR == 1 && TFS_PRI_HDR_FW == 1)
			txtfIndex = 0;
		}
	}
#endif // TFS_SPLIT == 1
}
#endif // BLOCK_BUF == 0


#if BLOCK_BUF == 0
void onApplicationTerminate() {
	if (LIKELY(txt_file != NULL)) {
#if (TFS_PRI_HDR == 1 && TFS_EXTENDED_HEADER == 1)
		funcs.fseek(txt_file, 0, SEEK_SET);
		funcs.fprintf(txt_file, "%s %lu", HDR_CHR, totalFlows);
#endif // (TFS_PRI_HDR == 1 && TFS_EXTENDED_HEADER == 1)
		funcs.fclose(txt_file);
	}
}
#endif // BLOCK_BUF == 0


// TODO compress header file?
#if TFS_HDR_FILE == 1
static void print_hdr_file() {
	// open header output file
	FILE *file = t2_open_file(baseFileName, HEADER_SUFFIX, "w");
	if (UNLIKELY(!file)) exit(-1);

	// calc time
	struct timeval t;
	gettimeofday(&t, NULL);

	// get name and information about current kernel
	struct utsname buf;
	uname(&buf);

	// write headers
	t2_log_date(file, "# Date: ", t, TSTAMP_R_UTC);
	fprintf(file, "# %s %s (%s), %s.\n", APPNAME, APPVERSION, CODENAME, RELEASE_TYPE);
	fprintf(file, "# sensorID: %"PRIu32"\n", sensorID);
	fprintf(file, "# PID: %d\n", getpid());
	fprintf(file, "# Command line: %s\n", cmdline);
	fprintf(file, "# HW Info: %s;%s;%s;%s;%s\n#\n", buf.nodename, buf.sysname, buf.release, buf.version, buf.machine);

	if (capType & IFACE) {
		fprintf(file, "# Live captured from interface: %s\n", capName);

		char bH[1024];
		getIinfo(bH);
		fprintf(file, "%s\n#\n", &bH[0]);
	}

	fputs("# Plugins loaded:\n", file);
	for (uint_fast8_t i = 0; i < t2_plugins->num_plugins; i++) {
		fprintf(file, "#   %02u: %s, version %s\n", i+1, t2_plugins->plugin[i].name, t2_plugins->plugin[i].version);
	}

#if BLOCK_BUF == 0
	fputs("#\n", file);
	print_values_description(main_header_bv, file, b2t_funcs);
#endif // BLOCK_BUF == 0

	fclose(file);
}
#endif // TFS_HDR_FILE == 1


#if TFS_HDR_FILE == 1
static void getIinfo(char *buf) {
	struct ifaddrs *ifaddr;
	if (getifaddrs(&ifaddr) == -1) return;

	char *h = buf;
	sprintf(h, "# Interfaces: ");
	h += strlen(h);

	char hbuf[NI_MAXHOST];
	uint64_t *ip6, k1;
	uint32_t ip, k, l;
	uint8_t *mac;

	for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr) continue;

		sprintf(h, "%s(", ifa->ifa_name);
		h += strlen(h);

		switch (ifa->ifa_addr->sa_family) {
			case AF_INET:
				ip = *(uint32_t*)&((struct sockaddr_in*)ifa->ifa_netmask)->sin_addr;
				for (k = ~ntohl(ip), l = 0; k & 1; k >>= 1, l++);
				if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), hbuf, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0) {
					sprintf(h, "%s/%u", hbuf, 32-l);
					h += strlen(h);
				}
				break;

			case AF_INET6:
				ip6 = (uint64_t*)&((struct sockaddr_in6*)ifa->ifa_netmask)->sin6_addr;
				for (k1 = ~ip6[0], l = 0; k1 & 1; k1 >>= 1, l++);
				for (k1 = ~ip6[1]; k1 & 1; k1 >>= 1, l++);
				if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6), hbuf, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0) {
					sprintf(h, "%s/%u", strtok(hbuf, "%"), 128-l);
					h += strlen(h);
				}
				break;

#ifdef __APPLE__
			case AF_LINK:
				mac = (unsigned char*)LLADDR((struct sockaddr_dl*)(ifa)->ifa_addr);
#else // !__APPLE__
			case AF_PACKET:
				mac = ((struct sockaddr_ll*)ifa->ifa_addr)->sll_addr;
#endif // !__APPLE__
				sprintf(h, "%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s"
				           "%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s%02"B2T_PRIX8,
				           mac[0], MAC_SEP, mac[1], MAC_SEP, mac[2], MAC_SEP,
				           mac[3], MAC_SEP, mac[4], MAC_SEP, mac[5]);
				h += strlen(h);
				break;

			default:
				break;
		}
		sprintf(h, ") ");
		h += 2;
	}

	freeifaddrs(ifaddr);
}
#endif // TFS_HDR_FILE == 1
