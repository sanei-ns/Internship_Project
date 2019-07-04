/*
 * portClassifier.c
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

#include "portClassifier.h"


// Static variables

static portAppl_t portArray[65536]; // association port-application


// Tranalyzer plugin functions

T2_PLUGIN_INIT("portClassifier", "0.8.4", 0, 8);


void initialize() {

	/* Open the ports file */
	FILE *file = t2_open_file(pluginFolder, PBC_CLASSFILE, "r");
	if (UNLIKELY(!file)) exit(-1);

	/* Parse the Input */

	char name[PBC_NMLENMAX+1];
	char proto[4];
	uint32_t port;
	int n;

	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	while ((read = getline(&line, &len, file)) != -1) {
		// Skip comments and empty lines
		if (UNLIKELY(line[0] == '#' || line[0] == ' ' || line[0] == '\n' || line[0] == '\t')) continue;

		// scan the line (corrected port key files)
		n = sscanf(line, "%"SCNu32"\t%3s\t%"STR(PBC_NMLENMAX)"s\t", &port, proto, name);
		if (UNLIKELY(n != 3)) {
			T2_PWRN("portClassifier", "failed to parse line '%s': expected port <tab> proto <tab> name", line);
			continue;
		}

		if (UNLIKELY(port > UINT16_MAX)) {
			T2_PWRN("portClassifier", "invalid port %"PRIu32, port);
			continue;
		}

		// TCP
		if (strncmp("tcp", proto, 3) == 0) {
			if (portArray[port].name_tcp[0] == '\0')
				memcpy(portArray[port].name_tcp, name, strlen(name)+1);
		// UDP
		} else if (strncmp("udp", proto, 3) == 0) {
			if (portArray[port].name_udp[0] == '\0')
				memcpy(portArray[port].name_udp, name, strlen(name)+1);
		// other:error. ignore it
		} else T2_PWRN("portClassifier", "invalid protocol '%s'", proto);
	}

	free(line);
	fclose(file);
}


binary_value_t* printHeader() {
	binary_value_t *bv = NULL;
#if PBC_NUM == 1
	BV_APPEND_U16(bv, "dstPortClassN", "Port based classification of the destination port number");
#endif
#if PBC_STR == 1
	BV_APPEND_STRC(bv, "dstPortClass", "Port based classification of the destination port name");
#endif
	return bv;
}


#if BLOCK_BUF == 0 && (PBC_NUM == 1 || PBC_STR == 1)
void onFlowTerminate(unsigned long flowIndex) {

	const flow_t * const flowP = &flows[flowIndex];
	const uint16_t dport = (flowP->status & L3FLOWINVERT) ? flowP->srcPort : flowP->dstPort;

#if PBC_NUM == 1
	OUTBUF_APPEND_U16(main_output_buffer, dport);
#endif

#if PBC_STR == 1
	char *proto_str;
	const uint_fast8_t proto = flowP->layer4Protocol;
	if (proto == L3_TCP || proto == L3_SCTP) {
		proto_str = portArray[dport].name_tcp;
	} else if (proto == L3_UDP || proto == L3_UDPLITE) {
		proto_str = portArray[dport].name_udp;
	} else {
		proto_str = NULL;
	}

	if (proto_str && proto_str[0] != '\0') {
		OUTBUF_APPEND_STR(main_output_buffer, proto_str);
	} else {
		OUTBUF_APPEND_STR(main_output_buffer, PBC_UNKNOWN);
	}
#endif // PBC_STR == 1
}
#endif // BLOCK_BUF == 0 && (PBC_NUM == 1 || PBC_STR == 1)
