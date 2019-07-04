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

#include "entropy.h"

#include <math.h>


// Global variables

entropyFlow_t *entropyFlow;


// Static variables

#if ENT_FLOW > 0
static uint64_t mf;
static uint32_t maxAddrLen;
static uint32_t flwCnt[ENT_NTUPLE][ENT_MAXPBIN+1];
#endif


// Tranalyzer Plugin functions

T2_PLUGIN_INIT("entropy", "0.8.4", 0, 8);


void initialize() {
	if (UNLIKELY(!(entropyFlow = calloc(mainHashMap->hashChainTableSize, sizeof(entropyFlow_t))))) {
		T2_PERR("entropy", "failed to allocate memory for entropyPerFlow");
		exit(-1);
	}
}


binary_value_t* printHeader() {
	binary_value_t *bv = NULL;
	bv = bv_append_bv(bv, bv_new_bv("Payload entropy", "PyldEntropy", 0, 1, bt_float));
	bv = bv_append_bv(bv, bv_new_bv("Payload_Character ratio", "PyldChRatio", 0, 1, bt_float));
	bv = bv_append_bv(bv, bv_new_bv("Payload_Binary ratio", "PyldBinRatio", 0, 1, bt_float));
#if ENT_ALPHA_D == 1
	bv = bv_append_bv(bv, bv_new_bv("Payload length", "Pyldlen", 0, 1, bt_uint_32));
	bv = bv_append_bv(bv, bv_new_bv("Payload histogram", "PyldHisto", 1, 1, bt_uint_32));
#endif // ENT_ALPHA_D == 1
	return bv;
}


void onFlowGenerated(packet_t* packet __attribute__((unused)), unsigned long flowIndex) {
	memset(&entropyFlow[flowIndex], '\0', sizeof(entropyFlow_t));

#if ENT_FLOW > 0
	const flow_t * const flowP = &flows[flowIndex];

	if (flowP->oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND && (flowP->status & L3FLOWINVERT)) return;

	mf++;
	const uint8_t * const p = (uint8_t*)&flowP->srcIP;
	const uint8_t * const pe = (uint8_t*)&flowP->layer4Protocol;
	maxAddrLen = (uint32_t)(pe - p) + 1;

	for (uint_fast32_t i = 0; i < maxAddrLen; i++) {
		flwCnt[i][p[i]]++;
	}
#endif // ENT_FLOW > 0
}


void claimLayer4Information(packet_t* packet, unsigned long flowIndex) {

	entropyFlow_t * const entropyFlowP = &entropyFlow[flowIndex];

#if ENT_D_OFFSET > 0
	if (packet->snapL7Length < ENT_D_OFFSET) return;
#endif

	const uint8_t * const pld = packet->layer7Header + ENT_D_OFFSET;
	const int_fast32_t snapIPPayloadLen = packet->snapL7Length - ENT_D_OFFSET;

	for (int_fast32_t i = 0; i < snapIPPayloadLen; i++) {
		entropyFlowP->binCount[pld[i]]++; // Increment counter for overall-entropy!
	}

	entropyFlowP->numBytes += snapIPPayloadLen; // only the true snaped payload
}


void onFlowTerminate(unsigned long flowIndex) {
	uint_fast32_t i;
	uint32_t actCount;
	float crp = -1.0, brp = -1, entropy = 0.0;

	const entropyFlow_t * const entropyFlowP = &entropyFlow[flowIndex];
	const uint32_t numBytesTotal = entropyFlowP->numBytes;

	if (numBytesTotal <= ENT_THRES) { // e.g. sqrt(m) = 16, m: alphabet = 256
		entropy = -1.0f;
	} else {
		float p;
		uint32_t pBinary = 0, pChar = 0;
		for (i = 0; i < ENT_MAXPBIN; i++) {
			actCount = entropyFlowP->binCount[i];
			if (actCount) {
				p = actCount / (float)numBytesTotal;
				entropy += p * log(p);
				if (i == 10 || i == 13 || (i >= 32 && i <= 127)) pChar += actCount;
				if (i < 10) pBinary += actCount;
			}
		}
		entropy /= -log(ENT_MAXPBIN); // Normalize to base 256, so that the result is between 0 and 1

		crp = pChar / (float)numBytesTotal;
		brp = pBinary / (float)numBytesTotal;
	}

	outputBuffer_append(main_output_buffer, (char*) &entropy, sizeof(float));
	outputBuffer_append(main_output_buffer, (char*) &crp, sizeof(float));
	outputBuffer_append(main_output_buffer, (char*) &brp, sizeof(float));

#if ENT_ALPHA_D == 1
	outputBuffer_append(main_output_buffer, (char*) &numBytesTotal, sizeof(uint32_t));

	actCount = ENT_MAXPBIN;
	outputBuffer_append(main_output_buffer, (char*) &actCount, sizeof(uint32_t));
	for (i = 0; i < ENT_MAXPBIN; i++) { // print payload distribution
		actCount = entropyFlowP->binCount[i];
		outputBuffer_append(main_output_buffer, (char*) &actCount, sizeof(uint32_t));
	}
#endif // ENT_ALPHA_D == 1
}


void onApplicationTerminate() {
#if ENT_FLOW > 0
	uint32_t a;
	uint_fast32_t i, j;
	float p = 0.0;
	float entropyS[ENT_NTUPLE];
	uint32_t z[ENT_NTUPLE];

	for (i = 0; i < maxAddrLen; i++) {
		z[i] = 0;
		for (j = 0; j < ENT_MAXPBIN; j++) {
			if (flwCnt[i][j] == 0) z[i]++;
#if ENT_FLOW == 1
		}
	}
#else // ENT_FLOW == 0
			printf("%"PRIu32" - ", flwCnt[i][j]);
		}
		printf("\n");
	}
	printf("\n");

	printf("%"PRIu64" %d\n", mf, maxAddrLen);
#endif // ENT_FLOW == 0

	for (i = 0; i < maxAddrLen; i++) {
		printf("%"PRIu32" - ", z[i]);
	}
	printf("\n");

	for (i = 0; i < maxAddrLen; i++) {
		entropyS[i] = 0.0;
		for (j = 0; j < ENT_MAXPBIN; j++) {
			a = flwCnt[i][j];
			if (a) {
				p = a / (float)mf;
				entropyS[i] += p * log(p);
			}
		}
		entropyS[i] /= -log(ENT_MAXPBIN); // Normalize to base ENT_MAXPBIN
		printf ("%f - ", entropyS[i]);
	}
	printf("\n");
#endif // ENT_FLOW > 0

	free(entropyFlow);
}
