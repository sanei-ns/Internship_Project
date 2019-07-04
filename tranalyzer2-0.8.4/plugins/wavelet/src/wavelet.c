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

#include "dwt.h"
#include "wavelet.h"


// global variables

wavelet_t *waveletP;


// Tranalyzer functions

T2_PLUGIN_INIT("wavelet", "0.8.4", 0, 8);


void initialize() {
	if (UNLIKELY(!(waveletP = calloc(mainHashMap->hashChainTableSize, sizeof(wavelet_t))))) {
		T2_PERR("wavelet", "failed to allocate memory for waveletP");
		exit(-1);
	}
}


binary_value_t* printHeader() {
	binary_value_t *bv = NULL;
	binary_value_t *act_bv;

	bv = bv_append_bv(bv, bv_new_bv("Wavelet number of points", "waveNumPnts", 0, 1, bt_uint_16));
#if WAVELET_SIG == 1
	bv = bv_append_bv(bv, bv_new_bv("Wavelet signal", "waveSig", 1, 1, BTWPREC));
#endif // WAVELET_SIG == 1

	bv = bv_append_bv(bv, bv_new_bv("Number of Wavelet levels", "waveNumLvl", 0, 1, bt_uint_32));

	act_bv = bv_new_bv("Wavelet detail coefficients", WAVELET_DETAIL, 1, 1, 0);
	act_bv = bv_add_sv_to_bv(act_bv, 0, 1, 1, BTWPREC);
	bv = bv_append_bv(bv, act_bv);

	act_bv = bv_new_bv("Wavelet approximation coefficients", WAVELET_APPROX, 1, 1, 0);
	act_bv = bv_add_sv_to_bv(act_bv, 0, 1, 1, BTWPREC);
	bv = bv_append_bv(bv, act_bv);

	return bv;
}


void onFlowGenerated(packet_t *packet __attribute__((unused)), unsigned long flowIndex) {
	wavelet_t *waveP = &waveletP[flowIndex];
	memset( waveP, '\0', sizeof(wavelet_t) );

//	waveP->numSig = WAVELET_TYPE * 2;
#if WAVELET_IAT > 0
	waveP->lstPktTm = packet->pcapHeader->ts;
#endif // WAVELET_IAT > 0
}


#if ETH_ACTIVATE > 0
void claimLayer2Information(packet_t *packet, unsigned long flowIndex) {
	if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND || (packet->status & L2_FLOW) == 0) return;

	wavelet_t *waveP = &waveletP[flowIndex];

	if ( waveP->numSig < WAVELET_MAX_PKT ) {
#if WAVELET_IAT == 0
		waveP->sig[waveP->numSig] = packet->packetLength;
#else // WAVELET_IAT > 0
		struct timeval iat;
		timersub(&packet->pcapHeader->ts, &waveP->lstPktTm, &iat);
		waveP->iat[(waveP->numSig)++] = (WPREC)iat.tv_sec + (WPREC)iat.tv_usec/1000000.0;
		waveP->lstPktTm = packet->pcapHeader->ts;
#endif // WAVELET_IAT
	}
}
#endif // ETH_ACTIVATE > 0


void claimLayer4Information(packet_t *packet, unsigned long flowIndex) {
	wavelet_t *waveP = &waveletP[flowIndex];

	if ( waveP->numSig < WAVELET_MAX_PKT ) {
#if WAVELET_IAT == 0
		waveP->sig[(waveP->numSig)++] = packet->packetLength;
#else // WAVELET_IAT > 0
		struct timeval iat;
		timersub(&packet->pcapHeader->ts, &waveP->lstPktTm, &iat);
		waveP->iat[(waveP->numSig)++] = (WPREC)iat.tv_sec + (WPREC)iat.tv_usec/1000000.0;
		waveP->lstPktTm = packet->pcapHeader->ts;
#endif // WAVELET_IAT
	}
}


void onFlowTerminate(unsigned long flowIndex) {
	wavelet_t *waveP = &waveletP[flowIndex];

	uint32_t cnt = waveP->numSig, i;

	// waveNumPnts
	outputBuffer_append(main_output_buffer, (char*)&waveP->numSig, sizeof(uint16_t));

#if WAVELET_SIG == 1
	// Number of repetitions for waveSig
	outputBuffer_append(main_output_buffer, (char*)&cnt, sizeof(uint32_t));
	for (i = 0; i < cnt; i++) {
#if WAVELET_IAT == 0
		outputBuffer_append(main_output_buffer, (char*)&waveP->sig[i], sizeof(WPREC));
#else // WAVELET_IAT > 0
		outputBuffer_append(main_output_buffer, (char*)&waveP->iat[i], sizeof(WPREC));
#endif // WAVELET_IAT
	}
#endif // WAVELET_SIG == 1

	if ( cnt >= WAVELET_THRES ) {
		dwt1D( waveP, WAVELET_TYPE, WAVELET_LEVEL, WAVELET_EXTMODE ); // discrete wavelet transform

		cnt = WAVELET_LEVEL;
		outputBuffer_append(main_output_buffer, (char*)&cnt, sizeof(uint32_t));

		WPREC *p = waveP->wtDetail;

		outputBuffer_append(main_output_buffer, (char*)&cnt, sizeof(uint32_t));
		for (i = 0; i < WAVELET_LEVEL; i++) {
			cnt = waveP->wtlvl_len[i];
			outputBuffer_append(main_output_buffer, (char*)&cnt, sizeof(uint32_t));
			outputBuffer_append(main_output_buffer, (char*)p, cnt * sizeof(WPREC));
			p += cnt;
		}

		cnt = WAVELET_LEVEL;
		outputBuffer_append(main_output_buffer, (char*)&cnt, sizeof(uint32_t));

		p = waveP->wtApprox;
		for (i = 0; i < WAVELET_LEVEL; i++) {
			cnt = waveP->wtlvl_len[i];
			outputBuffer_append(main_output_buffer, (char*)&cnt, sizeof(uint32_t));
			outputBuffer_append(main_output_buffer, (char*)p, cnt * sizeof(WPREC));
			p += cnt;
		}
	} else {
		cnt = 0;
		outputBuffer_append(main_output_buffer, (char*)&cnt, sizeof(uint32_t));
		outputBuffer_append(main_output_buffer, (char*)&cnt, sizeof(uint32_t));
		outputBuffer_append(main_output_buffer, (char*)&cnt, sizeof(uint32_t));
	}
}


void onApplicationTerminate() {
	free(waveletP);
}
