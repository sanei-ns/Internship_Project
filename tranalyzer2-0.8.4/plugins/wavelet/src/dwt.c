#include "dwt.h"
#include "wavelet_types.h"

/*
 * This function computes the decomposition coefficients for all the levels
 */
static inline uint16_t convolution1D(WPREC *X, int dimX, WPREC *H, int dimH, WPREC *Y, int dimY, int shape);


inline void dwt1D(wavelet_t *waveP, uint16_t wave_type, uint16_t wave_level, uint16_t wave_ext) {
	uint32_t i;
#if WAVELET_IAT == 0
	WPREC *sig = waveP->sig;
#else // WAVELET_IAT > 0
	WPREC *sig = waveP->iat;
#endif // WAVELET_IAT
	WPREC *wt_detail = waveP->wtDetail;
	WPREC *wt_approx = waveP->wtApprox;
	uint16_t wt_len = WAVELETS[wave_type].length, sig_len = waveP->numSig;
	WPREC *lo_d = WAVELETS[wave_type].LO_D;
	WPREC *hi_d = WAVELETS[wave_type].HI_D;

	if (wave_ext != ZPD) {
/*		for (i = 0; i < wave_level; i++) {
			// Extend signal according to mode
			ext_signal_dim = signal_len + (lenEXT * 2);
			extend_signal_1D(signal, signal_len, lenEXT, ext_sig, ext_signal_dim);

			// Details
			convolution1D(ext_sig, EXT_signal_dim, hi_d, wave_len, conv_sign, conv_sig_dim, VALID);

			// Approximation
			conv_sig_dim = ext_signal_dim - wavelet_L + 1;
			convolution1D(ext_sig, ext_signal_dim, lo_d, wave_len, conv_sign, conv_sig_dim, VALID);
		}
*/
	} else {
		// default case, zero padding assumed or just take the signal and run, convolution is FULL
		for (i = 0; i < wave_level; i++) {
			// Details
			waveP->wtlvl_len[i] = convolution1D(sig, sig_len, hi_d, wt_len, wt_detail, sig_len, FULL);
			// Approximation
			sig_len = convolution1D(sig, sig_len, lo_d, wt_len, wt_approx, sig_len, FULL);
			wt_detail += sig_len;
			sig = wt_approx;
			wt_approx += sig_len;
		}
	}
}


/*THIS FUNCTION EXTENDS THE SIGNAL AT THE BORDERS IN ORDER TO AVOID THE DISTORTION DUE TO THE FINITE LENGTH OF SIGNAL
 * @lenEXT is the length of the extension

int extend_signal_1D(wavelet_t waveP, ) {

	int i, counter;
	int start_index = 0;

	switch (wavelet_extmode) {
	case (ZPD):
		for (i = 0; i < lenEXT; i++) final_sig[i] = 0;

		memcpy(final_sig + lenEXT, orig_signal, sizeof(WPREC) * orig_sig_dim);

		for (i = orig_sig_dim + lenEXT; i < final_sig_dim; i++) final_sig[i] = 0;

		break;
	case (SYM):

		if (orig_sig_dim < lenEXT) {
			// THIS IS THE SPECIAL CASE WHEN THE EXTENTION > THAN THE SIZE OF THE ORIGINAL ARRAY

			memcpy(final_sig + lenEXT, orig_signal, sizeof(WPREC) * orig_sig_dim);

			counter = 0;
			start_index = orig_sig_dim + lenEXT;

			for (i = orig_sig_dim + lenEXT; i < final_sig_dim; i++) {
				if (counter == orig_sig_dim) {
					start_index = start_index + counter;
					counter = 0;
				}
				final_sig[i] = final_sig[start_index - 1 - counter];
				counter++;
			}


			start_index = lenEXT;
			counter = 0;

			for (i = lenEXT-1; i >=0; i--) {
				if (counter == orig_sig_dim) {
					start_index = start_index - counter;
					counter = 0;
				}
				final_sig[i] = final_sig[start_index + counter];
				counter++;
			}

		} else {

			for (i = 0; i < lenEXT; i++) {
				final_sig[i] = orig_signal[lenEXT - i - 1];
			}
			memcpy(final_sig + lenEXT, orig_signal, sizeof(WPREC) * orig_sig_dim);

			counter = 0;
			for (i = orig_sig_dim + lenEXT; i < final_sig_dim; i++) {
				final_sig[i] = orig_signal[orig_sig_dim - 1 - counter];
				counter++;
			}
		}

		break;

	default:
		printf("extend_signal_1D: This extension mode was not implemented yet\n");
		return 0;
	}

	return 1;
*/


/*
 * CONVOLUTION of TWO ARRAYS
 * 1D DIMENSION
 * @X: input signal
 * @H: filter
 * @shape: if FULL complete convolution;
 *         if VALID compute only those parts of the convolution that are computed without the padded edges.
 *          The resulting array has size [dimX-dimH +1]. If dimX<dimH the array should be empty so return error
 * @Y: output signal
 **/
static inline uint16_t convolution1D(WPREC *X, int dimX, WPREC *H, int dimH, WPREC *Y, int dimY, int shape) {
    uint16_t i = 0, j = 0, j1, j2, k = 0;
    uint16_t ja1, ja2, jp1, ja;
    WPREC s;

    if (shape == FULL) {

            if (dimY < dimX) return 0;

            for (i = 0; i < dimY; i++) {
                    s = 0.0;
                    if ( i < dimX ) j1 = 0;
                    else j1 = i - dimX + 1;

                    if (i >= dimH) j2 = dimH - 1;
                    else j2 = i;

                    for (j = j1; j <= j2; j++) s += X[i-j] * H[j];

                    if (i % 2) Y[k++] = s; // downsampling, shift not included
            }

    } else if (shape == VALID) {

            if ((dimY != (dimX - dimH + 1)) || (dimX < dimH)) return 0;

            for (i = 0; i < dimY; i++) {
                s = 0.0;
                j = i + dimH - 1;
                jp1 = j + 1;

                if (dimH < jp1) ja1 = jp1 - dimH; // ja1 = max(1,jp1-nb);
                else ja1 = 0;

                if (dimX < j) ja2 = dimX; // ja2 = min(na,j);
                else ja2 = j;

                for (ja = ja1; ja <= ja2; ja++) s += X[ja] * H[jp1-ja-1];

                if (i % 2) Y[k++] = s; // downsampling, shift not included
            }

    } else return 0;

    return k;
}
