#ifndef DEFINE_GLOBAL_H
#define DEFINE_GLOBAL_H

// user defines
#define WAVELET_IAT       0 // 0: pktLen, 1: IAT calc
#define WAVELET_SIG       0 // 1: print signal
#define WAVELET_PREC      0 // 0: float; 1: double
#define WAVELET_THRES     8
#define WAVELET_MAX_PKT  40

#define WAVELET_LEVEL     3 // Wavelet decomposition level
#define WAVELET_EXTMODE ZPD // Extension Mode: SYM=0, ZPD=1
#define WAVELET_TYPE    DB3 // Mother Wavelet

// global defines
#define WAVELET_APPROX_MAX  (WAVELET_MAX_PKT / 2)
#define WAVELET_SIG_MAX (WAVELET_MAX_PKT + 4 * WAVELET_TYPE)     // Max number of packets considered for the wavelet transform + if extended 2 * waveletlength
#define WAVELET_MAX_WT_LEN (WAVELET_MAX_PKT * (2 - 1 / (2 << WAVELET_LEVEL))) // Max WT signal length

#if WAVELET_PREC == 1
#define WPREC double
#define BTWPREC bt_double
#else // WAVELET_PREC == 0
#define WPREC float
#define BTWPREC bt_float
#endif // WAVELET_PREC

// data types
enum {
	NON, // no extension
	SYM, // DEFAULT-Symmetric-Padding (Half Point): Boundary value symmetric replication
	ZPD  // Zero padding: X --> [00..00] X [00..00] from 0 to lf-1
};

// The order between the wavelet in the enum and WAVELETS[] MUST be the same */

enum {
	DB1,
	DB2,
	DB3,
	DB4
};

typedef struct {
	WPREC wtDetail[WAVELET_MAX_WT_LEN];
	WPREC wtApprox[WAVELET_MAX_WT_LEN];
#if WAVELET_IAT == 0
	WPREC sig[WAVELET_SIG_MAX];
#else // WAVELET_IAT > 0
	WPREC iat[WAVELET_SIG_MAX];
	struct timeval lstPktTm;
#endif // WAVELET_IAT
	uint16_t numSig;
	uint16_t waveStat;
	uint16_t wtlvl_len[WAVELET_LEVEL]; // len of wavelet detail/approximation
} wavelet_t;

#endif // DEFINE_GLOBAL_H
