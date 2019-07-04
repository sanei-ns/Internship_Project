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

#include "descriptiveStats.h"
#include "pktSIATHisto.h"

#include <math.h>


// Global Plugin Variables

#if ESOM_DEP == 0
unsigned long *dStats_actNumPackets;
dStats_t dStats_packetLengths, dStats_IATs;
#endif // ESOM_DEP == 0


// Variables from pktSIATHisto plugin

extern rbTreeNodePool_t *pktSIAT_treeNodePool __attribute__((weak));
extern pktSIAT_t *pktSIAT_trees __attribute__((weak));
extern psiat_val_t *psiat_vals __attribute__((weak));


// Static variables

#if ENABLE_PS_CALC == 1
// vars to carry over the target value if a quartile lies in between
// two target values and therefore between values of two nodes in a tree
static unsigned long carryOverLower, carryOverMedian, carryOverUpper;
#endif

#if ENABLE_PS_CALC == 1 || ENABLE_IAT_CALC == 1
static float quartilePosLower, quartilePosMedian, quartilePosUpper;
// var to store the act maximum num of packets for determining the mode
static unsigned long actNumPacketsForMode;
#endif


// Static functions

#if ENABLE_PS_CALC == 1
static inline long ds_get_min(const rbNode_t *tree);
static inline long ds_get_max(const rbNode_t *tree);

static long long ds_get_sum(const rbNode_t *tree, unsigned long *numPkts);

static void ds_get_stats(const pktSIAT_t *tree, uint32_t numPkts, dStats_t *dStats);
static void ds_get_stats_r(const rbNode_t *tree, unsigned long *numPkts, dStats_t *dStats);
#endif


// Tranalyzer plugin functions

T2_PLUGIN_INIT_WITH_DEPS("descriptiveStats", "0.8.4", 0, 8, "pktSIATHisto");


binary_value_t* printHeader() {

	binary_value_t *bv = NULL;

#if ENABLE_PS_CALC == 1
	BV_APPEND_FLT(bv, "dsMinPl"        , "Minimum packet length");
	BV_APPEND_FLT(bv, "dsMaxPl"        , "Maximum packet length");
	BV_APPEND_FLT(bv, "dsMeanPl"       , "Mean packet length");
	BV_APPEND_FLT(bv, "dsLowQuartilePl", "Lower quartile of packet lengths");
	BV_APPEND_FLT(bv, "dsMedianPl"     , "Median of packet lengths");
	BV_APPEND_FLT(bv, "dsUppQuartilePl", "Upper quartile of packet lengths");
	BV_APPEND_FLT(bv, "dsIqdPl"        , "Inter quartile distance of packet lengths");
	BV_APPEND_FLT(bv, "dsModePl"       , "Mode of packet lengths");
	BV_APPEND_FLT(bv, "dsRangePl"      , "Range of packet lengths");
	BV_APPEND_FLT(bv, "dsStdPl"        , "Standard deviation of packet lengths");
	BV_APPEND_FLT(bv, "dsRobStdPl"     , "Robust standard deviation of packet lengths");
	BV_APPEND_FLT(bv, "dsSkewPl"       , "Skewness of packet lengths");
	BV_APPEND_FLT(bv, "dsExcPl"        , "Excess of packet lengths");
#endif

#if ENABLE_IAT_CALC == 1
	BV_APPEND_FLT(bv, "dsMinIat"        , "Minimum inter arrival time");
	BV_APPEND_FLT(bv, "dsMaxIat"        , "Maximum inter arrival time");
	BV_APPEND_FLT(bv, "dsMeanIat"       , "Mean inter arrival time");
	BV_APPEND_FLT(bv, "dsLowQuartileIat", "Lower quartile of inter arrival times");
	BV_APPEND_FLT(bv, "dsMedianIat"     , "Median inter arrival times");
	BV_APPEND_FLT(bv, "dsUppQuartileIat", "Upper quartile of inter arrival times");
	BV_APPEND_FLT(bv, "dsIqdIat"        , "Inter quartile distance of inter arrival times");
	BV_APPEND_FLT(bv, "dsModeIat"       , "Mode of inter arrival times");
	BV_APPEND_FLT(bv, "dsRangeIat"      , "Range of inter arrival times");
	BV_APPEND_FLT(bv, "dsStdIat"        , "Standard deviation of inter arrival times");
	BV_APPEND_FLT(bv, "dsRobStdIat"     , "Robust standard deviation of inter arrival times");
	BV_APPEND_FLT(bv, "dsSkewIat"       , "Skewness of inter arrival times");
	BV_APPEND_FLT(bv, "dsExcIat"        , "Excess of inter arrival times");
#endif

	return bv;
}


void initialize() {
	if (UNLIKELY(!(dStats_actNumPackets = malloc(sizeof(unsigned long))))) {
		T2_PERR("descriptiveStats", "failed to allocate memory for dStats_actNumPackets");
		exit(-1);
	}
}


#if ENABLE_PS_CALC == 1 || ENABLE_IAT_CALC == 1
void onFlowTerminate(unsigned long flowIndex) {
	pktSIAT_t * const treeP = &pktSIAT_trees[flowIndex];

#if ENABLE_PS_CALC == 1
	memset(&dStats_packetLengths, '\0', sizeof(dStats_t));

	// calculate and print packetlength statistics
	if (treeP->packetTree) {
		const float min = ds_get_min(treeP->packetTree);
		const float max = ds_get_max(treeP->packetTree);

		dStats_packetLengths.min = min;
		dStats_packetLengths.max = max;
		dStats_packetLengths.range = max - min;

		*dStats_actNumPackets = 0;
		const long long sum = ds_get_sum(treeP->packetTree, dStats_actNumPackets);
		dStats_packetLengths.mean = sum / (float) *dStats_actNumPackets;
		dStats_packetLengths.numPackets = *dStats_actNumPackets;
		ds_get_stats(treeP, treeP->numPackets, &dStats_packetLengths);
	}

	dStats_packetLengths.stddev = sqrt(dStats_packetLengths.stddev);
	dStats_packetLengths.iqd = dStats_packetLengths.upperQuartile - dStats_packetLengths.lowerQuartile;

	if (dStats_packetLengths.stddev < dStats_packetLengths.iqd * 0.7413f) {
		dStats_packetLengths.stdrob = dStats_packetLengths.stddev;
	} else {
		dStats_packetLengths.stdrob = dStats_packetLengths.iqd * 0.7413f;
	}

#if BLOCK_BUF == 0
	OUTBUF_APPEND(main_output_buffer, dStats_packetLengths.min, 13 * sizeof(float));
#endif

#endif // ENABLE_PS_CALC == 1

#if ENABLE_IAT_CALC == 1
	/*
	 * calculate and print IAT statistics
	 *
	 * A Note to the calculation: Because the inter arrival times are binned, ALL values
	 * a just approximations, more or less bad. Please be aware of it!
	 * */

	// If numPackets is one, print dummy output
	if (treeP->numPackets <= 1) {
#if BLOCK_BUF == 0
		memset(&main_output_buffer->buffer[main_output_buffer->pos], '\0', 13 * sizeof(float));
		main_output_buffer->pos += 13 * sizeof(float);
#endif
		return;
	}

	// We ignore the IAT of the first packet, because it is always zero
	// -> decrement value in bucket zero by one.
	treeP->numPacketsInTimeBin[0]--;
	treeP->numPackets--;

	// Now we have to solve the special case of one packet
	if (treeP->numPackets == 1) {
#if BLOCK_BUF == 0
		// search for the bin of this packet
		unsigned long bin = 0;
		while (!treeP->numPacketsInTimeBin[bin]) bin++;

		// now print stats
		const float f = bin2iat(bin);
		for (uint_fast32_t i = 0; i < 6; i++) {
			OUTBUF_APPEND_FLT(main_output_buffer, f);
		}

		outputBuffer_append(main_output_buffer, "\0\0\0\0", sizeof(float));
		OUTBUF_APPEND_FLT(main_output_buffer, f);
		memset(&main_output_buffer->buffer[main_output_buffer->pos], '\0', 5 * sizeof(float));
		main_output_buffer->pos += 5 * sizeof(float);
#endif // BLOCK_BUF == 0
		return;
	}

	memset(&dStats_IATs, '\0', sizeof(dStats_t));

	// get minimum iat
	// TODO: IAT Bin 0 handling improvement: if bin[0] > 1 ? ...
	long i;
	for (i = 0; i < IATBINUMAX; i++) {
		if (treeP->numPacketsInTimeBin[i] > 0) {
			dStats_IATs.min = (bin2iat(i) + bin2iat(i+1)) / 2.0f;
			break;
		}
	}

	// get maximum iat
	for (i = IATBINUMAX - 1; i >= 0; i--) {
		if (treeP->numPacketsInTimeBin[i] > 0) {
			dStats_IATs.max = (bin2iat(i) + bin2iat(i+1)) / 2.0f;
			break;
		}
	}

	// get range of iat's
	dStats_IATs.range = dStats_IATs.max - dStats_IATs.min;

	// get mean iat
	// because of this crazy binning we have to transform it
	// into the mean ms value of the bin and
	// later back into the bin of the mean ms, understood ?!? If not, don't care...
	// Next problem: Last bin is from 1000ms to infinity
	// -> take 1000ms as approx value -> stat gets falsified, be aware of it!!!
	for (i = 0; i < IATBINUMAX - 1; i++) {
		dStats_IATs.mean += (bin2iat(i) + bin2iat(i+1)) / 2.0 * treeP->numPacketsInTimeBin[i] / (float) treeP->numPackets;
	}
	dStats_IATs.mean += bin2iat(IATBINUMAX-1) * treeP->numPacketsInTimeBin[IATBINUMAX-1] / (float) treeP->numPackets;

	/*
	 * get iat quartiles
	 * we want to avoid going through the array several times, so this code is not very
	 * readable - sorry
	 */

	// Note: The calculation of the iat quantiles differs a bit from the calculation
	// of the packetsize quantiles because of the binning.
	quartilePosLower  = (treeP->numPackets-1) * 0.25f + 1.0f;
	quartilePosMedian = (treeP->numPackets-1) * 0.50f + 1.0f;
	quartilePosUpper  = (treeP->numPackets-1) * 0.75f + 1.0f;

	long bin = 0;
	long numPkts = 0;

	// get lower quartile
	// check if lower quartile pos is an integer
	if (quartilePosLower == roundf(quartilePosLower)) {
		// it is an integer
		// get bin of element at quartilePosLower
		while (treeP->numPacketsInTimeBin[bin] + numPkts < quartilePosLower) {
			numPkts = treeP->numPacketsInTimeBin[bin] + numPkts;
			bin++;
		}
		// we found the bin
		const float carryOverLowerIAT = (bin2iat(bin) + bin2iat(bin+1)) / 2.0f;
		// get bin of element at quartilePosLower + 1
		while (treeP->numPacketsInTimeBin[bin] + numPkts < quartilePosLower+1) {
			numPkts = treeP->numPacketsInTimeBin[bin] + numPkts;
			bin++;
			if (UNLIKELY(bin > IATBINUMAX-1)) {
				T2_PERR("descriptiveStats", "BUG: calc of lower quartile: #packets: %u, l: %f, m: %f, u %f",
						treeP->numPackets-1, quartilePosLower, quartilePosMedian, quartilePosUpper);
#if DEBUG > 0
				for (uint_fast32_t ii = 0; ii < IATBINUMAX; ii++) {
					fprintf(stdout, "[%"PRId32"]", treeP->numPacketsInTimeBin[ii]);
				}
#endif // DEBUG > 0
				exit(1);
			}
		}
		// we found the bin
		dStats_IATs.lowerQuartile = (bin2iat(bin) + bin2iat(bin+1)) / 2.0f;
		dStats_IATs.lowerQuartile = (carryOverLowerIAT + dStats_IATs.lowerQuartile) / 2.0f;
	} else {
		// it is not an integer
		// get bin of element at ceil(quartilePosLower)
		while (treeP->numPacketsInTimeBin[bin] + numPkts < ceilf(quartilePosLower)) {
			numPkts = treeP->numPacketsInTimeBin[bin] + numPkts;
			bin++;
		}
		// we found the bin
		dStats_IATs.lowerQuartile = (bin2iat(bin) + bin2iat(bin+1)) / 2.0f;
	}

	// get median
	// check if median quartile pos is an integer
	if (quartilePosMedian == roundf(quartilePosMedian)) {
		// it is an integer
		// get bin of element at quartilePosMedian
		while (treeP->numPacketsInTimeBin[bin] + numPkts < quartilePosMedian) {
			numPkts = treeP->numPacketsInTimeBin[bin] + numPkts;
			bin++;
		}
		// we found the bin
		const float carryOverMedianIAT = (bin2iat(bin) + bin2iat(bin+1)) / 2.0f;
		// get bin of element at quartilePosMedian + 1
		while (treeP->numPacketsInTimeBin[bin] + numPkts < quartilePosMedian+1) {
			numPkts = treeP->numPacketsInTimeBin[bin] + numPkts;
			bin++;
		}
		// we found the bin
		dStats_IATs.median = (bin2iat(bin) + bin2iat(bin+1)) / 2.0f;
		dStats_IATs.median = (carryOverMedianIAT + dStats_IATs.median) / 2.0f;
	} else {
		// it is not an integer
		// get bin of element at ceil(quartilePosMedian)
		while (treeP->numPacketsInTimeBin[bin] + numPkts < ceilf(quartilePosMedian)) {
			numPkts = treeP->numPacketsInTimeBin[bin] + numPkts;
			bin++;
		}
		// we found the bin
		dStats_IATs.median = (bin2iat(bin) + bin2iat(bin+1)) / 2.0f;
	}

	// get upper quartile
	// check if upper quartile pos is an integer
	if (quartilePosUpper == roundf(quartilePosUpper)) {
		// it is an integer
		// get bin of element at quartilePosUpper
		while (treeP->numPacketsInTimeBin[bin] + numPkts < quartilePosUpper) {
			numPkts = treeP->numPacketsInTimeBin[bin] + numPkts;
			bin++;
		}
		// we found the bin
		const float carryOverUpperIAT = (bin2iat(bin) + bin2iat(bin+1)) / 2.0f;
		// get bin of element at quartilePosUpper + 1
		while (treeP->numPacketsInTimeBin[bin] + numPkts < quartilePosUpper+1) {
			numPkts = treeP->numPacketsInTimeBin[bin] + numPkts;
			bin++;
		}
		// we found the bin
		dStats_IATs.upperQuartile = (bin2iat(bin) + bin2iat(bin+1)) / 2.0f;
		dStats_IATs.upperQuartile = (carryOverUpperIAT + dStats_IATs.upperQuartile) / 2.0f;
	} else {
		// it is not an integer
		// get bin of element at ceil(quartilePosUpper)
		while (treeP->numPacketsInTimeBin[bin] + numPkts < ceilf(quartilePosUpper)) {
			numPkts = treeP->numPacketsInTimeBin[bin] + numPkts;
			bin++;
		}
		// we found the bin
		dStats_IATs.upperQuartile = (bin2iat(bin) + bin2iat(bin+1)) / 2.0f;
	}

	// get iqd
	dStats_IATs.iqd = dStats_IATs.upperQuartile - dStats_IATs.lowerQuartile;

	// get mode iat
	// TODO: Change to bin mean -> change var type of mode
	actNumPacketsForMode = treeP->numPacketsInTimeBin[0];
	dStats_IATs.mode = (bin2iat(0) + bin2iat(1)) / 2.0f;
	for (i = 1; i < IATBINUMAX; i++) {
		if (treeP->numPacketsInTimeBin[i] > actNumPacketsForMode) {
			actNumPacketsForMode = treeP->numPacketsInTimeBin[i];
			dStats_IATs.mode = (bin2iat(i) + bin2iat(i+1)) / 2.0f;
		}
	}

	/* get stddev, skewness and excess */
	dStats_IATs.stddev   = 0.0f;
	dStats_IATs.skewness = 0.0f;
	dStats_IATs.excess   = 0.0f;

	float temp_sum = 0.0f;
	float temp1, temp2;

	// sum bins
	for (i = 0; i < IATBINUMAX; i++) {
		temp1 = (bin2iat(i) + bin2iat(i+1)) / 2.0f - dStats_IATs.mean;
		temp2 = temp1 * temp1;
		temp_sum += treeP->numPacketsInTimeBin[i] * temp2;
		temp2 *= temp1;
		dStats_IATs.skewness += treeP->numPacketsInTimeBin[i] * temp2;
		temp2 *= temp1;
		dStats_IATs.excess += treeP->numPacketsInTimeBin[i] * temp2;
	}

	temp1 = (1.0f / (float) treeP->numPackets) * temp_sum;
	temp2 = temp1 * temp1;

	// divide it thru the numPackets and take the squareroot
	dStats_IATs.stddev = sqrtf((1.0f / (float) (treeP->numPackets - 1)) * temp_sum);

	/* get stdrob */
	if (dStats_IATs.stddev < dStats_IATs.iqd * 0.7413f) {
		dStats_IATs.stdrob = dStats_IATs.stddev;
	} else {
		dStats_IATs.stdrob = dStats_IATs.iqd * 0.7413f;
	}

	// calc skewness, reuse value in temp_sum
	dStats_IATs.skewness = ((1.0f / (float) treeP->numPackets) * dStats_IATs.skewness) / sqrtf(temp2 * temp1);

	// calc excess, reuse value in temp_sum
	dStats_IATs.excess = ((1.0f / (float) treeP->numPackets) * dStats_IATs.excess) / temp2 - 3;

	// check if NaN
	if (isnan(dStats_IATs.stddev))   dStats_IATs.stddev   = 0.0f;
	if (isnan(dStats_IATs.skewness)) dStats_IATs.skewness = 0.0f;
	if (isnan(dStats_IATs.excess))   dStats_IATs.excess   = 0.0f;

	// print out
#if BLOCK_BUF == 0
	outputBuffer_append(main_output_buffer, (char*) &dStats_IATs.min, 13 * sizeof(float));
#endif // BLOCK_BUF == 0

	// increment first bucket to return to original values
	treeP->numPacketsInTimeBin[0]++;
	treeP->numPackets++;
#endif // ENABLE_IAT_CALC == 1
}
#endif // ENABLE_PS_CALC == 1 || ENABLE_IAT_CALC == 1


void onApplicationTerminate() {
	free(dStats_actNumPackets);
}


#if ENABLE_PS_CALC == 1
static inline long ds_get_min(const rbNode_t *tree) {
	// search for the leftmost entry
	while (tree->left) tree = tree->left;
	return tree->value;
}
#endif // ENABLE_PS_CALC == 1


#if ENABLE_PS_CALC == 1
static inline long ds_get_max(const rbNode_t *tree) {
	// search for the rightmost entry
	while (tree->right) tree = tree->right;
	return tree->value;
}
#endif // ENABLE_PS_CALC == 1


#if ENABLE_PS_CALC == 1
static long long ds_get_sum(const rbNode_t *tree, unsigned long *numPkts) {
	long long sum = 0;
	if (tree->left) sum += ds_get_sum(tree->left, numPkts);
	sum += tree->value * psiat_vals[tree - &pktSIAT_treeNodePool->nodePool[0]].numPackets;
	*numPkts += psiat_vals[tree - &pktSIAT_treeNodePool->nodePool[0]].numPackets;
	if (tree->right) sum += ds_get_sum(tree->right, numPkts);
	return sum;
}
#endif // ENABLE_PS_CALC == 1


#if ENABLE_PS_CALC == 1
static void ds_get_stats(const pktSIAT_t *tree, uint32_t numPkts, dStats_t *dStats) {
	// Calculate the absolute positions of the quantiles
	// The sorted packet lengths are taken as
	// the (0.5/N), (1.5/n),..., ((N-0.5)/N) quantiles,
	// N is the number of packets.
	// Therefore the position x of quantile q equals q * N - 0.5 (starting with index nr 0)
	quartilePosLower  = numPkts * 0.25f + 0.5f;
	quartilePosMedian = numPkts * 0.50f + 0.5f;
	quartilePosUpper  = numPkts * 0.75f + 0.5f;

	// fill in max and min to be safe
	const float min = dStats->min;
	const float max = dStats->max;
	dStats->lowerQuartile = min;
	dStats->upperQuartile = max;
	dStats->median = (min + max) / 2.0f;
	dStats->mode = tree->packetTree->value;
	dStats->stddev = 0.0f;

	carryOverLower  = 0;
	carryOverMedian = 0;
	carryOverUpper  = 0;
	actNumPacketsForMode = 0;

	// start with the searching
	*dStats_actNumPackets = 0;

	// only process if there are at least 2 packets
	if (numPkts > 1) {
		ds_get_stats_r(tree->packetTree, dStats_actNumPackets, dStats);
		const float variance = dStats->stddev;
		if (variance != 0.0f) {
			dStats->skewness /= powf(variance, 3.0f / 2.0f);
			dStats->excess = dStats->excess / (variance * variance) - 3; // powf(variance, 2.0f) - 3;
		}
	}
}
#endif // ENABLE_PS_CALC == 1


#if ENABLE_PS_CALC == 1
static void ds_get_stats_r(const rbNode_t *tree, unsigned long *numPkts, dStats_t *dStats) {
	// PLEASE NOTE:
	// The quartiles are calculated either using mean or linear interpolation.
	// Codelines for both ways are already given, you just have to uncomment the
	// one you want.
	// current version: linear interpolation

	// check left child
	if (tree->left) ds_get_stats_r(tree->left, numPkts, dStats);

	const unsigned long numPktsInNode = psiat_vals[tree - &pktSIAT_treeNodePool->nodePool[0]].numPackets;

	// lower quantile
	// quantile lies in this bucket
	if ((quartilePosLower >= *numPkts+1) && (quartilePosLower <= *numPkts + numPktsInNode)) {
		dStats->lowerQuartile = tree->value;
	// quantile lies in between this and the next bucket -> carry over needed!
	} else if ((quartilePosLower > *numPkts + numPktsInNode) && (quartilePosLower < *numPkts + numPktsInNode+1)) {
		carryOverLower = tree->value;
	// quantile lies in between the last and this bucket
	} else if ((quartilePosLower > *numPkts) && (quartilePosLower < *numPkts+1)) {
		// dStats->lowerQuartile = (carryOverLower + tree->value) / 2.0f; // mean
		dStats->lowerQuartile = (tree->value - carryOverLower) * (quartilePosLower - floor(quartilePosLower)) + carryOverLower; // linear interpolation
	}

	// median
	// quantile lies in this bucket
	if ((quartilePosMedian >= *numPkts+1) && (quartilePosMedian <= *numPkts + numPktsInNode)) {
		dStats->median = tree->value;
	// quantile lies in between this and the next bucket -> carry over needed!
	} else if ((quartilePosMedian > *numPkts + numPktsInNode) && (quartilePosMedian < *numPkts + numPktsInNode+1)) {
		carryOverMedian = tree->value;
	// quantile lies in between the last and this bucket
	} else if ((quartilePosMedian > *numPkts) && (quartilePosMedian < *numPkts+1)) {
		// dStats->median = (carryOverMedian + tree->value) / 2.0f; // mean
		dStats->median = (tree->value - carryOverMedian) * (quartilePosMedian - floor(quartilePosMedian)) + carryOverMedian; // linear interpolation
	}

	// upper quantile
	// quantile lies in this bucket
	if ((quartilePosUpper >= *numPkts+1) && (quartilePosUpper <= *numPkts + numPktsInNode)) {
		dStats->upperQuartile = tree->value;
	// quantile lies in between this and the next bucket -> carry over needed!
	} else if ((quartilePosUpper > *numPkts + numPktsInNode) && (quartilePosUpper < *numPkts + numPktsInNode+1)) {
		carryOverUpper = tree->value;
	// quantile lies in between the last and this bucket
	} else if ((quartilePosUpper > *numPkts) && (quartilePosUpper < *numPkts+1)) {
		// dStats->upperQuartile = (carryOverUpper + tree->value) / 2.0f; // mean
		dStats->upperQuartile = (tree->value - carryOverUpper) * (quartilePosUpper - floor(quartilePosUpper)) + carryOverUpper; // linear interpolation
	}

	// mode
	if (numPktsInNode > actNumPacketsForMode) {
		dStats->mode = tree->value;
		actNumPacketsForMode = numPktsInNode;
	}

	const float temp1 = tree->value - dStats->mean;
	float temp2 = temp1 * temp1;

	// variance
	dStats->stddev += (1.0f / (float) (dStats->numPackets)) * numPktsInNode * temp2; // powf((float) tree->value - dStats->mean, 2.0f);

	// skewness
	temp2 = temp2 * temp1;
	dStats->skewness += (1.0f / (float) (dStats->numPackets)) * numPktsInNode * temp2; // powf((float) tree->value - dStats->mean, 3.0f);

	// kurtosis
	temp2 = temp2 * temp1;
	dStats->excess += (1.0f / (float) (dStats->numPackets)) * numPktsInNode * temp2; // powf((float) tree->value - dStats->mean, 4.0f);

	// update actual number of packets
	*numPkts += numPktsInNode;

	// proceed with right child
	if (tree->right) ds_get_stats_r(tree->right, numPkts, dStats);
}
#endif // ENABLE_PS_CALC == 1
