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

#ifndef __DESCRIPTIVE_STATS_H__
#define __DESCRIPTIVE_STATS_H__

// local includes
#include "global.h"

// User defines
#define ENABLE_PS_CALC  1 // enables calculation of statistics for packet sizes
#define ENABLE_IAT_CALC 1 // enables calculation of statistics for inter arrival times

/*
 * The structure for the basic descriptive statistics for each target.
 * A target can be, for example, the bytelength, the inter arrival time for each
 * packet
 * the descriptive statistics for each target are:
 */
typedef struct {
	uint64_t numPackets;    // the number of packets used to calculate these statistics
	float min;              // the minimum value
	float max;              // the maximum value
	float mean;             // the mean value
	float lowerQuartile;    // the lower quartile
	float median;           // the median value
	float upperQuartile;    // the upper quartile
	float iqd;              // the inter quartile distance = the distance between the lower and the upper quartile
	float mode;             // the mode = the value with the most occurrence
	float range;            // the range = maximum value - minimum value
	float stddev;           // the standard deviation of the values
	float stdrob;           // the robust standard deviation = the minimum of the standard deviation and the 0.7413'th iqd
	float skewness;         // the skewness of the values
	float excess;           // the excess kurtosis (= kurtosis - 3) of the values
} dStats_t;

#if ESOM_DEP == 1
unsigned long *dStats_actNumPackets;
dStats_t dStats_packetLengths, dStats_IATs;
#endif // ESOM_DEP == 1

#endif // __DESCRIPTIVE_STATS_H__
