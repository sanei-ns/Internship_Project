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

#ifndef WAVELET_H_
#define WAVELET_H_

/* local includes */
#include "global.h"
#include "define_global.h"

// local defines
//#define WAVELET_TXT "WaveCoef"WAVELET_TYPE""WAVELET_LEVEL""WAVELET_EXTMODE

#define WAVSTR(s) #s
#define WAVXSTR(s) WAVSTR(s)

#define WAVELET_DETAIL "waveCoefDetail"WAVXSTR(WAVELET_TYPE)
#define WAVELET_APPROX "waveCoefApprox"WAVXSTR(WAVELET_LEVEL)

// waveStat
#define WAVELET_ERR 0x01

#endif // WAVELET_H
