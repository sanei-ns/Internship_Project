#ifndef _DWT_H
#define _DWT_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "define_global.h"

#define FULL  1
#define VALID 2

void dwt1D(wavelet_t *waveP, uint16_t wave_type, uint16_t wave_level, uint16_t wave_ext);

#endif // _DWT_H
