#ifndef __UTILS_H__
#define __UTILS_H__

#include "networkHeaders.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>


// user defines
#define SUBRNG 0  // IP range definition 0: CIDR only 1: Begin-End
#define WHOLEN 23 // length of WHO record


// plugin defines
#define SUBVER 3 // Version of the subnet file

#define VERMSK 0x7fff // Version mask
#define SMLINE (1024 + WHOLEN) // line length of subnetfile
#define SUBNET_UNK "--" // Representation of unknown locations


typedef struct {
    uint32_t net; // in Host Order !
    uint32_t netVec;
    uint32_t netID;
#if SUBRNG == 0
    uint32_t mask;
#endif
    uint32_t asn;
    float lat, lng, oP;
    char loc[4];
    char who[WHOLEN+1];
#if SUBRNG == 1
    uint8_t mask;
    uint8_t beF;
#endif
} subnet4_t;

typedef struct {
    ipAddr_t net; // in Host Order !
#if SUBRNG == 0
    ipAddr_t mask;
#endif
    uint32_t netVec;
    uint32_t netID;
    uint32_t asn;
    float lat, lng, oP;
    char loc[4];
    char who[WHOLEN+1];
#if SUBRNG == 1
    uint8_t mask;
    uint8_t beF;
#endif
} subnet6_t;

#endif // __UTILS_H__
