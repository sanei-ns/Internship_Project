// Calculates entropy based features for a T2 column from a flow or a packet file, selected by awk or cut
// moreover it decodes % http notation for urls
// compile with gcc vc.c -lm

#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ENT_MAXPBIN 256

int main(int argc, char *argv[]) {
	size_t len = 0;
	uint32_t aveLen, varLen, vLn;
	int32_t vl, cd;
	uint32_t a[6] = {};
	uint32_t e[256];
	uint32_t pChar, pBin, nmLen, numPkt;
	float p, entropy;
	int i, j, k;
	uint8_t c, z[256];
	char *r = NULL;

	memset(z, 0, 256);
	memset(&z[48], 1, 10);
	memset(&z[97], 2, 26);
	memset(&z[65], 2, 26);
	for (i = 65; i <= 73; i += 4) z[i] = 3;
	z[74] = 3;
	z[79] = 3;
	z[85] = 3;
	for (i = 97; i <= 105; i += 4) z[i] = 3;
	z[106] = 3;
	z[111] = 3;
	z[117] = 3;
	for (i = 58; i <= 64; i++) z[i] = 4;
	for (i = 91; i <= 96; i++) z[i] = 4;
	for (i = 123; i <= 126; i++) z[i] = 4;
	z[46] = 5;
   	z[95] = 5;
	z[64] = 5;
	z[45] = 5;

	aveLen = 0;
	varLen = 0;
	numPkt = 0;

	while (getline(&r, &len, stdin) != -1) {
		memset(a, 0, 24);
		memset(e, 0, 1024);
		nmLen = strlen(r)-1;
		pBin = 0;
		pChar = 0;
		entropy = 0;
		numPkt++;
		vLn = 0;
		cd = 0;

		for (i = 0, k = 0; i < nmLen; i++, k++) {
			c = (uint8_t)r[i];
			if (i != k) r[k] = c;
			if (c == 0xc3) {
				vLn++;
				continue;
			} else if (c == '%') {
				cd++;
				sscanf(&r[i+1], "%02x", &c);
				r[k] = c;
				i += 2;
				continue;
			}

			for (j = 0; j < 6; j++) if (z[c] == j) a[j]++;
			e[c]++;
		}
		r[k] = 0x00;

		nmLen -= vLn;

		for (i = 0; i < ENT_MAXPBIN; i++) {
			if (e[i]) {
				p = (float)e[i] / (float)nmLen;
				entropy += p * log(p);
				if (i == 10 || i == 13 || (i >= 32 && i <= 127)) pChar += e[i];
				if (i < 10) pBin += e[i];
			}
		}
		entropy /= -logf(ENT_MAXPBIN); //  Normalize to base 256, so that the result is between 0 and 1

		aveLen += nmLen;
		vl = (float)aveLen/(float)numPkt - nmLen;
		varLen += vl * vl;

		printf("%d,%d,%d,%d,%d,%d,%d,%u\t%f %f %f %u %f %f\t%s\n", a[0], a[1], a[2], a[3], a[4], a[5], cd, vLn, pChar/(float)nmLen, pBin/(float)nmLen, entropy, nmLen, aveLen/(float)numPkt, sqrtf((float)varLen)/(float)numPkt, r);
	}

	return 0;
}
