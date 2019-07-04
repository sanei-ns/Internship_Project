#include "utils.h"

#include <string.h>


int main(int argc __attribute__((unused)), char *argv[] __attribute__((unused))) {
    int i = 0, j, m, sw = 0, d;
    uint32_t net;
    uint32_t a = 0;
    char B[100][SMLINE+1];
    char line[SMLINE+1], rline[SMLINE];

    while (fgets(line, SMLINE, stdin)) {
        if (line[0] != '0') continue;

        sscanf(line, "0x%"SCNx32"\t%d\t%d\t%500[^\n]", &net, &m, &d, rline);

        if (d & 1) {
            if (m > 31) {
                if (sw) {
                    for (j = i; j >= 0; j--) fputs(B[j], stdout);
                }
                fputs(line, stdout);
                sw = i = 0;
                continue;
            }

            if (net == a) {
                memcpy(B[++i], line, SMLINE+1);
                continue;
            }

            if (sw) {
                for (j = i; j >= 0; j--) fputs(B[j], stdout);
                memcpy(B[0], line, SMLINE+1);
                a = net;
                i = 0;
            } else {
                memcpy(B[0], line, SMLINE+1);
                a = net;
                i = 0;
                sw = 1;
            }
        } else {
            if (sw) {
                for (j = i; j >= 0; j--) fputs(B[j], stdout);
            }
            fputs(line, stdout);
            sw = i = 0;
        }
    }

    fputs(line, stdout);

    return EXIT_SUCCESS;
}
