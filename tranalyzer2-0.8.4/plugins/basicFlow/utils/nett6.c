#include "utils.h"

#include <string.h>


int main(int argc __attribute__((unused)), char *argv[] __attribute__((unused))) {
    int i = 0, j, m, sw = 0, d;
    uint64_t net[2];
    uint64_t a[2] = {};
    char B[100][SMLINE+1];
    char line[SMLINE+1], rline[SMLINE];

    while (fgets(line, SMLINE, stdin)) {
        if (line[0] != '0') continue;

        sscanf(line, "0x%"SCNx64" %"SCNx64"\t%d\t%d\t%512[^\n]", &net[0], &net[1], &m, &d, rline);

        if (d & 1) {
            if (m > 127) {
                if (sw) {
                    for (j = i; j >= 0; j--) fputs(B[j], stdout);
                }
                fputs(line, stdout);
                sw = i = 0;
                continue;
            }

            if (net[0] == a[0] && net[1] == a[1]) {
                memcpy(B[++i], line, SMLINE+1);
                continue;
            }

            if (sw) {
                for (j = i; j >= 0; j--) fputs(B[j], stdout);
                memcpy(B[0], line, SMLINE+1);
                a[0] = net[0];
                a[1] = net[1];
                i = 0;
            } else {
                memcpy(B[0], line, SMLINE+1);
                a[0] = net[0];
                a[1] = net[1];
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
