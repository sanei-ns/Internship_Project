#include "utils.h"


int main(int argc __attribute__((unused)), char *argv[] __attribute__((unused))) {
    int i = 1, j = 1, m, sw = 0, d;
    uint32_t net;
    int32_t A[100];
    char line[SMLINE+1], rline[SMLINE];

    A[0] = -1;
    A[1] = 0;

    while (fgets(line, SMLINE, stdin)) {
        if (line[0] != '0') continue;

        sscanf(line, "0x%"SCNx32"\t%d\t%d\t%500[^\n]", &net, &m, &d, rline);

        if (m < 32) {
            sw = 0;
        } else {
            if (sw == 0 && m == 32) {
                printf("0x%08"PRIx32"\t%02d\t%d\t%d\t%s\n", net, m, A[j], d, rline);
                sw = 1;
                i++;
            } else {
                sw = 0;
            }
            continue;
        }

        if ((d & 1) == 0) {
            printf("0x%08"PRIx32"\t%02d\t%d\t%d\t%s\n",
                    net, m, A[j], d, rline);
            A[++j] = i;
        } else if (j) {
            printf("0x%08"PRIx32"\t%02d\t%d\t%d\t%s\n",
                    net, m, A[j-1], d, rline);
            j--;
        }
        i++;

    }

    return EXIT_SUCCESS;
}
