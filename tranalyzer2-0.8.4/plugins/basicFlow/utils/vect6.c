#include "utils.h"


int main(int argc __attribute__((unused)), char *argv[] __attribute__((unused))) {
    int i = 1, j = 1, m, sw = 0, d;
    uint64_t net[2];
    int32_t A[100];
    char line[SMLINE+1], rline[SMLINE];

    A[0] = -1;
    A[1] = 0;

    while (fgets(line, SMLINE, stdin)) {
        if (line[0] != '0') continue;

        sscanf(line, "0x%"SCNx64" %"SCNx64"\t%d\t%d\t%500[^\n]", &net[0], &net[1], &m, &d, rline);

        if (m < 128) {
            sw = 0;
        } else {
            if (sw == 0 && m == 128) {
                printf("0x%016"PRIx64" %016"PRIx64"\t%d\t%d\t%d\t%s", net[0], net[1], m, A[j], d, rline);
                sw = 1;
                i++;
            } else {
                sw = 0;
            }
            continue;
        }

        if ((d & 1) == 0) {
            printf("0x%016"PRIx64" %016"PRIx64"\t%d\t%d\t%d\t%s\n",
                    net[0], net[1], m, A[j], d, rline);
            A[++j] = i;
        } else if (j) {
            printf("0x%016"PRIx64" %016"PRIx64"\t%d\t%d\t%d\t%s\n",
                    net[0], net[1], m, A[j-1], d, rline);
            j--;
        }
        i++;

    }

    return EXIT_SUCCESS;
}
