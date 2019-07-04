#include "utils.h"
#include "t2log.h"

#include <errno.h>
#include <string.h>


int main(int argc, char *argv[]) {

    if (argc < 2) {
        printf("Usage: ext4 subnets4.txt\n");
        exit(EXIT_FAILURE);
    }

    FILE *fin;
    if (!(fin = fopen(argv[1], "r"))) {
        T2_ERR("Failed to open file '%s' for reading: %s", argv[1], strerror(errno));
        exit(EXIT_FAILURE);
    }

    uint32_t n, e, add = 0;
    int m;

#if SUBRNG == 1
    uint32_t adde = 0;
    char netE[20];
#else // SUBRNG == 0
    int m1, madd = 0;
    uint32_t ip, mm;
#endif // SUBRNG

    char line[SMLINE+1], netA[20], netr[40], rline[SMLINE];
    while (fgets(line, SMLINE, fin)) {
        if (line[0] == '\n' || line[0] == '#' || line[0] == ' ' || line[0] == '\t') continue;

#if SUBRNG == 0
        if (*line == '-') continue;

        sscanf(line, "%15[^/]/%d\t%d\t%32[^\t]\t%500[^\n]", netA, &m, &m1, netr, rline);

        inet_pton(AF_INET, netA, &ip);

        if (ip == add && m == madd) continue;

        add = ip;
        madd = m;
        mm = ntohl(0xffffffff << (32-m));
        n = ip & mm;
        e = ip | ~mm;
#else // SUBRNG == 1
        //sscanf(line, "%15[^/]/%d\t%d\t%15[^-]-%15[^\t]\t%500[^\n]", netr, &m, &m1, netA, netE, rline);
        sscanf(line, "%[^\t]\t%d\t%15[^-]-%15[^\t]\t%500[^\n]", netr, &m, netA, netE, rline);

        inet_pton(AF_INET, netA, &n);
        inet_pton(AF_INET, netE, &e);
        if (n == add && e == adde) continue;
        add = n;
        adde = e;
#endif // SUBRNG

        printf("0x%08x\t%02d\t0\t%s\n", ntohl(n), m, rline);
        printf("0x%08x\t%02d\t1\t%s\n", ntohl(e), m, rline);
    }

    fclose(fin);

    return EXIT_SUCCESS;
}
