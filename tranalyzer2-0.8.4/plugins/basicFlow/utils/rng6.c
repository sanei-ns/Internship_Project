#include "utils.h"
#include "t2log.h"
#ifdef __APPLE__
#include "missing.h" // for htobe64
#endif

#include <errno.h>
#include <string.h>


#define MASK64 0xffffffffffffffff
#define INET6_ADDRSTRLEN2 92


int main(int argc, char *argv[]) {

    if (argc < 2) {
        printf("Usage: rng6 subnets6.txt\n");
        exit(EXIT_FAILURE);
    }

    FILE *fin;
    if (!(fin = fopen(argv[1], "r"))) {
        T2_ERR("Failed to open file '%s' for reading: %s", argv[1], strerror(errno));
        exit(EXIT_FAILURE);
    }

    ipAddr_t ip6A, ip6E;
    int m;
    char line[SMLINE+1], rline[SMLINE], netA[INET6_ADDRSTRLEN+1], netr[2*INET6_ADDRSTRLEN+1];

    uint64_t mask0, mask1;

    while (fgets(line, SMLINE, fin)) {
        if (line[0] == '\n' || line[0] == ' ' || line[0] == '\t') continue;

        if (line[0] == '#') {
            fputs(line, stdout);
            continue;
        }

        sscanf(line, "%"STR(INET6_ADDRSTRLEN)"[^/]/%d\t%"STR(INET6_ADDRSTRLEN2)"[^\t]\t%500[^\n]", netA, &m, netr, rline);

        if (netr[0] == '-') {
            inet_pton(AF_INET6, netA, &ip6A);

            if (m > 64) {
                mask0 = MASK64;
                mask1 = htobe64(MASK64 << (128-m));
            } else {
                mask0 = htobe64(MASK64 << (64-m));
                mask1 = 0;
            }

            ip6E.IPv6L[0] = ip6A.IPv6L[0] | ~mask0;
            ip6E.IPv6L[1] = ip6A.IPv6L[1] | ~mask1;

            inet_ntop(AF_INET6, (char*)&ip6E, netr, INET6_ADDRSTRLEN);

            printf("%s/%d\t%s-%s\t%s\n", netA, m, netA, netr, rline);

        } else {
            printf("%s/%d\t%s\t%s\n", netA, m, netr, rline);
        }
    }

    fclose(fin);

    return EXIT_SUCCESS;
}
