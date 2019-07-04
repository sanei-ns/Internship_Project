#include "utils.h"
#include "t2log.h"
#ifdef __APPLE__
#include "missing.h" // for htobe64
#endif

#include <errno.h>
#include <string.h>


#define MASK64 0xffffffffffffffff


int main(int argc, char *argv[]) {

    if (argc < 2) {
        printf("Usage: corr6 subnets6_N.txt\n");
        exit(EXIT_FAILURE);
    }

    FILE *fin;
    if (!(fin = fopen(argv[1], "r"))) {
        T2_ERR("Failed to open file '%s' for reading: %s", argv[1], strerror(errno));
        exit(EXIT_FAILURE);
    }

    int m;
    ipAddr_t ip6A, iphA, iphE;
    uint64_t mask0, mask1;
    char addr[INET6_ADDRSTRLEN];
    char addr1[INET6_ADDRSTRLEN];
    char line[SMLINE+1], rline[SMLINE], net[41], netr[82];

    while (fgets(line, SMLINE, fin)) {
        if (*line == '\n' || *line == '#' || *line == ' ' ||
            *line == '\t' || *line == '-')
        {
            continue;
        }

        sscanf(line, "%39[^/]/%d\t%81[^\t]\t%500[^\n]", net, &m, netr, rline);

        inet_pton(AF_INET6, net, &ip6A);

        if (m > 64) {
            mask0 = MASK64;
            mask1 = htobe64(MASK64 << (128-m));
        } else {
            mask0 = htobe64(MASK64 << (64-m));
            mask1 = 0;
        }

        iphA.IPv6L[0] = ip6A.IPv6L[0] & mask0;
        iphA.IPv6L[1] = ip6A.IPv6L[1] & mask1;
        iphE.IPv6L[0] = ip6A.IPv6L[0] | ~mask0;
        iphE.IPv6L[1] = ip6A.IPv6L[1] | ~mask1;

        inet_ntop(AF_INET6, &iphA.IPv6, addr, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &iphE.IPv6, addr1, INET6_ADDRSTRLEN);

        printf("%s/%d\t%s-%s\t%s\n", addr, m, addr, addr1, rline);
    }

    fclose(fin);

    return EXIT_SUCCESS;
}
