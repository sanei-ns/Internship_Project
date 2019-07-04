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
        printf("Usage: ext6 subnets6.txt\n");
        exit(EXIT_FAILURE);
    }

    FILE *fin;
    if (!(fin = fopen(argv[1], "r"))) {
        T2_ERR("Failed to open file '%s' for reading: %s", argv[1], strerror(errno));
        exit(EXIT_FAILURE);
    }

    ipAddr_t ip6A;
    uint64_t iphA0, iphA1, iphE0, iphE1;
    int m;

#if SUBRNG == 1
    ipAddr_t ip6E;
    char netE[41];
#else // SUBRNG == 0
    ipAddr_t add = {};
    uint64_t mask0, mask1;
    int madd = 0;
#endif // SUBRNG

    char line[SMLINE+1], rline[SMLINE], netA[INET6_ADDRSTRLEN+1], netr[2*INET6_ADDRSTRLEN+1];
    while (fgets(line, SMLINE, fin)) {
        if (line[0] == '\n' || line[0] == '#' || line[0] == ' ' || line[0] == '\t') continue;

#if SUBRNG == 0
        if (*line == '-') continue;

        //sscanf(line, "%40[^/]/%d\t%81[^\t]\t%500[^\n]", netA, &m, netr, rline);
        sscanf(line, "%"STR(INET6_ADDRSTRLEN)"[^/]/%d\t%"STR(INET6_ADDRSTRLEN2)"[^\t]\t%500[^\n]", netA, &m, netr, rline);

        inet_pton(AF_INET6, netA, &ip6A);

        if (ip6A.IPv6L[0] == add.IPv6L[0] && ip6A.IPv6L[1] == add.IPv6L[1] && m == madd) continue;

        add = ip6A;
        madd = m;
        //iph0 = htobe64(ip6.IPv6L[0]);
        //iph1 = htobe64(ip6.IPv6L[1]);

        if (m > 64) {
            mask0 = MASK64;
            mask1 = htobe64(MASK64 << (128-m));
        } else {
            mask0 = htobe64(MASK64 << (64-m));
            mask1 = 0;
        }

        iphA0 = ip6A.IPv6L[0] & mask0;
        iphA1 = ip6A.IPv6L[1] & mask1;
        iphE0 = ip6A.IPv6L[0] | ~mask0;
        iphE1 = ip6A.IPv6L[1] | ~mask1;
#else // SUBRNG == 1
        sscanf(line, "%39[^/]/%d\t%39[^-]-%39[^\t]\t%500[^\n]", netr, &m, netA, netE, rline);

        inet_pton(AF_INET6, netA, &ip6A);
        iphA0 = ip6A.IPv6L[0];
        iphA1 = ip6A.IPv6L[1];

        inet_pton(AF_INET6, netE, &ip6E);
        iphE0 = ip6E.IPv6L[0];
        iphE1 = ip6E.IPv6L[1];
#endif // SUBRNG

        printf("0x%016"PRIx64" %016"PRIx64"\t%03d\t0\t%s\n", be64toh(iphA0), be64toh(iphA1), m, rline);
        printf("0x%016"PRIx64" %016"PRIx64"\t%03d\t1\t%s\n", be64toh(iphE0), be64toh(iphE1), m, rline);
    }

    fclose(fin);

    return EXIT_SUCCESS;
}
