#include "utils.h"
#include "subnetHL6.h"


FILE *dooF;


int main(int argc, char *argv[]) {

    if (argc < 2) {
        printf("Usage: upwho6 updatefile.bin\n");
        exit(EXIT_FAILURE);
    }

    uint32_t subnetNr;
    int msk, asn;
    ipAddr_t add = {};
    float lat, lng;
    char ip[INET6_ADDRSTRLEN], iprng[2*INET6_ADDRSTRLEN+3], loc[4], who[SMLINE+1], p[12], id[12];

    subnet6_t *subnP;
    dooF = stdout;

    size_t len = 0;
    char *line = NULL;

    subnettable6_t *subnet_table6P = subnet_init6(NULL, argv[1]);

    while (getline(&line, &len, stdin) != -1) {
        if (line[0] == '#') {
            fputs(line, stdout);
            continue;
        }

        sscanf(line, "%[^/]/%d\t%[^\t]\t%[^\t]\t%d\t%[^\t]\t%f\t%f\t%02[^\t]\t%[^\n\t]", ip, &msk, iprng, id, &asn, p, &lat, &lng, loc, who);

        inet_pton(AF_INET6, ip, &add);
        subnetNr = subnet_testHL6(subnet_table6P, add); // subnet test source ip
        if (subnetNr) {
            subnP = &subnet_table6P->subnets[subnetNr];
            if (lng == 666.0) {
                lat = subnP->lat;
                lng = subnP->lng;
            }
            if (asn == 0) asn = subnP->asn;

            printf ("%s/%d\t%s\t%s\t%d\t%s\t%f\t%f\t%s\t%s\n",
                    ip, msk, iprng, id, asn, p, lat, lng, subnP->loc, subnP->who);

        } else {
            fputs(line, stdout);
        }
    }

    subnettable6_destroy(subnet_table6P);

    return EXIT_SUCCESS;
}
