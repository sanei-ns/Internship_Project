#include "utils.h"
#include "subnetHL4.h"

#include <errno.h>
#include <string.h>


FILE *dooF;


int main(int argc, char *argv[]) {

    if (argc < 2) {
        printf("Usage: upwho4 updatefile.bin\n");
        exit(EXIT_FAILURE);
    }

    uint32_t subnetNr, add;
    int msk, m, asn;
    float lat, lng;
    char ip[INET_ADDRSTRLEN], iprng[2*INET_ADDRSTRLEN+3], loc[4], who[SMLINE+1], p[12], id[12];

    subnet4_t *subnP;
    dooF = stdout;

    size_t len = 0;
    char *line = NULL;

    subnettable4_t *subnet_table4P = subnet_init4(NULL, argv[1]);

    while (getline(&line, &len, stdin) != -1) {
        if (line[0] == '#') {
            fputs(line, stdout);
            continue;
        }

        sscanf(line, "%[^/]/%d\t%d\t%[^\t]\t%[^\t]\t%d\t%[^\t]\t%f\t%f\t%02[^\t]\t%[^\n\t]", ip, &msk, &m, iprng, id, &asn, p, &lat, &lng, loc, who);

        inet_pton(AF_INET, ip, &add);
        subnetNr = subnet_testHL4(subnet_table4P, add); // subnet test source ip
        if (subnetNr) {
            subnP = &subnet_table4P->subnets[subnetNr];
            if (lng == 666.0 || lng == 0.0) {
                lat = subnP->lat;
                lng = subnP->lng;
            }
            if (asn == 0) asn = subnP->asn;
            //if (*loc == "f") memcpy(loc, subnP->loc, 2);
            //if (memcmp(who, "--", 2) == 0) strncpy(who, subnP->who, strlen(subnP->who)+1);

            printf ("%s/%d\t%d\t%s\t%s\t%d\t%s\t%f\t%f\t%s\t%s\n",
                    ip, msk, m, iprng, id, asn, p, lat, lng, subnP->loc, subnP->who);

        } else {
            fputs(line, stdout);
        }
    }

    subnettable4_destroy(subnet_table4P);

    return EXIT_SUCCESS;
}
