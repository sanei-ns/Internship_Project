#include "utils.h"
#include "t2log.h"

#include <ctype.h>
#include <errno.h>
#include <string.h>


static void usage() {
    printf("Usage:\n");
    printf("    sbm4 subnets_in.txt subnets_out.bin version revision\n");
    printf("    sbm4 subnets.bin # returns the version of the subnet file\n");
}


// Extract and print version information from binary file
static void print_version_info(const char *filename) {
    FILE *file;
    if (!(file = fopen(filename, "r"))) {
        T2_ERR("Failed to open file '%s' for reading: %s", filename, strerror(errno));
        exit(EXIT_FAILURE);
    }

    subnet4_t srec;
    if (fread(&srec, sizeof(srec), 1, file) == 0) {
        T2_ERR("Failed to read record in file '%s'", filename);
        exit(EXIT_FAILURE);
    }

    fclose(file);

    printf("Version: %"PRIu32"\n", (srec.netVec & VERMSK));
    printf("Revision: %"PRIu32"\n", srec.netID);
    printf("Range_Mode: %"PRIu32"\n", (srec.netVec & ~VERMSK) >> 31);
    printf("Num_Subnets: %"PRIu32"\n", srec.net/2);
}


int main(int argc, char *argv[]) {

    if (argc < 2 || argc > 5 ||
        (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)))
    {
        usage();
        exit(argc == 2 ? EXIT_SUCCESS : EXIT_FAILURE);
    }

    if (argc == 2) {
        print_version_info(argv[1]);
        exit(EXIT_SUCCESS);
    }

    FILE *fin;
    if (!(fin = fopen(argv[1], "r"))) {
        T2_ERR("Failed to open file '%s' for reading: %s", argv[1], strerror(errno));
        exit(EXIT_FAILURE);
    }

    FILE *fout;
    if (!(fout = fopen(argv[2], "wb"))) {
        T2_ERR("Failed to open file '%s' for writing: %s", argv[2], strerror(errno));
        exit(EXIT_FAILURE);
    }

    subnet4_t srec;
    memset(&srec, '\0', sizeof(srec));
    fwrite(&srec, sizeof(srec), 1, fout);

    int32_t count = 0, i;
    uint32_t mask;

    size_t len = 0;
    char *line = NULL;
    while (getline(&line, &len, fin) != -1) {
        if (line[0] == '#' || isspace(line[0])) continue;
    	memset(&srec, '\0', sizeof(srec));

        sscanf(line, "0x%08x\t%"SCNu32"\t%"SCNd32"\t%"SCNd32"\t0x%08x\t%"SCNu32"\t%f\t%f\t%f\t%2[^\n\t]\t%"STR(WHOLEN)"[^\n\t]",
                &srec.net, &mask, &srec.netVec, &i, &srec.netID, &srec.asn, &srec.oP, &srec.lat, &srec.lng, srec.loc, srec.who);

#if SUBRNG == 1
        srec.beF = i;
        srec.mask = mask;
#else // SUBRNG == 0
        srec.mask = 0xffffffff << (32-mask);
#endif // SUBRNG

        fwrite(&srec, sizeof(srec), 1, fout);
        count++;
    }

    fclose(fin);
    free(line);

    // Write version information
    fseek(fout, 0, SEEK_SET);
    memset(&srec, '\0', sizeof(srec));
    srec.net = count;
    srec.netVec = atol(argv[3]) | (SUBRNG << 31);
    srec.netID = atol(argv[4]);
    // TODO are those memcpy really necessary?
    memcpy(srec.loc, SUBNET_UNK, strlen(SUBNET_UNK));
    memcpy(srec.who, SUBNET_UNK, strlen(SUBNET_UNK));
    fwrite(&srec, sizeof(srec), 1, fout);

    fclose(fout);

    return EXIT_SUCCESS;
}
