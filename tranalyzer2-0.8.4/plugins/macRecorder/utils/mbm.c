#include "macLbl.h"
#include "t2log.h"

#include <errno.h>
#include <string.h>



#define SMLINE 255


int main(int argc __attribute__((unused)), char *argv[]) {

    FILE *fout;
    if (!(fout = fopen(argv[1], "wb"))) {
        T2_ERR("Failed to open file '%s' for writing: %s", argv[2], strerror(errno));
        exit(EXIT_FAILURE);
    }

    maclbl_t srec = {};
    fwrite(&srec, sizeof(maclbl_t), 1, fout);

    char line[SMLINE+1], who[WHOLEN+1] = {};

    uint64_t mac;
    int32_t count = 0;
    uint32_t macID;

    while (fgets(line, SMLINE, stdin)) {
        if (line[0] == '\n' || line[0] == '#' || line[0] == ' ' || line[0] == '\t') continue;
        sscanf(line, "0x%"SCNx64"\t%"SCNu32"\t%11[^\n\t]", &mac, &macID, who);
        srec.mac = mac;
        srec.macID = macID;
        memcpy(srec.who, who, strlen(who)+1);
        fwrite(&srec, sizeof(maclbl_t), 1, fout);
        count++;
    }

    fseek(fout, 0, SEEK_SET);

    memset(&srec, '\0', sizeof(maclbl_t));
    srec.mac = count;
    fwrite(&srec, sizeof(maclbl_t), 1, fout);

    fclose(fout);

    return EXIT_SUCCESS;
}
