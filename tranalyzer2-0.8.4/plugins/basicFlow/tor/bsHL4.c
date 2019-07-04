#include "subnetHL4.h"
#include "t2log.h"

#include <errno.h>
#include <string.h>


FILE *dooF;


int main(int argc, char *argv[]) {

	dooF = stdout;

	if (argc < 2) {
		printf("Usage: bsHL4 torfile\n");
		exit(EXIT_FAILURE);
	}

	uint32_t subnetNr, i, addr, netID;
	subnet4_t *subnP;

	struct sockaddr_in sa;
	char str[INET_ADDRSTRLEN];

	FILE *file;
	if (!(file = fopen(argv[1], "r"))) {
		T2_ERR("Failed to open file '%s' for reading: %s", argv[1], strerror(errno));
		exit(EXIT_FAILURE);
	}

	subnettable4_t *bfo_subnet_table4P = subnet_init4(NULL, SUBNETFILE4);

	size_t len = 0;
	char *line = NULL;
	while (getline(&line, &len, file) != -1) {
		if (line[0] == '#') continue;
		sscanf(line, "%s[^\n\t]", str);
		inet_pton(AF_INET, str, &(sa.sin_addr));
		addr = sa.sin_addr.s_addr;
		subnetNr = subnet_testHL4(bfo_subnet_table4P, addr); // subnet test source ip
		addr = ntohl(addr);
		subnP = &bfo_subnet_table4P->subnets[subnetNr];
		netID = subnP->netID | 0x00800000;
		for (i = 0; i < 2; i++) {
			printf("0x%08x\t32\t%"PRIu32"\t0x%08x\t%d\t1.0\t%f\t%f\t%s\tTOR,%s\n", addr, i, netID, subnP->asn, subnP->lng, subnP->lat, subnP->loc, subnP->who);
		}
	}

	fclose(file);

	subnettable4_destroy(bfo_subnet_table4P);

	return EXIT_SUCCESS;
}
