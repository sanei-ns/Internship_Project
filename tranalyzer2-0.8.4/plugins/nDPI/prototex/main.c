#include <stdio.h>
#include <stdint.h>
#include "ndpi_api.h"

int main() {
    // init nDPI module
    struct ndpi_detection_module_struct *ndpi_struct = ndpi_init_detection_module();

    // enable all protocols
    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_struct, &all);

    // print tex first lines
    printf("\\begin{multicols}{3}\n\\begin{description}\n");

    // buffer for ndpi proto with escaped characters
    char buffer[256];

    // print all protocols values
    const uint16_t proto_count = ndpi_get_num_supported_protocols(ndpi_struct);
    for (uint16_t i = 0; i < proto_count; ++i) {
        char* proto = ndpi_get_proto_name(ndpi_struct, i);
        // escape underscore
        const size_t len = strlen(proto);
        size_t diff = 0;
        for (size_t j = 0; j < len; ++j) {
            if (proto[j] == '_') {
                buffer[j+diff] = '\\';
                buffer[j+diff+1] = '_';
                ++diff;
            } else {
                buffer[j+diff] = proto[j];
            }
        }
        buffer[len+diff] = '\0';
        // print result
        printf("\\item [%d] %s\n", i, buffer);
    }

    // print tex last lines
    printf("\\end{description}\n\\end{multicols}\n");

    // clean ndpi module
    ndpi_exit_detection_module(ndpi_struct);

    return 0;
}
