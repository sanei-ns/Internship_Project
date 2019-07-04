/*
 * jsonSink.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "jsonSink.h"
#include "bin2txt.h"

#if GZ_COMPRESS == 1
#include "gz2txt.h"
#else // GZ_COMPRESS == 0
#include "bin2txt.h"
#endif // GZ_COMPRESS == 0


#if BLOCK_BUF == 0

// Static variables

#if GZ_COMPRESS == 1
static gzFile jsonFD;
#endif // GZ_COMPRESS == 1

#if SOCKET_ON == 0
static char jsonFileName[MAX_FILENAME_LEN+1];
#if GZ_COMPRESS == 0
static FILE *jsonFD;
#endif // GZ_COMPRESS == 0
#else // SOCKET_ON == 1
static struct sockaddr_in server;
static int sock;
#endif // SOCKET_ON == 1

static b2t_func_t funcs;
static char *bv_buffer;
static char *json_buffer;
static uint64_t json_buffer_size;
static uint64_t json_buffer_pos;
static uint64_t main_buf_pos;
static uint64_t corrupt_flows;

#if SOCKET_ON == 0 && JSON_SPLIT == 1
// -W option
static uint64_t oFileNum, oFileLn;
static uint64_t jsnfIndex;
static char *oFileNumP;
#endif // SOCKET_ON == 0 && JSON_SPLIT == 1


// Function prototypes

static int parse_binary_value(uint32_t type);
static int parse_subval_compound(const binary_subvalue_t * const sv);
static inline int buf_get_val(void *dest, const uint64_t size, const uint64_t n);
static int sanitize_utf8(const uint8_t * const input, char *output, uint64_t *input_bytes_processed, uint64_t *output_bytes_written);

#endif // BLOCK_BUF == 0


// Tranalyzer plugin API functions

T2_PLUGIN_INIT("jsonSink", "0.8.4", 0, 8);


#if JSON_ROOT_NODE == 1 && BLOCK_BUF == 0
static inline void json_add_root(uint8_t end) {
    const char c = end ? ']' : '[';
#if SOCKET_ON == 0
#if GZ_COMPRESS == 1
    gzprintf(jsonFD, "%c\n", c);
#else // GZ_COMPRESS == 0
    fprintf(jsonFD, "%c\n", c);
#endif // GZ_COMPRESS == 0
#else // SOCKET_ON == 1
#if GZ_COMPRESS == 1
    if (UNLIKELY(gzwrite(jsonFD, "%c\n", c) <= 0)) {
#else // GZ_COMPRESS == 0
    if (UNLIKELY(write(sock, "%c\n", c) == -1)) {
#endif // SOCKET_ON == 1
        T2_PERR("jsonSink", "Could not send '%c' to socket %s:%d: %s", c, inet_ntoa(server.sin_addr), server.sin_port, strerror(errno));
        exit(-1);
    }
#endif // GZ_COMPRESS == 0
}
#endif // JSON_ROOT_NODE == 1 && BLOCK_BUF == 0


void initialize() {
#if BLOCK_BUF == 1
    T2_PWRN("jsonSink", "BLOCK_BUF is set in 'tranalyzer.h', no flow file will be produced");
#else // BLOCK_BUF == 0

#if GZ_COMPRESS == 1
    GZ2TXT_TEST_ZLIB_VERSION("jsonSink");
    funcs = b2t_funcs_gz;
#else // GZ_COMPRESS == 0
    funcs = b2t_funcs;
#endif // GZ_COMPRESS == 0

    json_buffer_size = JS_BUFFER_SIZE;
    if (UNLIKELY(!(json_buffer = malloc(json_buffer_size * sizeof(char))))) {
        T2_PERR("jsonSink", "Could not allocate memory for json output buffer");
        exit(-1);
    }

    if (UNLIKELY(!(bv_buffer = calloc(40, sizeof(char))))) {
        T2_PERR("jsonSink", "Could not allocate memory for bv_buffer");
        exit(-1);
    }

#if SOCKET_ON == 0
    if (capType & WSTDOUT) {
#if GZ_COMPRESS == 1
        if (UNLIKELY((jsonFD = gzdopen(fileno(stdout), "w")) == NULL)) {
            T2_PERR("jsonSink", "Could not create compressed stream: %s", strerror(errno));
            free(bv_buffer);
            exit(-1);
        }
#else // GZ_COMPRESS == 0
        jsonFD = stdout;
#endif // GZ_COMPRESS == 0
        return;
    }

    size_t len = baseFileName_len + sizeof(JSON_SUFFIX) + 1;
#if GZ_COMPRESS == 1
    len += sizeof(GZ_SUFFIX);
#endif // GZ_COMPRESS == 1
    if (UNLIKELY(len > MAX_FILENAME_LEN)) {
        T2_PERR("jsonSink", "filename too long");
        exit(1);
    }

    strncpy(jsonFileName, baseFileName, baseFileName_len+1);
    strcat(jsonFileName, JSON_SUFFIX);
#if GZ_COMPRESS == 1
    strcat(jsonFileName, GZ_SUFFIX);
#endif // GZ_COMPRESS == 1

#if JSON_SPLIT == 1
    if (capType & OFILELN) {
        jsnfIndex = 0;
        oFileLn = (uint64_t)oFragFsz;
        oFileNumP = jsonFileName + strlen(jsonFileName);
        oFileNum = oFileNumB;
        sprintf(oFileNumP, "%"PRIu64, oFileNum);
    }
#endif // JSON_SPLIT == 1

    // Open json file
    if (UNLIKELY((jsonFD = funcs.fopen(jsonFileName, "w")) == NULL)) {
        T2_PERR("jsonSink", "Failed to open file '%s' for writing: %s", jsonFileName, strerror(errno));
        free(bv_buffer);
        exit(-1);
    }

#else // SOCKET_ON == 1

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (UNLIKELY(sock == -1)) {
        T2_PERR("jsonSink", "Could not create socket: %s", strerror(errno));
        free(bv_buffer);
        exit(-1);
    }

#if GZ_COMPRESS == 1
    if (UNLIKELY((jsonFD = gzdopen(sock, "w")) == NULL)) {
        T2_PERR("jsonSink", "Could not create compressed stream: %s", strerror(errno));
        free(bv_buffer);
        exit(-1);
    }
#endif // GZ_COMPRESS == 1

    server.sin_addr.s_addr = inet_addr(SOCKET_ADDR);
    server.sin_family = AF_INET;
    server.sin_port = htons(SOCKET_PORT);

    // Connect to remote server
    if (UNLIKELY(connect(sock, (struct sockaddr *)&server , sizeof(server)) < 0)) {
        T2_PERR("jsonSink", "Could not connect to socket %s:%d: %s", inet_ntoa(server.sin_addr), SOCKET_PORT, strerror(errno));
        free(bv_buffer);
        exit(-1);
    }
#endif // SOCKET_ON == 1

#if JSON_ROOT_NODE == 1
    json_add_root(0);
#endif // JSON_ROOT_NODE == 1

#endif // BLOCK_BUF == 0
}


// If BLOCK_BUF == 1, the plugin does not produce any output.
// All the code below is therefore not activated.


#if BLOCK_BUF == 0

static inline void js_write_value_name(binary_value_t *act_bv) {
    if (LIKELY(act_bv != main_header_bv)) {
        json_buffer[json_buffer_pos++] = ','; // value separator
#if JSON_NO_SPACES == 0
        json_buffer[json_buffer_pos++] = ' '; // space
#endif
    }
    // Write object name -> value name short
    json_buffer[json_buffer_pos++] = '"'; // starting quotation marks
    strcpy(&(json_buffer[json_buffer_pos]), act_bv->name); // object name itself
    json_buffer_pos += strlen(act_bv->name); // increase buffer pos
    json_buffer[json_buffer_pos++] = '"'; // ending quotation marks
    json_buffer[json_buffer_pos++] = ':'; // name-value separator
#if JSON_NO_SPACES == 0
    json_buffer[json_buffer_pos++] = ' '; // space
#endif
}


void bufferToSink(outputBuffer_t* buffer __attribute__((unused))) {
    uint64_t i;

    if (LIKELY(main_buf_pos != 0)) {
#if JSON_ROOT_NODE == 1
#if SOCKET_ON == 0
#if GZ_COMPRESS == 1
        gzputc(jsonFD, ',');
#else // GZ_COMPRESS == 0
        fputc(',', jsonFD);
#endif // GZ_COMPRESS == 0
#else // SOCKET_ON == 1
        int ii;
#if GZ_COMPRESS == 1
        ii = gzwrite(jsonFD, ",", 1);
#else // GZ_COMPRESS == 0
        ii = write(sock, ",", 1);
#endif // GZ_COMPRESS == 0
        if (UNLIKELY(ii <= 0)) {
            T2_PERR("jsonSink", "Could not send comma to socket %s:%d: %s", inet_ntoa(server.sin_addr), server.sin_port, strerror(errno));
            exit(-1);
        }
#endif // SOCKET_ON == 1
#endif // JSON_ROOT_NODE == 1
        main_buf_pos = 0;
    }

    binary_value_t* act_bv = main_header_bv;
    uint32_t num_repeat = 0, j;

    json_buffer_pos = 0; // reset actual output buffer pos to start of array
    json_buffer[json_buffer_pos++] = '{'; // write object opening bracket
    while (act_bv != NULL) {
        switch (act_bv->is_repeating) {
            case 0:
                num_repeat = 1;
                js_write_value_name(act_bv);
                break;

            case 1:
                if (UNLIKELY(buf_get_val(&num_repeat, sizeof(uint32_t), 1) != 0)) {
                    return;
                }
#if SUPPRESS_EMPTY_ARRAY == 1
                if (num_repeat == 0) break;
#endif // SUPPRESS_EMPTY_ARRAY
                js_write_value_name(act_bv);
                json_buffer[json_buffer_pos++] = '['; // It's repeating -> print repeat array bracket
                break;

            default:
                T2_PERR("jsonSink", "Could not determine state of value repetition");
                return;
        }

        for (i = 0; i < num_repeat; i++) {

            if (i > 0) {
                json_buffer[json_buffer_pos++] = ','; // repeat separator
#if JSON_NO_SPACES == 0
                json_buffer[json_buffer_pos++] = ' '; // space
#endif
            }

            if (act_bv->num_values > 1) {
                json_buffer[json_buffer_pos++] = '['; // Val has two or more subvalues -> print value array opening bracket
            }

            for (j = 0; j < act_bv->num_values; j++) {
                if (j > 0) {
                    json_buffer[json_buffer_pos++] = ','; // value separator
#if JSON_NO_SPACES == 0
                    json_buffer[json_buffer_pos++] = ' '; // space
#endif
                }
                const binary_subvalue_t * const subval = &act_bv->subval[j];
                if (subval->type == bt_compound) {
                    if (UNLIKELY(parse_subval_compound(subval) == 1)) {
                        return;
                    }
                } else {
                    if (UNLIKELY(parse_binary_value(subval->type) == 1)) {
                        return;
                    }
                }
            }
            if (act_bv->num_values > 1) {
                json_buffer[json_buffer_pos++] = ']'; // print value array closing bracket
            }
        }

#if SUPPRESS_EMPTY_ARRAY == 1
        if (act_bv->is_repeating == 1 && num_repeat > 0) {
#else // SUPPRESS_EMPTY_ARRAY
        if (act_bv->is_repeating == 1) {
#endif // SUPPRESS_EMPTY_ARRAY
            json_buffer[json_buffer_pos++] = ']'; // It's repeating -> close repeating array bracket
        }

        act_bv = act_bv->next;
    }

    json_buffer[json_buffer_pos++] = '}'; // write object closing bracket
    json_buffer[json_buffer_pos++] = 0; // String terminator

#if SOCKET_ON == 0
#if GZ_COMPRESS == 1
    gzputs(jsonFD, json_buffer);
    gzputc(jsonFD, '\n');
#else // GZ_COMPRESS == 0
    fputs(json_buffer, jsonFD);
    fputc('\n', jsonFD);
#endif // GZ_COMPRESS == 0

#if JSON_SPLIT == 1
    if (capType & OFILELN) {
        const uint64_t offset = ((capType & WFINDEX) ? ++jsnfIndex : (uint64_t)funcs.ftell(jsonFD));
        if (offset >= oFileLn) {
#if JSON_ROOT_NODE == 1
            json_add_root(1);
#endif // JSON_ROOT_NODE == 1
            funcs.fclose(jsonFD);

            oFileNum++;
            sprintf(oFileNumP, "%"PRIu64, oFileNum);

            if (UNLIKELY((jsonFD = funcs.fopen(jsonFileName, "w")) == NULL)) {
                T2_PERR("jsonSink", "Failed to open file '%s' for writing: %s", jsonFileName, strerror(errno));
                exit(-1);
            }
#if JSON_ROOT_NODE == 1
            json_add_root(0);
#endif // JSON_ROOT_NODE == 1
            main_buf_pos = 0;

            jsnfIndex = 0;
        }
    }
#endif // JSON_SPLIT == 1

#else // SOCKET_ON == 1

    // Send json dump
    uint64_t len = strlen(json_buffer);
    char *ptr = json_buffer;
    while (len > 0) {
#if GZ_COMPRESS == 1
        i = gzwrite(jsonFD, ptr, len);
#else // GZ_COMPRESS == 0
        i = write(sock, ptr, len);
#endif // GZ_COMPRESS == 0
        if (UNLIKELY(i <= 0)) {
            T2_PERR("jsonSink", "Could not send message '%s' to socket %s:%d: %s", ptr, inet_ntoa(server.sin_addr), server.sin_port, strerror(errno));
            exit(-1);
        }
        ptr += i;
        len -= i;
    }

    // Send \n char, necessary for compability e.g. logstash
#if GZ_COMPRESS == 1
    if (UNLIKELY(gzwrite(jsonFD, "\n", 1) <= 0)) {
#else // GZ_COMPRESS == 0
    if (UNLIKELY(write(sock, "\n", 1) == -1)) {
#endif // GZ_COMPRESS == 0
        T2_PERR("jsonSink", "Could not send newline to socket %s:%d: %s", inet_ntoa(server.sin_addr), server.sin_port, strerror(errno));
        exit(-1);
    }
#endif // SOCKET_ON == 1
}


void pluginReport(FILE *stream) {
    T2_FPLOG_NUMP(stream, "jsonSink", "flows discarded due to main buffer problems", corrupt_flows, totalFlows);
}


void onApplicationTerminate() {
#if JSON_ROOT_NODE == 1
#if SOCKET_ON == 1
    if (LIKELY(sock != 0))
#else // SOCKET_ON == 0
    if (LIKELY(jsonFD != NULL))
#endif // SOCKET_ON == 0
        json_add_root(1);
#endif // JSON_ROOT_NODE == 1

    // cleanup

#if GZ_COMPRESS == 1 || SOCKET_ON == 0
    funcs.fclose(jsonFD);
#endif // GZ_COMPRESS == 1 || SOCKET_ON == 0

#if SOCKET_ON == 1
    close(sock);
#endif // SOCKET_ON == 1

    free(bv_buffer);
    free(json_buffer);
}


// This function assumes main_output_buffer exists and is not null
// (if it could not be created the program would have exited already)
static inline int buf_get_val(void *dest, const uint64_t size, const uint64_t n) {
    const uint64_t sn = size * n;

    if (UNLIKELY(main_output_buffer->size < main_buf_pos + sn)) {
        if (corrupt_flows == 0) {
            T2_PERR("jsonSink", "Position in main output buffer exceeds its size, first occurence after %"PRIu64" flows. This is mostly caused of corrupt data in it. discarding line.", totalFlows);
        }
        ++corrupt_flows;
        return 1; // error
    }

    memcpy(dest, main_output_buffer->buffer + main_buf_pos, sn);
    main_buf_pos += sn;

    return 0; // success
}


static int parse_subval_compound(const binary_subvalue_t *sv) {
    // check if output can be repeated. If yes, read amount of repeats, if no set num_repeat to 1
    uint32_t num_repeat = 1;
    if (sv->is_repeating) {
        if (UNLIKELY(buf_get_val(&num_repeat, sizeof(uint32_t), 1) != 0)) {
            return 1;
        }

        if (num_repeat == 0) {
            return 0;
        }

        json_buffer[json_buffer_pos++] = '[';
    }

    uint_fast32_t i, j;
    for (i = 0; i < num_repeat; i++) {
        if (i > 0) {
            json_buffer[json_buffer_pos++] = ',';
#if JSON_NO_SPACES == 0
            json_buffer[json_buffer_pos++] = ' '; // space
#endif
        }

        if (sv->num_values > 1 || sv->subval[0].type == bt_compound) {
            json_buffer[json_buffer_pos++] = '[';
        }

        for (j = 0; j < sv->num_values; j++) {
            if (j > 0) {
                json_buffer[json_buffer_pos++] = ',';
#if JSON_NO_SPACES == 0
                json_buffer[json_buffer_pos++] = ' '; // space
#endif
            }
            if (sv->subval[j].type == bt_compound) {
                if (UNLIKELY(parse_subval_compound(&sv->subval[j]) == 1)) {
                    return 1;
                }
            } else {
                if (UNLIKELY(parse_binary_value(sv->subval[j].type) == 1)) {
                    return 1;
                }
            }
        }

        if (sv->num_values > 1 || sv->subval[0].type == bt_compound) {
            json_buffer[json_buffer_pos++] = '[';
        }

    }

    if (sv->is_repeating) {
        json_buffer[json_buffer_pos++] = ']';
    }

    return 0;
}


static void print_double_val(long double val) {
    const uint64_t start_pos = json_buffer_pos;
    json_buffer_pos += sprintf(&(json_buffer[json_buffer_pos]), "%.*Lg", 17, val);

    // make sure there is an 'e' or a '.' in the double,
    // otherwise it could be interpreted as an int
    if (strchr(&(json_buffer[start_pos]), '.') == NULL &&
        strchr(&(json_buffer[start_pos]), 'e') == NULL)
    {
        json_buffer[json_buffer_pos++] = '.';
        json_buffer[json_buffer_pos++] = '0';
        json_buffer[json_buffer_pos] = '\0';
        return;
    }

    // remove leading zeros in the exponent, e.g., 0.1e-002 -> 0.1e-2

    char *start = strchr(&(json_buffer[start_pos]), 'e');
    if (!start) return;

    // Skip 'e'
    start++;

    // Skip +/- sign
    if (*start == '-' || *start == '+') start++;

    // Skip leading zeros
    char *end = start;
    while (*end == '0') end++;

    if (end == start) return; // No leading zeros to remove

    // Shift the buffer backward to overwrite leading zeros
    const size_t len = strlen(&(json_buffer[start_pos]));
    memmove(start, end, len - (size_t)(end - &(json_buffer[start_pos])));
    json_buffer_pos -= (uint64_t)(end - start);
}


static int parse_binary_value(uint32_t type) {
    int retval = 0;
    switch (type) {
        case bt_int_8:
            retval = buf_get_val(bv_buffer, sizeof(int8_t), 1);
            json_buffer_pos += sprintf(&(json_buffer[json_buffer_pos]), "%"PRId8, *((int8_t*) bv_buffer));
            break;

        case bt_int_16:
            retval = buf_get_val(bv_buffer, sizeof(int16_t), 1);
            json_buffer_pos += sprintf(&(json_buffer[json_buffer_pos]), "%"PRId16, *((int16_t*) bv_buffer));
            break;

        case bt_int_32:
            retval = buf_get_val(bv_buffer, sizeof(int32_t), 1);
            json_buffer_pos += sprintf(&(json_buffer[json_buffer_pos]), "%"PRId32, *((int32_t*) bv_buffer));
            break;

        case bt_int_64:
            retval = buf_get_val(bv_buffer, sizeof(int64_t), 1);
            json_buffer_pos += sprintf(&(json_buffer[json_buffer_pos]), "%"PRId64, *((int64_t*) bv_buffer));
            break;

        case bt_uint_8:
            retval = buf_get_val(bv_buffer, sizeof(uint8_t), 1);
            json_buffer_pos += sprintf(&(json_buffer[json_buffer_pos]), "%"PRIu8, *((uint8_t*) bv_buffer));
            break;

        case bt_uint_16:
            retval = buf_get_val(bv_buffer, sizeof(uint16_t), 1);
            json_buffer_pos += sprintf(&(json_buffer[json_buffer_pos]), "%"PRIu16, *((uint16_t*) bv_buffer));
            break;

        case bt_uint_32:
            retval = buf_get_val(bv_buffer, sizeof(uint32_t), 1);
            json_buffer_pos += sprintf(&(json_buffer[json_buffer_pos]), "%"PRIu32, *((uint32_t*) bv_buffer));
            break;

        case bt_uint_64:
            retval = buf_get_val(bv_buffer, sizeof(uint64_t), 1);
            json_buffer_pos += sprintf(&(json_buffer[json_buffer_pos]), "%"PRIu64, *((uint64_t*) bv_buffer));
            break;

        case bt_hex_8:
            retval = buf_get_val(bv_buffer, sizeof(uint8_t), 1);
            json_buffer_pos += sprintf(&(json_buffer[json_buffer_pos]), "\"0x%02"B2T_PRIX8"\"", *((uint8_t*) bv_buffer));
            break;

        case bt_hex_16:
            retval = buf_get_val(bv_buffer, sizeof(uint16_t), 1);
            json_buffer_pos += sprintf(&(json_buffer[json_buffer_pos]), "\"0x%04"B2T_PRIX16"\"", *((uint16_t*) bv_buffer));
            break;

        case bt_hex_32:
            retval = buf_get_val(bv_buffer, sizeof(uint32_t), 1);
            json_buffer_pos += sprintf(&(json_buffer[json_buffer_pos]), "\"0x%08"B2T_PRIX32"\"", *((uint32_t*) bv_buffer));
            break;

        case bt_hex_64:
            retval = buf_get_val(bv_buffer, sizeof(uint64_t), 1);
            json_buffer_pos += sprintf(&(json_buffer[json_buffer_pos]), "\"0x%016"B2T_PRIX64"\"", *((uint64_t*) bv_buffer));
            break;

        case bt_float:
            retval = buf_get_val(bv_buffer, sizeof(float), 1);
            print_double_val((long double) *((float*) bv_buffer));
            break;

        case bt_double:
            retval = buf_get_val(bv_buffer, sizeof(double), 1);
            print_double_val((long double) *((double*) bv_buffer));
            break;

        case bt_long_double:
            retval = buf_get_val(bv_buffer, sizeof(long double), 1);
            print_double_val(*((long double*) bv_buffer));
            break;

        case bt_char:
            retval = buf_get_val(bv_buffer, sizeof(uint8_t), 1);
            json_buffer[json_buffer_pos++] = *bv_buffer;
            break;

        case bt_string_class:
        case bt_string:
            sanitize_utf8((uint8_t*) &(main_output_buffer->buffer[main_buf_pos]), &(json_buffer[json_buffer_pos]), (uint64_t*) bv_buffer, (uint64_t*) (bv_buffer + sizeof(uint64_t)));
            main_buf_pos += *((uint64_t*) bv_buffer);
            json_buffer_pos += *((uint64_t*) (bv_buffer + sizeof(uint64_t)));
            json_buffer[json_buffer_pos] = '\0';
            break;

        case bt_mac_addr: {
            retval = buf_get_val(bv_buffer, l_bt_mac_addr * sizeof(uint8_t), 1);
            const uint8_t * const val8 = (uint8_t*)bv_buffer;
#if MAC_FORMAT == 1
            json_buffer_pos += snprintf(&(json_buffer[json_buffer_pos]), 21,
                    "\"0x%016"B2T_PRIX64"\"",
                    ((uint64_t)val8[0] << 40) | ((uint64_t)val8[1] << 32) | ((uint64_t)val8[2] << 24) |
                    ((uint64_t)val8[3] << 16) | ((uint64_t)val8[4] << 8)  |  (uint64_t)val8[5]);
#else // MAC_FORMAT == 0
            const size_t len = 15 + 5 * sizeof(MAC_SEP);
            json_buffer_pos += snprintf(&(json_buffer[json_buffer_pos]), len,
                    "\"%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s"
                      "%02"B2T_PRIX8"%s%02"B2T_PRIX8"%s%02"B2T_PRIX8"\"",
                    val8[0], MAC_SEP, val8[1], MAC_SEP, val8[2], MAC_SEP,
                    val8[3], MAC_SEP, val8[4], MAC_SEP, val8[5]);
#endif // MAC_FORMAT == 0
            break;
        }

        case bt_ip4_addr: {
json_bt_ip4:
            retval = buf_get_val(bv_buffer, l_bt_ip4_addr * sizeof(uint8_t), 1);
            const uint8_t * const val8 = (uint8_t*)bv_buffer;
#if IP4_FORMAT == 1
            json_buffer_pos += snprintf(&(json_buffer[json_buffer_pos]), 18,
                    "\"%03"PRIu8".%03"PRIu8".%03"PRIu8".%03"PRIu8"\"",
                    val8[0], val8[1], val8[2], val8[3]);
#elif IP4_FORMAT == 2
            json_buffer_pos += snprintf(&(json_buffer[json_buffer_pos]), 13,
                    "\"0x%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"\"",
                    val8[0], val8[1], val8[2], val8[3]);
#elif IP4_FORMAT == 3
            json_buffer_pos += snprintf(&(json_buffer[json_buffer_pos]), 11, "%"PRIu32,
                    (val8[0] << 24) | (val8[1] << 16) | (val8[2] << 8) | val8[3]);
#else // IP4_FORMAT == 0
            json_buffer_pos += sprintf(&(json_buffer[json_buffer_pos]),
                    "\"%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\"",
                    val8[0], val8[1], val8[2], val8[3]);
#endif // IP4_FORMAT == 0
            break;
        }

        case bt_ip6_addr: {
json_bt_ip6:
            retval = buf_get_val(bv_buffer, l_bt_ip6_addr * sizeof(uint8_t), 1);
            json_buffer[json_buffer_pos++] = '"';
#if IP6_FORMAT == 1
            const uint16_t * const val16 = (uint16_t*)bv_buffer;
            json_buffer_pos += snprintf(&(json_buffer[json_buffer_pos]), 40,
                    "%04"B2T_PRIX16":%04"B2T_PRIX16":%04"B2T_PRIX16":%04"B2T_PRIX16":"
                    "%04"B2T_PRIX16":%04"B2T_PRIX16":%04"B2T_PRIX16":%04"B2T_PRIX16,
                    ntohs(val16[0]), ntohs(val16[1]), ntohs(val16[2]), ntohs(val16[3]),
                    ntohs(val16[4]), ntohs(val16[5]), ntohs(val16[6]), ntohs(val16[7]));
#elif IP6_FORMAT == 2
            const uint8_t * const val8 = (uint8_t*)bv_buffer;
            json_buffer_pos += snprintf(&(json_buffer[json_buffer_pos]), 35,
                    "0x%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8
                      "%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8
                      "%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8
                      "%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8,
                    val8[0], val8[1], val8[2], val8[3], val8[4], val8[5], val8[6], val8[7],
                    val8[8], val8[9], val8[10], val8[11], val[12], val8[13], val8[14], val8[15]);
#elif IP6_FORMAT == 3
#if JSON_NO_SPACES == 0
            const char *space = " ";
#else // JSON_NO_SPACES == 1
            const char *space = "";
#endif // JSON_NO_SPACES == 1
            json_buffer_pos += snprintf(&(json_buffer[json_buffer_pos]), 41,
                    "[0x%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8
                        "%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8",%s"
                    "0x%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8
                        "%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"%02"B2T_PRIX8"]",
                    val8[0], val8[1], val8[2], val8[3], val8[4], val8[5], val8[6], val8[7], space,
                    val8[8], val8[9], val8[10], val8[11], val8[12], val8[13], val8[14], val8[15]);
#else // IP6_FORMAT == 0
            char addr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, bv_buffer, addr, INET6_ADDRSTRLEN);
            json_buffer_pos += snprintf(&(json_buffer[json_buffer_pos]), strlen(addr)+1, "%s", addr);
#endif // IP6_FORMAT
            json_buffer[json_buffer_pos++] = '"';
            json_buffer[json_buffer_pos] = '\0';
            break;
        }

        case bt_ipx_addr: {
            if (UNLIKELY(buf_get_val(bv_buffer, sizeof(uint8_t), 1) != 0)) {
                return 1;
            }
            if (*bv_buffer == 6) goto json_bt_ip6;
            else if (*bv_buffer == 4) goto json_bt_ip4;
            else {
                T2_PERR("jsonSink", "Invalid IP version %"PRIu8, *bv_buffer);
                return 1;
            }
            break;
        }

        case bt_timestamp:
        case bt_duration:
            if (UNLIKELY(buf_get_val(bv_buffer, sizeof(uint64_t), 1) != 0)) { // read seconds
                return 1;
            }
            retval = buf_get_val(bv_buffer + sizeof(uint64_t), sizeof(uint32_t), 1); // read nanoseconds

#if B2T_TIME_IN_MICRO_SECS != 0
            *((uint32_t*) (bv_buffer + sizeof(uint64_t))) /= 1000;
#endif // B2T_TIME_IN_MICRO_SECS != 0

            *(bv_buffer + sizeof(uint64_t) + sizeof(uint32_t)) = 0; // reuse val array for counter
            json_buffer[json_buffer_pos++] = '"';

#if B2T_TIMESTR == 1
            if (type == bt_duration) {
#endif // B2T_TIMESTR == 1
                json_buffer_pos += sprintf(&(json_buffer[json_buffer_pos]), "%"PRIu64".%"B2T_TPFRMT, *((uint64_t*) bv_buffer), *(((uint32_t*) (bv_buffer + sizeof(uint64_t)))));
#if B2T_TIMESTR == 1
            } else {
                const struct tm *t;
#if TSTAMP_UTC == 1
                t = gmtime((time_t*) bv_buffer);
#else // TSTAMP_UTC == 0
                t = localtime((time_t*) bv_buffer);
#endif // TSTAMP_UTC == 0
                char timeBuf[30];
                // ISO 8601 time format
                // <year>-<month>-<day>T<hours>:<minutes>:<seconds>.<micro/nano-seconds><+/-offset>
                strftime(timeBuf, sizeof(timeBuf), B2T_TIMEFRMT, t);
                json_buffer_pos += sprintf(&(json_buffer[json_buffer_pos]), "%s.%"B2T_TPFRMT, timeBuf, *((uint32_t*) (bv_buffer + sizeof(uint64_t))));
#if TSTAMP_UTC == 1 && defined(__APPLE__)
                json_buffer_pos += sprintf(&(json_buffer[json_buffer_pos]), "+0000");
#else // TSTAMP_UTC == 0 || !defined(__APPLE__)
                strftime(timeBuf, sizeof(timeBuf), "%z", t); // time offset
                json_buffer_pos += sprintf(&(json_buffer[json_buffer_pos]), "%s", timeBuf);
#endif // TSTAMP_UTC == 0 || !defined(__APPLE__)
            }
#endif // B2T_TIMESTR == 1

            json_buffer[json_buffer_pos++] = '"';
            break;

        case bt_flow_direction:
            retval = buf_get_val(bv_buffer, sizeof(uint8_t), 1);
            json_buffer_pos += sprintf(&(json_buffer[json_buffer_pos]), "\"%c\"", (*((uint8_t*) bv_buffer) == 0) ? 'A' : 'B');
            break;

        default:
            T2_PERR("jsonSink", "Unhandled output type: %"PRIu32, type);
            return 1;
    }

    if (UNLIKELY(json_buffer_pos > json_buffer_size * 0.9)) {
        json_buffer_size <<= 1; // Double the buffer
        T2_PLOG("jsonSink", "Increasing output buffer size to %"PRIu64, json_buffer_size);
        char *tmp;
        if (UNLIKELY(!(tmp = realloc(json_buffer, json_buffer_size * sizeof(char))))) {
            T2_PERR("jsonSink", "Failed to double size of json_buffer");
            free(json_buffer);
            exit(1);
        }
        json_buffer = tmp;
    }

    return retval;
}


/**
 * @brief Skip invalid multi-bytes UTF-8 chars
 * @param input                 pointer to the string to sanitize
 * @param output                pointer where to write the sanitized string
 * @param input_bytes_processed the number of bytes read from input
 * @param output_bytes_written  the number of bytes written to output
 * @retval 0 on successful UTF-8 sanitization (currently always
 *                       returned)
 * @retval 1 on error (currently not returned)
 */
static int sanitize_utf8(const uint8_t *input, char *output, uint64_t *input_bytes_processed, uint64_t *output_bytes_written) {
    // backup original input and output pointers to compute read/written bytes
    const uint8_t * const orig_input = input;
    char * const orig_output = output;

    uint8_t b1, b2, b3, b4; // variables for multi-bytes characters

    *output++ = '"'; // print startsign '"'
    while (*input != '\0') {
        b1 = *input;
        input++;
        if (b1 < 0x80) { // single byte char
            switch (b1) {
                case '\t':
                    *output++ = '\\';
                    *output++ = 't';
                    break;
                case '\n':
                    *output++ = '\\';
                    *output++ = 'n';
                    break;
                case '\r':
                    *output++ = '\\';
                    *output++ = 'r';
                    break;
                case '\\':
                case '"':
                    *output++ = '\\';
                    *output++ = b1;
                    break;
                default:
                    // In order to be valid JSON, control characters in 0x00-0x1f
                    // must be escaped (see: https://tools.ietf.org/html/rfc7159#page-8)
                    // Most parsers also want the DEL (0x7f) escaped even though not in RFC
                    if (b1 <= 0x1f || b1 == 0x7f) {
                        output += sprintf(output, "\\u00%02X", b1);
                    } else {
                        *output++ = b1;
                    }
                    break;
            }
        } else if (b1 < 0xc2) { // 0xc0 and 0xc1 are invalid first byte (overlong sequence)
            T2_DBG("UTF-8: Overlong sequence!");
            *output++ = '.';
        } else if (b1 < 0xe0) { // 2 bytes char
            b2 = *input;
            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of two bytes char!");
                *output++ = '.';
                continue;
            }
            if ((b2 & 0xc0) != 0x80) { // second byte must start with 0b10...
                T2_DBG("UTF-8: invalid second byte in two byte char (was 0x%"B2T_PRIX8")!", b2);
                *output++ = '.';
                continue;
            }
            input++;
            // valid UTF-8 char! -> write it out
            *output++ = b1;
            *output++ = b2;
        } else if (b1 < 0xf0) { // 3 bytes char
            b2 = *input;
            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of two bytes char!");
                *output++ = '.';
                continue;
            }
            if ((b2 & 0xc0) != 0x80) { // second byte must start with 0b10...
                T2_DBG("UTF-8: invalid second byte in three byte char (was 0x%"B2T_PRIX8")!", b2);
                *output++ = '.';
                continue;
            }
            input++;
            if (b1 == 0xe0 && b2 < 0xa0) { // invalid overlong
                T2_DBG("UTF-8: Overlong three byte sequence!");
                *output++ = '.';
                continue;
            }

            // check third byte
            b3 = *input;
            if (b3 == '\0') {
                T2_DBG("UTF-8: string terminator at third byte of three bytes char!");
                *output++ = '.';
                continue;
            }
            if ((b3 & 0xc0) != 0x80) { // third byte must start with 0b10...
                T2_DBG("UTF-8: invalid third byte in three byte char (was 0x%"B2T_PRIX8")!", b3);
                *output++ = '.';
                continue;
            }
            input++;

            // check that code point is not in the surrogate range
            uint16_t tmp = ((uint16_t) (b1 & 0x0f) << 12) | ((uint16_t) (b2 & 0x3f) << 6) | (b3 & 0x3f);
            if (tmp >= 0xd800 && tmp <= 0xdfff) {
                T2_DBG("UTF-8: code point is in the surrogate range!");
                *output++ = '.';
                continue;
            }

            // valid UTF-8 char! -> write it out
            *output++ = b1;
            *output++ = b2;
            *output++ = b3;
        } else if (b1 < 0xf5) { // 4 bytes char
            b2 = *input;
            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of four bytes char!");
                *output++ = '.';
                continue;
            }
            if ((b2 & 0xc0) != 0x80) {
                T2_DBG("UTF-8: invalid second byte in four byte char (was 0x%"B2T_PRIX8")!", b2);
                *output++ = '.';
                continue; // second byte must start with 0b10...
            }
            input++;
            if (b1 == 0xf0 && b2 < 0x90) { // invalid overlong
                T2_DBG("UTF-8: Overlong four byte sequence!");
                *output++ = '.';
                continue;
            }
            if (b1 == 0xf4 && b2 >= 0x90) { // code point > U+10FFFF
                T2_DBG("UTF-8: Code point > U+10FFFF!");
                *output++ = '.';
                continue;
            }

            // check third byte
            b3 = *input;
            if (b3 == '\0') {
                T2_DBG("UTF-8: string terminator at third byte of four bytes char!");
                *output++ = '.';
                continue;
            }
            if ((b3 & 0xc0) != 0x80) {  // third byte must start with 0b10...
                T2_DBG("UTF-8: invalid third byte in four byte char (was 0x%"B2T_PRIX8")!", b3);
                *output++ = '.';
                continue;
            }
            input++;

            // check fourth byte
            b4 = *input;
            if (b4 == '\0') {
                T2_DBG("UTF-8: string terminator at fourth byte of four bytes char!");
                *output++ = '.';
                continue;
            }
            if ((b4 & 0xc0) != 0x80) { // fourth byte must start with 0b10...
                T2_DBG("UTF-8: invalid fourth byte in four byte char (was 0x%"B2T_PRIX8")!", b4);
                *output++ = '.';
                continue;
            }
            input++;

            // valid UTF-8 char! -> write it out
            *output++ = b1;
            *output++ = b2;
            *output++ = b3;
            *output++ = b4;
        } else { // invalid first byte >= 0xf5
            T2_DBG("UTF-8: invalid first byte (was 0x%"B2T_PRIX8")!", b1);
            *output++ = '.';
        }
    }

    *output++ = '"'; // print stopsign '"'
    *input_bytes_processed = input - orig_input + 1; // We always stop on the terminator, so we need to add +1
    *output_bytes_written = output - orig_output;

    return 0;
}

#endif // BLOCK_BUF == 0
