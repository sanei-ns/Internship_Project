/*
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

/*
 * This product includes GeoLite/GeoLite2 data created by MaxMind,
 *     available from http://www.maxmind.com
 */

#include "geoip.h"

#if GEOIP_LEGACY == 0
#include <maxminddb.h>
#else // GEOIP_LEGACY == 1
#include <GeoIPCity.h>
#endif // GEOIP_LEGACY == 1


// Static variables

#if GEOIP_LEGACY == 1
static GeoIP *geoip_db;
static GeoIP *geoip_db6;
#else // GEOIP_LEGACY == 0
static MMDB_s geoip_db;

static const uint8_t geoip_type[] = {
#if GEOIP_CONTINENT > 0
    MMDB_DATA_TYPE_UTF8_STRING,
#endif // GEOIP_CONTINENT > 0
#if GEOIP_COUNTRY > 0
    MMDB_DATA_TYPE_UTF8_STRING,
#endif // GEOIP_COUNTRY > 0
#if GEOIP_CITY == 1
    MMDB_DATA_TYPE_UTF8_STRING,
#endif // GEOIP_CITY == 1
#if GEOIP_POSTCODE == 1
    MMDB_DATA_TYPE_UTF8_STRING,
#endif // GEOIP_POSTCODE == 1
#if GEOIP_ACCURACY == 1
    MMDB_DATA_TYPE_UINT16,
#endif // GEOIP_ACCURACY == 1
#if GEOIP_POSITION == 1
    MMDB_DATA_TYPE_DOUBLE,
    MMDB_DATA_TYPE_DOUBLE,
#endif // GEOIP_POSITION == 1
#if GEOIP_METRO_CODE == 1
    MMDB_DATA_TYPE_UINT16,
#endif // GEOIP_METRO_CODE == 1
#if GEOIP_TIMEZONE == 1
    MMDB_DATA_TYPE_UTF8_STRING,
#endif // GEOIP_TIMEZONE == 1
};

static const char *geoip_path[][4] = {
#if GEOIP_CONTINENT == 1
    { "continent", "names", GEOIP_LANG, NULL },
#elif GEOIP_CONTINENT == 2
    { "continent", "code", NULL, NULL },
#endif // GEOIP_CONTINENT == 2
#if GEOIP_COUNTRY == 1
    { "country", "names", GEOIP_LANG, NULL },
#elif GEOIP_COUNTRY == 2
    { "country", "iso_code", NULL, NULL },
#endif // GEOIP_COUNTRY == 2
#if GEOIP_CITY == 1
    { "city", "names", GEOIP_LANG, NULL },
#endif // GEOIP_CITY == 1
#if GEOIP_POSTCODE == 1
    { "postal", "code", NULL, NULL },
#endif // GEOIP_POSTCODE == 1
#if GEOIP_ACCURACY == 1
    { "location", "accuracy_radius", NULL, NULL },
#endif // GEOIP_ACCURACY == 1
#if GEOIP_POSITION == 1
    { "location", "latitude", NULL, NULL },
    { "location", "longitude", NULL, NULL },
#endif // GEOIP_POSITION == 1
#if GEOIP_METRO_CODE == 1
    { "location", "metro_code", NULL, NULL },
#endif // GEOIP_METRO_CODE == 1
#if GEOIP_TIMEZONE == 1
    { "location", "time_zone", NULL, NULL },
#endif // GEOIP_TIMEZONE == 1
    { NULL, NULL, NULL, NULL }
};
#endif // GEOIP_LEGACY == 0


// Tranalyzer functions

T2_PLUGIN_INIT("geoip", "0.8.4", 0, 8);


void initialize() {
    char dbname[pluginFolder_len + GEOIP_DB_LEN + 1];
    strncpy(dbname, pluginFolder, pluginFolder_len+1);

#if GEOIP_LEGACY == 0
    strcat(dbname, GEOIP_DB_FILE);
    if (UNLIKELY(MMDB_open(dbname, MMDB_MODE_MMAP, &geoip_db) != MMDB_SUCCESS)) {
        T2_PERR("geoip", "failed to open GeoIP database '%s'", dbname);
        exit(-1);
    }
#else // GEOIP_LEGACY == 1

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    strncpy(dbname+pluginFolder_len, GEOIP_DB_FILE, sizeof(GEOIP_DB_FILE)+1);
    geoip_db = GeoIP_open(dbname, GEOIP_DB_CACHE_FLAG);
    if (UNLIKELY(geoip_db == NULL)) {
        T2_PERR("geoip", "failed to open GeoIP database '%s'", dbname);
        exit(-1);
    }
    GeoIP_set_charset(geoip_db, GEOIP_CHARSET_UTF8);
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if IPV6_ACTIVATE > 0
    strncpy(dbname+pluginFolder_len, GEOIP_DB_FILE6, sizeof(GEOIP_DB_FILE6)+1);
    geoip_db6 = GeoIP_open(dbname, GEOIP_DB_CACHE_FLAG);
    if (UNLIKELY(geoip_db6 == NULL)) {
        T2_PERR("geoip", "failed to open GeoIP database '%s'", dbname);
        GeoIP_delete(geoip_db);
        exit(-1);
    }
    GeoIP_set_charset(geoip_db6, GEOIP_CHARSET_UTF8);
#endif // IPV6_ACTIVATE > 0
#endif // GEOIP_LEGACY == 1
}


binary_value_t* printHeader() {
    binary_value_t *bv = NULL;
#if GEOIP_SRC == 1
#if GEOIP_CONTINENT > 0
    bv = bv_append_bv(bv, bv_new_bv("IP source continent", "srcIpContinent", 0, 1, GEOIP_CONTINENT_TYPE));
#endif // GEOIP_CONTINENT > 0
#if GEOIP_COUNTRY > 0
    bv = bv_append_bv(bv, bv_new_bv("IP source country", "srcIpCountry", 0, 1, GEOIP_COUNTRY_TYPE));
#endif // GEOIP_COUNTRY > 0
#if GEOIP_REGION > 0
    bv = bv_append_bv(bv, bv_new_bv("IP source region", "srcIpRegion", 0, 1, GEOIP_REGION_TYPE));
#endif // GEOIP_REGION > 0
#if GEOIP_CITY == 1
    bv = bv_append_bv(bv, bv_new_bv("IP source city", "srcIpCity", 0, 1, bt_string));
#endif // GEOIP_CITY == 1
#if GEOIP_POSTCODE == 1
    bv = bv_append_bv(bv, bv_new_bv("IP source postcode", "srcIpPostcode", 0, 1, bt_string_class));
#endif // GEOIP_POSTCODE == 1
#if GEOIP_ACCURACY == 1
    bv = bv_append_bv(bv, bv_new_bv("IP source accuracy", "srcIpAccuracy", 0, 1, bt_uint_16));
#endif // GEOIP_ACCURACY == 1
#if GEOIP_POSITION == 1
    bv = bv_append_bv(bv, bv_new_bv("IP source latitude", "srcIpLat", 0, 1, GEOIP_POS_TYPE));
    bv = bv_append_bv(bv, bv_new_bv("IP source longitude", "srcIpLong", 0, 1, GEOIP_POS_TYPE));
#endif // GEOIP_POSITION == 1
#if GEOIP_METRO_CODE == 1
    bv = bv_append_bv(bv, bv_new_bv("IP source metro (dma) code", "srcIpMetroCode", 0, 1, GEOIP_DMA_TYPE));
#endif // GEOIP_METRO_CODE == 1
#if GEOIP_AREA_CODE == 1
    bv = bv_append_bv(bv, bv_new_bv("IP source area code", "srcIpAreaCode", 0, 1, bt_int_32));
#endif // GEOIP_AREA_CODE == 1
#if GEOIP_NETMASK > 0
    bv = bv_append_bv(bv, bv_new_bv("IP source netmask", "srcIpNetmask", 0, 1, GEOIP_NETMASK_TYPE));
#endif // GEOIP_NETMASK > 0
#if GEOIP_TIMEZONE == 1
    bv = bv_append_bv(bv, bv_new_bv("IP source time zone", "srcIpTimeZone", 0, 1, bt_string));
#endif // GEOIP_TIMEZONE == 1
#endif // GEOIP_SRC == 1

#if GEOIP_DST == 1
#if GEOIP_CONTINENT > 0
    bv = bv_append_bv(bv, bv_new_bv("IP destination continent", "dstIpContinent", 0, 1, GEOIP_CONTINENT_TYPE));
#endif // GEOIP_CONTINENT > 0
#if GEOIP_COUNTRY > 0
    bv = bv_append_bv(bv, bv_new_bv("IP destination country", "dstIpCountry", 0, 1, GEOIP_COUNTRY_TYPE));
#endif // GEOIP_COUNTRY > 0
#if GEOIP_REGION > 0
    bv = bv_append_bv(bv, bv_new_bv("IP destination region", "dstIpRegion", 0, 1, GEOIP_REGION_TYPE));
#endif // GEOIP_REGION > 0
#if GEOIP_CITY == 1
    bv = bv_append_bv(bv, bv_new_bv("IP destination city", "dstIpCity", 0, 1, bt_string));
#endif // GEOIP_CITY == 1
#if GEOIP_POSTCODE == 1
    bv = bv_append_bv(bv, bv_new_bv("IP destination postcode", "dstIpPostcode", 0, 1, bt_string_class));
#endif // GEOIP_POSTCODE == 1
#if GEOIP_ACCURACY == 1
    bv = bv_append_bv(bv, bv_new_bv("IP destination accuracy", "dstIpAccuracy", 0, 1, bt_uint_16));
#endif // GEOIP_ACCURACY == 1
#if GEOIP_POSITION == 1
    bv = bv_append_bv(bv, bv_new_bv("IP destination latitude", "dstIpLat", 0, 1, GEOIP_POS_TYPE));
    bv = bv_append_bv(bv, bv_new_bv("IP destination longitude", "dstIpLong", 0, 1, GEOIP_POS_TYPE));
#endif // GEOIP_POSITION == 1
#if GEOIP_METRO_CODE == 1
    bv = bv_append_bv(bv, bv_new_bv("IP destination metro (dma) code", "dstIpMetroCode", 0, 1, GEOIP_DMA_TYPE));
#endif // GEOIP_METRO_CODE == 1
#if GEOIP_AREA_CODE == 1
    bv = bv_append_bv(bv, bv_new_bv("IP destination area code", "dstIpAreaCode", 0, 1, bt_int_32));
#endif // GEOIP_AREA_CODE == 1
#if GEOIP_NETMASK > 0
    bv = bv_append_bv(bv, bv_new_bv("IP destination netmask", "dstIpNetmask", 0, 1, GEOIP_NETMASK_TYPE));
#endif // GEOIP_NETMASK > 0
#if GEOIP_TIMEZONE == 1
    bv = bv_append_bv(bv, bv_new_bv("IP destination time zone", "dstIpTimeZone", 0, 1, bt_string));
#endif // GEOIP_TIMEZONE == 1
#endif // GEOIP_DST == 1
#if GEOIP_LEGACY == 0
    bv = bv_append_bv(bv, bv_new_bv("GeoIP status", "geoStat", 0, 1, bt_hex_8));
#endif // GEOIP_LEGACY == 0
    return bv;
}


#if BLOCK_BUF == 0
void onFlowTerminate(unsigned long flowIndex) {
    const flow_t * const flow = &flows[flowIndex];

#if GEOIP_LEGACY == 0
    int iperr, dberr;
    MMDB_lookup_result_s res[GEOIP_SRC+GEOIP_DST];

    uint8_t i, j, r = 0;
    MMDB_entry_data_s entry;
    uint16_t u16;
    double d;
    char buf[GEOIP_BUFSIZE] = {};

#if GEOIP_SRC == 1
    char srcIP[INET6_ADDRSTRLEN];
    if (FLOW_IS_IPV6(flow)) {
        inet_ntop(AF_INET6, &flow->srcIP, srcIP, INET6_ADDRSTRLEN);
        res[r++] = MMDB_lookup_string(&geoip_db, srcIP, &iperr, &dberr);
    } else { // IPv4
        inet_ntop(AF_INET, &flow->srcIP.IPv4, srcIP, INET_ADDRSTRLEN);
        res[r++] = MMDB_lookup_string(&geoip_db, srcIP, &iperr, &dberr);
    }
    if (iperr != 0 || dberr != MMDB_SUCCESS) {
        T2_PERR("geoip", "Failed to lookup IP address '%s' in database", srcIP);
        return;
    }
#endif // GEOIP_SRC == 1

#if GEOIP_DST == 1
    char dstIP[INET6_ADDRSTRLEN];
    if (FLOW_IS_IPV6(flow)) {
        inet_ntop(AF_INET6, &flow->dstIP, dstIP, INET6_ADDRSTRLEN);
        res[r++] = MMDB_lookup_string(&geoip_db, dstIP, &iperr, &dberr);
    } else { // IPv4
        inet_ntop(AF_INET, &flow->dstIP.IPv4, dstIP, INET_ADDRSTRLEN);
        res[r++] = MMDB_lookup_string(&geoip_db, dstIP, &iperr, &dberr);
    }
    if (iperr != 0 || dberr != MMDB_SUCCESS) {
        T2_PERR("geoip", "Failed to lookup IP address '%s' in database", dstIP);
        return;
    }
#endif // GEOIP_DST == 1

    uint8_t status = 0;
    uint32_t slen;
    for (j = 0; j < r; j++) { // for src/dst IP address
        if (res[j].found_entry) {
            for (i = 0; geoip_path[i][0]; i++) {
                MMDB_aget_value(&res[j].entry, &entry, geoip_path[i]);
                switch (geoip_type[i]) {
                    case MMDB_DATA_TYPE_UTF8_STRING:
                        if (entry.has_data) {
                            slen = MIN(entry.data_size, GEOIP_BUFSIZE);
                            if (slen < entry.data_size) status |= GEOIP_STAT_TRUNC;
                            strncpy(buf, entry.utf8_string, slen);
                            buf[slen] = '\0';
                            outputBuffer_append(main_output_buffer, buf, slen+1);
                        } else {
                            outputBuffer_append(main_output_buffer, GEOIP_UNKNOWN, sizeof(GEOIP_UNKNOWN));
                        }
                        break;
                    case MMDB_DATA_TYPE_DOUBLE:
                        d = (entry.has_data) ? entry.double_value : 0.0;
                        outputBuffer_append(main_output_buffer, (char*)&d, sizeof(double));
                        break;
                    case MMDB_DATA_TYPE_UINT16:
                        u16 =  (entry.has_data) ? entry.uint16 : 0;
                        outputBuffer_append(main_output_buffer, (char*)&u16, sizeof(uint16_t));
                        break;
                    default:
                        T2_PWRN("geoip", "Unhandled type %d", entry.type);
                        break;
                }
            }
        } else {
            const char *unk = GEOIP_UNKNOWN;
#if GEOIP_CONTINENT > 0
            outputBuffer_append(main_output_buffer, unk, strlen(unk)+1); // continent
#endif // GEOIP_CONTINENT > 0
#if GEOIP_COUNTRY > 0
            outputBuffer_append(main_output_buffer, unk, strlen(unk)+1); // country
#endif // GEOIP_COUNTRY > 0
#if GEOIP_CITY == 1
            outputBuffer_append(main_output_buffer, unk, strlen(unk)+1); // city
#endif // GEOIP_CITY == 1
#if GEOIP_POSTCODE == 1
            outputBuffer_append(main_output_buffer, unk, strlen(unk)+1); // postcode
#endif // GEOIP_POSTCODE == 1
#if GEOIP_POSITION == 1
            d = 0.0;
            outputBuffer_append(main_output_buffer, (char*)&d, sizeof(double)); // longitude
            outputBuffer_append(main_output_buffer, (char*)&d, sizeof(double)); // latitude
#endif // GEOIP_POSITION == 1
#if GEOIP_METRO_CODE == 1
            u16 = 0;
            outputBuffer_append(main_output_buffer, (char*)&u16, sizeof(uint16_t)); // metro code
#endif // GEOIP_METRO_CODE == 1
#if GEOIP_TIMEZONE == 1
            outputBuffer_append(main_output_buffer, unk, strlen(unk)+1); // time zone
#endif // GEOIP_TIMEZONE == 1
        }
    }
    outputBuffer_append(main_output_buffer, (char*)&status, sizeof(uint8_t));

#else // GEOIP_LEGACY == 1

#if GEOIP_METRO_CODE == 1 || GEOIP_AREA_CODE == 1
    int i;
#endif // GEOIP_METRO_CODE == 1 || GEOIP_AREA_CODE == 1
#if GEOIP_POSITION == 1
    float f;
#endif // GEOIP_POSITION == 1
#if GEOIP_NETMASK > 0
    uint32_t u;
#endif // GEOIP_NETMASK > 0
    uint8_t j, r = 0;
    const char *str;
    GeoIPRecord *rec[GEOIP_SRC+GEOIP_DST] = {};
#if GEOIP_SRC == 1
    if (FLOW_IS_IPV6(flow)) {
#if IPV6_ACTIVATE > 0
        rec[r++] = GeoIP_record_by_ipnum_v6(geoip_db6, flow->srcIP.IPv6);
#endif // IPV6_ACTIVATE > 0
    } else { // IPv4
        const struct in_addr sip = flow->srcIP.IPv4;
        rec[r++] = GeoIP_record_by_ipnum(geoip_db, ntohl(*(uint32_t*)&sip));
    }
#endif // GEOIP_SRC == 1

#if GEOIP_DST == 1
    if (FLOW_IS_IPV6(flow)) {
#if IPV6_ACTIVATE > 0
        rec[r++] = GeoIP_record_by_ipnum_v6(geoip_db6, flow->dstIP.IPv6);
#endif // IPV6_ACTIVATE > 0
    } else { // IPv4
        const struct in_addr dip = flow->dstIP.IPv4;
        rec[r++] = GeoIP_record_by_ipnum(geoip_db, ntohl(*(uint32_t*)&dip));
    }
#endif // GEOIP_DST == 1

    for (j = 0; j < r; j++) {
#if GEOIP_CONTINENT > 0
        str = rec[j] ? rec[j]->continent_code : GEOIP_UNKNOWN;
        if (!str) str = GEOIP_UNKNOWN;
        outputBuffer_append(main_output_buffer, str, strlen(str)+1);
#endif // GEOIP_CONTINENT > 0
#if GEOIP_COUNTRY > 0
#if GEOIP_COUNTRY == 1
        str = rec[j] ? rec[j]->country_name : GEOIP_UNKNOWN;
#elif GEOIP_COUNTRY == 2
        str = rec[j] ? rec[j]->country_code : GEOIP_UNKNOWN;
#elif GEOIP_COUNTRY == 3
        str = rec[j] ? rec[j]->country_code3 : GEOIP_UNKNOWN;
#endif // GEOIP_COUNTRY == 3
        if (!str) str = GEOIP_UNKNOWN;
        outputBuffer_append(main_output_buffer, str, strlen(str)+1);
#endif // GEOIP_COUNTRY > 0

#if GEOIP_REGION > 0
        if (rec[j]) {
#if GEOIP_REGION == 1
            str = GeoIP_region_name_by_code(rec[j]->country_code, rec[j]->region);
#else // GEOIP_REGION != 1
            str = rec[j]->region;
#endif // GEOIP_REGION != 1
        }
        if (!str) str = GEOIP_UNKNOWN;
        outputBuffer_append(main_output_buffer, str, strlen(str)+1);
#endif // GEOIP_REGION > 0
#if GEOIP_CITY == 1
        str = rec[j] ? rec[j]->city : GEOIP_UNKNOWN;
        if (!str) str = GEOIP_UNKNOWN;
        outputBuffer_append(main_output_buffer, str, strlen(str)+1);
#endif // GEOIP_CITY == 1
#if GEOIP_POSTCODE == 1
        str = rec[j] ? rec[j]->postal_code : GEOIP_UNKNOWN;
        if (!str) str = GEOIP_UNKNOWN;
        outputBuffer_append(main_output_buffer, str, strlen(str)+1);
#endif // GEOIP_POSTCODE == 1
#if GEOIP_POSITION == 1
        f = rec[j] ? rec[j]->latitude : 0.0;
        outputBuffer_append(main_output_buffer, (char*)&f, sizeof(float));
        f = rec[j] ? rec[j]->longitude : 0.0;
        outputBuffer_append(main_output_buffer, (char*)&f, sizeof(float));
#endif // GEOIP_POSITION == 1
#if GEOIP_METRO_CODE == 1
        i = rec[j] ? rec[j]->metro_code : 0;
        outputBuffer_append(main_output_buffer, (char*)&i, sizeof(int));
#endif // GEOIP_METRO_CODE == 1
#if GEOIP_AREA_CODE == 1
        i = rec[j] ? rec[j]->area_code : 0;
        outputBuffer_append(main_output_buffer, (char*)&i, sizeof(int));
#endif // GEOIP_AREA_CODE == 1
#if GEOIP_NETMASK > 0
        u = (uint32_t) (rec[j] ? rec[j]->netmask : 0);
        if (FLOW_IS_IPV6(flow)) {
#if GEOIP_NETMASK == 2
            // TODO
#elif GEOIP_NETMASK == 3
            // TODO
#endif // GEOIP_NETMASK == 3
        } else { // IPv4
#if GEOIP_NETMASK == 2
            u = GEOIP_CIDR_TO_HEX(u);
#elif GEOIP_NETMASK == 3
            u = GEOIP_CIDR_TO_IP(u);
#endif // GEOIP_NETMASK == 3
        }
        outputBuffer_append(main_output_buffer, (char*)&u, sizeof(uint32_t));
#endif // GEOIP_NETMASK > 0
        if (rec[j]) {
            GeoIPRecord_delete(rec[j]);
            rec[j] = NULL;
        }
    }
#endif // GEOIP_LEGACY == 1
}
#endif // BLOCK_BUF == 0


void onApplicationTerminate() {
#if GEOIP_LEGACY == 0
    MMDB_close(&geoip_db);
#else // GEOIP_LEGACY == 1
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    if (LIKELY(geoip_db != NULL)) {
        GeoIP_delete(geoip_db);
    }
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
#if IPV6_ACTIVATE > 0
    if (LIKELY(geoip_db6 != NULL)) {
        GeoIP_delete(geoip_db6);
    }
#endif // IPV6_ACTIVATE > 0
#endif // GEOIP_LEGACY == 1
}
