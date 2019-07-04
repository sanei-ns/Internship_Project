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

#ifndef __LOAD_PLUGINS_H__
#define __LOAD_PLUGINS_H__

#include "binaryValue.h"
#include "networkHeaders.h"
#include "outputBuffer.h"
#include "tranalyzer.h"

#include <stdbool.h>
#include <stdio.h>


#define USE_PLLIST   1 // 0: load [0-9]{3}_*.so, 1: use whitelist, 2: use blacklist
#define PLLIST      "plugins.txt" // default filename for plugin white-/black-list (-b option)

// Current (max) version of plugin architecture
#define PL_V_MAJOR_MAX 0
#define PL_V_MINOR_MAX 8

// Supported (min) version of plugin architecture
#define PL_V_MAJOR_MIN 0 // when changed to a value >= 1, uncomment test in loadPlugins.c:133
#define PL_V_MINOR_MIN 8

#define PL_PATH_MAXLEN     512 // maximum length of plugin path
#define PL_DEPS_MAXLEN     256 // maximum length of plugin dependencies
#define PL_NAME_MAXLEN      32 // maximum length of plugin name
#define PL_VERSION_MAXLEN   16 // maximum length of plugin version

// State for monitoring callback
#define T2_MON_PRI_HDR    0 // print the header
#define T2_MON_PRI_VAL    1 // print the values to monitor
#define T2_MON_PRI_REPORT 2 // print the report
//#define T2_MON_UPDATE_VAL 3 // update the values to monitor (diff mode)
//#define T2_MON_RESET_VAL  4 // reset the values to monitor (diff mode)

#define T2_PLUGIN_INIT(name, version, major, minor) \
    static const char * const plugin_name = name; \
    const char *get_plugin_name() { return plugin_name; } \
    const char *get_plugin_version() { return version; } \
    unsigned int get_supported_tranalyzer_version_major() { return major; } \
    unsigned int get_supported_tranalyzer_version_minor() { return minor; }

#define T2_PLUGIN_INIT_WITH_DEPS(name, version, major, minor, deps) \
    T2_PLUGIN_INIT(name, version, major, minor); \
    const char *get_dependencies() { return deps; }

// Call callback for every plugin
#define FOREACH_PLUGIN_DO(callback, ...) \
    for (uint_fast32_t i = 0; i < t2_plugins->num_plugins; i++) { \
        if (t2_plugins->plugin[i].callback) { \
            t2_plugins->plugin[i].callback(__VA_ARGS__); \
        } \
    }

// Typedef for plugin functions
typedef const char* (*name_func)();
typedef const char* (*version_func)();
typedef const char* (*get_deps_func)();
typedef unsigned int (*v_major_func)();
typedef unsigned int (*v_minor_func)();
typedef void (*init_func)();
typedef binary_value_t* (*pri_hdr_func)();
typedef void (*on_flow_gen_func)(packet_t*, unsigned long);
typedef void (*claim_l2_func)(packet_t*, unsigned long);
//typedef void (*claim_l3_func)(packet_t*);
typedef void (*claim_l4_func)(packet_t*, unsigned long);
typedef void (*on_flow_term_func)(unsigned long);
typedef void (*report_func)(FILE*);
typedef void (*on_app_term_func)();
typedef void (*buf_to_sink_func)(outputBuffer_t*);
typedef void (*monitoring_func)(FILE *stream, uint8_t state);
typedef void (*save_state_func)(FILE *stream);
typedef void (*restore_state_func)(const char *str);

#if USE_T2BUS == 1
typedef void (*t2Bus_callback)(uint32_t status);

/* t2Bus */
typedef struct {
    uint16_t pl_num; // plugin number
    t2Bus_callback cb;
} t2Bus_cb_t;
#endif // USE_T2BUS == 1

typedef struct {
    char name[PL_NAME_MAXLEN];
    char version[PL_VERSION_MAXLEN];
    uint16_t number;

    void *handle;

    // Pointers to plugin functions
    init_func          init;
    pri_hdr_func       priHdr;
    on_flow_gen_func   onFlowGen;
    claim_l2_func      claimL2Info;
    //claim_l3_func      claimL3Info;
    claim_l4_func      claimL4Info;
    on_flow_term_func  onFlowTerm;
#if PLUGIN_REPORT == 1
    report_func        report;
#endif // PLUGIN_REPORT == 1
    monitoring_func    monitoring;
    on_app_term_func   onAppTerm;
    buf_to_sink_func   bufToSink;
#if USE_T2BUS == 1
    t2Bus_cb_t         t2BusCb;
#endif // USE_T2BUS == 1
#if REPORT_HIST == 1
    save_state_func    saveState;
    restore_state_func restoreState;
#endif // REPORT_HIST == 1
} t2_plugin_t;

typedef struct {
    uint8_t num_plugins;
    t2_plugin_t *plugin;
} t2_plugin_array_t;


/*
 * Loads the plugins (dynamic libraries) from a given folder.
 */
t2_plugin_array_t* load_tranalyzer_plugins(const char *folder);


/*
 * Unloads all plugins from a t2_plugin_array_t struct.
 */
void unload_tranalyzer_plugins(t2_plugin_array_t *plugins);

#endif /* __LOAD_PLUGINS_H__ */
