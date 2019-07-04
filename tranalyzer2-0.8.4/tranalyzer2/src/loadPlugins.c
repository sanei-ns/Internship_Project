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

#include "loadPlugins.h"
#include "global.h"

#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>


// Plugin functions (MUST match order of funcs array)
enum {
    PL_GET_NAME,       // get_plugin_name
    PL_GET_VERSION,    // get_plugin_version
    PL_GET_V_MAJOR,    // get_supported_tranalyzer_version_major
    PL_GET_V_MINOR,    // get_supported_tranalyzer_version_minor
    PL_GET_DEPS,       // get_dependencies
    PL_INIT,           // initialize
    PL_PRI_HDR,        // printHeader
    PL_FLOW_GEN,       // onFlowGenerated
    PL_CLAIM_L2,       // claimLayer2Information
    //PL_CLAIM_L3,       // claimLayer3Information [deprecated]
    PL_CLAIM_L4,       // claimLayer4Information
    PL_FLOW_TERM,      // onFlowTerminate
#if PLUGIN_REPORT == 1
    PL_REPORT,         // pluginReport
#endif // PLUGIN_REPORT == 1
    PL_MONITORING,     // monitoring
    PL_APP_TERM,       // onApplicationTerminate
    PL_BUF_TO_SINK,    // bufferToSink
#if USE_T2BUS == 1
    PL_T2BUS_CB,       // t2BusCallback
#endif // USE_T2BUS == 1
#if REPORT_HIST == 1
    PL_SAVE_STATE,     // saveState
    PL_RESTORE_STATE,  // restoreState
#endif // REPORT_HIST == 1
    PL_NUM_FUNCS,
};

static const char *func_name[] = {
    "get_plugin_name",
    "get_plugin_version",
    "get_supported_tranalyzer_version_major",
    "get_supported_tranalyzer_version_minor",
    "get_dependencies",
    "initialize",
    "printHeader",
    "onFlowGenerated",
    "claimLayer2Information",
    //"claimLayer3Information", // [deprecated]
    "claimLayer4Information",
    "onFlowTerminate",
#if PLUGIN_REPORT == 1
    "pluginReport",
#endif // PLUGIN_REPORT == 1
    "monitoring",
    "onApplicationTerminate",
    "bufferToSink",
#if USE_T2BUS == 1
    "t2BusCallback",
#endif // USE_T2BUS == 1
#if REPORT_HIST == 1
    "saveState",
    "restoreState",
#endif // REPORT_HIST == 1
    NULL
};

#if USE_PLLIST > 0
static FILE *pllist_file;
#if USE_PLLIST == 2
static uint8_t num_blacklisted;
#endif // USE_PLLIST == 2
#endif // USE_PLLIST > 0

static inline int plugin_filter(const struct dirent *de) {
    size_t len = strlen(de->d_name);
    if (len < 8) return 0; // [0-9]{3}_[A-Za-z0-9_]+.so

    // check prefix
    if (!isdigit(de->d_name[0]) ||
        !isdigit(de->d_name[1]) ||
        !isdigit(de->d_name[2]) ||
        de->d_name[3] != '_') return 0;

    // check suffix
    if (de->d_name[len-3] != '.' ||
        de->d_name[len-2] != 's' ||
        de->d_name[len-1] != 'o') return 0;

#if USE_PLLIST > 0
    if (!pllist_file) return 1;

    rewind(pllist_file);

    len = 0;
    ssize_t read;
    char *line = NULL;
    while ((read = getline(&line, &len, pllist_file)) != -1) {
        if (line[0] == '#' || read < 8) continue; // skip comments
        if (line[read-1] == '\n') line[--read] = '\0';
        if (strncmp(de->d_name, line, read)   == 0 || // [0-9]{3}_[A-Za-z0-9_]+.so
            strncmp(de->d_name+4, line, read) == 0)   // [A-Za-z0-9_]+
        {
#if USE_PLLIST == 1
            free(line);
            return 1;
#else // USE_PLLIST == 2
            T2_DBG("Plugin %s is blacklisted", de->d_name);
            num_blacklisted++;
            free(line);
            return 0;
#endif // USE_PLLIST
        }
    }
    free(line);
#endif // USE_PLLIST > 0

#if USE_PLLIST == 1
    return 0;
#else // USE_PLLIST != 1
    return 1;
#endif // USE_PLLIST
}


static inline bool t2_validate_plugin_name(const char *filename, const char *name) {
    const size_t namelen = name ? strlen(name) : 0;
    if (namelen == 0) {
        T2_ERR("%s: plugin name is required", filename);
        return false;
    } else if (namelen > PL_NAME_MAXLEN) {
        T2_PERR(name, "plugin name too long (%zu characters, limited to %u)", namelen, PL_NAME_MAXLEN);
        return false;
    }
    return true;
}


static inline bool t2_validate_plugin_version_num(const char *name, unsigned int v_major, unsigned int v_minor) {
    bool valid = true;
    if (/*v_major < PL_V_MAJOR_MIN ||*/ v_major > PL_V_MAJOR_MAX)   valid = false;
    else if (v_major == PL_V_MAJOR_MIN && v_minor < PL_V_MINOR_MIN) valid = false;
    else if (v_major == PL_V_MAJOR_MAX && v_minor > PL_V_MINOR_MAX) valid = false;
    if (!valid) {
        T2_PERR(name, "version %u.%u not supported (minimum required is %u.%u)",
                v_major, v_minor, PL_V_MAJOR_MIN, PL_V_MINOR_MIN);
    }
    return valid;
}


static inline bool t2_validate_plugin_version_str(const char *name, const char *version) {
    const size_t verlen = version ? strlen(version) : 0;
    if (verlen == 0) {
        T2_ERR("%s: plugin version is required", name);
        return false;
    } else if (verlen > PL_VERSION_MAXLEN) {
        T2_PERR(name, "plugin version too long (%zu characters, limited to %u)", verlen, PL_VERSION_MAXLEN);
        return false;
    }
    return true;
}


static inline bool t2_validate_plugin_version(const char *name, const char *version, unsigned int v_major, unsigned int v_minor) {
    bool valid = t2_validate_plugin_version_str(name, version);
    valid &= t2_validate_plugin_version_num(name, v_major, v_minor);
    return valid;
}


static bool check_deps(const char *dependencies, t2_plugin_t plugins[], uint8_t num_plugins) {
    const size_t len = dependencies ? strlen(dependencies) : 0;
    if (len == 0) return true;

    char deps[PL_DEPS_MAXLEN];
    strncpy(deps, dependencies, strlen(dependencies)+1);

    char *token = strtok(deps, ",");
    while (token) {
        bool found = false;
        for (uint_fast8_t i = 0; i < num_plugins; i++) {
            if (strcmp(token, plugins[i].name) == 0) {
               found = true;
               break;
            }
        }
        if (!found) return false;
        token = strtok(NULL, ",");
    }

    return true;
}


t2_plugin_array_t* load_tranalyzer_plugins(const char *folder) {
    const size_t dirlen = strlen(folder);
    if (dirlen > PL_PATH_MAXLEN) {
        T2_ERR("Plugin path too long (limited to %u)", PL_PATH_MAXLEN);
        exit(1);
    }

#if USE_PLLIST > 0
    // load plugin loading list
    if (pluginList) {
        pllist_file = fopen(pluginList, "r");
    } else {
        const size_t len = strlen(folder) + 1 + sizeof(PLLIST);
        char temp[len+1];
        strncpy(temp, folder, strlen(folder)+1);
        strcat(temp, "/" PLLIST);
        pllist_file = fopen(temp, "r");
    }
#endif // USE_PLLIST > 0

    struct dirent **namelist;
    const int n = scandir(folder, &namelist, plugin_filter, alphasort);
    if (n < 0) {
        T2_ERR("Failed to scan plugin folder '%s': %s", folder, strerror(errno));
#if USE_PLLIST > 0
        if (pllist_file) fclose(pllist_file);
#endif // USE_PLLIST > 0
        exit(1);
    }

#if USE_PLLIST > 0
    if (pllist_file) {
#if USE_PLLIST == 2
        if (num_blacklisted) T2_INF("Blacklisted plugins: %u", num_blacklisted);
#endif // USE_PLLIST == 2
        fclose(pllist_file);
    }
#endif // USE_PLLIST > 0

    int i, j;

#if DEBUG > 0 && VERBOSE > 3
    if (n > 0) printf("\nPlugin directory content:\n");
    for (i = 0; i < n; i++) {
        printf("    |- %s\n", namelist[i]->d_name);
    }
    printf("\n");
#endif // DEBUG > 0 && VERBOSE > 3

    t2_plugin_array_t *plugins = calloc(1, sizeof(*plugins));
    if (UNLIKELY(!plugins)) {
        T2_ERR("Failed to allocate memory for plugin array");
        exit(1);
    }

    plugins->num_plugins = n;
    plugins->plugin = calloc(n, sizeof(t2_plugin_t));
    if (UNLIKELY(!plugins->plugin)) {
        T2_ERR("Failed to allocate memory for plugins");
        free(plugins);
        exit(1);
    }

    void *handle;
    uint8_t num_plugins = 0;

    void *func[PL_NUM_FUNCS];
    uint8_t num_funcs[PL_NUM_FUNCS] = {};

    char filename[PL_PATH_MAXLEN];
    strncpy(filename, folder, dirlen+1);

    bool abort = false;

    for (i = 0; i < n; i++) {
        const char * const plugin_name = namelist[i]->d_name;
        T2_DBG("Checking if file '%s' is a valid tranalyzer plugin...", plugin_name);

        const size_t flen = strlen(plugin_name);
        if (dirlen + flen + 1 > PL_PATH_MAXLEN) {
            T2_ERR("Filename too long (limited to %u)", PL_PATH_MAXLEN);
            free(namelist[i]);
            continue;
        }

        // load plugin
        strncpy(filename + dirlen, plugin_name, flen+1);
        if (UNLIKELY(!(handle = dlopen(filename, RTLD_NODELETE|RTLD_GLOBAL|RTLD_LAZY)))) {
            //T2_DBG("Failed to open file '%s': %s", plugin_name, dlerror());
            T2_ERR("%s", dlerror());
            free(namelist[i]);
            continue;
        }

        // load plugin functions
        //T2_DBG("File '%s':", plugin_name);
        for (j = 0; func_name[j]; j++) {
            if ((func[j] = dlsym(handle, func_name[j]))) {
                //T2_DBG("    - %s() [found]", func_name[j]);
                num_funcs[j]++;
            } else {
                //T2_DBG("    - %s() [not found]", func_name[j]);
                dlerror(); // clear error
                if (j < PL_GET_DEPS) { // name and version are required
                    T2_ERR("%s is missing required plugin function %s", plugin_name, func_name[j]);
                    if (j > 0) {
                        for (j = j-1; j != 0; j--) {
                            num_funcs[j] = 0;
                        }
                    }
                    abort = true;
                    break;
                }
            }
        }

        if (abort) {
            free(namelist[i]);
            abort = false;
            continue;
        }

        // validate plugin name and version
        const char *name = (*(name_func)func[PL_GET_NAME])();
        if (!t2_validate_plugin_name(plugin_name, name)) {
            name = plugin_name;
            abort = true;
        }

        const char * const version = (*(version_func)func[PL_GET_VERSION])();
        const unsigned int v_major = (*(v_major_func)func[PL_GET_V_MAJOR])();
        const unsigned int v_minor = (*(v_minor_func)func[PL_GET_V_MINOR])();

        abort |= !t2_validate_plugin_version(name, version, v_major, v_minor);

        // check dependencies
        if (func[PL_GET_DEPS]) {
            const char * const deps = (*(get_deps_func)func[PL_GET_DEPS])();
            if (deps && !check_deps(deps, plugins->plugin, num_plugins)) {
                T2_PERR(name, "missing dependencies: %s", deps);
                abort = true;
            }
        }

        if (abort) {
            free(namelist[i]);
            for (j = 0; j < PL_NUM_FUNCS; j++) {
                num_funcs[j] = 0;
            }
            abort = false;
            continue;
        }

        // extract plugin number from filename
        const uint16_t pl_num = strtoul(plugin_name, NULL, 0);

        // plugin is valid
        plugins->plugin[num_plugins].handle = handle;
        strncpy(plugins->plugin[num_plugins].name, name, strlen(name)+1);
        strncpy(plugins->plugin[num_plugins].version, version, strlen(version)+1);
        plugins->plugin[num_plugins].number        = pl_num;
        plugins->plugin[num_plugins].init          = func[PL_INIT];
        plugins->plugin[num_plugins].priHdr        = func[PL_PRI_HDR];
        plugins->plugin[num_plugins].onFlowGen     = func[PL_FLOW_GEN];
        plugins->plugin[num_plugins].claimL2Info   = func[PL_CLAIM_L2];
        //plugins->plugin[num_plugins].claimL3Info   = func[PL_CLAIM_L3];
        plugins->plugin[num_plugins].claimL4Info   = func[PL_CLAIM_L4];
        plugins->plugin[num_plugins].onFlowTerm    = func[PL_FLOW_TERM];
#if PLUGIN_REPORT == 1
        plugins->plugin[num_plugins].report        = func[PL_REPORT];
#endif // PLUGIN_REPORT == 1
        plugins->plugin[num_plugins].monitoring    = func[PL_MONITORING];
        plugins->plugin[num_plugins].onAppTerm     = func[PL_APP_TERM];
        plugins->plugin[num_plugins].bufToSink     = func[PL_BUF_TO_SINK];
#if USE_T2BUS == 1
        plugins->plugin[num_plugins].t2BusCb       = (t2Bus_cb_t){ pl_num, func[PL_T2BUS_CB] };
#endif // USE_T2BUS == 1
#if REPORT_HIST == 1
        plugins->plugin[num_plugins].saveState     = func[PL_SAVE_STATE];
        plugins->plugin[num_plugins].restoreState  = func[PL_RESTORE_STATE];
#endif // REPORT_HIST == 1

        // count number of plugins and functions
        num_plugins++;
        for (j = 0; j < PL_NUM_FUNCS; j++) {
            num_funcs[j] = 0;
        }

        free(namelist[i]);
    }

    free(namelist);

    if (num_plugins == 0) {
#if VERBOSE > 0
        T2_WRN("No valid plugins found in folder '%s'", folder);
#endif // VERBOSE > 0
        free(plugins->plugin);
        plugins->plugin = NULL;
        plugins->num_plugins = 0;
        return plugins;
    }

    if (num_plugins != plugins->num_plugins) {
        // Some plugins could not be loaded... get rid of unused memory
        plugins->num_plugins = num_plugins;
        t2_plugin_t *tmp = realloc(plugins->plugin, num_plugins * sizeof(*tmp));
        if (UNLIKELY(!tmp)) {
            T2_ERR("Failed to give back unused memory from plugins list");
            free(plugins->plugin);
            free(plugins);
            exit(1);
        }

        plugins->plugin = tmp;
    }

#if VERBOSE > 1
    T2_LOG("Active plugins:");
    for (i = 0; i < num_plugins; i++) {
        t2_plugin_t p = plugins->plugin[i];
        T2_LOG("    %02d: %s, %s", i+1, p.name, p.version);
    }
#endif // VERBOSE > 1

    return plugins;
}


void unload_tranalyzer_plugins(t2_plugin_array_t *plugins) {
    if (UNLIKELY(!plugins)) return;

    if (LIKELY(plugins->plugin != NULL)) {
        for (uint_fast8_t i = 0; i < plugins->num_plugins; i++) {
            if (plugins->plugin[i].onAppTerm) {
                plugins->plugin[i].onAppTerm();
            }
            dlclose(plugins->plugin[i].handle);
        }
        free(plugins->plugin);
    }

    free(plugins);
}
