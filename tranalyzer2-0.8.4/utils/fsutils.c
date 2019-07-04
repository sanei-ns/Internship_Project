/*
 * fsutils.c
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

#if !defined(_XOPEN_SOURCE) || _XOPEN_SOURCE < 500
#undef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500 // required for nftw
#endif // !defined(_XOPEN_SOURCE) || _XOPEN_SOURCE < 500

#define _FILE_OFFSET_BITS 64 // fseeko and ftello work on file >4G on 32-bits machines

#include <ftw.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/resource.h>

#include "fsutils.h"
#include "t2log.h"

static int init_rm_func(const char *fpath, const struct stat *sb  __attribute__ ((unused)),
        int typeflag, struct FTW *ftwbuf __attribute__ ((unused))) {
    // rmdir directories and unlink files
    switch (typeflag) {
        case FTW_DP:
            return rmdir(fpath);
        case FTW_F:
            return unlink(fpath);
        default:
            return -1;
    }
}

bool rmrf(const char *path) {
    // do not return an error if top directory does not exist
    struct stat sb;
    if (stat(path, &sb) != 0 && errno == ENOENT) {
        return true;
    }
    // recursively delete directory and its content
    return nftw(path, init_rm_func, FSUTILS_MAX_OPEN_FD, FTW_DEPTH | FTW_MOUNT | FTW_PHYS) == 0;
}

bool mkpath(const char *path, mode_t mode) {
    // allocate space for copy of path
    const size_t len = strlen(path);
    char * const copy = malloc(len + 2); // 2 bytes for '/' + '\0'
    if (!copy) {
        return false;
    }
    // copy path and make sure it ends with '/'
    if (memcpy(copy, path, len + 1) != copy) {
        free(copy);
        return false;
    }
    if (copy[len - 1] != '/') {
        copy[len] = '/';
        copy[len + 1] = '\0';
    }

    // build path, directory by directory
    for (char *p = copy; *p; ++p) {
        if (*p == '/' && p != copy) {
            *p = 0;
            // make next directory
            if (mkdir(copy, mode) != 0) {
                if (errno != EEXIST) {
                    free(copy);
                    return false;
                }
                // something exists, test that it is a directoy
                struct stat sb;
                if (stat(copy, &sb) != 0 || !S_ISDIR(sb.st_mode)) {
                    free(copy);
                    return false;
                }
            }
            *p = '/';
        }
    }

    free(copy);
    return true;
}

// -------------  file manager related code  ----------------------- //

struct file_object_s {
    FILE *fp;
    off_t pos; // cursor position in file before it was closed
    // pointers for LRU
    TAILQ_ENTRY(file_object_s) lru;
    // pointers for list of all files in manager
    TAILQ_ENTRY(file_object_s) all;
    // path of file
    char *path;
    // open mode
    char mode[8];
};

struct file_manager_s {
    const size_t max;
    size_t opened;
    // LRU of opened files
    TAILQ_HEAD(, file_object_s) lru;
    // List of all existing files in manager
    TAILQ_HEAD(, file_object_s) all;
};

inline const char *file_object_get_path(const file_object_t *object) {
    return object ? object->path : NULL;
}

// set this process max file descriptors to maximum allowed by kernel
static inline size_t file_manager_maximize_fd() {
    // get max number of file descriptor allowed for this process
    struct rlimit rlp;
    if (getrlimit(RLIMIT_NOFILE, &rlp) != 0) {
        T2_ERR("Failed to get process file descriptors limit: %s.", strerror(errno));
        exit(1);
    }
#ifdef __APPLE__
    if (rlp.rlim_max == RLIM_INFINITY) rlp.rlim_cur = OPEN_MAX;
    else
#endif // __APPLE__
    rlp.rlim_cur = rlp.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &rlp) != 0) {
        T2_ERR("Failed to set process file descriptors limit: %s", strerror(errno));
        exit(1);
    }
    // check that the file descriptor is high enough for file manager
    if (rlp.rlim_cur < FSUTILS_MIN_FD_REQUIRED) {
        T2_ERR("Process file descriptor limit is too low, cannot create file manager.");
        exit(1);
    }
    if (rlp.rlim_cur > FSUTILS_SPARE_FD) {
        return rlp.rlim_cur - FSUTILS_SPARE_FD;
    }
    return rlp.rlim_cur;
}

file_manager_t *file_manager_new(size_t max) {
    if (max == 0) {
        return NULL;
    }
    if (max == SIZE_MAX) {
        max = file_manager_maximize_fd();
    }
    file_manager_t *manager = malloc(sizeof(*manager));
    if (!manager) {
        return NULL;
    }
    // ugly way to initialize const field
    *(size_t *)&manager->max = max;
    manager->opened = 0;
    TAILQ_INIT(&manager->lru);
    TAILQ_INIT(&manager->all);

    return manager;
}

void file_manager_destroy(file_manager_t *manager) {
    if (!manager) {
        return;
    }
    // close all remaining files in manager
    while (!TAILQ_EMPTY(&manager->all)) {
        file_object_t *file = TAILQ_FIRST(&manager->all);
        file_manager_close(manager, file);
    }
    // free memory
    free(manager);
}

// Returns true on success and false on error.
static bool open_file(file_manager_t *manager, file_object_t *file) {
    if (!manager || !file || file->fp) {
        return false;
    }

    while (manager->opened >= manager->max) {
        // close and remove oldest file from LRU list
        file_object_t *oldest = TAILQ_FIRST(&manager->lru);
        if (!oldest->fp) {
            return false;
        }
        // save cursor position before closing file
        if ((oldest->pos = ftello(oldest->fp)) == -1) {
            return false;
        }
        if (fclose(oldest->fp) != 0) {
            return false;
        }
        oldest->fp = NULL;
        TAILQ_REMOVE(&manager->lru, oldest, lru);
        --manager->opened;
    }

    // open new file and seek to correct position
    if (!(file->fp = fopen(file->path, file->mode))) {
        return false;
    }
    if (file->pos) {
        if (fseeko(file->fp, file->pos, SEEK_SET) != 0) {
            fclose(file->fp);
            return false;
        }
    }

    // add file to LRU list
    TAILQ_INSERT_TAIL(&manager->lru, file, lru);
    ++manager->opened;

    return true;
}

// change the file mode so the file does not get truncated on re-open
static void fix_mode(char *mode) {
    char *w    = strchr(mode, 'w');
    char *plus = strchr(mode, '+');
    if (!w) {
        return;
    } else if (plus) { // w && plus
        w[0] = 'r';
    } else { // w && !plus
        // replace the w by a r+
        size_t len = strlen(mode);
        for (size_t i = w - mode + 1; i < len; ++i) {
            mode[i+1] = mode[i];
        }
        mode[len+1] = '\0';
        w[0] = 'r';
        w[1] = '+';
    }

}

file_object_t *file_manager_open(file_manager_t *manager, const char *path, const char *mode) {
    size_t mode_len = strlen(mode);
    if (!manager || mode_len > 6) {
        return NULL;
    }

    // allocate memory for new file
    file_object_t *file = malloc(sizeof(*file));
    if (!file) {
        return NULL;
    }
    memset(file, 0, sizeof(*file));

    // copy file path and mode
    if (!(file->path = strdup(path))) {
        free(file);
        return NULL;
    }
    strncpy(file->mode, mode, sizeof(file->mode) - 1);

    // open file
    if (!open_file(manager, file)) {
        free(file->path);
        free(file);
        return NULL;
    }
    fix_mode(file->mode);

    // add file to global list in manager
    TAILQ_INSERT_TAIL(&manager->all, file, all);

    return file;
}

bool file_manager_close(file_manager_t *manager, file_object_t *file) {
    if (!manager || !file || !file->path) {
        return false;
    }

    // if FILE* is open, close it
    if (file->fp) {
        if (fclose(file->fp) != 0) {
            return false; // should never happen
        }
        TAILQ_REMOVE(&manager->lru, file, lru);
        --manager->opened;
    }

    // remove from manager list of files
    TAILQ_REMOVE(&manager->all, file, all);

    // free memory
    free(file->path);
    file->path = NULL;
    free(file);

    return true;
}

FILE *file_manager_fp(file_manager_t *manager, file_object_t *file) {
    if (!manager || !file) {
        return NULL;
    }

    if (file->fp) {
        // place file at the end of the LRU list (last one to be closed)
        TAILQ_REMOVE(&manager->lru, file, lru);
        TAILQ_INSERT_TAIL(&manager->lru, file, lru);
        return file->fp;
    }

    if (!open_file(manager, file)) {
        return NULL;
    }

    return file->fp;
}
