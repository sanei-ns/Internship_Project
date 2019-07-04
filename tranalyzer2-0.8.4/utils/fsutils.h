/*
 * fsutils.h
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

#ifndef __FS_UTILS_H__
#define __FS_UTILS_H__

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>

#define FSUTILS_MIN_FD_REQUIRED 200 // Min process file descriptors limit required
#define FSUTILS_SPARE_FD        100 // Number of file descriptors to keep away from the file manager

#define FSUTILS_MAX_OPEN_FD 20

// equivalent of "rm -rf path"
extern bool rmrf(const char *path);
// equivalent of "mkdir -p path" where each created dir is chmod mode
extern bool mkpath(const char *path, mode_t mode);

// opaque declaration of struct used in file manager
typedef struct file_manager_s file_manager_t;
typedef struct file_object_s  file_object_t;

// Returns the path associated to a file object.
extern const char *file_object_get_path(const file_object_t *object);

// Creates a new filemanager which keeps at most "max" files open in parallel. Returns NULL on error.
extern file_manager_t *file_manager_new(size_t max);

// Destroys a file manager.
extern void file_manager_destroy(file_manager_t *manager);

// Opens a new file in the file manager. Returns NULL on error.
extern file_object_t *file_manager_open(file_manager_t *manager, const char *path, const char *mode);

// Closes a file in the file manager. Returns true on success and false on error.
extern bool file_manager_close(file_manager_t *manager, file_object_t *file);

/*
 * Returns the FILE pointer associated to a file_object_t. Returns NULL on error.
 *
 * This function opens the file if needed, it must therefore be called each time before using a
 * function operating on the FILE*. The FILE* should not be stored and re-used later as the file
 * could be temporarily closed by the file manager when too many files are open.
 */
extern FILE *file_manager_fp(file_manager_t *manager, file_object_t *file);

#endif // __FS_UTILS_H__
