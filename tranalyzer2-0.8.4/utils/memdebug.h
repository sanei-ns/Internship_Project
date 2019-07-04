/*
 * memdebug.h
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

#ifndef __MEM_DEBUG_H__
#define __MEM_DEBUG_H__


/**
 * memdebug_check_overflow()
 *
 * This function can be called at any point in the program. It will check if there
 * was a buffer overflow in any memory block allocated on the heap (with malloc or
 * calloc). It prints an error message on stderr for any detected overflow.
 *
 *
 * memdebug_check_leak()
 *
 * This function should be called at the very end of the program. It checks for
 * any memory block which was allocated but not freed. It prints an error message
 * on stderr and then free the leaking memory. This function is already called in
 * the tranalyzer2 core, you should not call it in plugins.
 *
 *
 * These functions are macro and produce no code if MEMORY_DEBUG != 1.
 * Therefore, they do not need to be commented in release code.
 *
 *
 * How to use memdebug in a plugin:
 *   - #include "memdebug.h" in the C file of the plugin,
 *   - change MEMORY_DEBUG in tranalyzer.h to enable or disable memory check,
 *   - recompile tranalyzer2 and the plugin;
 */

#if MEMORY_DEBUG == 1

extern void* memdebug_malloc(size_t size, const char* file, unsigned int line);
extern void  memdebug_free(void* ptr, const char* file, unsigned int line);
extern void* memdebug_calloc(size_t nmemb, size_t size, const char* file, unsigned int line);
extern void* memdebug_realloc(void* ptr, size_t size, const char* file, unsigned int line);

extern char* memdebug_strdup(const char* s, const char* file, unsigned int line);
extern char* memdebug_strndup(const char* s, size_t n, const char* file, unsigned int line);

extern void memdebug_check_overflow_int(const char* file, unsigned int line);
extern void memdebug_check_leak_int(const char* file, unsigned int line);

// overwrite all memory management functions
#define malloc(size)         memdebug_malloc((size), __FILE__, __LINE__)
#define calloc(nmemb, size)  memdebug_calloc((nmemb), (size), __FILE__, __LINE__)
#define realloc(ptr, size)   memdebug_realloc((ptr), (size), __FILE__, __LINE__)
#define free(ptr)            memdebug_free((ptr), __FILE__, __LINE__)

#undef strdup
#undef strndup
#define strdup(s)       memdebug_strdup((s), __FILE__, __LINE__)
#define strndup(s, n)   memdebug_strndup((s), (n), __FILE__, __LINE__)

#define memdebug_check_overflow()  memdebug_check_overflow_int(__FILE__, __LINE__)
#define memdebug_check_leak()      memdebug_check_leak_int(__FILE__, __LINE__)

#else // MEMORY_DEBUG != 1

// mem_check functions do nothing in non memory debug mode
#define memdebug_check_overflow()
#define memdebug_check_leak()

#endif // MEMORY_DEBUG

#endif // __MEM_DEBUG_H__
