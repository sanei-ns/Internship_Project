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

#ifndef __BINARY_VALUE_H__
#define __BINARY_VALUE_H__

#include <stdint.h>

#define BV_STRBUF_LONG  1023 // Buffer for long names
#define BV_STRBUF_SHORT  127 // Buffer for short names

// Following values represent the number of uint32_t words
#define HDRBUF_MIN_SZ  (BUF_DATA_SHFT+3)
#define HDRBUF_INIT_SZ 8092              // Initial size of the header buffer

// The magic value that should be at the start of every tranalyzer binary file
#define BV_MAGIC_VALUE   "ANTEATER"
#define BV_MAGIC_VALUE_1 0x45544e41 // part 1
#define BV_MAGIC_VALUE_2 0x52455441 // part 2

// The version of the library
#define BV_VERSION 1

// Whether the binary value is repetitive or not
#define BV_REPEAT_NO  0
#define BV_REPEAT_YES 1


// Append a binary value with name, description, repeat flag,
// number of values and size to an existing bv
#define BV_APPEND_FULL(bv, name, desc, repeat, num_val, args...) \
	(bv) = bv_append_bv((bv), bv_new_bv(desc, name, repeat, num_val, ##args))

// Append a binary value with name, description, number of values and types to an existing bv
#define BV_APPEND(bv, name, desc, num_val, args...) \
    BV_APPEND_FULL(bv, name, desc, BV_REPEAT_NO, num_val, ##args)
#define BV_APPEND_R(bv, name, desc, num_val, args...) \
    BV_APPEND_FULL(bv, name, desc, BV_REPEAT_YES, num_val, ##args)

// Append a binary value with name, description and size to an existing bv
#define BV_APPEND_SIMPLE(bv, name, desc, type) BV_APPEND(bv, name, desc, 1, type)
#define BV_APPEND_SIMPLE_R(bv, name, desc, type) BV_APPEND_R(bv, name, desc, 1, type)

// Append a binary value with name and description of type int to an existing bv
#define BV_APPEND_I8(bv, name, desc)  BV_APPEND_SIMPLE(bv, name, desc, bt_int_8)
#define BV_APPEND_I16(bv, name, desc) BV_APPEND_SIMPLE(bv, name, desc, bt_int_16)
#define BV_APPEND_I32(bv, name, desc) BV_APPEND_SIMPLE(bv, name, desc, bt_int_32)
#define BV_APPEND_I64(bv, name, desc) BV_APPEND_SIMPLE(bv, name, desc, bt_int_64)

#define BV_APPEND_I8_R(bv, name, desc)  BV_APPEND_SIMPLE_R(bv, name, desc, bt_int_8)
#define BV_APPEND_I16_R(bv, name, desc) BV_APPEND_SIMPLE_R(bv, name, desc, bt_int_16)
#define BV_APPEND_I32_R(bv, name, desc) BV_APPEND_SIMPLE_R(bv, name, desc, bt_int_32)
#define BV_APPEND_I64_R(bv, name, desc) BV_APPEND_SIMPLE_R(bv, name, desc, bt_int_64)

// Append a binary value with name and description of type uint to an existing bv
#define BV_APPEND_U8(bv, name, desc)  BV_APPEND_SIMPLE(bv, name, desc, bt_uint_8)
#define BV_APPEND_U16(bv, name, desc) BV_APPEND_SIMPLE(bv, name, desc, bt_uint_16)
#define BV_APPEND_U32(bv, name, desc) BV_APPEND_SIMPLE(bv, name, desc, bt_uint_32)
#define BV_APPEND_U64(bv, name, desc) BV_APPEND_SIMPLE(bv, name, desc, bt_uint_64)

#define BV_APPEND_U8_R(bv, name, desc)  BV_APPEND_SIMPLE_R(bv, name, desc, bt_uint_8)
#define BV_APPEND_U16_R(bv, name, desc) BV_APPEND_SIMPLE_R(bv, name, desc, bt_uint_16)
#define BV_APPEND_U32_R(bv, name, desc) BV_APPEND_SIMPLE_R(bv, name, desc, bt_uint_32)
#define BV_APPEND_U64_R(bv, name, desc) BV_APPEND_SIMPLE_R(bv, name, desc, bt_uint_64)

// Append a binary value with name and description of type hex to an existing bv
#define BV_APPEND_H8(bv, name, desc)  BV_APPEND_SIMPLE(bv, name, desc, bt_hex_8)
#define BV_APPEND_H16(bv, name, desc) BV_APPEND_SIMPLE(bv, name, desc, bt_hex_16)
#define BV_APPEND_H32(bv, name, desc) BV_APPEND_SIMPLE(bv, name, desc, bt_hex_32)
#define BV_APPEND_H64(bv, name, desc) BV_APPEND_SIMPLE(bv, name, desc, bt_hex_64)

#define BV_APPEND_H8_R(bv, name, desc)  BV_APPEND_SIMPLE_R(bv, name, desc, bt_hex_8)
#define BV_APPEND_H16_R(bv, name, desc) BV_APPEND_SIMPLE_R(bv, name, desc, bt_hex_16)
#define BV_APPEND_H32_R(bv, name, desc) BV_APPEND_SIMPLE_R(bv, name, desc, bt_hex_32)
#define BV_APPEND_H64_R(bv, name, desc) BV_APPEND_SIMPLE_R(bv, name, desc, bt_hex_64)

// Append a binary value with name and description of type float or double to an existing bv
#define BV_APPEND_FLT(bv, name, desc) BV_APPEND_SIMPLE(bv, name, desc, bt_float)
#define BV_APPEND_DBL(bv, name, desc) BV_APPEND_SIMPLE(bv, name, desc, bt_double)

#define BV_APPEND_FLT_R(bv, name, desc) BV_APPEND_SIMPLE_R(bv, name, desc, bt_float)
#define BV_APPEND_DBL_R(bv, name, desc) BV_APPEND_SIMPLE_R(bv, name, desc, bt_double)

// Append a binary value with name and description of type MAC, IPv4 or IPv6 address to an existing bv
#define BV_APPEND_MAC(bv, name, desc) BV_APPEND_SIMPLE(bv, name, desc, bt_mac_addr)
#define BV_APPEND_IP4(bv, name, desc) BV_APPEND_SIMPLE(bv, name, desc, bt_ip4_addr)
#define BV_APPEND_IP6(bv, name, desc) BV_APPEND_SIMPLE(bv, name, desc, bt_ip6_addr)
#define BV_APPEND_IPX(bv, name, desc) BV_APPEND_SIMPLE(bv, name, desc, bt_ipx_addr)

#define BV_APPEND_MAC_R(bv, name, desc) BV_APPEND_SIMPLE_R(bv, name, desc, bt_mac_addr)
#define BV_APPEND_IP4_R(bv, name, desc) BV_APPEND_SIMPLE_R(bv, name, desc, bt_ip4_addr)
#define BV_APPEND_IP6_R(bv, name, desc) BV_APPEND_SIMPLE_R(bv, name, desc, bt_ip6_addr)
#define BV_APPEND_IPX_R(bv, name, desc) BV_APPEND_SIMPLE_R(bv, name, desc, bt_ipx_addr)

// Append a binary value with name and description of type timestamp or duration to an existing bv
#define BV_APPEND_TIMESTAMP(bv, name, desc) BV_APPEND_SIMPLE(bv, name, desc, bt_timestamp)
#define BV_APPEND_DURATION(bv, name, desc)  BV_APPEND_SIMPLE(bv, name, desc, bt_duration)

#define BV_APPEND_TIMESTAMP_R(bv, name, desc) BV_APPEND_SIMPLE_R(bv, name, desc, bt_timestamp)
#define BV_APPEND_DURATION_R(bv, name, desc)  BV_APPEND_SIMPLE_R(bv, name, desc, bt_duration)

// Append a binary value with name and description of type string or string class to an existing bv
#define BV_APPEND_CHAR(bv, name, desc) BV_APPEND_SIMPLE(bv, name, desc, bt_char)
#define BV_APPEND_STR(bv, name, desc)  BV_APPEND_SIMPLE(bv, name, desc, bt_string)
#define BV_APPEND_STRC(bv, name, desc) BV_APPEND_SIMPLE(bv, name, desc, bt_string_class)

#define BV_APPEND_CHAR_R(bv, name, desc) BV_APPEND_SIMPLE_R(bv, name, desc, bt_char)
#define BV_APPEND_STR_R(bv, name, desc)  BV_APPEND_SIMPLE_R(bv, name, desc, bt_string)
#define BV_APPEND_STRC_R(bv, name, desc) BV_APPEND_SIMPLE_R(bv, name, desc, bt_string_class)

// Append a binary value with name and description of variable type to an existing bv
#define BV_APPEND_TYPE(bv, name, desc, type) BV_APPEND_SIMPLE(bv, name, desc, type)
#define BV_APPEND_TYPE_R(bv, name, desc, type) BV_APPEND_SIMPLE_R(bv, name, desc, type)


/*
 * Definition of types
 */
enum binary_types {
	bt_compound = 0,
	// all signed integers
	bt_int_8 = 1,
	bt_int_16,
	bt_int_32,
	bt_int_64,
	bt_int_128,
	bt_int_256,
	// all unsigned integers
	bt_uint_8,
	bt_uint_16,
	bt_uint_32,
	bt_uint_64, // = 10
	bt_uint_128,
	bt_uint_256,
	// hex values
	bt_hex_8,
	bt_hex_16,
	bt_hex_32,
	bt_hex_64,
	bt_hex_128,
	bt_hex_256, // 32 bytes
	// floating point
	bt_float,
	bt_double, // = 20
	bt_long_double,
	// char and string
	bt_char,
	bt_string,
	// now the special types
	bt_flow_direction,
	bt_timestamp,   // date whose representation depends on B2T_TIMESTR in utils/bin2txt.h:
	                // 0: unix timestamp, 1: human readable date and time
	bt_duration,    // the time struct consists of one uint64 value for the seconds
	                // and one uint32_t value for the micro-/nano-secs
	bt_mac_addr,
	bt_ip4_addr,
	bt_ip6_addr,
	bt_ipx_addr,     // version (8 bits), address (16 bytes)
	bt_string_class, // A string for classnames. CAUTION: textOutput doesn't escape control characters.
	                 // Advantage: We don't need '"' chars at the beginning and end of the string
	                 // Disadvantage: Usage of underscore, blank, semicolon, and every non-printable
	                 // ASCII are STRICTLY FORBIDDEN !!! If your classnames contain such chars, you'll
	                 // CORRUPT THE OUTPUT!!!
};

/*
 * Definition of typelengths in bytes
 */
enum binary_types_lengths {
	// all signed integers
	l_bt_int_8   =  1,
	l_bt_int_16  =  2,
	l_bt_int_32  =  4,
	l_bt_int_64  =  8,
	l_bt_int_128 = 16,
	l_bt_int_256 = 32,
	// all unsigned integers
	l_bt_uint_8   =  1,
	l_bt_uint_16  =  2,
	l_bt_uint_32  =  4,
	l_bt_uint_64  =  8,
	l_bt_uint_128 = 16,
	l_bt_uint_256 = 32,
	// hex values
	l_bt_hex_8   =  1,
	l_bt_hex_16  =  2,
	l_bt_hex_32  =  4,
	l_bt_hex_64  =  8,
	l_bt_hex_128 = 16,
	l_bt_hex_256 = 32,
	// floating point
	l_bt_float  = 4,
	l_bt_double = 8,
	l_bt_long_double = 10,
	// char and string
	l_bt_char   = 1,
	l_bt_string = 0, // because a string is a set of chars with variable amount, this has to be handled special
	// now the special types
	l_bt_flow_direction = 1,
	l_bt_timestamp = 12,
	l_bt_duration  = 12,
	l_bt_mac_addr  =  6,
	l_bt_ip4_addr  =  4,
	l_bt_ip6_addr  = 16,
	l_bt_ipx_addr  = 17,   // version (8 bits), address (16 bytes)
	l_bt_string_class = 0, // because a string is a set of chars with variable amount, this has to be handled special
};

typedef struct binary_subvalue_s {
	uint32_t type;                    // type of the value
	                                  // If 0, it contains subvalues
	uint32_t num_values;              // amount of subvalues
	uint32_t is_repeating;            // are the subvalues repeating?
	struct binary_subvalue_s *subval; // definition of the subvalues
} binary_subvalue_t;

typedef struct binary_value_s {
	uint32_t num_values;          // amount of values in this column
	uint32_t is_repeating;        // are the subvalues repeating?
	char name[BV_STRBUF_SHORT+1]; // name
	char desc[BV_STRBUF_LONG+1];  // description
	binary_subvalue_t *subval;    // definition of the subvalues
	struct binary_value_s *next;  // next value
} binary_value_t;

typedef struct {
	uint32_t  length; // length of the header (in uint32_t)
	                  // (including the trailing terminate sign)
	uint32_t *header; // The header including the trailing terminate sign
} binary_header_t;


/* Functions */

binary_header_t* build_header(binary_value_t *bv);
void bv_header_destroy(binary_value_t *header);

binary_value_t* bv_new_bv(const char *desc, const char *name, uint32_t is_repeating, uint32_t num_values, ...);
extern binary_value_t* bv_append_bv(binary_value_t *dest, binary_value_t *new);
binary_value_t* bv_add_sv_to_bv(binary_value_t *dest, uint32_t pos, uint32_t is_repeating, uint32_t num_values, ...);
binary_subvalue_t* bv_add_sv_to_sv(binary_subvalue_t *dest, uint32_t pos, uint32_t is_repeating, uint32_t num_values, ...);

#endif /* __BINARY_VALUE_H__ */
