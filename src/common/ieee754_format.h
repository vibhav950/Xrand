/**
 * ieee754_format.h
 *
 * IEEE-754 single precision and double precision formats.
 *
 * LICENSE
 * ======= 
 *
 * Copyright (C) 2024-25  Xrand
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef IEEE754_FORMAT_H
#define IEEE754_FORMAT_H

#include "endianness.h"

typedef union _ieee754_float_t {
    float f;

    /* IEEE 754 single-precision format */
    struct {
#ifdef __BIG_ENDIAN__
	unsigned int sign:1;
	unsigned int exponent:8;
	unsigned int mantissa:23;
#endif					/* Big endian */
#ifdef __LITTLE_ENDIAN__
	unsigned int mantissa:23;
	unsigned int exponent:8;
	unsigned int sign:1;
#endif					/* Little endian */
    } fmt;
} ieee754_float_t;

#define IEEE754_SINGLE_PREC_BIAS 0x7f

typedef union _ieee754_double_t {
	double d;

	/* IEEE 754 double-precision format */
	struct {
#ifdef __BIG_ENDIAN__
	unsigned int sign:1;
	unsigned int exponent:11;
	unsigned int mantissa0:20;
	unsigned int mantissa1:32;
#endif					/* Big endian */
#ifdef __LITTLE_ENDIAN__
	unsigned int mantissa1:32;
	unsigned int mantissa0:20;
	unsigned int exponent:11;
	unsigned int sign:1;
#endif					/* Little endian */
	} fmt;
} ieee754_double_t;

#define IEEE754_DOUBLE_PREC_BIAS 0x3ff

#endif /* IEEE754_FORMAT_H */
