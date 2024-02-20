/**
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

#ifndef CRC_H
#define CRC_H

extern const unsigned int crc32_lookup[];

#define UPDC32(octet, crc)\
    (crc32_lookup[((crc >> 24 ) ^ (octet)) & 0xff] ^ ((crc) << 8))

unsigned int crc32(const unsigned char *str, int len);

void crc32_self_test(void);

#endif /* CRC_H */
