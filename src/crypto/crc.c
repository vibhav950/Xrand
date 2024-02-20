/**
 * crc.c
 *
 * This file is part of the Xrand cryptographic library.
 * Written by vibhav950 on GitHub.
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

#include "crc.h"

/* Calculate the CRC-32 checksum of the given string 
   using the above table. */
inline uint32_t crc32(const uint8_t *str, size_t len)
{
    uint32_t crc;

    crc = ~0u;
    while (len--)
        crc = crc32_lookup[(crc ^ *str++) & 0xff] ^ (crc >> 8);
    return crc ^ ~0u;
}

void crc32_self_test(void)
{
    const uint8_t tv[8] = {0x01u, 0x23u, 0x45u, 0x67u, 0x89u, 0xabu, 0xcdu, 0xefu};
    ASSERT(crc32(tv, 8) == 0x28c7d1aeu);
}
