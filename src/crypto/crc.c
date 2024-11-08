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

#include <string.h>

/* Calculate the CRC-32 checksum of the given string. */
uint32_t crc32(const uint8_t *str, size_t len) {
  uint32_t crc;

  crc = ~0u;
  while (len--)
    crc = crc32_lookup[(crc ^ *str++) & 0xff] ^ (crc >> 8);
  return crc ^ ~0u;
}

void crc32_self_test(void) {
  uint8_t buf1[32];

  memset(buf1, 0, sizeof(buf1));
  ASSERT(crc32(buf1, sizeof(buf1)) == 0x190a55ad);

  memset(buf1, 0xff, sizeof(buf1));
  ASSERT(crc32(buf1, sizeof(buf1)) == 0xff6cab0b);

  for (size_t i = 0; i < sizeof(buf1); ++i)
    buf1[i] = (uint8_t)i;
  ASSERT(crc32(buf1, sizeof(buf1)) == 0x91267e8a);

  for (size_t i = 0; i < sizeof(buf1); ++i)
    buf1[i] = (uint8_t)(31 - i);
  ASSERT(crc32(buf1, sizeof(buf1)) == 0x9ab0ef72);

  const uint8_t buf2[] = {
      0x01u, 0x23u, 0x45u, 0x67u,
      0x89u, 0xabu, 0xcdu, 0xefu
  };
  ASSERT(crc32(buf2, sizeof(buf2)) == 0x28c7d1ae);

  const uint8_t buf3[] = {
      0x32u, 0xd0u, 0x70u, 0xc6u, 0x7du, 0xa0u, 0x51u, 0x87u,
      0x70u, 0xf6u, 0x12u, 0xafu, 0x4au, 0xceu, 0x63u, 0x5au
  };
  ASSERT(crc32(buf3, sizeof(buf3)) == 0xaf6bebe3);

  const uint8_t buf4[] = {
      0xedu, 0x41u, 0x98u, 0xdcu, 0xa2u, 0x92u, 0xb8u, 0xdau, 0xd0u, 0x52u, 0x45u,
      0xf9u, 0xbbu, 0x88u, 0x0fu, 0x30u, 0x2bu, 0x79u, 0xacu, 0x86u, 0xbdu, 0x39u,
      0xefu, 0x2du, 0xccu, 0x49u, 0xd5u, 0xe2u, 0xd5u, 0x28u, 0x52u, 0x70u
  };
  ASSERT(crc32(buf4, sizeof(buf4)) == 0x04f94fc3);

  const uint8_t buf5[] = {
      0x0eu, 0xf9u, 0x53u, 0xf1u, 0x3du, 0xb6u, 0x1au, 0x15u, 0x46u,
      0xbfu, 0xfcu, 0x0bu, 0xb0u, 0x1au, 0xcbu, 0xc3u, 0xa6u, 0xacu,
      0x6cu, 0xa6u, 0xe7u, 0xb2u, 0xbcu, 0xc2u, 0x56u, 0x46u, 0x7au,
      0x8au, 0x48u, 0xb9u, 0x7bu, 0x8bu, 0x45u, 0x5au, 0x8eu, 0xe2u,
      0x6au, 0x5eu, 0xf0u, 0xb4u, 0xeau, 0x33u, 0x9au, 0xf9u, 0x16u,
      0xe6u, 0xf2u, 0xdfu
  };
  ASSERT(crc32(buf5, sizeof(buf5)) == 0xa1d59ee5);
}
