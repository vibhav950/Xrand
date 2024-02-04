/**
 * aes.c - Implementation for the AES-256 key schedule and encryption procedures
 * as provided in the 'Intel Advanced Encryption Standard (AES) Instruction Set'
 * White Paper by Shay Gueron.
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

#include "crypto/aes.h"

static inline void KEY_256_ASSIST_1(__m128i *temp1, __m128i *temp2)
{
    __m128i temp4;
    *temp2 = _mm_shuffle_epi32(*temp2, 0xff);
    temp4 = _mm_slli_si128(*temp1, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    *temp1 = _mm_xor_si128(*temp1, *temp2);
}

static inline void KEY_256_ASSIST_2(__m128i *temp1, __m128i *temp3)
{
    __m128i temp2, temp4;
    temp4 = _mm_aeskeygenassist_si128(*temp1, 0x0);
    temp2 = _mm_shuffle_epi32(temp4, 0xaa);
    temp4 = _mm_slli_si128(*temp3, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    *temp3 = _mm_xor_si128(*temp3, temp2);
}

void aes256_expand_key(const aes256_key_t *key,
                       aes256_ks_t *ks)
{
    uint8_t *k = (uint8_t*)key;
    __m128i *rk = (__m128i*)ks;
    __m128i temp1, temp2, temp3;
    __m128i *Key_Schedule = (__m128i *)rk;
    temp1 = _mm_loadu_si128((__m128i *)k);
    temp3 = _mm_loadu_si128((__m128i *)(k + 16));
    Key_Schedule[0] = temp1;
    Key_Schedule[1] = temp3;
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[2] = temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[3] = temp3;
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[4] = temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[5] = temp3;
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[6] = temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[7] = temp3;
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[8] = temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[9] = temp3;
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[10] = temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[11] = temp3;
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[12] = temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[13] = temp3;
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[14] = temp1;
    _mm256_zeroall();
}

#define LOAD128(x)              _mm_loadu_si128(x)
#define STORE128(x, y)          _mm_storeu_si128(x, y)
#define XOR128(x, y)            _mm_xor_si128(x, y)
#define ZEROALL256              _mm256_zeroall

#define AESENC(x, y)            _mm_aesenc_si128(x, y)
#define AESENCLAST(x, y)        _mm_aesenclast_si128(x, y)

void aes256_encr_block(const uint8_t *pt,
                       uint8_t *ct,
                       const aes256_ks_t *ks)
{
    __m128i *rk = (__m128i*)ks;
    __m128i tmp;
    int i;
    tmp = LOAD128((__m128i *)pt);
    tmp = XOR128(tmp, ((__m128i *)rk)[0]);
    for (i = 1; i < AES256_ROUNDS; i++)
    {
        tmp = AESENC(tmp, ((__m128i *)rk)[i]);
    }
    tmp = AESENCLAST(tmp, ((__m128i *)rk)[i]);
    STORE128((__m128i *)ct, tmp);
    ZEROALL256();
}