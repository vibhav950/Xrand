/** @file aes.h
 *  @brief Advanced Encryption Standard (AES)
 *
 *  Defines, typedefs and function prototypes for AES256
 *  key expansion and block encryption.
 *
 *  @author Vibhav Tiwari [vibhav950 on GitHub]
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

#ifndef AES256_H
#define AES256_H

#include <stdint.h>
#include <immintrin.h>

#define ALIGN16 __attribute__( ( aligned(16) ) )

#define AES256

#define AES256_KEY_SIZE     32U
#define AES_BLOCK_SIZE      16U
#define AES256_ROUNDS       14U

/** The AES-256 cipher key. */
typedef ALIGN16 struct _aes256_key_t {
    uint8_t k[AES256_KEY_SIZE];
} aes256_key_t;

/**
 * The AES-256 key schedule holds the expanded round keys;
 * Must be 16-bytes aligned.
 */
typedef ALIGN16 struct _aes256_ks_t {
    __m128i rk[AES256_ROUNDS + 1];
} aes256_ks_t;

/** @brief  Expand the cipher key into a key schedule
 *          containing the round keys.
 *
 *  @param key                          The 256-bit cipher key.
 *  @param ks                           The expanded key schedule.
 *
 *  @return  Void.
 */
void aes256_expand_key(const aes256_key_t *key,
                       aes256_ks_t *ks);


/** @brief  Encrypt one 128-bit block.
 *
 *  @param pt                           The block containing plaintext.
 *  @param ct                           The encrypted block; out = Enc(in, ks).
 *  @param ks                           The expanded key schedule.
 *
 *  @return  Void.
 */
void aes256_encr_block(const uint8_t *pt,
                       uint8_t *ct,
                       const aes256_ks_t *ks);

#endif /* AES256_H */