/**
 * trivium.c
 *
 * Implementation of the ECRYPT Trivium pseudorandom generator.
 *
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


#include "common/defs.h"
#include "rngw32.h"
#include "trivium.h"

/* 288-bit internal state */
static uint32_t x1, x2, x3, x4, x5, x6, x7, x8, x9;

static uint32_t t1, t2, t3;
static uint8_t z;

/* Global counter to handle periodic reseeding */
static int32_t _reseed_cnt = -1;

/*
 * The constant key is the first 80 bits from the
 * first 7 decimal digits of the square roots of
 * the first 4 primes.
 */
static const uint8_t _xr_trm_const_key[XR_TRM_KEY_SIZE] =\
{
    0xfc, 0xd0, 0xdf, 0x7d, 0x9d,
    0xe4, 0x80, 0xac, 0xf8, 0xa2,
};

/*
 * Update and rotate the internal state and generate 
 * one output bit per iteration.
 */
#define _rotate do {\
    t1 = ((x3 >> 30) ^ (x3 >> 3)) & 0x1;\
    t2 = ((x6 >> 30) ^ (x6 >> 15)) & 0x1;\
    t3 = ((x8 >> 13) ^ x9) & 0x1;\
    z = t1 ^ t2 ^ t3;\
    t1 = (t1 ^ ((x3 >> 5) & (x3 >> 4)) ^ (x6 >> 21)) & 0x1;\
    t2 = (t2 ^ ((x6 >> 17) & (x6 >> 16)) ^ (x9 >> 24)) & 0x1;\
    t3 = (t3 ^ ((x9 >> 2) & (x9 >> 1)) ^ (x3 >> 27)) & 0x1;\
    x9 = (x9 >> 1) | (x8 << 31);\
    x8 = (x8 >> 1) | (x7 << 31);\
    x7 = (x7 >> 1) | (x6 << 31);\
    x6 = (x6 >> 1) | (x5 << 31);\
    x5 = (x5 >> 1) | (x4 << 31);\
    x4 = (x4 >> 1) | (x3 << 31);\
    x3 = (x3 >> 1) | (x2 << 31);\
    x2 = (x2 >> 1) | (x1 << 31);\
    x1 = (x1 >> 1);\
    x1 = (x1 & 0x7fffffff) | (t3 << 31);\
    x3 = (x3 & 0xfffffffb) | (t1 << 2);\
    x6 = (x6 & 0xffffbfff) | (t2 << 14);\
    } while (0)

#define _hardrotate do { for (int i = 0; i < 512; ++i) { _rotate; } } while (0)

/*
 * Initialize the internal state by inserting the key 
 * and IV (both 8-bit unsigned int arrays of size 10), 
 * and rotate the internal state over 4 full cycles 
 * without generating any key-stream bits.
 */
void _init (const uint8_t *key, const uint8_t *iv)
{
    x1 = 0;
    x2 = 0;
    x3 = 0;
    x4 = 0;
    x5 = 0;
    x6 = 0;
    x7 = 0;
    x8 = 0;
    x9 = 0;

    /* Insert 80-bit key */
    x1 |= ((uint32_t) key[0] << 24) | ((uint32_t) key[1] << 16) | ((uint32_t) key[2] << 8) | key[3];
    x2 |= ((uint32_t) key[4] << 24) | ((uint32_t) key[5] << 16) | ((uint32_t) key[6] << 8) | key[7];
    x3 |= ((uint32_t) key[8] << 24) | key[9];

    /* Insert 80-bit IV */
    x3 |= ((uint32_t) iv[0] >> 5);
    x4 |= (((uint32_t) iv[0] >> 3) << 27) | ((uint32_t) iv[1] << 19) | ((uint32_t) iv[2] << 11)\
       | ((uint32_t) iv[3] << 3) | (iv[4] >> 5);
    x5 |= (((uint32_t) iv[4] >> 3) << 27) | ((uint32_t) iv[5] << 19) | ((uint32_t) iv[6] << 11)\
       | ((uint32_t) iv[7] << 3) | (iv[8] >> 5);
    x6 |= (((uint32_t) iv[8] >> 3) << 27) | ((uint32_t) iv[9] << 19);

    x9 |= 0x7;

    /* Blank rounds */
    for (uint16_t i = 0; i < 4 * 288; ++i)
    {
        _rotate;
    }
}

/*
 * (Re) initialize the internal state with a new
 * key-IV pair by calling the underlying CRNG
 */
void _set_seed (void)
{
    /* 
     * Fetch random bytes from the noise source as
     * the IV. This IV combined with the constant
     * key forms the new seed
     *
     * Note: the constant key is chosen to be
     * statistically independent from the bytes
     * collected from the noise source
     */
    uint8_t iv [XR_TRM_IV_SIZE];
    if (RngFetchBytes (iv, XR_TRM_IV_SIZE) != TRUE);
    _init (_xr_trm_const_key, iv);
    _reseed_cnt = 0;
    zeroize (iv, XR_TRM_IV_SIZE);
}

/* Returns 8 bits of keystream */
uint8_t RandU8 (void)
{
    if (_reseed_cnt >= XR_TRM_RESEED_PERIOD || _reseed_cnt == -1)
    {
        _set_seed ();
    }

    uint8_t ret = 0;

    for (uint8_t i = 0; i < 8; ++i)
    {
        _rotate;
        ret = (ret << 1) | z;
    }

    _reseed_cnt += 8;
    return ret;
}

/* Returns 16 bits of keystream */
uint16_t RandU16 (void)
{
    if (_reseed_cnt >= XR_TRM_RESEED_PERIOD || _reseed_cnt == -1)
    {
        _set_seed ();
    }

    uint16_t ret = 0;

    for (uint8_t i = 0; i < 16; ++i)
    {
        _rotate;
        ret = (ret << 1) | z;
    }

    _reseed_cnt += 16;
    return ret;
}

/* Returns 32 bits of keystream */
uint32_t RandU32 (void)
{
    if (_reseed_cnt >= XR_TRM_RESEED_PERIOD || _reseed_cnt == -1)
    {
        _set_seed ();
    }

    uint32_t ret = 0;

    for (uint8_t i = 0; i < 32; ++i)
    {
        _rotate;
        ret = (ret << 1) | z;
    }

    _reseed_cnt += 32;
    return ret;
}

/* Returns 64 bits of keystream */
uint64_t RandU64 (void)
{
    if (_reseed_cnt >= XR_TRM_RESEED_PERIOD || _reseed_cnt == -1)
    {
        _set_seed ();
    }

    uint64_t ret = 0;

    for (uint8_t i = 0; i < 64; ++i)
    {
        _rotate;
        ret = (ret << 1) | z;
    }

    _reseed_cnt += 64;
    return ret;
}


status_t TriviumCsprngStart (void)
{
    if (!RngStart ()) return FAILURE;

    _set_seed ();

    return SUCCESS;
}

void TriviumCsprngStop (void)
{
    /* Clear the internal state to prevent leaks */
    x1 = 0;
    x2 = 0;
    x3 = 0;
    x4 = 0;
    x5 = 0;
    x6 = 0;
    x7 = 0;
    x8 = 0;
    x9 = 0;

    /* Safely stop the RNG */
    RngStop ();
}