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

#include "trivium.h"
#include "rngw32.h"

/* 288-bit internal state */
static u32 x1, x2, x3, x4, x5, x6, x7, x8, x9;

static u32 t1, t2, t3;
static u8 z;

/* Global counter to handle periodic reseeding */
static s32 ctr = -1;

/*
 * The constant key is the first 80 bits from the
 * first 7 decimal digits of the square roots of
 * the first 4 primes.
 */
static const u8 trivium_k[TRIVIUM_KEY_SIZE] = {0xfc, 0xd0, 0xdf, 0x7d, 0x9d,
                                               0xe4, 0x80, 0xac, 0xf8, 0xa2};

/*
 * Update and rotate the internal state and generate
 * one output bit per iteration.
 */
#define TRIVIUM_UPDATE_ROTATE                                                  \
  {                                                                            \
    t1 = ((x3 >> 1) ^ (x3 >> 28)) & 0x1;                                       \
    t2 = ((x6 >> 1) ^ (x6 >> 16)) & 0x1;                                       \
    t3 = ((x8 >> 18) ^ (x9 >> 31)) & 0x1;                                      \
    z = t1 ^ t2 ^ t3;                                                          \
    t1 = (t1 ^ ((x3 >> 26) & (x3 >> 27)) ^ (x6 >> 10)) & 0x1;                  \
    t2 = (t2 ^ ((x6 >> 14) & (x6 >> 15)) ^ (x9 >> 7)) & 0x1;                   \
    t3 = (t3 ^ ((x9 >> 29) & (x9 >> 30)) ^ (x3 >> 4)) & 0x1;                   \
    x9 = (x9 << 1) | (x8 >> 31);                                               \
    x8 = (x8 << 1) | (x7 >> 31);                                               \
    x7 = (x7 << 1) | (x6 >> 31);                                               \
    x6 = ((x6 << 1) & (((u32)t2 << 17) | 0xfffdffff)) | (x5 >> 31);            \
    x5 = (x5 << 1) | (x4 >> 31);                                               \
    x4 = (x4 << 1) | (x3 >> 31);                                               \
    x3 = ((x3 << 1) & (((u32)t1 << 29) | 0xdfffffff)) | (x2 >> 31);            \
    x2 = (x2 << 1) | (x1 >> 31);                                               \
    x1 = (x1 << 1) | t3;                                                       \
  }

/*
 * Initialize the internal state by inserting the key
 * and IV (both 8-bit unsigned int arrays of size 10),
 * and rotate the internal state over 4 full cycles
 * without generating any key-stream bits.
 */
void trivium_init(const u8 *k, const u8 *iv) {
  /* Insert 80-bit key */
  x1 = ((u32)k[3] << 24) | ((u32)k[2] << 16) | ((u32)k[1] << 8) | k[0];
  x2 = ((u32)k[7] << 24) | ((u32)k[6] << 16) | ((u32)k[5] << 8) | k[4];
  x3 = (u32)0 | (((u32)iv[0] & 0x7) << 29) | ((u32)k[9] << 8) | k[8];
  x4 = (((u32)iv[4] & 0x7) << 29) | ((u32)iv[3] << 21) | ((u32)iv[2] << 13) |
       ((u32)iv[1] << 5) | ((iv[0] & 0xf8) >> 3);
  x5 = (((u32)iv[8] & 0x7) << 29) | ((u32)iv[7] << 21) | ((u32)iv[6] << 13) |
       ((u32)iv[5] << 5) | ((iv[4] & 0xf8) >> 3);
  x6 = (u32)0 | (iv[8] & 0xf8) >> 3;
  x7 = x8 = 0;
  x9 = (u32)0xe0000000;

  /* Blank rounds */
  for (int i = 0; i < 4 * 288; ++i)
    TRIVIUM_UPDATE_ROTATE
}

/*
 * (Re) initialize the internal state with a new
 * key-IV pair by calling the underlying CRNG
 */
static void trivium_set_seed(void) {
  /*
   * Fetch random bytes from the noise source as
   * the IV. This IV combined with the constant
   * key `trivium_k` forms the new seed.
   */
  u8 iv[TRIVIUM_IV_SIZE];

  /* TODO although any failures in the RNG should
     be caught under the hood, this function CAN
     still return FAILURE; handle this somehow. */
  (void)RngFetchBytes(iv, TRIVIUM_IV_SIZE);

  ctr = 0;
  trivium_init(trivium_k, iv);
  zeroize(iv, TRIVIUM_IV_SIZE);
}

/* Return 8 bits of random keystream. */
u8 TriviumRand8() {
  u8 rand = 0;

  if (ctr >= TRIVIUM_RESEED_PERIOD || ctr == -1)
    trivium_set_seed();

  for (int i = 0; i < 8; ++i) {
    TRIVIUM_UPDATE_ROTATE

    rand = (rand << 1) | z;
  }
  ctr += 8;

  return rand;
}

/* Return 16 bits of random keystream. */
u16 TriviumRand16() {
  u16 rand = 0;

  if (ctr >= TRIVIUM_RESEED_PERIOD || ctr == -1)
    trivium_set_seed();

  for (int i = 0; i < 16; ++i) {
    TRIVIUM_UPDATE_ROTATE

    rand = (rand << 1) | z;
  }
  ctr += 16;

  return rand;
}

/* Return 32 bits of random keystream. */
u32 TriviumRand32() {
  u32 rand = 0;

  if (ctr >= TRIVIUM_RESEED_PERIOD || ctr == -1)
    trivium_set_seed();

  for (int i = 0; i < 32; ++i) {
    TRIVIUM_UPDATE_ROTATE

    rand = (rand << 1) | z;
  }
  ctr += 32;

  return rand;
}

/* Return 64 bits of random keystream. */
u64 TriviumRand64() {
  u64 rand = 0;

  if (ctr >= TRIVIUM_RESEED_PERIOD || ctr == -1)
    trivium_set_seed();

  for (int i = 0; i < 64; ++i) {
    TRIVIUM_UPDATE_ROTATE

    rand = (rand << 1) | z;
  }
  ctr += 64;

  return rand;
}

/* Init the Trivium CSPRNG.
   The RNG must be started before calling this function.
   Returns a status_t SUCCESS/FAILURE. */
status_t TriviumCsprngInit() {
  if (!DidRngStart())
    return FAILURE;

  /*if !*/ trivium_set_seed();
  // return FAILURE;

  return SUCCESS;
}

/* Reset the counter and internal state. */
void TriviumCsprngReset() {
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

  /* Reset the reseed counter */
  ctr = -1;
}