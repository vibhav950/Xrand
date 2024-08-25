/** @file trivium.h
 *  @brief Macros and function prototypes for the Trivium pseudorandom generator.
 *
 *  This PRNG is based on the original Trivium key-stream generator selected 
 *  for the eSTREAM (part of the EU ECRYPT project) portfolio of lightweight 
 *  stream ciphers [https://www.ecrypt.eu.org/stream/e2-trivium.html].
 *
 *  The cipher uses a 80-bit key and 80-bit initialization vector (IV), and its
 *  secret state has 288 bits. Although Trivium guarantees 2^64 key-stream bits,
 *  this generator is reseeded with a new IV after every 2^20 bytes generated.
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

#ifndef TRIVIUM_H
#define TRIVIUM_H

#include "common/defs.h" 

/* The Trivium key size in bytes. */
#define TRIVIUM_KEY_SIZE            10
/* The Trivium IV size in bytes. */
#define TRIVIUM_IV_SIZE             10

/* Period for re-seeding the CSPRNG. */
#define TRIVIUM_RESEED_PERIOD       (1ULL << 20)

/* Init the Trivium CSPRNG. */
status_t TriviumCsprngInit(void);
/* Reset the counter and internal state. */
void TriviumCsprngReset(void);

/* Fetch an 8-bit random number. */
u8 TriviumRand8();
/* Fetch a 16-bit random number. */
u16 TriviumRand16();
/* Fetch a 32-bit random number. */
u32 TriviumRand32();
/* Fetch a 64-bit random number. */
u64 TriviumRand64();

#endif /* TRIVIUM_H */