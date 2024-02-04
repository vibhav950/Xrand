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

#define XR_TRM_KEY_SIZE            10
#define XR_TRM_IV_SIZE             10

#define XR_TRM_RESEED_PERIOD       (1ULL << 20)

/* Setup the PRNG */
status_t TriviumCsprngStart (void);
/* Stop the PRNG and clear the internal state */
void TriviumCsprngStop (void);

/* Get an 8-bit random number */
uint8_t  RandU8  (void);
/* Get a 16-bit random number */
uint16_t RandU16 (void);
/* Get a 32-bit random number */
uint32_t RandU32 (void);
/* Get a 64-bit random number */
uint64_t RandU64 (void);

#endif /* TRIVIUM_H */