/** @file hash_drbg.h
 *  @brief Function prototypes and macros for the
 *         HASH_DRBG pseudorandom generator.
 *
 *  As defined in NIST SP 800-90Ar1, HASH_DRBG requires
 *  that an approved hash algorithm (see SP 800-57 4.1)
 *  be used for the instantiate, reseed and generate
 *  mechanism functions. The Xrand implementation uses
 *  SHA-512 for the hash derivation (Hash_df) and hash
 *  generation (Hashgen) mechanisms.
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

#ifndef HASH_DRBG_H
#define HASH_DRBG_H

#include "common/defs.h"

/* SHA-512 digest length */
#define HASH_DBRG_SHA512_OUTLEN 64U

/* SP 800-90Ar1, Table 2 */
#define HASH_DRBG_SEED_LEN                (111U) /* Seed length */
#define HASH_DRBG_MIN_ENTROPY_LEN          (32U) /* Min entropy length */
#define HASH_DRBG_MAX_ENTROPY_LEN   (1ULL << 32) /* Max entropy length */
#define HASH_DRBG_MAX_NONCE_LEN     (1ULL << 16) /* Max nonce length */
#define HASH_DRBG_MAX_PERS_STR_LEN  (1ULL << 32) /* Max personalization string length */
#define HASH_DRBG_MAX_ADDN_INP_LEN  (1ULL << 32) /* Max additional input length */
#define HASH_DRBG_MAX_OUT_LEN       (1ULL << 16) /* Max output length */
#define HASH_DRBG_MAX_RESEED_CNT    (1ULL << 48) /* Max reseed count */

/**
 * This struct defines the internal state of the
 * HASH_DRBG; See SP 800-90Ar1 Section 10.1.1.1.
*/
typedef struct _HASH_DRBG_STATE {
    /* Value V */
    uint8_t V[HASH_DRBG_SEED_LEN];
    /* Constant C */
    uint8_t C[HASH_DRBG_SEED_LEN];
    /* 64-bit reseed counter */
    uint64_t reseed_counter;
    /* Flags (usage specific) */
    uint8_t flags;
} HASH_DRBG_STATE;


#define ERR_HASH_DRBG_SUCCESS     0x00    /* Success */
#define ERR_HASH_DRBG_NOT_INIT   -0x01    /* Not initialized */
#define ERR_HASH_DRBG_NULL_PTR   -0x02    /* Invalid null pointer passed */
#define ERR_HASH_DRBG_BAD_ARGS   -0x03    /* Bad argument passed */
#define ERR_HASH_DRBG_INTERNAL   -0x04    /* Internal library failed */
#define ERR_HASH_DRBG_MEM_FAIL   -0x05    /* Ran out of memory */
#define ERR_HASH_DRBG_DO_RESEED  -0x06    /* Reseed required */


/** @brief  Allocate a new @p HASH_DRBG_STATE state.
 *
 *  @return  A @p pointer to a HASH_DRBG_STATE state.
 */
HASH_DRBG_STATE *hash_drbg_new();


/**  @brief  Safely stop the HASH_DRBG instance and free
 *           the allocated memory.
 *
 *   @return  Void.
 */
void hash_drbg_clear(HASH_DRBG_STATE *state);


/** @brief  Instantiate a @p HASH_DRBG state.
 *
 *  @param state                    The HASH_DRBG state.
 *  @param entropy                  The entropy from a randomness source.
 *  @param entropy_len              The length of @p entropy in bytes.
 *  @param nonce                    A string of random bits (cannot be Null).
 *  @param nonce_len                The length of @p nonce in bytes.
 *  @param personalization_str      The personalization string received from
 *                                  the consuming application (can be Null).
 *  @param personalization_str_len  The length of @p personalization_str in
 *                                  bytes (can be zero if @p personalization_str
 *                                  is Null).
 *
 *  @return  A ERR_HASH_DRBG_* value.
 */
int hash_drbg_init(HASH_DRBG_STATE *state,
                   const uint8_t *entropy,
                   size_t entropy_len,
                   const uint8_t *nonce,
                   size_t nonce_len,
                   const uint8_t *personalization_str,
                   size_t personalization_str_len);


/** @brief  Reseed a @p HASH_DRBG state.
 *
 *  @param state                    The HASH_DRBG state (must be instantiated
 *                                  once first by calling @p hash_drbg_init).
 *  @param entropy                  The entropy from a randomness source.
 *  @param entropy_len              The length of @p entropy in bytes.
 *  @param additional_input         The additional input string received from
 *                                  the consuming application (can be Null).
 *  @param additional_input_len     The length of @p additional_input in bytes
 *                                  (can be zero if @p additional_input is Null).
 *  @return  A ERR_HASH_DRBG_* value.
 */
int hash_drbg_reseed(HASH_DRBG_STATE *state,
                     const uint8_t *entropy,
                     size_t entropy_len,
                     const uint8_t *additional_input,
                     size_t additional_input_len);


/** @brief  Generate pseudorandom bits from a @p HASH_DRBG state.
 *
 *  @param state                    The HASH_DRBG state (must be instantiated
 *                                  once first by calling @p hash_drbg_init).
 *  @param output                   The output buffer.
 *  @param output_len               Then length of @p output in bytes.
 *  @param additional_input         The additional input string received from
 *                                  the consuming application (can be Null).
 *  @param additional_input_len     The length of @p additional_input in bytes
 *                                  (can be zero if @p additional_input is Null).
 *
 *  @return  A ERR_HASH_DRBG_* value.
 */
int hash_drbg_generate(HASH_DRBG_STATE *state,
                       uint8_t *output,
                       size_t output_len,
                       const uint8_t *additional_input,
                       size_t additional_input_len);


#endif /* HASH_DRBG_H */