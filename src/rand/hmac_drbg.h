/** @file hmac_drbg.h
 *  @brief Function prototypes and macros for the
 *         HMAC_DRBG pseudorandom generator.
 *
 *  As defined in NIST SP 800-90Ar1, HMAC_DRBG uses multiple
 *  occurrences of an approved keyed hash function, which is
 *  based on an approved hash function (see SP 800-57 4.1).
 *
 *  The Xrand implementation uses SHA-512 for the HMAC
 *  operation in the HMAC_DRBG_Update() and
 *  HMAC_DRBG_Generate() functions (see SP 800-90Ar1 10.1.2).
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

#ifndef HMAC_DRBG_H
#define HMAC_DRBG_H

#include "common/defs.h"

/* SHA-512 digest length */
#define HMAC_DRBG_SHA512_OUTLEN 64U

/* SP 800-90Ar1, Table 2 */
#define HMAC_DRBG_MIN_ENTROPY_LEN (32U)        /* Min entropy length */
#define HMAC_DRBG_MAX_ENTROPY_LEN (1ULL << 32) /* Max entropy length */
#define HMAC_DRBG_MAX_NONCE_LEN (1ULL << 16)   /* Max nonce length */
#define HMAC_DRBG_MAX_PERS_STR_LEN                                             \
  (1ULL << 32) /* Max personalization string length */
#define HMAC_DRBG_MAX_ADDN_INP_LEN                                             \
  (1ULL << 32)                                /* Max additional input length */
#define HMAC_DRBG_MAX_OUTPUT_LEN (1ULL << 16) /* Max output length */
#define HMAC_DRBG_MAX_RESEED_CNT (1ULL << 48) /* Max reseed count */

#define HMAC_DRBG_MAX_INPUT_LEN (1ULL << 32) /* Max input length */

/**
 * This struct defines the internal state of the
 * HMAC_DRBG; See SP 800-90Ar1 Section 10.1.2.1.
 */
typedef struct _HMAC_DRBG_STATE {
  /* HMAC Key */
  uint8_t K[HMAC_DRBG_SHA512_OUTLEN];
  /* Value V */
  uint8_t V[HMAC_DRBG_SHA512_OUTLEN];
  /* 64-bit reseed counter */
  uint64_t reseed_counter;
  /* Flags (usage specific) */
  uint8_t flags;
} HMAC_DRBG_STATE;

#define ERR_HMAC_DRBG_SUCCESS 0x00 /* Success */
#define ERR_HMAC_DRBG_NOT_INIT -0x01 /* Not initialized */
#define ERR_HMAC_DRBG_NULL_PTR -0x02 /* Invalid null pointer passed */
#define ERR_HMAC_DRBG_BAD_ARGS -0x03 /* Bad argument passed */
#define ERR_HMAC_DRBG_INTERNAL -0x04 /* Internal library failed */
#define ERR_HMAC_DRBG_MEM_FAIL -0x05 /* Ran out of memory */
#define ERR_HMAC_DRBG_DO_RESEED -0x06 /* Reseed required */

/* Return the error message. */
const char *hmac_drbg_err_string(int err);

/** @brief  Allocate a new @p HMAC_DRBG_STATE state.
 *
 *  @return  A pointer to a @p HMAC_DRBG_STATE state.
 */
HMAC_DRBG_STATE *hmac_drbg_new();

/**  @brief  Safely stop the HMAC_DRBG instance and free
 *           the allocated memory.
 *
 *   @return  Void.
 */
void hmac_drbg_clear(HMAC_DRBG_STATE *state);

/** @brief  Instantiate a @p HMAC_DRBG state.
 *
 *  @param state                    The HMAC_DRBG state.
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
 *  @return  A ERR_HMAC_DRBG_* value.
 */
int hmac_drbg_init(HMAC_DRBG_STATE *state, const uint8_t *entropy,
                   size_t entropy_len, const uint8_t *nonce, size_t nonce_len,
                   const uint8_t *personalization_str,
                   size_t personalization_str_len);

/** @brief  Reseed a @p HMAC_DRBG state.
 *
 *  @param state                    The HMAC_DRBG state (must be instantiated
 *                                  once first by calling @p hmac_drbg_init).
 *  @param entropy                  The entropy from a randomness source.
 *  @param entropy_len              The length of @p entropy in bytes.
 *  @param additional_input         The additional input string received from
 *                                  the consuming application (can be Null).
 *  @param additional_input_len     The length of @p additional_input in bytes
 *                                  (can be zero if @p additional_input is
 * Null).
 *  @return  A ERR_HMAC_DRBG_* value.
 */
int hmac_drbg_reseed(HMAC_DRBG_STATE *state, const uint8_t *entropy,
                     size_t entropy_len, const uint8_t *additional_input,
                     size_t additional_input_len);

/** @brief  Generate pseudorandom bits from a @p HMAC_DRBG state.
 *
 *  @param state                    The HMAC_DRBG state (must be instantiated
 *                                  once first by calling @p hmac_drbg_init).
 *  @param output                   The output buffer.
 *  @param output_len               Then length of @p output in bytes.
 *  @param additional_input         The additional input string received from
 *                                  the consuming application (can be Null).
 *  @param additional_input_len     The length of @p additional_input in bytes
 *                                  (can be zero if @p additional_input is
 * Null).
 *
 *  @return  A ERR_HMAC_DRBG_* value.
 */
int hmac_drbg_generate(HMAC_DRBG_STATE *state, uint8_t *output,
                       size_t output_len, const uint8_t *additional_input,
                       size_t additional_input_len);

#endif /* HMAC_DRBG_H */