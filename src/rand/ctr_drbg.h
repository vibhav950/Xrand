/** @file ctr_drbg.h
 *  @brief Function prototypes and macros for the
 *         CTR_DRBG pseudorandom generator.
 *
 *  As defined in NIST SP 800-90Ar1, CTR_DRBG uses an
 *  approved block cipher algorithm [see SP 800-38A] in
 *  counter mode. The Xrand implementation uses AES-256
 *  as the block cipher, without a derivation function.
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

#ifndef CTR_DRBG_H
#define CTR_DRBG_H

#include <string.h>
#include "defs.h"
#include "aes.h"

/* AES_BLOCK_SIZE as 4-byte words */
#define AES_BLOCK_WORDS       (AES_BLOCK_SIZE / 4)

/* SP 800-90Ar1, Table 3 */
#define CTR_DRBG_ENTROPY_LEN 48U                /* Seed length */
#define CTR_DRBG_MAX_OUT_LEN (1ULL << 16)       /* Max output length */
#define CTR_DRBG_MAX_RESEED_CNT (1ULL << 48)    /* Max reseed count */

/**
 * This struct defines the internal state of the
 * CTR_DRBG; See SP 800-90Ar1 Section 10.2.1.1.
 */
typedef struct _CTR_DRBG_STATE {
    /* 128-bit vector */
    union {
        uint8_t bytes[AES_BLOCK_SIZE];
        uint32_t words[AES_BLOCK_WORDS];
    } V;
    /* 256-bit AES key */
    aes256_key_t K;
    /* Reseed counter */
    uint64_t counter;
} CTR_DRBG_STATE;


/** @brief  Instantiate the CTR_DRBG and set up the
 *          @p CTR_DRBG_STATE context.
 * 
 *  @param state                        The CTR_DRBG context to initialize.
 *  @param entropy                      The entropy from the noise source.
 *  @param personalization_str          The personalization_string from the
 *                                      consuming application. Can be null.
 *  @param personalization_str_len      The length of @p personalization_str
 *                                      in bytes.
 *  @return  A @p status_t status code.
 */
status_t ctr_drbg_init(CTR_DRBG_STATE *state,
                       const uint8_t entropy[CTR_DRBG_ENTROPY_LEN],
                       const uint8_t *personalization_str,
                       size_t personalization_str_len);


/** @brief  Update the internal state of the CTR_DRBG
 *          using the provided_data performing block
 *          operations from the underlying block cipher.
 * 
 *  @param state                        The CTR_DRBG context to update.
 *  @param provided_data                Additional data to update the state.
 *                                      Can be null.
 *  @param data_len                     The length of @p provided_data in bytes.
 * 
 *  @return  A @p status_t status code.
 */
status_t ctr_drbg_update(CTR_DRBG_STATE *state,
                         const uint8_t *provided_data,
                         size_t data_len);


/** @brief  Reseed the internal state of the CTR_DRBG
 *          with entropy from the noise source.
 * 
 *  @param state                        The CTR_DRBG context to reseed.
 *  @param entropy                      The entropy from the noise source.
 *  @param additional_input             Additional data from the consuming
 *                                      application. Can be null.
 *  @param additional_input_len         The length of @p additional_input
 *                                      in bytes.
 * 
 *  @return  A @p status_t status code.
 */
status_t ctr_drbg_reseed(CTR_DRBG_STATE *state,
                         const uint8_t entropy[CTR_DRBG_ENTROPY_LEN],
                         const uint8_t *additional_input,
                         size_t additional_input_len);


/** @brief  Generate the requested number of pseudo-
 *          random bytes from the CTR_DRBG.
 * 
 *  @note   Backtracking resistance is enabled by default.
 * 
 *  @param state                        The CTR_DRBG context.
 *  @param entropy                      The entropy from the noise source.
 *  @param additional_input             Additional data from the consuming
 *                                      application. Can be NULL.
 *  @param additional_input_len         The length of @p additional_input
 *                                      in bytes.
 * 
 *  @return  A @p status_t status code.
 */
status_t ctr_drbg_generate(CTR_DRBG_STATE *state,
                           uint8_t *out,
                           size_t out_len,
                           const uint8_t *additional_input,
                           size_t additional_input_len);


/** @brief  Safely stop the instance of the CTR_DRBG
 *          and release the context.
 * 
 *  @param state                        The CTR_DRBG context to clear.
 * 
 *  @return  Void.
 */
void ctr_drbg_clear(CTR_DRBG_STATE *state);

#endif /* CTR_DRBG_H */