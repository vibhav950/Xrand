/**
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

#include "ctr_drbg.h"
#include "common/endianness.h"

/* Add a 32-bit value to the last 4 bytes of the counter,
   represented in big-endian format */
static inline void _ctr_drbg_incr32 (CTR_DRBG_STATE *state, uint32_t n)
{
#if defined(__LITTLE_ENDIAN__)
    state->V.words[3] = 
        BSWAP32(BSWAP32(state->V.words[3]) + n);
#else
    state->V.words[3] = (state->V.words[3] + n);
#endif
}

/* Section 10.2.1.3.1 */
status_t ctr_drbg_init(CTR_DRBG_STATE *state, 
                       const uint8_t entropy[CTR_DRBG_ENTROPY_LEN],
                       const uint8_t *personalization_str,
                       size_t personalization_str_len)
{
    if (personalization_str_len > CTR_DRBG_ENTROPY_LEN)
        return FAILURE;

    uint8_t seed_material[CTR_DRBG_ENTROPY_LEN];

    memcpy(seed_material, entropy, CTR_DRBG_ENTROPY_LEN);

    if (personalization_str_len > 0) {
        for (size_t i = 0; i < personalization_str_len; ++i)
            seed_material[i] ^= personalization_str[i];
    }

    /* keylen bits of zeros */
    memset(state->K.k, 0, AES256_KEY_SIZE);
    /* blocklen bits of zeros */
    memset(state->V.bytes, 0, AES_BLOCK_SIZE);

    if (SUCCESS != ctr_drbg_update(state, seed_material, CTR_DRBG_ENTROPY_LEN))
        return FAILURE;
    
    /* Reseed counter set to 1 */
    state->counter = 1;

    return SUCCESS;
}

/* Section 10.2.1.2 */
status_t ctr_drbg_update (CTR_DRBG_STATE *state,
                          const uint8_t *provided_data,
                          size_t data_len)
{
    if (data_len > CTR_DRBG_ENTROPY_LEN)
        return FAILURE;

    uint8_t temp[CTR_DRBG_ENTROPY_LEN];

    aes256_ks_t ks;
    aes256_expand_key(&state->K, &ks);

    for (size_t i = 0; i < CTR_DRBG_ENTROPY_LEN; i += AES_BLOCK_SIZE) {
        _ctr_drbg_incr32(state, 1); /* Increment counter */

        aes256_encr_block(state->V.bytes, temp + i, &ks);
    }

    /* Add the provided_data */
    for (size_t i = 0; i < data_len; i++)
        temp[i] ^= provided_data[i];

    memcpy(state->K.k, temp, AES256_KEY_SIZE);
    memcpy(state->V.bytes, temp + AES256_KEY_SIZE, AES_BLOCK_SIZE);

    return SUCCESS;
}

/* Section 10.2.1.4.1 */
status_t ctr_drbg_reseed (CTR_DRBG_STATE *state,
                          const uint8_t entropy[CTR_DRBG_ENTROPY_LEN],
                          const uint8_t *additional_input,
                          size_t additional_input_len)
{
    uint8_t seed_material[CTR_DRBG_ENTROPY_LEN];

    memcpy(seed_material, entropy, CTR_DRBG_ENTROPY_LEN);

    /* Add the additional_input */
    if (additional_input_len > 0) {
        if (additional_input_len > CTR_DRBG_ENTROPY_LEN)
            return FAILURE;

        for (size_t i = 0; i < additional_input_len; ++i)
            seed_material[i] ^= additional_input[i];
    }

    if (SUCCESS != ctr_drbg_update(state, seed_material, CTR_DRBG_ENTROPY_LEN))
        return FAILURE;
    
    /* Reseed counter reset to 1 */
    state->counter = 1;

    return SUCCESS;
}

/* Section 10.2.1.5.1 */
status_t ctr_drbg_generate (CTR_DRBG_STATE *state,
                            uint8_t *out,
                            size_t out_len,
                            const uint8_t *additional_input,
                            size_t additional_input_len)
{
    if (out_len > CTR_DRBG_MAX_OUT_LEN)
        return FAILURE;

    if (additional_input_len > CTR_DRBG_ENTROPY_LEN)
        return FAILURE;

    if (state->counter > CTR_DRBG_MAX_RESEED_CNT)
        return FAILURE;

    uint8_t add_input[CTR_DRBG_ENTROPY_LEN];
    uint8_t temp[AES_BLOCK_SIZE];
    size_t rem_out = out_len;
    size_t i = 0;

    memset(add_input, 0, CTR_DRBG_ENTROPY_LEN);

    /* Add the additional_input*/
    if (additional_input_len > 0) {
        memcpy(add_input, additional_input, additional_input_len);

        if (SUCCESS != ctr_drbg_update(state, add_input, CTR_DRBG_ENTROPY_LEN))
            return FAILURE;
    }

    aes256_ks_t ks;
    aes256_expand_key(&state->K, &ks);

    /* Generate the requested number of blocks */
    for (;;) {
        _ctr_drbg_incr32(state, 1); /* Increment counter */
        
        aes256_encr_block(state->V.bytes, temp, &ks);

        if (rem_out < AES_BLOCK_SIZE) {
            memcpy(out + i, temp, rem_out);
            break;
        }

        memcpy(out + i, temp, AES_BLOCK_SIZE);

        rem_out -= AES_BLOCK_SIZE;
        i += AES_BLOCK_SIZE;
    }

    /* Update for backtracking resistance */
    if (SUCCESS != ctr_drbg_update(state, add_input, CTR_DRBG_ENTROPY_LEN))
        return FAILURE;

    state->counter++;

    return SUCCESS;
}

void ctr_drbg_clear (CTR_DRBG_STATE *state)
{
    /* Clear the state buffers to prevent leaks */
    zeroize ((uint8_t *) state, sizeof(CTR_DRBG_STATE));
}