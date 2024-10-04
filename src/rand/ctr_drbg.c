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
#include <string.h>

/* Add a 32-bit value to the last 4 bytes of the counter,
   represented in big-endian format */
#define CTR_DRBG_INCR32(x, n)                    \
do {                                             \
    state->V.words[3] =                          \
    BSWAP32(BSWAP32(state->V.words[3]) + n);     \
} while (0)

/* Section 10.2.1.3.1 */
status_t ctr_drbg_init(CTR_DRBG_STATE *state, 
                       const uint8_t entropy[CTR_DRBG_ENTROPY_LEN],
                       const uint8_t *personalization_str,
                       size_t personalization_str_len)
{
    uint8_t seed_material[CTR_DRBG_ENTROPY_LEN];

    if (personalization_str_len > CTR_DRBG_ENTROPY_LEN)
        return FAILURE;

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
    
    state->reseed_counter = 1;

	/* Destroy secrets */
	zeroize(seed_material, CTR_DRBG_ENTROPY_LEN);
    return SUCCESS;
}

/* Section 10.2.1.2 */
status_t ctr_drbg_update(CTR_DRBG_STATE *state,
                         const uint8_t *provided_data,
                         size_t data_len)
{
    uint8_t temp[CTR_DRBG_ENTROPY_LEN];

    if (data_len > CTR_DRBG_ENTROPY_LEN)
        return FAILURE;

    aes256_ks_t ks;
    aes256_expand_key(&state->K, &ks);

    for (size_t i = 0; i < CTR_DRBG_ENTROPY_LEN; i += AES_BLOCK_SIZE) {
        CTR_DRBG_INCR32(state, 1); /* Increment counter */
        aes256_encr_block(state->V.bytes, temp + i, &ks);
    }

    /* Add the provided_data */
    for (size_t i = 0; i < data_len; i++)
        temp[i] ^= provided_data[i];

    memcpy(state->K.k, temp, AES256_KEY_SIZE);
    memcpy(state->V.bytes, temp + AES256_KEY_SIZE, AES_BLOCK_SIZE);

	/* Destroy secrets */
	zeroize(temp, CTR_DRBG_ENTROPY_LEN);
    return SUCCESS;
}

/* Section 10.2.1.4.1 */
status_t ctr_drbg_reseed(CTR_DRBG_STATE *state,
                         const uint8_t entropy[CTR_DRBG_ENTROPY_LEN],
                         const uint8_t *additional_input,
                         size_t additional_input_len)
{
    uint8_t seed_material[CTR_DRBG_ENTROPY_LEN];

	if (additional_input_len > CTR_DRBG_ENTROPY_LEN)
		return FAILURE;

    memcpy(seed_material, entropy, CTR_DRBG_ENTROPY_LEN);

    /* Add the additional_input */
	for (size_t i = 0; i < additional_input_len; ++i)
		seed_material[i] ^= additional_input[i];

    if (SUCCESS != ctr_drbg_update(state, seed_material, CTR_DRBG_ENTROPY_LEN))
        return FAILURE;
    
    state->reseed_counter = 1;

	/* Destroy secrets */
	zeroize(seed_material, CTR_DRBG_ENTROPY_LEN);
    return SUCCESS;
}

/* Section 10.2.1.5.1 */
status_t ctr_drbg_generate(CTR_DRBG_STATE *state,
                           uint8_t *out,
                           size_t out_len,
                           const uint8_t *additional_input,
                           size_t additional_input_len)
{
    if (out_len > CTR_DRBG_MAX_OUT_LEN)
        return FAILURE;

    if (additional_input_len > CTR_DRBG_ENTROPY_LEN)
        return FAILURE;

    if (state->reseed_counter > CTR_DRBG_MAX_RESEED_CNT)
        return FAILURE;

    /* Add the additional_input */
    if ((additional_input_len > 0) &&
        (SUCCESS != ctr_drbg_update(state, additional_input, additional_input_len)))
            return FAILURE;

    aes256_ks_t ks;
    aes256_expand_key(&state->K, &ks);

	/* Generate (out_len / AES_BLOCK_SIZE) blocks */
    while (out_len >= AES_BLOCK_SIZE) {
        CTR_DRBG_INCR32(state, 1); /* Increment counter */
        aes256_encr_block(state->V.bytes, out, &ks);

        out += AES_BLOCK_SIZE;
        out_len -= AES_BLOCK_SIZE;
    }
	/* Generate (out_len % AES_BLOCK_SIZE) bytes */
    if (out_len) {
        uint8_t temp[AES_BLOCK_SIZE];
        CTR_DRBG_INCR32(state, 1);
        aes256_encr_block(state->V.bytes, temp, &ks);
        memcpy(out, temp, out_len);
    }

    /* Update for backtracking resistance */
    if (SUCCESS !=
        ctr_drbg_update(state, additional_input, additional_input_len))
        return FAILURE;

    state->reseed_counter++;

    return SUCCESS;
}

void ctr_drbg_clear(CTR_DRBG_STATE *state)
{
    /* Clear the state buffers to prevent leaks */
    zeroize((uint8_t *)state, sizeof(CTR_DRBG_STATE));
}

#if defined(XR_CTR_DRBG_TESTS)
#include <stdio.h>
#include <ctype.h>
#include <assert.h>

static inline void skip_spaces(FILE *f)
{
    int ch;

    while ((ch = fgetc(f)) != EOF && isspace(ch));
    if (ch != EOF)
        ungetc(ch, f);
}

static int read_hex(FILE *f, uint8_t **val, const char *prefix, const unsigned int len)
{
    unsigned int i, value;
    char buffer[2048];

    skip_spaces(f);
    fgets(buffer, strlen(prefix) + 1, f);
    if (strcmp(buffer, prefix)) {
        printf("Cant read \"%s\"\n", prefix);
        return 1;
    }
    *val = (uint8_t *)malloc(len);
    if (*val == NULL) {
        printf("Out of memory\n");
        exit(1);
    }
    for (i = 0; i < len; ++i) {
		fscanf(f, "%02x", &value);
		(*val)[i] = (uint8_t)value;
	}
    return 0;
}

static int read_uint(FILE *f, unsigned int *val, const char *format, const char *name)
{
    skip_spaces(f);
    if (!fscanf(f, format, val)) {
        printf("Cant read \"%s\"\n", name);
        return 1;
    }
    return 0;
}

static int run_test_vecs(const char *filename)
{
    FILE *f;
    bool done;
    unsigned int i;
    unsigned int count, passed;
	unsigned int entropy_input_length;
	unsigned int nonce_length;
	unsigned int personalization_string_length;
	unsigned int additional_input_length;
	unsigned int returned_bits_length;
    uint8_t *entropy_input;
	uint8_t *nonce;
	uint8_t *personalization_string;
	uint8_t *additional_input;
	uint8_t *returned_bits;
    uint8_t *generate_output;
	CTR_DRBG_STATE state;
    char buffer[2048];

    if (NULL == (f = fopen(filename, "r"))) {
        printf("Cant open file %s\n", filename);
        return 1;
    }

    // Skip past the [AES-256 no df] line
    count = 1;
    while (!feof(f)) {
        fgets(buffer, sizeof(buffer), f);
        if (!strcmp(buffer, "[AES-256 no df]\n"))
            break;
    }

    done = false;
    while (!feof(f)) {
        fgets(buffer, sizeof(buffer), f);
        if (!strcmp(buffer, "[PredictionResistance = False]")) {
            printf("Error in parsing; the test vectors must be extracted from drbgvectors_pr_false.zip\n");
            return 1;
		}

        // read length params and convert to bytes
        if (read_uint(f, &entropy_input_length, "[EntropyInputLen = %u]", "EntropyInputLen"))
                return 1;
        entropy_input_length >>= 3;
        if (read_uint(f, &nonce_length, "[NonceLen = %u]", "NonceLen"))
            return 1;
        nonce_length >>= 3;
        if (read_uint(f, &personalization_string_length, "[PersonalizationStringLen = %u]", "PersonalizationStringLen"))
            return 1;
        personalization_string_length >>= 3;
        if (read_uint(f, &additional_input_length, "[AdditionalInputLen = %u]", "AdditionalInputLen"))
            return 1;
        additional_input_length >>= 3;
        if (read_uint(f, &returned_bits_length, "[ReturnedBitsLen = %u]", "ReturnedBitsLen"))
            return 1;
        returned_bits_length >>= 3;

        while (!feof(f)) {
            skip_spaces(f);
            fgets(buffer, sizeof(buffer), f);
            if (!strcmp(buffer, "[AES-256 no df]\n")) // next set of tests
                break;
            if (feof(f)) { // end of tests
                done = true;
                break;
            }

            // init
            if (read_hex(f, &entropy_input, "EntropyInput = ", entropy_input_length))
                return 1;
            if (read_hex(f, &nonce, "Nonce = ", nonce_length))
                return 1;
            if (read_hex(f, &personalization_string, "PersonalizationString = ", personalization_string_length))
                return 1;
            assert(SUCCESS == ctr_drbg_init(&state, entropy_input, personalization_string, personalization_string_length));

            free(entropy_input);
            // reseed
            if (read_hex(f, &entropy_input, "EntropyInputReseed = ", entropy_input_length))
                return 1;
            if (read_hex(f, &additional_input, "AdditionalInputReseed = ", additional_input_length))
                return 1;
            assert(SUCCESS == ctr_drbg_reseed(&state, entropy_input, additional_input, additional_input_length));

            // generate
            if (NULL == (returned_bits = (uint8_t *)malloc(returned_bits_length))) {
                printf("Out of memory\n");
                exit(1);
            }
            if (NULL == (generate_output = (uint8_t *)malloc(returned_bits_length))) {
                printf("Out of memory\n");
                exit(1);
            }
            for (i = 0; i < 2; ++i) { // generate twice and overwrite the first output with the second
                if (read_hex(f, &additional_input, "AdditionalInput = ", additional_input_length))
                    return 1;
                if (additional_input_length == 0) {
                    free(additional_input);
                    additional_input = NULL;
                }
                assert(SUCCESS == ctr_drbg_generate(&state, generate_output, returned_bits_length, additional_input, additional_input_length));
                if (additional_input_length)
                    free(additional_input);
            }

            // comapre result
            if (read_hex(f, &returned_bits, "ReturnedBits = ", returned_bits_length))
                return 1;
            if (!memcmp(generate_output, returned_bits, returned_bits_length)) {
                passed++;
                printf("Test #%d PASSED\n", count);
            } else {
                printf("Test #%d FAILED\n", count);
            }
            free(entropy_input);
            free(nonce);
            free(personalization_string);
            free(returned_bits);
            free(generate_output);
            count++;
        }
        if (done) {
            count--;
            printf("\nTests completed\n"
			"Total: %d, Passed: %d, Failed: %d", count, passed, count - passed);
            break;
        }
    }

    ctr_drbg_clear(&state);
    fclose(f);
    return 0;
}

int ctr_drbg_run_test(void)
{
	// Run 'AES-256 no df' based tests
    printf("CTR_DRBG AES-256 no df no pr\n\n");
	return run_test_vecs("test/CTR_DRBG.rsp");
}

#endif /* XR_CTR_DRBG_TESTS */
