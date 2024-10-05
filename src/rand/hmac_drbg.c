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

#include "hmac_drbg.h"

#include <string.h>

#if __has_include(<openssl/sha.h>)
    #include <openssl/evp.h>
    #include <openssl/hmac.h>
#else
    #error "OpenSSL not found"
#endif

#define HMAC_DRBG_STATE_IS_INIT(x) ((!x) ? (0) : ((x)->flags & 0x01))

/* Allocate a new HMAC_DRBG_STATE. */
HMAC_DRBG_STATE *hmac_drbg_new()
{
    HMAC_DRBG_STATE *state;

    if (!(state = malloc(sizeof(HMAC_DRBG_STATE))))
        return NULL;
    return state;
}

/* Safely clear and free the HMAC_DRBG_STATE. */
void hmac_drbg_clear(HMAC_DRBG_STATE *state)
{
    if (!state)
        return;

    /* Clear the state info to prevent leaks */
    zeroize((uint8_t *)state, sizeof(HMAC_DRBG_STATE));
    free(state);
}

/* Update HMAC_DRBG internal state (10.1.2.2) */
static int hmac_drbg_update(HMAC_DRBG_STATE *state,
                            const uint8_t *data,
                            size_t data_len)
{
    int ret = ERR_HMAC_DRBG_SUCCESS;
    uint8_t byte_val;
    uint8_t md_value[EVP_MAX_MD_SIZE];
    const EVP_MD *md = EVP_sha512();
    uint8_t *buf, *temp;
    size_t buf_len;

    /* provided_data can be Null but not Null
       with non-zero length */
    if (!data && data_len > 0)
        return ERR_HMAC_DRBG_NULL_PTR;

    if (data_len > HMAC_DRBG_MAX_INPUT_LEN)
        return ERR_HMAC_DRBG_BAD_ARGS;

    buf_len = 1 + HMAC_DRBG_SHA512_OUTLEN + data_len;
    if (!(buf = (uint8_t *)malloc(buf_len)))
        return ERR_HMAC_DRBG_MEM_FAIL;
    temp = buf;

    /* HMAC(K, V || 0x00 || provided_data) */
    memcpy(temp, state->V, HMAC_DRBG_SHA512_OUTLEN);
    temp += HMAC_DRBG_SHA512_OUTLEN;
    byte_val = 0x00;
    memcpy(temp, &byte_val, 1);
    temp += 1;
    if (data_len)
        memcpy(temp, data, data_len);
    if (!HMAC(md, state->K, HMAC_DRBG_SHA512_OUTLEN,
        buf, buf_len, md_value, NULL)) {
        ret = ERR_HMAC_DRBG_INTERNAL;
        goto cleanup;
    }
    memcpy(state->K, md_value, HMAC_DRBG_SHA512_OUTLEN);

    /* V = HMAC(K, V) */
    if (!HMAC(md, state->K, HMAC_DRBG_SHA512_OUTLEN,
        state->V, HMAC_DRBG_SHA512_OUTLEN, md_value, NULL)) {
        ret = ERR_HMAC_DRBG_INTERNAL;
        goto cleanup;
    }
    memcpy(state->V, md_value, HMAC_DRBG_SHA512_OUTLEN);

    if (data_len) {
        /* K = HMAC(K, V || 0x01 || provided_data) */
        temp = buf;
        memcpy(temp, state->V, HMAC_DRBG_SHA512_OUTLEN);
        temp += HMAC_DRBG_SHA512_OUTLEN;
        byte_val = 0x01;
        memcpy(temp, &byte_val, 1);
        temp += 1;
        memcpy(temp, data, data_len);
        if (!HMAC(md, state->K, HMAC_DRBG_SHA512_OUTLEN,
            buf, buf_len, md_value, NULL)) {
            ret = ERR_HMAC_DRBG_INTERNAL;
            goto cleanup;
        }
        memcpy(state->K, md_value, HMAC_DRBG_SHA512_OUTLEN);

        /* V = HMAC(K, V) */
        if (!HMAC(md, state->K, HMAC_DRBG_SHA512_OUTLEN,
            state->V, HMAC_DRBG_SHA512_OUTLEN, md_value, NULL)) {
            ret = ERR_HMAC_DRBG_INTERNAL;
            goto cleanup;
        }
        memcpy(state->V, md_value, HMAC_DRBG_SHA512_OUTLEN);
    }

cleanup:
    /* Destroy secrets */
    zeroize(md_value, EVP_MAX_MD_SIZE);
    zeroize(buf, buf_len);
    free(buf);
    return ret;
}

/* Instantiate the HMAC_DRBG (10.1.2.3) */
int hmac_drbg_init(HMAC_DRBG_STATE *state,
                   const uint8_t *entropy,
                   size_t entropy_len,
                   const uint8_t *nonce,
                   size_t nonce_len,
                   const uint8_t *personalization_str,
                   size_t personalization_str_len)
{
    int ret = ERR_HMAC_DRBG_SUCCESS;
    size_t seed_material_len;
    uint8_t *seed_material, *temp;

    /* Entropy can not be null */
    if (!entropy)
        return ERR_HMAC_DRBG_NULL_PTR;

    if (entropy_len < HMAC_DRBG_MIN_ENTROPY_LEN ||
        entropy_len > HMAC_DRBG_MAX_ENTROPY_LEN)
        return ERR_HMAC_DRBG_BAD_ARGS;

    /* Nonce can not be null */
    if (!nonce)
        return ERR_HMAC_DRBG_NULL_PTR;

    if (!nonce_len || nonce_len > HMAC_DRBG_MAX_NONCE_LEN)
        return ERR_HMAC_DRBG_BAD_ARGS;

    /* Personalization string can be null but not null with
       non-zero length */
    if (!personalization_str && personalization_str_len > 0)
        return ERR_HMAC_DRBG_NULL_PTR;

    if (personalization_str_len > HMAC_DRBG_MAX_PERS_STR_LEN)
        return ERR_HMAC_DRBG_BAD_ARGS;

    seed_material_len = entropy_len + nonce_len + personalization_str_len;
    if(!(seed_material = (uint8_t *)malloc(seed_material_len)))
        return ERR_HMAC_DRBG_MEM_FAIL;
    temp = seed_material;

    memcpy(temp, entropy, entropy_len);
    temp += entropy_len;
    memcpy(temp, nonce, nonce_len);
    temp += nonce_len;
    if (personalization_str_len)
        memcpy(temp, personalization_str, personalization_str_len);

    /* outlen bits */
    memset(state->K, 0x00, HMAC_DRBG_SHA512_OUTLEN);
    /* outlen bits */
    memset(state->V, 0x01, HMAC_DRBG_SHA512_OUTLEN);

    /* Update K and V */
    if (ERR_HMAC_DRBG_SUCCESS !=
        (ret = hmac_drbg_update(state, seed_material, seed_material_len)))
        goto cleanup;

    state->reseed_counter = 1;
    state->flags = 0x01; /* Set init flag */

cleanup:
    zeroize(seed_material, seed_material_len);
    free(seed_material);
    return ret;
}

/* Reseed the HMAC_DRBG (10.1.2.4) */
int hmac_drbg_reseed(HMAC_DRBG_STATE *state,
                     const uint8_t *entropy,
                     size_t entropy_len,
                     const uint8_t *additional_input,
                     size_t additional_input_len)
{
    int ret = ERR_HMAC_DRBG_SUCCESS;
    size_t seed_material_len;
    uint8_t *seed_material, *temp;

    if (!HMAC_DRBG_STATE_IS_INIT(state))
        return ERR_HMAC_DRBG_NOT_INIT;

    /* Entropy can not be null */
    if (!entropy)
        return ERR_HMAC_DRBG_NULL_PTR;

    if (entropy_len < HMAC_DRBG_MIN_ENTROPY_LEN ||
        entropy_len > HMAC_DRBG_MAX_ENTROPY_LEN)
        return ERR_HMAC_DRBG_BAD_ARGS;

    /* Additional input can be Null but not Null with
       non-zero length */
    if (!additional_input && additional_input_len > 0)
        return ERR_HMAC_DRBG_NULL_PTR;

    seed_material_len = entropy_len + additional_input_len;
    if (!(seed_material = (uint8_t *)malloc(seed_material_len)))
        return ERR_HMAC_DRBG_MEM_FAIL;
    temp = seed_material;

    memcpy(temp, entropy, entropy_len);
    temp += entropy_len;
    if (additional_input_len)
        memcpy(temp, additional_input, additional_input_len);

    if (ERR_HMAC_DRBG_SUCCESS !=
        (ret =
        hmac_drbg_update(state, seed_material, seed_material_len)))
        goto cleanup;

    state->reseed_counter = 1;

cleanup:
    zeroize(seed_material, seed_material_len);
    free(seed_material);
    return ret;
}

/* Generate pseudorandom bits (10.1.2.5) */
int hmac_drbg_generate(HMAC_DRBG_STATE *state,
                       uint8_t *output,
                       size_t output_len,
                       const uint8_t *additional_input,
                       size_t additional_input_len)
{
    int ret = ERR_HMAC_DRBG_SUCCESS;
    size_t remaining;
    uint8_t md_value[EVP_MAX_MD_SIZE];
    const EVP_MD *md = EVP_sha512();

    if (!HMAC_DRBG_STATE_IS_INIT(state))
        return ERR_HMAC_DRBG_NOT_INIT;

    if (!output && output_len > 0)
        return ERR_HMAC_DRBG_NULL_PTR;

    if (output_len > HMAC_DRBG_MAX_OUTPUT_LEN)
        return ERR_HMAC_DRBG_BAD_ARGS;

    /* Additional input can be null but not null with
       non-zero length */
    if (!additional_input && additional_input_len > 0)
        return ERR_HMAC_DRBG_NULL_PTR;

    if (additional_input_len > HMAC_DRBG_MAX_ADDN_INP_LEN)
        return ERR_HMAC_DRBG_BAD_ARGS;

    if (state->reseed_counter > HMAC_DRBG_MAX_RESEED_CNT)
        return ERR_HMAC_DRBG_DO_RESEED;

    if (additional_input_len) {
        if (ERR_HMAC_DRBG_SUCCESS !=
            (ret =
            hmac_drbg_update(state, additional_input, additional_input_len)))
            return ret;
    }

    remaining = output_len;
    /* generate (output_len / HMAC_DRBG_SHA512_OUTLEN) blocks */
    while (remaining >= HMAC_DRBG_SHA512_OUTLEN) {
        if (!HMAC(md, state->K, HMAC_DRBG_SHA512_OUTLEN,
            state->V, HMAC_DRBG_SHA512_OUTLEN, state->V, NULL)) {
            ret = ERR_HMAC_DRBG_INTERNAL;
            goto cleanup;
        }
        memcpy(output, state->V, HMAC_DRBG_SHA512_OUTLEN);
        output += HMAC_DRBG_SHA512_OUTLEN;
        remaining -= HMAC_DRBG_SHA512_OUTLEN;
    }

    /* generate (output_len % HMAC_DRBG_SHA512_OUTLEN) bits */
    if (remaining) {
        if (!HMAC(md, state->K, HMAC_DRBG_SHA512_OUTLEN,
            state->V, HMAC_DRBG_SHA512_OUTLEN, state->V, NULL)) {
            ret = ERR_HMAC_DRBG_INTERNAL;
            goto cleanup;
        }
        memcpy(output, state->V, remaining);
    }

    if (ERR_HMAC_DRBG_SUCCESS !=
        (ret =
        hmac_drbg_update(state, additional_input, additional_input_len)))
        goto cleanup;
    state->reseed_counter += 1;

cleanup:
    zeroize(md_value, EVP_MAX_MD_SIZE);
    return ret;
}

const char *hmac_drbg_err_string(int err)
{
    switch (err) {
        case ERR_HMAC_DRBG_SUCCESS:
            return "Success";
        case ERR_HMAC_DRBG_NOT_INIT:
            return "Uninstantiated state";
        case ERR_HMAC_DRBG_NULL_PTR:
            return "Null pointer input";
        case ERR_HMAC_DRBG_BAD_ARGS:
            return "Bad input arguments";
        case ERR_HMAC_DRBG_INTERNAL:
            return "Internal libary failure";
        case ERR_HMAC_DRBG_MEM_FAIL:
            return "Memory allocation failure";
        case ERR_HMAC_DRBG_DO_RESEED:
            return "Reseed required";
        default:
            return "Unknown error";
    }
}


#if defined(XR_HMAC_DRBG_TESTS)
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
	HMAC_DRBG_STATE *state;
    char buffer[2048];

    if (NULL == (state = hmac_drbg_new())) {
        printf("Out of memory\n");
        exit(1);
    }

    if (NULL == (f = fopen(filename, "r"))) {
        printf("Cant open file %s\n", filename);
        return 1;
    }

    // Skip past the [SHA-512] line
    count = 1;
    while (!feof(f)) {
        fgets(buffer, sizeof(buffer), f);
        if (!strcmp(buffer, "[SHA-512]\n"))
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
            if (!strcmp(buffer, "[SHA-512]\n")) // next set of tests
                break;
            if (!strcmp(buffer, "[SHA-512/224]\n")) { // end of 'SHA-512' based tests
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
            assert(ERR_HMAC_DRBG_SUCCESS == hmac_drbg_init(state, entropy_input, entropy_input_length, nonce, nonce_length, personalization_string, personalization_string_length));

            free(entropy_input);
            // reseed
            if (read_hex(f, &entropy_input, "EntropyInputReseed = ", entropy_input_length))
                return 1;
            if (read_hex(f, &additional_input, "AdditionalInputReseed = ", additional_input_length))
                return 1;
            assert(ERR_HMAC_DRBG_SUCCESS == hmac_drbg_reseed(state, entropy_input, entropy_input_length, additional_input, additional_input_length));

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
                assert(ERR_HMAC_DRBG_SUCCESS == hmac_drbg_generate(state, generate_output, returned_bits_length, additional_input, additional_input_length));
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
    hmac_drbg_clear(state);
    fclose(f);
    return 0;
}

int hmac_drbg_run_test(void)
{
	// Run 'SHA-512' based tests
    printf("HMAC_DRBG SHA-512 no pr\n\n");
	return run_test_vecs("test/HMAC_DRBG.rsp");
}

#endif /* XR_HMAC_DRBG_TESTS */