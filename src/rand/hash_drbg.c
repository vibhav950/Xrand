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

#include "hash_drbg.h"

#include <string.h>

#if __has_include(<openssl/sha.h>)
#include <openssl/evp.h>
#else
#error "OpenSSL not found"
#endif

#define HASH_DRBG_STATE_IS_INIT(x) ((!x) ? (0) : ((x)->flags & 0x01))

/* V = (V + N) mod 2^seedlen represented in big-endian format */
static inline void hash_drbg_add_int(uint8_t *V, const uint8_t *N, int len) {
  uint32_t carry = 0;
  size_t i = HASH_DRBG_SEED_LEN;
  for (; i > 0 && len > 0; --i, --len) {
    carry = V[i - 1] + carry + N[len - 1];
    V[i - 1] = carry;
    carry >>= 8;
  }
  for (; i > 0; --i) {
    carry += V[i - 1];
    V[i - 1] = carry;
    carry >>= 8;
  }
}

/* The hash-based derivation function (10.3.1). */
static int hash_drbg_df(const uint8_t *input, size_t input_len, uint8_t *output,
                        size_t output_len) {
  int ret = ERR_HASH_DRBG_SUCCESS;
  int i, remaining;
  uint32_t output_len_bits;
  uint8_t counter;
  uint8_t output_len_bits_str[4];
  uint8_t md_value[EVP_MAX_MD_SIZE];
  EVP_MD_CTX *md_ctx;
  const EVP_MD *md = EVP_sha512();

  if (!input && input_len > 0) {
    ret = ERR_HASH_DRBG_NULL_PTR;
    goto cleanup;
  }

  if (!output && output_len > 0) {
    ret = ERR_HASH_DRBG_NULL_PTR;
    goto cleanup;
  }

  if (output_len > 255 * HASH_DBRG_SHA512_OUTLEN) {
    ret = ERR_HASH_DRBG_BAD_ARGS;
    goto cleanup;
  }

  if (!(md_ctx = EVP_MD_CTX_new())) {
    ret = ERR_HASH_DRBG_INTERNAL;
    goto cleanup;
  }

  output_len_bits = output_len << 3;
  /* output_len_bits as a big-endian 32-bit string */
  output_len_bits_str[0] = (uint8_t)((output_len_bits >> 24) & 0xff);
  output_len_bits_str[1] = (uint8_t)((output_len_bits >> 16) & 0xff);
  output_len_bits_str[2] = (uint8_t)((output_len_bits >> 8) & 0xff);
  output_len_bits_str[3] = (uint8_t)(output_len_bits & 0xff);

  i = 0;
  counter = 0x01;
  /* This is a safe cast since at this point we have
     output_len <= 255 * HASH_DBRG_SHA512_OUTLEN. */
  remaining = (int)output_len;
  for (;;) {
    EVP_DigestInit_ex(md_ctx, md, NULL);
    EVP_DigestUpdate(md_ctx, &counter, sizeof(counter));
    EVP_DigestUpdate(md_ctx, output_len_bits_str, sizeof(output_len_bits_str));
    EVP_DigestUpdate(md_ctx, input, input_len);
    /* Hash(counter || no_of_bits_to_return || input_string) */
    EVP_DigestFinal_ex(md_ctx, md_value, NULL);

    if (remaining < HASH_DBRG_SHA512_OUTLEN) {
      memcpy(output + i, md_value, remaining);
      break;
    }
    memcpy(output + i, md_value, HASH_DBRG_SHA512_OUTLEN);

    counter++;
    remaining -= HASH_DBRG_SHA512_OUTLEN;
    i += HASH_DBRG_SHA512_OUTLEN;
  }

  EVP_MD_CTX_free(md_ctx);

cleanup:
  zeroize(md_value, EVP_MAX_MD_SIZE);
  return ret;
}

/* Allocate a new HASH_DRBG_STATE. */
HASH_DRBG_STATE *hash_drbg_new() {
  HASH_DRBG_STATE *state;

  if (!(state = malloc(sizeof(HASH_DRBG_STATE))))
    return NULL;
  return state;
}

/* Safely clear and free the HASH_DRBG_STATE. */
void hash_drbg_clear(HASH_DRBG_STATE *state) {
  if (!state)
    return;

  /* Clear the state info to prevent leaks */
  zeroize((uint8_t *)state, sizeof(HASH_DRBG_STATE));
  free(state);
}

/* Instantiate the HASH_DRBG state (10.1.1.2). */
int hash_drbg_init(HASH_DRBG_STATE *state, const uint8_t *entropy,
                   size_t entropy_len, const uint8_t *nonce, size_t nonce_len,
                   const uint8_t *personalization_str,
                   size_t personalization_str_len) {
  int ret = ERR_HASH_DRBG_SUCCESS;
  int seed_material_len;
  uint8_t *seed_material, *temp, *buf;

  /* Entropy can not be null */
  if (!entropy) {
    ret = ERR_HASH_DRBG_NULL_PTR;
    goto cleanup;
  }

  if (entropy_len < HASH_DRBG_MIN_ENTROPY_LEN ||
      entropy_len > HASH_DRBG_MAX_ENTROPY_LEN) {
    ret = ERR_HASH_DRBG_BAD_ARGS;
    goto cleanup;
  }

  /* Nonce can not be null */
  if (!nonce) {
    ret = ERR_HASH_DRBG_NULL_PTR;
    goto cleanup;
  }

  if (!nonce_len || nonce_len > HASH_DRBG_MAX_NONCE_LEN) {
    ret = ERR_HASH_DRBG_BAD_ARGS;
    goto cleanup;
  }

  /* Personalization string can be null but not null with
     non-zero length */
  if (!personalization_str && personalization_str_len > 0) {
    ret = ERR_HASH_DRBG_NULL_PTR;
    goto cleanup;
  }

  if (personalization_str_len > HASH_DRBG_MAX_PERS_STR_LEN) {
    ret = ERR_HASH_DRBG_BAD_ARGS;
    goto cleanup;
  }

  seed_material_len = (int)(entropy_len + nonce_len + personalization_str_len);
  if (!(seed_material = (uint8_t *)malloc(seed_material_len))) {
    ret = ERR_HASH_DRBG_MEM_FAIL;
    goto cleanup;
  }
  temp = seed_material;

  memcpy(temp, entropy, entropy_len);
  temp += entropy_len;
  mempcpy(temp, nonce, nonce_len);
  temp += nonce_len;
  if (personalization_str_len)
    memcpy(temp, personalization_str, personalization_str_len);

  if ((ret = hash_drbg_df(seed_material, seed_material_len, state->V,
                          HASH_DRBG_SEED_LEN))) {
    zeroize(seed_material, seed_material_len);
    free(seed_material);
    goto cleanup;
  }
  zeroize(seed_material, seed_material_len);
  free(seed_material);

  if (!(buf = (uint8_t *)malloc(1 + HASH_DRBG_SEED_LEN))) {
    ret = ERR_HASH_DRBG_MEM_FAIL;
    goto cleanup;
  }
  temp = buf;
  /* Precede V with a byte of zeros */
  temp[0] = 0x00;
  temp++;
  memcpy(temp, state->V, HASH_DRBG_SEED_LEN);

  if ((ret = hash_drbg_df(buf, (1 + HASH_DRBG_SEED_LEN), state->C,
                          HASH_DRBG_SEED_LEN))) {
    zeroize(buf, 1 + HASH_DRBG_SEED_LEN);
    free(buf);
    goto cleanup;
  }
  zeroize(buf, 1 + HASH_DRBG_SEED_LEN);
  free(buf);

  state->reseed_counter = 1;
  state->flags = 0x01; /* Set init flag */

cleanup:
  return ret;
}

/* Reseed the HASH_DRBG state (10.1.1.3). */
int hash_drbg_reseed(HASH_DRBG_STATE *state, const uint8_t *entropy,
                     size_t entropy_len, const uint8_t *additional_input,
                     size_t additional_input_len) {
  int ret = ERR_HASH_DRBG_SUCCESS;
  int seed_material_len;
  uint8_t *seed_material, *temp, *buf;

  if (!HASH_DRBG_STATE_IS_INIT(state)) {
    ret = ERR_HASH_DRBG_NOT_INIT;
    goto cleanup;
  }

  /* Entropy can not be null */
  if (!entropy) {
    ret = ERR_HASH_DRBG_NULL_PTR;
    goto cleanup;
  }

  if (entropy_len < HASH_DRBG_MIN_ENTROPY_LEN ||
      entropy_len > HASH_DRBG_MAX_ENTROPY_LEN) {
    ret = ERR_HASH_DRBG_BAD_ARGS;
    goto cleanup;
  }

  /* Additional input can be null but not null with
     non-zero length */
  if (!additional_input && additional_input_len > 0) {
    ret = ERR_HASH_DRBG_NULL_PTR;
    goto cleanup;
  }

  if (additional_input_len > HASH_DRBG_MAX_ADDN_INP_LEN) {
    ret = ERR_HASH_DRBG_BAD_ARGS;
    goto cleanup;
  }

  seed_material_len =
      (int)(1 + HASH_DRBG_SEED_LEN + entropy_len + additional_input_len);
  if (!(seed_material = (uint8_t *)malloc(seed_material_len))) {
    ret = ERR_HASH_DRBG_MEM_FAIL;
    goto cleanup;
  }
  temp = seed_material;

  temp[0] = 0x01;
  temp++;
  memcpy(temp, state->V, HASH_DRBG_SEED_LEN);
  temp += HASH_DRBG_SEED_LEN;
  memcpy(temp, entropy, entropy_len);
  temp += entropy_len;
  if (additional_input_len)
    memcpy(temp, additional_input, additional_input_len);

  if ((ret = hash_drbg_df(seed_material, seed_material_len, state->V,
                          HASH_DRBG_SEED_LEN))) {
    zeroize(seed_material, seed_material_len);
    free(seed_material);
    goto cleanup;
  }
  zeroize(seed_material, seed_material_len);
  free(seed_material);

  if (!(buf = (uint8_t *)malloc(1 + HASH_DRBG_SEED_LEN)))
    return FAILURE;
  temp = buf;
  /* Precede V with a byte of zeros */
  temp[0] = 0x00;
  temp++;
  memcpy(temp, state->V, HASH_DRBG_SEED_LEN);

  if ((ret = hash_drbg_df(buf, (1 + HASH_DRBG_SEED_LEN), state->C,
                          HASH_DRBG_SEED_LEN))) {
    zeroize(buf, 1 + HASH_DRBG_SEED_LEN);
    free(buf);
    goto cleanup;
  }
  zeroize(buf, 1 + HASH_DRBG_SEED_LEN);
  free(buf);

  state->reseed_counter = 1;

cleanup:
  return ret;
}

static int hash_drbg_hashgen(HASH_DRBG_STATE *state, uint8_t *output,
                             size_t output_len) {
  int ret = ERR_HASH_DRBG_SUCCESS;
  int i, remaining;
  const uint8_t one = 1;
  uint8_t data[HASH_DRBG_SEED_LEN];
  uint8_t md_value[EVP_MAX_MD_SIZE];
  EVP_MD_CTX *md_ctx;
  const EVP_MD *md = EVP_sha512();

  if (!HASH_DRBG_STATE_IS_INIT(state)) {
    ret = ERR_HASH_DRBG_NOT_INIT;
    goto cleanup;
  }

  if (!output && output_len > 0) {
    ret = ERR_HASH_DRBG_NULL_PTR;
    goto cleanup;
  }

  if (!(md_ctx = EVP_MD_CTX_new())) {
    ret = ERR_HASH_DRBG_INTERNAL;
    goto cleanup;
  }

  i = 0;
  memcpy(data, state->V, HASH_DRBG_SEED_LEN);
  remaining = (int)output_len;
  for (;;) {
    EVP_DigestInit_ex(md_ctx, md, NULL);
    EVP_DigestUpdate(md_ctx, data, HASH_DRBG_SEED_LEN);
    EVP_DigestFinal_ex(md_ctx, md_value, NULL);

    if (remaining < HASH_DBRG_SHA512_OUTLEN) {
      memcpy(output + i, md_value, remaining);
      break;
    }
    memcpy(output + i, md_value, HASH_DBRG_SHA512_OUTLEN);

    remaining -= HASH_DBRG_SHA512_OUTLEN;
    i += HASH_DBRG_SHA512_OUTLEN;

    /* data = (data + 1) mod 2^seedlen */
    hash_drbg_add_int(data, &one, sizeof(one));
  }

  EVP_MD_CTX_free(md_ctx);

cleanup:
  zeroize(data, HASH_DRBG_SEED_LEN);
  zeroize(md_value, EVP_MAX_MD_SIZE);
  return ret;
}

/* Generate pseudorandom bits from the HASH_DRBG (10.1.1.4). */
int hash_drbg_generate(HASH_DRBG_STATE *state, uint8_t *output,
                       size_t output_len, const uint8_t *additional_input,
                       size_t additional_input_len) {
  int ret = ERR_HASH_DRBG_SUCCESS;
  uint8_t prefix_byte;
  uint8_t reseed_ctr[8];
  uint8_t md_value[EVP_MAX_MD_SIZE];
  EVP_MD_CTX *md_ctx;
  const EVP_MD *md = EVP_sha512();

  if (!HASH_DRBG_STATE_IS_INIT(state)) {
    ret = ERR_HASH_DRBG_NOT_INIT;
    goto cleanup;
  }

  /* Why even bother then? */
  if (!output && output_len > 0) {
    ret = ERR_HASH_DRBG_NULL_PTR;
    goto cleanup;
  }

  if (output_len > HASH_DRBG_MAX_OUT_LEN) {
    ret = ERR_HASH_DRBG_BAD_ARGS;
    goto cleanup;
  }

  /* Additional input can be null but not null with
     non-zero length */
  if (!additional_input && additional_input_len > 0) {
    ret = ERR_HASH_DRBG_NULL_PTR;
    goto cleanup;
  }

  if (additional_input_len > HASH_DRBG_MAX_ADDN_INP_LEN) {
    ret = ERR_HASH_DRBG_BAD_ARGS;
    goto cleanup;
  }

  if (state->reseed_counter > HASH_DRBG_MAX_RESEED_CNT) {
    ret = ERR_HASH_DRBG_DO_RESEED;
    goto cleanup;
  }

  if (!(md_ctx = EVP_MD_CTX_new())) {
    ret = ERR_HASH_DRBG_INTERNAL;
    goto cleanup;
  }

  if (additional_input_len) {
    prefix_byte = 0x02;
    EVP_DigestInit_ex(md_ctx, md, NULL);
    EVP_DigestUpdate(md_ctx, &prefix_byte, sizeof(prefix_byte));
    EVP_DigestUpdate(md_ctx, state->V, HASH_DRBG_SEED_LEN);
    EVP_DigestUpdate(md_ctx, additional_input, additional_input_len);
    /* w = Hash(0x02 || V || additional_input) */
    EVP_DigestFinal_ex(md_ctx, md_value, NULL);
    /* V = (V + w) mod 2^seedlen */
    hash_drbg_add_int(state->V, md_value, HASH_DBRG_SHA512_OUTLEN);
  }

  hash_drbg_hashgen(state, output, output_len);

  prefix_byte = 0x03;
  EVP_DigestInit_ex(md_ctx, md, NULL);
  EVP_DigestUpdate(md_ctx, &prefix_byte, sizeof(prefix_byte));
  EVP_DigestUpdate(md_ctx, state->V, HASH_DRBG_SEED_LEN);
  /* H = Hash(0x03 || V) */
  EVP_DigestFinal(md_ctx, md_value, NULL);

  reseed_ctr[0] = (uint8_t)((state->reseed_counter >> 56) & 0xff);
  reseed_ctr[1] = (uint8_t)((state->reseed_counter >> 48) & 0xff);
  reseed_ctr[2] = (uint8_t)((state->reseed_counter >> 40) & 0xff);
  reseed_ctr[3] = (uint8_t)((state->reseed_counter >> 32) & 0xff);
  reseed_ctr[4] = (uint8_t)((state->reseed_counter >> 24) & 0xff);
  reseed_ctr[5] = (uint8_t)((state->reseed_counter >> 16) & 0xff);
  reseed_ctr[6] = (uint8_t)((state->reseed_counter >> 8) & 0xff);
  reseed_ctr[7] = (uint8_t)(state->reseed_counter & 0xff);

  /* V = (V + H + C + reseed_counter) mod 2^seedlen */
  hash_drbg_add_int(state->V, md_value, HASH_DBRG_SHA512_OUTLEN);
  hash_drbg_add_int(state->V, state->C, HASH_DRBG_SEED_LEN);
  hash_drbg_add_int(state->V, reseed_ctr, sizeof(reseed_ctr));
  state->reseed_counter += 1;

  EVP_MD_CTX_free(md_ctx);

cleanup:
  zeroize(reseed_ctr, 8);
  zeroize(md_value, EVP_MAX_MD_SIZE);
  return ret;
}

#if defined(XR_TESTS_HASH_DRBG)
#include <assert.h>
#include <ctype.h>
#include <stdio.h>


static inline void skip_spaces(FILE *f) {
  int ch;

  while ((ch = fgetc(f)) != EOF && isspace(ch))
    ;
  if (ch != EOF)
    ungetc(ch, f);
}

static int read_hex(FILE *f, uint8_t **val, const char *prefix,
                    const unsigned int len) {
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

static int read_uint(FILE *f, unsigned int *val, const char *format,
                     const char *name) {
  skip_spaces(f);
  if (!fscanf(f, format, val)) {
    printf("Cant read \"%s\"\n", name);
    return 1;
  }
  return 0;
}

static int run_test_vecs(const char *filename) {
  int rv;
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
  HASH_DRBG_STATE *state;
  char buffer[1024];

  if (NULL == (state = hash_drbg_new())) {
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
  passed = 0;
  while (!feof(f)) {
    fgets(buffer, sizeof(buffer), f);
    if (!strcmp(buffer, "[PredictionResistance = False]")) {
      printf("Error in parsing; the test vectors must be extracted from "
             "drbgvectors_pr_false.zip\n");
      rv = 1;
      goto clean0;
    }

    // read length params and convert to bytes
    if (read_uint(f, &entropy_input_length, "[EntropyInputLen = %u]",
                  "EntropyInputLen")) {
      rv = 1;
      goto clean0;
    }
    entropy_input_length >>= 3;
    if (read_uint(f, &nonce_length, "[NonceLen = %u]", "NonceLen")) {
      rv = 1;
      goto clean0;
    }
    nonce_length >>= 3;
    if (read_uint(f, &personalization_string_length,
                  "[PersonalizationStringLen = %u]",
                  "PersonalizationStringLen")) {
      rv = 1;
      goto clean0;
    }
    personalization_string_length >>= 3;
    if (read_uint(f, &additional_input_length, "[AdditionalInputLen = %u]",
                  "AdditionalInputLen")) {
      rv = 1;
      goto clean0;
    }
    additional_input_length >>= 3;
    if (read_uint(f, &returned_bits_length, "[ReturnedBitsLen = %u]",
                  "ReturnedBitsLen")) {
      rv = 1;
      goto clean0;
    }
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
      if (read_hex(f, &entropy_input,
                   "EntropyInput = ", entropy_input_length)) {
        rv = 1;
        goto clean0;
      }
      if (read_hex(f, &nonce, "Nonce = ", nonce_length)) {
        rv = 1;
        goto clean1;
      }
      if (read_hex(f, &personalization_string,
                   "PersonalizationString = ", personalization_string_length)) {
        rv = 1;
        goto clean2;
      }
      assert(ERR_HASH_DRBG_SUCCESS ==
             hash_drbg_init(state, entropy_input, entropy_input_length, nonce,
                            nonce_length, personalization_string,
                            personalization_string_length));

      free(entropy_input);
      entropy_input = NULL;
      // reseed
      if (read_hex(f, &entropy_input,
                   "EntropyInputReseed = ", entropy_input_length)) {
        rv = 1;
        goto clean3;
      }
      if (read_hex(f, &additional_input,
                   "AdditionalInputReseed = ", additional_input_length)) {
        rv = 1;
        goto clean3;
      }
      assert(ERR_HASH_DRBG_SUCCESS ==
             hash_drbg_reseed(state, entropy_input, entropy_input_length,
                              additional_input, additional_input_length));

      // generate
      if (NULL == (generate_output = (uint8_t *)malloc(returned_bits_length))) {
        printf("Out of memory\n");
        exit(1);
      }
      for (i = 0; i < 2; ++i) { // generate twice and overwrite the first output
                                // with the second
        if (read_hex(f, &additional_input,
                     "AdditionalInput = ", additional_input_length)) {
          rv = 1;
          goto clean4;
        }
        if (additional_input_length == 0) {
          free(additional_input);
          additional_input = NULL;
        }
        assert(ERR_HASH_DRBG_SUCCESS ==
               hash_drbg_generate(state, generate_output, returned_bits_length,
                                  additional_input, additional_input_length));
        free(additional_input);
        additional_input = NULL;
      }

      // comapre result
      if (read_hex(f, &returned_bits,
                   "ReturnedBits = ", returned_bits_length)) {
        rv = 1;
        goto clean4;
      }
      if (!memcmp(generate_output, returned_bits, returned_bits_length)) {
        passed++;
        printf("Test #%-3d \x1B[92mPASS\x1B[0m\n", count);
      } else {
        printf("Test #%-3d \x1B[91mFAIL\x1B[0m\n", count);
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
      printf("Total: %d, Passed: %d, Failed: %d\n", count, passed,
             count - passed);
      break;
    }
  }
  rv = 0;
  goto clean0;

clean4:
  free(generate_output);
  free(additional_input);
clean3:
  free(personalization_string);
clean2:
  free(nonce);
clean1:
  free(entropy_input);
clean0:
  hash_drbg_clear(state);
  fclose(f);
  return rv;
}

int hash_drbg_run_test(void) {
  // Run 'SHA-512' based tests
  printf("Hash_DRBG SHA-512 no pr\n");
  return run_test_vecs("test/Hash_DRBG.rsp");
}

#endif /* XR_TESTS_HASH_DRBG */
