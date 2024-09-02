#include "hash_drbg.h"

#include <string.h>

#if __has_include(<openssl/sha.h>)
    #include <openssl/evp.h>
#else
    #error "OpenSSL not found"
#endif

#define HASH_DRBG_STATE_IS_INIT(x) ((!x) ? (0) : ((x)->flags & 0x01))

/* V = (V + N) mod 2^seedlen represented in big-endian format */
static inline int hash_drbg_add_int(uint8_t *V,
                                    const uint8_t *N,
                                    int len)
{
    int ret = ERR_HASH_DRBG_SUCCESS;
    int i, j;
    uint8_t t, carry = 0;

    if (!V || !N) {
        ret = ERR_HASH_DRBG_NULL_PTR;
        goto cleanup;
    }

    if (!(len > 0)) {
        ret = ERR_HASH_DRBG_BAD_ARGS;
        goto cleanup;
    }

    for (i = HASH_DRBG_SEED_LEN - 1, j = len - 1; i >= 0; i--, j--) {
        if (j >= 0) {
            t = V[i] + N[j] + carry;
            carry = (t < V[i]) | (t < N[j]);
        } else {
            t = V[i] + carry;
            carry = (t < V[i]);
        }
        V[i] = t;
    }

cleanup:
    return ret;
}

/* The hash-based derivation function (10.3.1). */
static int hash_drbg_df(const uint8_t *input, size_t input_len,
                        uint8_t *output, size_t output_len)
{
    status_t ret = ERR_HASH_DRBG_SUCCESS;
    int i, remaining;
    int output_len_bits;
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
    output_len_bits_str[0] = (uint8_t)(output_len_bits >> 24);
    output_len_bits_str[1] = (uint8_t)(output_len_bits >> 16);
    output_len_bits_str[2] = (uint8_t)(output_len_bits >> 8);
    output_len_bits_str[3] = (uint8_t)output_len_bits;

    i = 0;
    counter = 0x01;
    /* This is a safe cast since at this point we have
       output_len <= 255 * HASH_DBRG_SHA512_OUTLEN. */
    remaining = (int)output_len;
    for (;;) {
        EVP_DigestInit_ex(md_ctx, md, NULL);
        EVP_DigestUpdate(md_ctx, &counter, sizeof(counter));
        EVP_DigestUpdate(md_ctx, output_len_bits_str,
                         sizeof(output_len_bits_str));
        EVP_DigestUpdate(md_ctx, input, input_len);
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
    return ret;
}

/* Allocate a new HASH_DRBG_STATE. */
HASH_DRBG_STATE *hash_drbg_new()
{
    HASH_DRBG_STATE *state;

    if (!(state = malloc(sizeof(HASH_DRBG_STATE))))
        return NULL;

    state->flags = 0x01;
    return state;
}

/* Safely clear and free the HASH_DRBG_STATE. */
void hash_drbg_clear(HASH_DRBG_STATE *state)
{
    if (!state)
        return;

    /* Clear the state info to prevent leaks */
    zeroize((uint8_t *)state, sizeof(HASH_DRBG_STATE));

    free(state);
}

/* Instantiate the HASH_DRBG state (10.1.1.2). */
int hash_drbg_init(HASH_DRBG_STATE *state,
                   const uint8_t *entropy,
                   size_t entropy_len,
                   const uint8_t *nonce,
                   size_t nonce_len,
                   const uint8_t *personalization_str,
                   size_t personalization_str_len)
{
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

    seed_material_len = (int)(entropy_len + nonce_len +
                              personalization_str_len);
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

    if (!(ret = hash_drbg_df(seed_material, seed_material_len,
                             state->V, HASH_DRBG_SEED_LEN))) {
        free(seed_material);
        goto cleanup;
    }
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

    if (!(ret = hash_drbg_df(buf, (1 + HASH_DRBG_SEED_LEN),
                             state->C, HASH_DRBG_SEED_LEN))) {
        free(buf);
        goto cleanup;
    }
    free(buf);

    state->reseed_counter = 1;

cleanup:
    return ret;
}

/* Reseed the HASH_DRBG state (10.1.1.3). */
int hash_drbg_reseed(HASH_DRBG_STATE *state,
                     const uint8_t *entropy,
                     size_t entropy_len,
                     const uint8_t *additional_input,
                     size_t additional_input_len)
{
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

    seed_material_len = (int)(1 + HASH_DRBG_SEED_LEN +
                              entropy_len +
                              additional_input_len);
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

    if (!(ret = hash_drbg_df(seed_material, seed_material_len,
                             state->V, HASH_DRBG_SEED_LEN))) {
        free(seed_material);
        goto cleanup;
    }
    free(seed_material);

    if (!(buf = (uint8_t *)malloc(1 + HASH_DRBG_SEED_LEN)))
        return FAILURE;
    temp = buf;
    /* Precede V with a byte of zeros */
    temp[0] = 0x00;
    temp++;
    memcpy(temp, state->V, HASH_DRBG_SEED_LEN);

    if (!(ret = hash_drbg_df(buf, (1 + HASH_DRBG_SEED_LEN),
                             state->C, HASH_DRBG_SEED_LEN))) {
        free(buf);
        goto cleanup;
    }
    free(buf);

    state->reseed_counter = 1;

cleanup:
    return ret;
}

static int hash_drbg_hashgen(HASH_DRBG_STATE *state,
                             uint8_t *output,
                             size_t output_len)
{
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
        if (!(ret = hash_drbg_add_int(data, &one, sizeof(one))))
            goto cleanup;
    }

cleanup:
    return ret;
}

/* Generate pseudorandom bits from the HASH_DRBG (10.1.1.4). */
int hash_drbg_generate(HASH_DRBG_STATE *state,
                       uint8_t *output,
                       size_t output_len,
                       const uint8_t *additional_input,
                       size_t additional_input_len)
{
    int ret = ERR_HASH_DRBG_SUCCESS;
    uint8_t prefix_byte;
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

    if (additional_input) {
        prefix_byte = 0x02;
        EVP_DigestInit_ex(md_ctx, md, NULL);
        EVP_DigestUpdate(md_ctx, &prefix_byte, sizeof(prefix_byte));
        EVP_DigestUpdate(md_ctx, state->V, HASH_DRBG_SEED_LEN);
        EVP_DigestUpdate(md_ctx, additional_input, additional_input_len);
        EVP_DigestFinal_ex(md_ctx, md_value, NULL);
        /* V = (V + w) mod 2^seedlen */
        hash_drbg_add_int(state->V, md_value, HASH_DBRG_SHA512_OUTLEN);
    }

    hash_drbg_hashgen(state, output, output_len);

    prefix_byte = 0x03;
    EVP_DigestInit_ex(md_ctx, md, NULL);
    EVP_DigestUpdate(md_ctx, &prefix_byte, sizeof(prefix_byte));
    EVP_DigestUpdate(md_ctx, state->V, HASH_DRBG_SEED_LEN);
    EVP_DigestFinal(md_ctx, md_value, NULL);

    /* V = (V + H + C + reseed_counter) mod 2^seedlen */
    hash_drbg_add_int(state->V, md_value, HASH_DBRG_SHA512_OUTLEN);
    hash_drbg_add_int(state->V, state->C, HASH_DRBG_SEED_LEN);
    hash_drbg_add_int(state->V, (uint8_t *)&(state->reseed_counter),
                      sizeof(state->reseed_counter));
    (state->reseed_counter)++;

cleanup:
    return ret;
}

#if defined(HASH_DRBG_TESTS)
// TODO: Write tests
#endif /* HASH_DRBG_TESTS */