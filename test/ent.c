/**
 * ent.c
 *
 * Generate an output stream for the 'ent' statistical
 * test suite (see https://www.fourmilab.ch/random/).
 *
 * Written by Vibhav Tiwari for Xrand.
 */

#include "common/defs.h"
#include "rand/rngw32.h"
#include "rand/hash_drbg.h"

#include <stdio.h>

#define ENTROPY_IN_LEN 256
#define NONCE_IN_LEN 256

int main()
{
    int done, rv;
    FILE *fp = fopen("out.bin", "w");
    HASH_DRBG_STATE *ctx;
    byte entropy[ENTROPY_IN_LEN];
    byte nonce[NONCE_IN_LEN];
    byte rand[HASH_DRBG_MAX_OUT_LEN];

    ASSERT(NULL != fp);
    ASSERT(1 == RngStart());
    RngEnableUserEvents();
    ASSERT(NULL != (ctx = hash_drbg_new()));

    ASSERT(1 == RngFetchBytes(entropy, ENTROPY_IN_LEN));
    ASSERT(1 == RngFetchBytes(nonce, NONCE_IN_LEN));
    ASSERT(ERR_HASH_DRBG_SUCCESS == hash_drbg_init(ctx, entropy, ENTROPY_IN_LEN, nonce, NONCE_IN_LEN, NULL, 0));

    done = 0;
    for (;;) {
        if (done >= (1 << 30))
            break;

        if (ERR_HASH_DRBG_SUCCESS != (rv = hash_drbg_generate(ctx, rand, HASH_DRBG_MAX_OUT_LEN, NULL, 0))) {
            if (rv == ERR_HASH_DRBG_DO_RESEED) {
                ASSERT(1 == RngFetchBytes(entropy, ENTROPY_IN_LEN));
                ASSERT(ERR_HASH_DRBG_SUCCESS == hash_drbg_reseed(ctx, entropy, ENTROPY_IN_LEN, NULL, 0));
            } else {
                exit(1);
            }
            ASSERT(ERR_HASH_DRBG_SUCCESS == hash_drbg_generate(ctx, rand, HASH_DRBG_MAX_OUT_LEN, NULL, 0));
        }

        fwrite(rand, sizeof(byte), HASH_DRBG_MAX_OUT_LEN, fp);
        done += HASH_DRBG_MAX_OUT_LEN;
    }

    hash_drbg_clear(ctx);
    RngStop();
    fclose(fp);

    return 0;
}
