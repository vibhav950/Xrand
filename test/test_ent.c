#include "common/defs.h"
#include "rand/hash_drbg.h"
#include "rand/rngw32.h"
#include "test.h"

#include <stdio.h>

#define ENTROPY_IN_LEN 256
#define NONCE_IN_LEN 256

int test_ent(const char *filename, size_t nb) {
  int ret = 0, rv;
  FILE *fp = NULL;
  size_t done;
  HASH_DRBG_STATE *ctx = NULL;
  byte entropy[ENTROPY_IN_LEN];
  byte nonce[NONCE_IN_LEN];
  byte rand[HASH_DRBG_MAX_OUT_LEN];

  GUARD(NULL != (fp = fopen(filename, "r")));
  GUARD(NULL != (ctx = hash_drbg_new()));
  GUARD(1 == RngStart());

  GUARD(1 == RngFetchBytes(entropy, ENTROPY_IN_LEN));
  GUARD(1 == RngFetchBytes(nonce, NONCE_IN_LEN));
  GUARD(ERR_HASH_DRBG_SUCCESS == hash_drbg_init(ctx, entropy, ENTROPY_IN_LEN,
                                                nonce, NONCE_IN_LEN, NULL, 0));

  done = 0;
  for (;;) {
    if (done >= nb)
      break;
    if (ERR_HASH_DRBG_SUCCESS !=
        (rv = hash_drbg_generate(ctx, rand, HASH_DRBG_MAX_OUT_LEN, NULL, 0))) {
      if (rv == ERR_HASH_DRBG_DO_RESEED) {
        GUARD(1 == RngFetchBytes(entropy, ENTROPY_IN_LEN));
        GUARD(ERR_HASH_DRBG_SUCCESS ==
              hash_drbg_reseed(ctx, entropy, ENTROPY_IN_LEN, NULL, 0));
      } else {
        ret = 1;
        goto exit;
      }
      GUARD(ERR_HASH_DRBG_SUCCESS ==
            hash_drbg_generate(ctx, rand, HASH_DRBG_MAX_OUT_LEN, NULL, 0));
    }

    fwrite(rand, sizeof(byte), HASH_DRBG_MAX_OUT_LEN, fp);
    done += HASH_DRBG_MAX_OUT_LEN;
  }

exit:
  RngStop();
  hash_drbg_clear(ctx);
  fclose(fp);
  return ret;
}
