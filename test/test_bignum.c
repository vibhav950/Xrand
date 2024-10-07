#include "common/bignum.h"
#include "common/defs.h"
#include "rand/hmac_drbg.h"
#include "rand/rngw32.h"
#include "test.h"

#define BUFFER_SIZE 32

int test_bignum(void) {
  int ret = 0;
  BIGNUM X;
  HMAC_DRBG_STATE *state = NULL;
  byte entropy[BUFFER_SIZE];
  byte nonce[BUFFER_SIZE];

  bn_init(&X, NULL);
  GUARD(1 == RngStart());
  GUARD(NULL != (state = hmac_drbg_new()));

  GUARD(1 == RngFetchBytes(entropy, BUFFER_SIZE));
  GUARD(1 == RngFetchBytes(nonce, BUFFER_SIZE));
  GUARD(ERR_HMAC_DRBG_SUCCESS == hmac_drbg_init(state, entropy, BUFFER_SIZE,
                                                nonce, BUFFER_SIZE, NULL, 0));

  GUARD(0 == bn_self_test(hmac_drbg_generate, state, 1, NULL));

exit:
  zeroize(entropy, BUFFER_SIZE);
  zeroize(nonce, BUFFER_SIZE);
  hmac_drbg_clear(state);
  RngStop();
  bn_zfree(&X, NULL);
  return ret;
}
