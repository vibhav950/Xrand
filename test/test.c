#include "common/bignum.h"
#include "common/defs.h"
#include "rand/hmac_drbg.h"
#include "rand/rngw32.h"

#define BUFFER_SIZE 32

int main()
{
    BIGNUM X;
    HMAC_DRBG_STATE *state;
    byte entropy[BUFFER_SIZE];
    byte nonce[BUFFER_SIZE];

    bn_init(&X, NULL);
    ASSERT(1 == RngStart());
    ASSERT(NULL != (state = hmac_drbg_new()));

    ASSERT(1 == RngFetchBytes(entropy, BUFFER_SIZE));
    ASSERT(1 == RngFetchBytes(nonce, BUFFER_SIZE));
    ASSERT(ERR_HMAC_DRBG_SUCCESS ==
           hmac_drbg_init(state, entropy, BUFFER_SIZE, nonce, BUFFER_SIZE, NULL, 0));
    zeroize(entropy, BUFFER_SIZE);
    zeroize(nonce, BUFFER_SIZE);

    ASSERT(0 == bn_self_test(hmac_drbg_generate, state, 1, NULL));

    hmac_drbg_clear(state);
    RngStop();
    bn_zfree(&X, NULL);
    return 0;
}
