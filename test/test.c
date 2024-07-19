#include "common/bignum.h"
#include "rand/ctr_drbg.h"
#include "rand/rngw32.h"

int main() {
    BIGNUM X;

    bn_init(&X, NULL);

    assert(1 == RngStart());
    
    CTR_DRBG_STATE rng;
    byte entropy[CTR_DRBG_ENTROPY_LEN];

    assert(1 == RngFetchBytes(entropy, CTR_DRBG_ENTROPY_LEN));
    assert(SUCCESS == ctr_drbg_init(&rng, entropy, NULL, 0));
    zeroize(entropy, CTR_DRBG_ENTROPY_LEN);

    assert(0 == bn_self_test(&rng, 1, NULL));

    ctr_drbg_clear(&rng);
    RngStop();

    bn_zfree(&X, NULL);

    return 0;
}