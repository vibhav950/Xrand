#include "prime.h"
#include "common/bn.h"
#include "common/defs.h"
#include "rand/ctr_drbg.h"
#include "rand/rngw32.h"



/* Calculate the number of trial divisions that should be performed in
   combination with the Miller-Rabin test, depending on the bit size */
static int num_trial_divisions(int nbits)
{
    if (nbits <= 512)
        return 128;
    else if (nbits <= 1024)
        return 256;
    else if (nbits <= 2048)
        return 512;
    return N_PRIMES;
}

/* Miller-Rabin probabilistic primality test [FIPS 186-5 B.3.1] 
   Returns 0 if the number is COMPOSITE, 1 if it is PROBABLY_PRIME */
int bn_check_probable_prime(BIGNUM *w, int iter, void *rng)
{
    BIGNUM wminus1, m, b;
    int a = 0, i, j;
    int wlen = bignum_msb(w);

    /* Number too small */
    if (wlen < 32)
        return -1;

    if (!bignum_is_odd(w))
        return 0;
    
    bignum_init(&b);
    bignum_sub_int(w, &wminus1, 1);
    bignum_assign(&m, &wminus1);

    /* Find the largest 'a' such that 2^a divides w-1 */
    while (bignum_is_even(&m)) {
        a++;
        bignum_rshift(&m, &m, 1);
    }

    for (i = 0; i < iter; ++i) {
        /* Pick a random 'b' such that len(b) == wlen and 1 < b < w-1 */
        do {
            if (ctr_drbg_generate(rng, Ptr8((&b)->array), ceil_div(wlen, 8), NULL, 0) == FAILURE)
                return -1;

            int blen = bignum_msb(&b);

            if (wlen > blen)
                bignum_lshift(&b, &b, wlen - blen);
            else if (blen > wlen)
                bignum_rshift(&b, &b, blen - wlen);

            (&b)->array[0] |= 2;
        } while (bignum_cmp(&b, &wminus1) >= 0);

        /* b = b^m (mod w) */
        bignum_exp_mod(&b, &m, w, &b);

        if (bignum_cmp_int(&b, 1) == 0 || bignum_cmp(&b, &wminus1) == 0)
			continue;
        
        for (j = 1; j <= a - 1; ++j) {
            /* b = b^2 (mod w) */
            bignum_sqr(&b);
            bignum_mod(&b, w, &b);

            /* Composite if b == 1 */
            if (bignum_cmp_int(&b, 1) == 0)
                return 0;
            if (bignum_cmp(&b, &wminus1) == 0)
                goto next;
        }

        /* Composite if b != w-1 */
        return 0;
    next:
        continue;
    }

    return 1;
}

/* Generate a random probable prime [HAC 4.44] 
   Returns SUCCESS if the prime was successfully generated, FAILURE otherwise */
status_t bn_generate_proabable_prime(BIGNUM *x, int nbits, int dh_flag, void *rng)
{
    BIGNUM y;
    int ret, i, j;
    uint32_t r;

    if (nbits < 32 || nbits > BN_MAX_BITS)
        return FAILURE;

generate:
    bignum_init(x);
    bignum_init(&y);

    /* Generate an odd k-bit random number */
    if (ctr_drbg_generate(rng, Ptr8(x->array), ceil_div(nbits, 8), NULL, 0) == FAILURE)
        return FAILURE;
    
    j = bignum_msb(x);

    if (j < nbits)
        bignum_lshift(x, x, nbits - j);
    if (j > nbits)
        bignum_rshift(x, x, j - nbits);
    
    x->array[0] |= 1;

    /* Calculate the number of rounds of Miller-Rabin which gives
       a false positive rate of 2^{-80} [HAC Table 4.4] */
    int t = (nbits >= 1300) ? 2 :
        (nbits >= 850) ? 3 :
        (nbits >= 550) ? 5 :
        (nbits >= 350) ? 8 :
        (nbits >= 250) ? 12 :
        (nbits >= 150) ? 18 : 27;

    if (dh_flag == 0) {
        for (;;) {
            if ((ret = bn_check_probable_prime(x, t, rng)) < 0)
                return FAILURE;
            if (ret == 1)
                break;
            bignum_add_int(x, x, 2);
        }

        if (bignum_msb(x) != nbits)
            goto generate;
    } else {
        /* A necessary condition for y and x = 2y + 1 to be prime
           is x = 2 mod 3 (which is equivalent to y = 2 mod 3).
           Make sure it is satisfied, while keeping x = 3 mod 4 */
        x->array[0] |= 2;

        bignum_mod_int(&r, x, 3);
        if (r == 0)
            bignum_add_int(x, x, 8);
        else if (r == 1)
            bignum_add_int(x, x, 4);
        
        /* Set y = (x-1) / 2, which is x / 2 since x is odd */
        bignum_init(&y);
        bignum_rshift(x, &y, 1);

        for(;;) {
            /* Test with small factors first */
            for (i = 0; i < num_trial_divisions(nbits); ++i) {
                if (bignum_cmp_int(x, primes[i]) <= 0 || bignum_cmp_int(&y, primes[i]) <= 0)
            		goto next;
                bignum_mod_int(&r, x, primes[i]);
                if (r == 0)
                    goto next;
                bignum_mod_int(&r, &y, primes[i]);
                if (r == 0)
                    goto next;
            }

            if (bn_check_probable_prime(x, t, rng) == 1 &&
                bn_check_probable_prime(&y, t, rng) == 1)
                break;

        next:
            /* Up x by 12 and y by 6, and test the next candidate */
            bignum_add_int(x, x, 12);
            bignum_add_int(&y, &y, 6);
        }

        if (bignum_msb(x) != nbits)
            goto generate;
    }

    return SUCCESS;
}

static const uint64_t test_primes[24] = {
    13541837047354514699ull, 11482137299118693707ull, 14287940918865387113ull, 10120279974895627553ull,
    14895576077380784113ull, 12576535594587839761ull, 11549535704659004153ull, 16732162743889269931ull,
    10036021854698400299ull, 12748495651575645193ull, 14192101576074053833ull, 14546590944809174707ull,
    14016092726950390393ull, 12719768151834263519ull, 16729058806973093947ull, 14961602683434188807ull,
    15459199153977669427ull, 15459199153977669427ull, 15459199153977669427ull, 15459199153977669427ull,
    13176432008857319999ull, 12778241984776090871ull, 16429718256786499207ull, 14630459379556164227ull,
};

static const uint64_t test_composites[24] = {
    10574814068688352009ull, 10574814068688352009ull, 5287861076572492133ull, 8218870243874079947ull,
    11321516760146882137ull,  8352904206657371839ull, 6529615664111464081ull, 7235499105493574221ull,
    8649229734828310963ull, 16101129338421456491ull, 15604384686487615639ull, 14170715138485288109ull,
    6836339213695843751ull, 9917718734443855331ull, 6435506140383106139ull, 6420092896969674187ull,
    14326074188423877323ull, 7182496337731210039ull, 7931621731272428183ull, 185984449421681ull,
    231914319788213ull, 122144845450367ull, 129545555348477ull, 163780048516769ull,
};

void self_test(void *rng)
{
    BIGNUM x;
    for (int i = 0; i < 24; ++i) {
        bignum_from_int(&x, test_primes[i]);
        ASSERT(bn_check_probable_prime(&x, 27, &rng) == 1);
        bignum_from_int(&x, test_composites[i]);
        ASSERT(bn_check_probable_prime(&x, 27, &rng) == 0);
    }
}

int main() {
    if (!RngStart())
        exit(1);
    
    CTR_DRBG_STATE rng;
    byte entropy[CTR_DRBG_ENTROPY_LEN];

    RngFetchBytes(entropy, CTR_DRBG_ENTROPY_LEN);
    ctr_drbg_init(&rng, entropy, NULL, 0);
    zeroize(entropy, CTR_DRBG_ENTROPY_LEN);

    self_test(&rng);

    ctr_drbg_clear(&rng);
    RngStop();

    return 0;
}
