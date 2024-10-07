#include <stdint.h>

#define GUARD(cond)                                                            \
  do {                                                                         \
    if (!(cond)) {                                                             \
      ret = 1;                                                                 \
      goto exit;                                                               \
    }                                                                          \
  } while (0)

// ent statistical test suite
extern int test_ent(const char *filename, size_t nb);
// common/bignum.c
extern int test_bignum(void);
// common/crypto_mem.c
extern int test_mem(void);
// rand/ctr_drbg.c
extern int ctr_drbg_run_test(void);
// rand/hash_drbg.c
extern int hash_drbg_run_test(void);
// rand/hmac_drbg.c
extern int hmac_drbg_run_test(void);
