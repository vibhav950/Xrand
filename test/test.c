#include "test.h"

#include <stdio.h>

#define STATUS_MSG(rv)                                                         \
  printf(!rv ? "All tests ran successfully.\n\n"                               \
             : "All tests did not run successfully.\n\n")

int main(void) {
  int rv = 0;

#if defined(XR_TESTS_BIGNUM)
  printf("Running tests for common/bignum.c\n");
  rv = test_bignum();
  STATUS_MSG(rv);
#endif

#if defined(XR_TESTS_ENT)
  printf("Running tests for ent\n");
  const char *filename = "test/out.bin";
  size_t nb = 1 << 20; /* 1MB of data */
  rv = test_ent(filename, nb);
  printf("Wrote %zu bytes to %s\n", nb, filename);
  STATUS_MSG(rv);
#endif

#if defined(XR_TESTS_CRYPTO_MEM)
  printf("Running tests for common/crypto_mem.c\n");
  rv = test_mem();
  STATUS_MSG(rv);
#endif

#if defined(XR_TESTS_CTR_DRBG)
  rv = ctr_drbg_run_test();
  STATUS_MSG(rv);
#endif

#if defined(XR_TESTS_HASH_DRBG)
  rv = hash_drbg_run_test();
  STATUS_MSG(rv);
#endif

#if defined(XR_TESTS_HMAC_DRBG)
  rv = hmac_drbg_run_test();
  STATUS_MSG(rv);
#endif
  return 0;
}
