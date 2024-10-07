#include "common/defs.h" // xr_mem functions
#include "test.h"

#include <string.h>

int test_mem(void) {
  int ret = 0;
  unsigned char a[32] = {0xee}, b[32] = {0xee}, c[32] = {0xee}, d[32] = {0xee};

  // xr_memset
  memset(a, 0x12, 32);
  xr_memset(b, 0x12, 32);
  GUARD(!memcmp(a, b, 12));

  // xr_memzero
  memset(a, 0x00, 28);
  xr_memzero(b, 28);
  GUARD(!memcmp(a, b, 32));

  // xr_memcpy
  memcpy(c, a, 32);
  xr_memcpy(d, b, 32);
  GUARD(!memcmp(c, d, 32));

  // xr_memmove (no overlap)
  memset(c, 0xee, 32);
  memset(d, 0xee, 32);
  memmove(c, a, 32);
  xr_memmove(d, b, 32);
  GUARD(!memcmp(c, d, 32));

  // xr_memmove (with overlap)
  memmove(a, a + 12, 20);
  xr_memmove(b, b + 12, 20);
  GUARD(!memcmp(a, b, 32));

  // xr_memcmp
  GUARD(xr_memcmp(a, b, 32));

  // xr_strcmp (equal same length)
  char s1[] = "eq same length";
  char s2[] = "eq same length";
  GUARD(xr_strcmp(s1, s2) == 0);
  GUARD(xr_strcmp(s2, s1) == 0);

  // xr_strcmp (not equal same length)
  char s3[] = "eq same length";
  char s4[] = "ne same length";
  GUARD(xr_strcmp(s3, s4) != 0);
  GUARD(xr_strcmp(s4, s3) != 0);

  // xr_strcmp (diff len)
  char s5[] = "diff len";
  char s6[] = "diff length";
  GUARD(xr_strcmp(s5, s6) != 0);
  GUARD(xr_strcmp(s6, s5) != 0);

exit:
  return ret;
}
