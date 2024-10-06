#include "common/defs.h"

void xr_mem_cpy(void *dst, const void *src, const size_t size) {
  volatile char *_a = (volatile char *)src;
  volatile char *_b = (volatile char *)dst;
  size_t c = size;

  while (c--) {
    *_b++ = *_a++;
  }
}

void xr_mem_set(void *mem, const int val, const size_t size) {
  volatile char *_p = (volatile char *)mem;
  size_t c = size;

  while (c--) {
    *_p++ = (char)val;
  }
}

void xr_mem_clr(void *mem, const size_t size) {
  volatile char *_p = (volatile char *)mem;
  size_t c = size;

  while (c--) {
    *_p++ = 0;
  }
}

int xr_mem_cmp(const void *a, const void *b, const size_t size) {
  const unsigned char *_a = (const unsigned char *)a;
  const unsigned char *_b = (const unsigned char *)b;
  unsigned char res = 0;
  size_t c = size;

  while (c--) {
    res |= *_a++ ^ *_b++;
  }

  return res;
}
