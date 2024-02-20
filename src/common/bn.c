/*

Big number library - arithmetic on multiple-precision unsigned integers.

This library is an implementation of arithmetic on arbitrarily large integers.

The difference between this and other implementations, is that the data structure
has optimal memory utilization (i.e. a 1024 bit integer takes up 128 bytes RAM),
and all memory is allocated statically: no dynamic allocation for better or worse.

Primary goals are correctness, clarity of code and clean, portable implementation.
Secondary goal is a memory footprint small enough to make it suitable for use in
embedded applications.


The current state is correct functionality and adequate performance.
There may well be room for performance-optimizations and improvements.

*/

#include <stdio.h>
#include <assert.h>
#include "bn.h"
#include "defs.h"

#include <stdlib.h>

/* Functions for shifting number in-place. */
static void _lshift_one_bit(struct bn* a);
static void _rshift_one_bit(struct bn* a);
static void _lshift_word(struct bn* a, int nwords);
static void _rshift_word(struct bn* a, int nwords);



/* Public / Exported functions. */
void bignum_init(struct bn* n)
{
  require(n, "n is null");

  int i;
  for (i = 0; i < BN_ARRAY_SIZE; ++i)
  {
    n->array[i] = 0;
  }
}


void bignum_from_int(struct bn* n, DTYPE_TMP i)
{
  require(n, "n is null");

  bignum_init(n);

  /* Endianness issue if machine is not little-endian? */
#ifdef WORD_SIZE
 #if (WORD_SIZE == 1)
  n->array[0] = (i & 0x000000ff);
  n->array[1] = (i & 0x0000ff00) >> 8;
  n->array[2] = (i & 0x00ff0000) >> 16;
  n->array[3] = (i & 0xff000000) >> 24;
 #elif (WORD_SIZE == 2)
  n->array[0] = (i & 0x0000ffff);
  n->array[1] = (i & 0xffff0000) >> 16;
 #elif (WORD_SIZE == 4)
  n->array[0] = i;
  DTYPE_TMP num_32 = 32;
  DTYPE_TMP tmp = i >> num_32; /* bit-shift with U64 operands to force 64-bit results */
  n->array[1] = tmp;
 #endif
#endif
}


int bignum_to_int(struct bn* n)
{
  require(n, "n is null");

  int ret = 0;

  /* Endianness issue if machine is not little-endian? */
#if (WORD_SIZE == 1)
  ret += n->array[0];
  ret += n->array[1] << 8;
  ret += n->array[2] << 16;
  ret += n->array[3] << 24;  
#elif (WORD_SIZE == 2)
  ret += n->array[0];
  ret += n->array[1] << 16;
#elif (WORD_SIZE == 4)
  ret += n->array[0];
#endif

  return ret;
}


void bignum_from_string(struct bn* n, char* str, int nbytes)
{
  require(n, "n is null");
  require(str, "str is null");
  require(nbytes > 0, "nbytes must be positive");
  require((nbytes & 1) == 0, "string format must be in hex -> equal number of bytes");
  require((nbytes % (sizeof(DTYPE) * 2)) == 0, "string length must be a multiple of (sizeof(DTYPE) * 2) characters");
  
  bignum_init(n);

  DTYPE tmp;                        /* DTYPE is defined in bn.h - uint{8,16,32,64}_t */
  int i = nbytes - (2 * WORD_SIZE); /* index into string */
  int j = 0;                        /* index into array */

  /* reading last hex-byte "MSB" from string first -> big endian */
  /* MSB ~= most significant byte / block ? :) */
  while (i >= 0)
  {
    tmp = 0;
    sscanf(&str[i], SSCANF_FORMAT_STR, &tmp);
    n->array[j] = tmp;
    i -= (2 * WORD_SIZE); /* step WORD_SIZE hex-byte(s) back in the string. */
    j += 1;               /* step one element forward in the array. */
  }
}


void bignum_to_string(struct bn* n, char* str, int nbytes)
{
  require(n, "n is null");
  require(str, "str is null");
  require(nbytes > 0, "nbytes must be positive");
  require((nbytes & 1) == 0, "string format must be in hex -> equal number of bytes");

  int j = BN_ARRAY_SIZE - 1; /* index into array - reading "MSB" first -> big-endian */
  int i = 0;                 /* index into string representation. */

  /* reading last array-element "MSB" first -> big endian */
  while ((j >= 0) && (nbytes > (i + 1)))
  {
    sprintf(&str[i], SPRINTF_FORMAT_STR, n->array[j]);
    i += (2 * WORD_SIZE); /* step WORD_SIZE hex-byte(s) forward in the string. */
    j -= 1;               /* step one element back in the array. */
  }

  /* Count leading zeros: */
  j = 0;
  while (str[j] == '0')
  {
    j += 1;
  }
 
  /* Move string j places ahead, effectively skipping leading zeros */ 
  for (i = 0; i < (nbytes - j); ++i)
  {
    str[i] = str[i + j];
  }

  /* Zero-terminate string */
  str[i] = 0;
}


void bignum_dec(struct bn* n)
{
  require(n, "n is null");

  DTYPE tmp; /* copy of n */
  DTYPE res;

  int i;
  for (i = 0; i < BN_ARRAY_SIZE; ++i)
  {
    tmp = n->array[i];
    res = tmp - 1;
    n->array[i] = res;

    if (!(res > tmp))
    {
      break;
    }
  }
}


void bignum_inc(struct bn* n)
{
  require(n, "n is null");

  DTYPE res;
  DTYPE_TMP tmp; /* copy of n */

  int i;
  for (i = 0; i < BN_ARRAY_SIZE; ++i)
  {
    tmp = n->array[i];
    res = tmp + 1;
    n->array[i] = res;

    if (res > tmp)
    {
      break;
    }
  }
}


void bignum_add(struct bn* a, struct bn* b, struct bn* c)
{
  require(a, "a is null");
  require(b, "b is null");
  require(c, "c is null");

  DTYPE_TMP tmp;
  int carry = 0;
  int i;
  for (i = 0; i < BN_ARRAY_SIZE; ++i)
  {
    tmp = (DTYPE_TMP)a->array[i] + b->array[i] + carry;
    carry = (tmp > MAX_VAL);
    c->array[i] = (tmp & MAX_VAL);
  }
}


void bignum_sub(struct bn* a, struct bn* b, struct bn* c)
{
  require(a, "a is null");
  require(b, "b is null");
  require(c, "c is null");

  DTYPE_TMP res;
  DTYPE_TMP tmp1;
  DTYPE_TMP tmp2;
  int borrow = 0;
  int i;
  for (i = 0; i < BN_ARRAY_SIZE; ++i)
  {
    tmp1 = (DTYPE_TMP)a->array[i] + (MAX_VAL + 1); /* + number_base */
    tmp2 = (DTYPE_TMP)b->array[i] + borrow;;
    res = (tmp1 - tmp2);
    c->array[i] = (DTYPE)(res & MAX_VAL); /* "modulo number_base" == "% (number_base - 1)" if number_base is 2^N */
    borrow = (res <= MAX_VAL);
  }
}


void _bignum_mul(struct bn* a, struct bn* b, struct bn* c)
{
  // require(a, "a is null");
  // require(b, "b is null");
  // require(c, "c is null");

  struct bn row;
  struct bn tmp;
  int i, j;
  int awords = bignum_words(bignum_msb(a));
  int bwords = bignum_words(bignum_msb(b));

  bignum_init(c);

  for (i = 0; i < awords; ++i)
  {
    bignum_init(&row);

    for (j = 0; j < bwords; ++j)
    {
      if (i + j < BN_ARRAY_SIZE)
      {
        bignum_init(&tmp);
        DTYPE_TMP intermediate = ((DTYPE_TMP)a->array[i] * (DTYPE_TMP)b->array[j]);
        bignum_from_int(&tmp, intermediate);
        _lshift_word(&tmp, i + j);
        bignum_add(&tmp, &row, &row);
      }
    }
    bignum_add(c, &row, c);
  }
}


void bignum_div(struct bn* a, struct bn* b, struct bn* c)
{
  require(a, "a is null");
  require(b, "b is null");
  require(c, "c is null");

  struct bn current;
  struct bn denom;
  struct bn tmp;

  bignum_from_int(&current, 1);               // int current = 1;
  bignum_assign(&denom, b);                   // denom = b
  bignum_assign(&tmp, a);                     // tmp   = a

  const DTYPE_TMP half_max = 1 + (DTYPE_TMP)(MAX_VAL / 2);
  int overflow = false;
  while (bignum_cmp(&denom, a) != LARGER)     // while (denom <= a) {
  {
    if (denom.array[BN_ARRAY_SIZE - 1] >= half_max)
    {
      overflow = true;
      break;
    }
    _lshift_one_bit(&current);                //   current <<= 1;
    _lshift_one_bit(&denom);                  //   denom <<= 1;
  }
  if (!overflow)
  {
    _rshift_one_bit(&denom);                  // denom >>= 1;
    _rshift_one_bit(&current);                // current >>= 1;
  }
  bignum_init(c);                             // int answer = 0;

  while (!bignum_is_zero(&current))           // while (current != 0)
  {
    if (bignum_cmp(&tmp, &denom) != SMALLER)  //   if (dividend >= denom)
    {
      bignum_sub(&tmp, &denom, &tmp);         //     dividend -= denom;
      bignum_or(c, &current, c);              //     answer |= current;
    }
    _rshift_one_bit(&current);                //   current >>= 1;
    _rshift_one_bit(&denom);                  //   denom >>= 1;
  }                                           // return answer;
}


void bignum_lshift(struct bn* a, struct bn* b, int nbits)
{
  require(a, "a is null");
  require(b, "b is null");
  require(nbits >= 0, "no negative shifts");

  bignum_assign(b, a);
  /* Handle shift in multiples of word-size */
  const int nbits_pr_word = (WORD_SIZE * 8);
  int nwords = nbits / nbits_pr_word;
  if (nwords != 0)
  {
    _lshift_word(b, nwords);
    nbits -= (nwords * nbits_pr_word);
  }

  if (nbits != 0)
  {
    int i;
    for (i = (BN_ARRAY_SIZE - 1); i > 0; --i)
    {
      b->array[i] = (b->array[i] << nbits) | (b->array[i - 1] >> ((8 * WORD_SIZE) - nbits));
    }
    b->array[i] <<= nbits;
  }
}


void bignum_rshift(struct bn* a, struct bn* b, int nbits)
{
  require(a, "a is null");
  require(b, "b is null");
  require(nbits >= 0, "no negative shifts");
  
  bignum_assign(b, a);
  /* Handle shift in multiples of word-size */
  const int nbits_pr_word = (WORD_SIZE * 8);
  int nwords = nbits / nbits_pr_word;
  if (nwords != 0)
  {
    _rshift_word(b, nwords);
    nbits -= (nwords * nbits_pr_word);
  }

  if (nbits != 0)
  {
    int i;
    for (i = 0; i < (BN_ARRAY_SIZE - 1); ++i)
    {
      b->array[i] = (b->array[i] >> nbits) | (b->array[i + 1] << ((8 * WORD_SIZE) - nbits));
    }
    b->array[i] >>= nbits;
  }
  
}


void bignum_mod(struct bn* a, struct bn* b, struct bn* c)
{
  /*
    Take divmod and throw away div part
  */
  require(a, "a is null");
  require(b, "b is null");
  require(c, "c is null");

  struct bn tmp;

  bignum_divmod(a,b,&tmp,c);
}

void bignum_divmod(struct bn* a, struct bn* b, struct bn* c, struct bn* d)
{
  /*
    Puts a%b in d
    and a/b in c

    mod(a,b) = a - ((a / b) * b)

    example:
      mod(8, 3) = 8 - ((8 / 3) * 3) = 2
  */
  require(a, "a is null");
  require(b, "b is null");
  require(c, "c is null");

  struct bn tmp;

  /* c = (a / b) */
  bignum_div(a, b, c);

  /* tmp = (c * b) */
  bignum_mul(c, b, &tmp);

  /* c = a - tmp */
  bignum_sub(a, &tmp, d);
}


void bignum_and(struct bn* a, struct bn* b, struct bn* c)
{
  require(a, "a is null");
  require(b, "b is null");
  require(c, "c is null");

  int i;
  for (i = 0; i < BN_ARRAY_SIZE; ++i)
  {
    c->array[i] = (a->array[i] & b->array[i]);
  }
}


void bignum_or(struct bn* a, struct bn* b, struct bn* c)
{
  require(a, "a is null");
  require(b, "b is null");
  require(c, "c is null");

  int i;
  for (i = 0; i < BN_ARRAY_SIZE; ++i)
  {
    c->array[i] = (a->array[i] | b->array[i]);
  }
}


void bignum_xor(struct bn* a, struct bn* b, struct bn* c)
{
  require(a, "a is null");
  require(b, "b is null");
  require(c, "c is null");

  int i;
  for (i = 0; i < BN_ARRAY_SIZE; ++i)
  {
    c->array[i] = (a->array[i] ^ b->array[i]);
  }
}


int bignum_cmp(struct bn* a, struct bn* b)
{
  require(a, "a is null");
  require(b, "b is null");

  int i = BN_ARRAY_SIZE;
  do
  {
    i -= 1; /* Decrement first, to start with last array element */
    if (a->array[i] > b->array[i])
    {
      return LARGER;
    }
    else if (a->array[i] < b->array[i])
    {
      return SMALLER;
    }
  }
  while (i != 0);

  return EQUAL;
}


int bignum_is_zero(struct bn* n)
{
  require(n, "n is null");

  int i;
  for (i = 0; i < BN_ARRAY_SIZE; ++i)
  {
    if (n->array[i])
    {
      return 0;
    }
  }

  return 1;
}


void bignum_pow(struct bn* a, struct bn* b, struct bn* c)
{
  require(a, "a is null");
  require(b, "b is null");
  require(c, "c is null");

  struct bn tmp;

  bignum_init(c);

  if (bignum_cmp(b, c) == EQUAL)
  {
    /* Return 1 when exponent is 0 -- n^0 = 1 */
    bignum_inc(c);
  }
  else
  {
    struct bn bcopy;
    bignum_assign(&bcopy, b);

    /* Copy a -> tmp */
    bignum_assign(&tmp, a);

    bignum_dec(&bcopy);
 
    /* Begin summing products: */
    while (!bignum_is_zero(&bcopy))
    {

      /* c = tmp * tmp */
      bignum_mul(&tmp, a, c);
      /* Decrement b by one */
      bignum_dec(&bcopy);

      bignum_assign(&tmp, c);
    }

    /* c = tmp */
    bignum_assign(c, &tmp);
  }
}

void bignum_isqrt(struct bn *a, struct bn* b)
{
  require(a, "a is null");
  require(b, "b is null");

  struct bn low, high, mid, tmp;

  bignum_init(&low);
  bignum_assign(&high, a);
  bignum_rshift(&high, &mid, 1);
  bignum_inc(&mid);

  while (bignum_cmp(&high, &low) > 0) 
  {
    bignum_mul(&mid, &mid, &tmp);
    if (bignum_cmp(&tmp, a) > 0) 
    {
      bignum_assign(&high, &mid);
      bignum_dec(&high);
    }
    else 
    {
      bignum_assign(&low, &mid);
    }
    bignum_sub(&high,&low,&mid);
    _rshift_one_bit(&mid);
    bignum_add(&low,&mid,&mid);
    bignum_inc(&mid);
  }
  bignum_assign(b,&low);
}


void bignum_assign(struct bn* dst, struct bn* src)
{
  require(dst, "dst is null");
  require(src, "src is null");

  int i;
  for (i = 0; i < BN_ARRAY_SIZE; ++i)
  {
    dst->array[i] = src->array[i];
  }
}


/* Private / Static functions. */
static void _rshift_word(struct bn* a, int nwords)
{
  /* Naive method: */
  require(a, "a is null");
  require(nwords >= 0, "no negative shifts");

  int i;
  if (nwords >= BN_ARRAY_SIZE)
  {
    for (i = 0; i < BN_ARRAY_SIZE; ++i)
    {
      a->array[i] = 0;
    }
    return;
  }

  for (i = 0; i < BN_ARRAY_SIZE - nwords; ++i)
  {
    a->array[i] = a->array[i + nwords];
  }
  for (; i < BN_ARRAY_SIZE; ++i)
  {
    a->array[i] = 0;
  }
}


static void _lshift_word(struct bn* a, int nwords)
{
  require(a, "a is null");
  require(nwords >= 0, "no negative shifts");

  int i;
  /* Shift whole words */
  for (i = (BN_ARRAY_SIZE - 1); i >= nwords; --i)
  {
    a->array[i] = a->array[i - nwords];
  }
  /* Zero pad shifted words. */
  for (; i >= 0; --i)
  {
    a->array[i] = 0;
  }  
}


static void _lshift_one_bit(struct bn* a)
{
  require(a, "a is null");

  int i;
  for (i = (BN_ARRAY_SIZE - 1); i > 0; --i)
  {
    a->array[i] = (a->array[i] << 1) | (a->array[i - 1] >> ((8 * WORD_SIZE) - 1));
  }
  a->array[0] <<= 1;
}


static void _rshift_one_bit(struct bn* a)
{
  require(a, "a is null");

  int i;
  for (i = 0; i < (BN_ARRAY_SIZE - 1); ++i)
  {
    a->array[i] = (a->array[i] >> 1) | (a->array[i + 1] << ((8 * WORD_SIZE) - 1));
  }
  a->array[BN_ARRAY_SIZE - 1] >>= 1;
}

// ===================================================================================

int bignum_cmp_int(struct bn *x, uint64_t n)
{
  require(x, "x is null");

  struct bn y;
  bignum_from_int(&y, n);
  return bignum_cmp(x, &y);
}

int bignum_lsb(struct bn *x)
{
  require(x, "x is null");

  int i, j, count = 0;
  for (i = 0; i < BN_ARRAY_SIZE; ++i)
  {
    for (j = 0; j < BIW; ++j, ++count)
    {
      if (((x->array[i] >> j) & 1) != 0)
      {
        return count;
      }
    }
  }
  return 0;
}

int bignum_msb(struct bn *x)
{
  require(x, "x is null");

  int i, j;
  for (i = (BN_ARRAY_SIZE - 1); i > 0; --i)
  {
    if (x->array[i] != 0)
    {
      break;
    }
  }
  for (j = BIW - 1; j >= 0; --j)
  {
    if (((x->array[i] >> j) & 1) != 0)
    {
      break;
    }
  }
  return (i * BIW) + j + 1;
}

void bignum_add_int(struct bn *a, struct bn *x, int n)
{
  require(a, "a is null");
  require(x, "x is null");

  struct bn t;
  bignum_from_int(&t, n);
  bignum_add(a, &t, x);
}

void bignum_sub_int(struct bn *a, struct bn *x, int n)
{
  require(a, "a is null");
  require(x, "x is null");

  struct bn t;
  bignum_from_int(&t, n);
  bignum_sub(a, &t, x);
}

void bignum_sqr(struct bn *x)
{
  require(x, "x is null");

  struct bn tmp;
  // use memcpy() instead of bignum_assign() for faster copying
  memcpy(&tmp, x, sizeof(struct bn));
  bignum_mul(&tmp, &tmp, x);
}

int bignum_mod_int(uint32_t *r, struct bn *a, int b)
{
  require(a, "a is null");
  require(r, "r is null");

  int i;
  uint32_t x, y, z;
  if (b <= 0)
  {
    return -1;
  }
  if (b == 1)
  {
    *r = 0;
    return 0;
  }
  if (b == 2)
  {
    *r = a->array[0] & 1;
    return 0;
  }
  for (i = BN_ARRAY_SIZE - 1, y = 0; i >= 0; --i)
  {
    x = a->array[i];
    y = (y << BIH) | (x >> BIH);
    z = y / b;
    y -= z * b;
    x <<= BIH;
    y = (y << BIH) | (x >> BIH);
    z = y / b;
    y -= z * b;
  }
  *r = y;
  return 0;
}

/* x = a^k (mod n) [HAC 2.143] */
void bignum_exp_mod(struct bn *a, struct bn *k, struct bn *n, struct bn *x)
{
  require(a, "a is null");
  require(k, "k is null");
  require(n, "n is null");
  require(x, "x is null");

  struct bn b, kt, A, temp;
  int t = bignum_msb(k);
  bignum_assign(&kt, k);
  bignum_from_int(&b, 1);
  if (bignum_is_zero(&kt))
  {
    goto ret;
  }
  bignum_assign(&A, a);
  if (bignum_is_odd(&kt))
  {
    bignum_assign(&b, a);
  }
  for (int i = 0; i < t; ++i)
  {
    bignum_sqr(&A);
    bignum_mod(&A, n, &A);
    bignum_rshift(&kt, &kt, 1);
    if (bignum_is_odd(&kt))
    {
      bignum_mul(&A, &b, &temp);
      bignum_mod(&temp, n, &temp);
      bignum_assign(&b, &temp);
    }
  }
ret:
  bignum_assign(x, &b);
}

/* x = GCD(a, b) [HAC 15.54] */
void bignum_gcd(struct bn *a, struct bn *b, struct bn *x)
{
  require(a, "a is null");
  require(b, "b is null");
  require(x, "x is null");

  BIGNUM tg, ta, tb;
  bignum_init(&ta);
  bignum_init(&tb);
  bignum_from_int(&tg, 1);
  bignum_assign(&ta, a);
  bignum_assign(&tb, b);
  while (bignum_is_even(&ta) && bignum_is_even(&tb))
  {
    bignum_rshift(&ta, &ta, 1);
    bignum_rshift(&tb, &tb, 1);
    bignum_lshift(&tg, &tg, 1);
  }
  while (!bignum_is_zero(&ta))
  {
    while (bignum_is_even(&ta))
    {
      bignum_rshift(&ta, &ta, 1);
    }
    while (bignum_is_even(&tb))
    {
      bignum_rshift(&tb, &tb, 1);
    }
    if (bignum_cmp(&ta, &tb) >= 0)
    {
      bignum_sub(&ta, &tb, &ta);
      bignum_rshift(&ta, &ta, 1);
    }
    else
    {
      bignum_sub(&tb, &ta, &tb);
      bignum_rshift(&tb, &tb, 1);
    }
  }
  bignum_mul(&tg, &tb, x);
}

/* Recursive Karatsuba Multiplication - the bignum size threshold for which this 
   function dominates the naive approach must be carefully set. */
void _bignum_mul_karatsuba(struct bn *a, struct bn *b, struct bn *x, int size)
{
  if (size <= 0)
  {
    return;
  }

  if (bignum_is_zero(a) || bignum_is_zero(b))
  {
    bignum_init(x);
    return;
  }

  if (size == 1)
  {
    DTYPE_TMP result = (DTYPE_TMP)(a->array[0]) * (DTYPE_TMP)(b->array[0]);
    bignum_from_int(x, result);
    return;
  }

  int half = size / 2;
  struct bn a1, a0, b1, b0, c2, c1, c0, ct, cv;

  /* Split a into a1, a0, and b into b1, b0 */
  for (int i = 0; i < half; ++i)
  {
    a1.array[i] = a->array[i + half];
    a0.array[i] = a->array[i];
    b1.array[i] = b->array[i + half];
    b0.array[i] = b->array[i];
  }

  /* Compute subproducts */
  _bignum_mul_karatsuba(&a1, &b1, &c2, half); /* c2 = a1 * b1 */
  _bignum_mul_karatsuba(&a0, &b0, &c0, half); /* c0 = a0 * b0 */
  bignum_add(&a1, &a0, &ct);
  bignum_add(&b1, &b0, &cv);
  /* c1 = (a1 + a0) * (b1 + b0) - c2 - c0 */
  _bignum_mul_karatsuba(&ct, &cv, &c1, half);
  bignum_sub(&c1, &c2, &c1);
  bignum_sub(&c1, &c0, &c1);

  /* Combine subproducts */
  _lshift_word(&c2, 2 * half);
  _lshift_word(&c1, half);
  bignum_add(&c2, &c1, x);
  bignum_add(x, &c0, x);
}

#define BN_KARATSUBA_THRESHOLD 64
void bignum_mul(struct bn *a, struct bn *b, struct bn *x)
{
  require(a, "a is null");
  require(b, "b is null");
  require(x, "x is null");

  // int size = max(bignum_msb(a), bignum_msb(b));
  // if (size < BN_KARATSUBA_THRESHOLD)
  // {
  //   _bignum_mul(a, b, x);
  //   return;
  // }
  // _bignum_mul_karatsuba(a, b, x, BN_ARRAY_SIZE);

  _bignum_mul(a, b, x);
}