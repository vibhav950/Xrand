/**
 * bignum.h
 *
 * Library for big integer arithmetic.
 *
 * This file is a part of Xrand (https://github.com/vibhav950/Xrand).
 */

#ifndef BIGNUM_H
#define BIGNUM_H

#include "common/defs.h"
#include "common/endianness.h"
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>

#define WORD_SIZE 4

/* Defines for the word width depending upon the architecture. */
#ifndef WORD_SIZE
#if (defined(__GNUC__) || defined(_MSC_VER)) &&                                \
    (defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) ||         \
     defined(__powerpc64__))
#define WORD_SIZE 4
#elif (defined(__GNUC__) || defined(_MSC_VER)) &&                              \
    (defined(__i386__) || defined(_M_IX86) || defined(__arm__) ||              \
     defined(__powerpc__))
#define WORD_SIZE 2
#else
#define WORD_SIZE 1
#endif
#endif

/* Here comes the compile-time specialization for how large the underlying array
 * size should be. */
/* The choices are 1, 2 and 4 bytes in size with uint32, uint64 for
 * WORD_SIZE==4, as temporary. */
#ifndef WORD_SIZE
#error Failed to detect WORD_SIZE, must be explicitly defined as 1, 2, or 4
#elif (WORD_SIZE == 1)
/* Data type of array in structure */
typedef uint8_t bn_uint_t; /* Unsigned*/
typedef int8_t bn_sint_t;  /* Signed */
/* Data-type larger than bn_uint_t, for holding intermediate results of
 * calculations */
typedef uint32_t bn_udbl_t;
typedef int32_t bn_sdbl_t;
/* Bitmask for getting MSB */
#define BN_MSB_MASK ((bn_udbl_t)(0x80))
/* sprintf format string */
#define BN_SPRINTF_FORMAT_STR "%.02x"
#define BN_SSCANF_FORMAT_STR "%2hhx"
/* Max value of integer type */
#define BM_MAX_VAL ((bn_udbl_t)0xFF)
#elif (WORD_SIZE == 2)
typedef uint16_t bn_uint_t;
typedef int16_t bn_sint_t;
typedef uint32_t bn_udbl_t;
typedef int32_t bn_sdbl_t;
#define BN_MSB_MASK ((bn_udbl_t)(0x8000))
#define BN_SPRINTF_FORMAT_STR "%.04x"
#define BN_SSCANF_FORMAT_STR "%4hx"
#define BN_MAX_VAL ((bn_udbl_t)0xFFFF)
#elif (WORD_SIZE == 4)
typedef uint32_t bn_uint_t;
typedef int32_t bn_sint_t;
typedef uint64_t bn_udbl_t;
typedef int64_t bn_sdbl_t;
#define BN_MSB_MASK ((bn_udbl_t)(0x80000000))
#define BN_SPRINTF_FORMAT_STR "%.08x"
#define BN_SSCANF_FORMAT_STR "%8x"
#define BN_MAX_VAL ((bn_udbl_t)0xFFFFFFFF)
#endif

typedef struct bignum_st {
  bn_uint_t *p; /* pointer to limbs */
  size_t n;     /* # of limbs */
  int s;        /* sign */
  int f;        /* flags */
} BIGNUM;

/* Error codes */
#define BN_ERR_INTERNAL_FAILURE                                                \
  -0x0001 /* Something went wrong, cleanup and exit */
#define BN_ERR_OUT_OF_MEMORY -0x0002 /* Failed memory allocation */
#define BN_ERR_BUFFER_TOO_SMALL -0x0003 /* Buffer too small to write to */
#define BN_ERR_BAD_INPUT_DATA -0x0004 /* Invalid input arguments provided */
#define BN_ERR_INVALID_CHARACTER                                               \
  -0x0005 /* Invalid character in the digit string */
#define BN_ERR_TOO_MANY_LIMBS -0x0006 /* Request exceeded max allowed        \
                                           limbs*/
#define BN_ERR_NEGATIVE_VALUE -0x0007 /* Negative input arguments provided */
#define BN_ERR_DIVISION_BY_ZERO -0x0008 /* Division by zero */

#define BN_MAX_LIMBS 1024
#define BN_MAX_BITS (BN_MAX_LIMBS * WORD_SIZE << 3)
#define BIW (WORD_SIZE << 3) /* bits in word */
#define BIH (WORD_SIZE << 2) /* bits in half word */

#define BN_CHECK(rv)                                                           \
  do {                                                                         \
    if ((ret = rv) != 0)                                                       \
      goto cleanup;                                                            \
  } while (0)

/* Always use this macro when checking for null functional arguments   */
#define BN_REQUIRE(cond, msg) assert((cond) && msg)

/* Convert an int to sign value; 1 for positive, -1 for negative */
#define BN_INT_TO_SIGN(x) ((int)(((bn_uint_t)x) >> (BIW - 1)) * -2 + 1)

/* Convert a dbl to sign value; 1 for positive, -1 for negative  */
#define BN_DBL_TO_SIGN(x) ((int)(((bn_udbl_t)x) >> ((BIW << 1) - 1)) * -2 + 1)

/* Get the number of bn_uint_t limbs from the number of bits  */
#define BN_BITS_TO_LIMBS(x) (((x) + BIW - 1) / BIW)

/* Get the number of bn_uint_t limbs from the number of words */
#define BN_WORDS_TO_LIMBS(x) (((x) + WORD_SIZE - 1) / WORD_SIZE)

/* Initialize one or multiple BIGNUM(s) */
void bn_init(BIGNUM *X, ...);
/* Unallocate one or multiple BIGNUM(s) */
void bn_zfree(BIGNUM *X, ...);
/* Expand X to (at least) nlimbs */
int bn_grow(BIGNUM *X, const size_t nlimbs);
/* Shrink X as much as possible while keeping at least nlimbs */
int bn_shrink(BIGNUM *X, const size_t nlimbs);
/* Resize X to exactly nlimbs */
int bn_resize(BIGNUM *X, int nlimbs);
/* Copy Y to X */
int bn_assign(BIGNUM *X, const BIGNUM *Y);
/* Copy udbl to the least significant limbs of X */
int bn_from_udbl(BIGNUM *X, const bn_udbl_t n);
/* Copy sdbl to the least significant limbs of X */
int bn_from_sdbl(BIGNUM *X, const bn_sdbl_t n);
/* Copy the least significant limbs of X to udbl */
void bn_to_udbl(const BIGNUM *X, bn_udbl_t *n);
/* Read X from an ASCII string */
int bn_read_string(int radix, char *s, BIGNUM *X);
/* Write X to an ASCII string */
int bn_write_string(int radix, char *s, int *slen, const BIGNUM *X);

/* Set the least significant bit of X */
void bn_set_lsb(BIGNUM *X);
/* Set the most significant bit of X*/
void bn_set_msb(BIGNUM *X);
/* Get the n-th bit of X */
int bn_get_bit(BIGNUM *X, size_t n);
/* Set the n-th bit of X to v */
int bn_set_bit(BIGNUM *X, size_t n, uint8_t v);
/* Get the # of most significant bits in X */
int bn_msb(const BIGNUM *X);
/* Get the # of least significant trailing zeros in X */
int bn_lsb(const BIGNUM *X);

/* Check if X is even */
int bn_is_even(const BIGNUM *X);
/* Check if X is odd */
int bn_is_odd(const BIGNUM *X);
/* Check if X is positive */
int bn_is_pos(const BIGNUM *X);
/* Check if X is negative */
int bn_is_neg(const BIGNUM *X);
/* Check if X is zero */
int bn_is_zero(const BIGNUM *X);
/* Compare unsigned values */
int bn_cmp_abs(const BIGNUM *X, const BIGNUM *Y);
/* Compare signed values */
int bn_cmp(const BIGNUM *X, const BIGNUM *Y);
/* Compare unsigned X with n */
int bn_cmp_udbl(const BIGNUM *X, const bn_udbl_t n);
/* Compare signed X with n */
int bn_cmp_sdbl(const BIGNUM *X, const bn_sdbl_t n);

/* Unsigned addition: X = abs(A) + abs(B) */
int bn_add_abs(BIGNUM *A, BIGNUM *B, BIGNUM *X);
/* Unsigned subtraction: X = abs(A) - abs(B) */
int bn_sub_abs(BIGNUM *A, BIGNUM *B, BIGNUM *X);
/* Signed addition: X = A + B */
int bn_add(BIGNUM *A, BIGNUM *B, BIGNUM *X);
/* Signed addition with sdbl: X = A + b */
int bn_add_sdbl(BIGNUM *A, const bn_sdbl_t b, BIGNUM *X);
/* Signed subtraction: X = A - B */
int bn_sub(BIGNUM *A, BIGNUM *B, BIGNUM *X);
/* Signed subtraction with sdbl: X = A - b */
int bn_sub_sdbl(BIGNUM *A, const bn_sdbl_t b, BIGNUM *X);
/* Left-shift: X = X << count */
int bn_lshift(BIGNUM *X, const int count);
/* Right-shift: X = X >> count */
int bn_rshift(BIGNUM *X, const int count);
/* Signed multiplication: X = A * B */
int bn_mul(BIGNUM *A, BIGNUM *B, BIGNUM *X);
/* Signed multiplication with sdbl: X = A * b */
int bn_mul_sdbl(BIGNUM *A, const bn_sdbl_t b, BIGNUM *X);
/* Integer square-root: X = isqrt(A) */
int bn_isqrt(BIGNUM *A, BIGNUM *X);
/* Division: A = Q * B + R */
int bn_div(BIGNUM *A, BIGNUM *B, BIGNUM *Q, BIGNUM *R);
/* Division by sdbl: A = Q * b + R */
int bn_div_sdbl(BIGNUM *A, const bn_sdbl_t b, BIGNUM *Q, BIGNUM *R);
/* Modulo: R = A (mod B) */
int bn_mod(BIGNUM *A, BIGNUM *B, BIGNUM *R);
/* Integer modulo: r = A (mod b) */
int bn_mod_uint(BIGNUM *A, bn_uint_t b, bn_uint_t *r);
/* Modular exponentiation: X = A^E (mod N) */
int bn_exp_mod(BIGNUM *A, BIGNUM *E, BIGNUM *N, BIGNUM *_RR, BIGNUM *X);
/* Greatest common divisor: G = gcd(A, B) */
int bn_gcd(BIGNUM *A, BIGNUM *B, BIGNUM *G);
/* Modular inverse: X = A^-1 mod N  */
int bn_inv_mod(BIGNUM *A, BIGNUM *N, BIGNUM *X);

/* Generic CRNG generate function */
typedef int (*f_rng_t)(void *, uint8_t *, size_t, const uint8_t *, size_t);

/* Miller-Rabin probabilistic primality test */
int bn_check_probable_prime(BIGNUM *W, int iter, f_rng_t f_rng, void *rng_ctx);
/* Generate a probable prime */
int bn_generate_proabable_prime(BIGNUM *X, int nbits, f_rng_t f_rng,
                                void *rng_ctx);

/* Perform tests */
int bn_self_test(f_rng_t f_rng, void *rng_ctx, int verbose, FILE *fp);

#endif /* BIGNUM_H */