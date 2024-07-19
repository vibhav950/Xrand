/**
 * bignum.c - Module for multi-precision arithmetic.
 * 
 * Written by vibhav950 for Xrand.
 * 
 * References:
 * 
 *  [1] https://cacr.uwaterloo.ca/hac
 *  [2] https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
 *  [3] https://github.com/kokke/tiny-bignum-c
 *  [4] https://github.com/axic/tropicssl/blob/master/library/bignum.c
 *  [5] https://github.com/libtom/libtommath
 */

#include "bignum.h"
#include "common/defs.h"
#include "rand/ctr_drbg.h"

#include <stdarg.h>
#include <string.h>


/* Initialize one or multiple BIGNUM(s)

   Note: Every BIGNUM variable MUST be initialized before 
   any memory is allocated for it, or before it is passed
   to any of the bn_* functions */
inline void bn_init(BIGNUM *X, ...)
{
	va_list args;

	va_start(args, X);

	while (X != NULL) {
		X->p = NULL;
		X->n = 0;
		X->s = 1;
		X->f = 0;

		X = va_arg(args, BIGNUM *);
	}

	va_end(args);
}


/* Zero and free one or multiple BIGNUM(s) */
void bn_zfree(BIGNUM *X, ...)
{
	va_list args;

	va_start(args, X);
	
	while (X != NULL) {
		if (X->p != NULL && X->n > 0) {
			zeroize(X->p, X->n * WORD_SIZE);
			free(X->p);
		}

		X->p = NULL; 
		X->n = 0;
		X->s = 1;
		X->f = 0;

		X = va_arg(args, BIGNUM *);
	}

	va_end(args);
}


/* Grow the BIGNUM to the specified number of limbs */
int bn_grow(BIGNUM *X, const size_t nlimbs)
{
	BN_REQUIRE(X, "X is null");
	
	int s, f;
	bn_uint_t *p;

	if (nlimbs > BN_MAX_LIMBS)
		return BN_ERR_NOT_ENOUGH_LIMBS;
	
	if (X->n >= nlimbs)
		return 0;
	
	s = X->s;
	f = X->f;

	if ((p = calloc(nlimbs, WORD_SIZE)) == NULL)
		return BN_ERR_OUT_OF_MEMORY;
	
	if (X->p != NULL) {
		memcpy(p, X->p, X->n * WORD_SIZE);
		bn_zfree(X, NULL);
	}

	X->p = p;
	X->n = nlimbs;
	X->s = s;
	X->f = f;

	return 0;
}


/* Resize down as much as possible, while keeping
   at least the specified number of limbs */
int bn_shrink(BIGNUM *X, const size_t nlimbs)
{
	BN_REQUIRE(X, "X is null");

	int s, f;
	bn_uint_t *p;
	size_t i;

	if (nlimbs > BN_MAX_LIMBS)
		return BN_ERR_NOT_ENOUGH_LIMBS;

	s = X->s;
	f = X->f;
	
	for (i = X->n; i > 0; --i) {
		if (X->p[i - 1] != 0)
			break;
	}
	
	if (i < nlimbs)
		i = nlimbs;
	
	if ((p = calloc(i, WORD_SIZE)) == NULL)
		return BN_ERR_OUT_OF_MEMORY;

	if (X->p != NULL) {
		memcpy(p, X->p, i * WORD_SIZE);
		bn_zfree(X, NULL);
	}

	X->p = p;
	X->n = nlimbs;
	X->s = s;
	X->f = f;

	return 0;
}


/* Copy the value of a udbl to the least significant 
   limbs of the BIGNUM */
int bn_from_udbl(BIGNUM *X, const bn_udbl_t n)
{
	BN_REQUIRE(X, "X is null");

	int ret = 0;
	bn_udbl_t n_cpy;

	BN_CHECK(bn_grow(X, sizeof(bn_udbl_t) / WORD_SIZE));
	memset(X->p, 0, X->n * WORD_SIZE);

	X->s = 1; X->f = 0;

	n_cpy = n;

	// Endianness issue if machine is not little-endian?
#if (WORD_SIZE == 1)
	n->p[0] = (n_cpy & 0x000000ff);
	n->p[1] = (n_cpy & 0x0000ff00) >> 8;
	n->p[2] = (n_cpy & 0x00ff0000) >> 16;
	n->p[3] = (n_cpy & 0xff000000) >> 24;
#elif (WORD_SIZE == 2)
	n->p[0] = (n_cpy & 0x0000ffff);
	n->p[1] = (n_cpy & 0xffff0000) >> 16;
#elif (WORD_SIZE == 4)
	X->p[0] = (bn_uint_t)n_cpy;
	n_cpy >>= 32;
	X->p[1] = n_cpy;
#endif

cleanup:

	return ret;
}


static inline bn_uint_t bn_sint_abs(bn_sint_t x)
{
	if (x >= 0)
		return x;

	/* Using this approach, we correctly handle the most negative
	   value -2^(BIW-1), where the naive approach -x would have ub.
	   Write this in a way so that the compiler doesn't complain. */
	return (bn_uint_t) 0 - (bn_uint_t) x;
}

static inline bn_udbl_t bn_sdbl_abs(bn_sdbl_t x)
{
	if (x >= 0)
		return x;

	return (bn_udbl_t) 0 - (bn_udbl_t) x;
}

/* Copy the value of a sdbl to the least significant 
   limbs of the BIGNUM */
int bn_from_sdbl(BIGNUM *X, const bn_sdbl_t n)
{
	BN_REQUIRE(X, "X is null");

	int ret = 0;
	bn_udbl_t n_abs;

	BN_CHECK(bn_grow(X, sizeof(bn_udbl_t) / WORD_SIZE));
	memset(X->p, 0, X->n * WORD_SIZE);

	X->s = BN_DBL_TO_SIGN(n);
	X->f = 0;

	n_abs = bn_sdbl_abs(n);

	// Endianness issue if machine is not little-endian?
#if (WORD_SIZE == 1)
	n->p[0] = (n_abs & 0x000000ff);
	n->p[1] = (n_abs & 0x0000ff00) >> 8;
	n->p[2] = (n_abs & 0x00ff0000) >> 16;
	n->p[3] = (n_abs & 0xff000000) >> 24;
#elif (WORD_SIZE == 2)
	n->p[0] = (n_abs & 0x0000ffff);
	n->p[1] = (n_abs & 0xffff0000) >> 16;
#elif (WORD_SIZE == 4)
	X->p[0] = (bn_uint_t)n_abs;
	n_abs >>= 32;
	X->p[1] = n_abs;
#endif

cleanup:

	return ret;
}


/* Copy the least significant limbs of the BIGNUM 
   to a udbl */
void bn_to_udbl(const BIGNUM *X, bn_udbl_t *n)
{
	BN_REQUIRE(X, "X is null");
	BN_REQUIRE(n, "n is null");

	bn_udbl_t t = 0;

	if (X->n == 0) {
		*n = 0;
		return;
	}

	/* Endianness issue if machine is not little-endian? */
#if (WORD_SIZE == 1)
	t += X->p[0];
	t += X->p[1] << 8;
	t += X->p[2] << 16;
	t += X->p[3] << 24;
#elif (WORD_SIZE == 2)
	t += X->p[0];
	t += X->p[1] << 16;
#elif (WORD_SIZE == 4)
	t += X->p[1];
	t <<= 32;
	t += X->p[0];
#endif

	*n = t;
}


/* Convert an ASCII character to digit value */
static inline int bn_get_digit(bn_uint_t *d, int radix, char c)
{
	*d = 255;

	if (c >= '0' && c <= '9')
		*d = c - 48;
	if (c >= 'A' && c <= 'Z')
		*d = c - 55;
	if (c >= 'a' && c <= 'z')
		*d = c - 87;

	if (*d >= (bn_uint_t)radix)
		return BN_ERR_INVALID_CHARACTER;

	return 0;
}

/* Read X from an ASCII string */
int bn_read_string(int radix, char *s, BIGNUM *X)
{
	int ret = 0, i, j, n;
	bn_uint_t d;
	BIGNUM T;

	if (radix < 2 || radix > 16)
		return BN_ERR_BAD_INPUT_DATA;

	bn_init(&T, NULL);

	if (radix == 16) {
		n = BN_BITS_TO_LIMBS(strlen(s) << 2);
		BN_CHECK(bn_grow(X, n));
		BN_CHECK(bn_from_udbl(X, 0));

		for (i = strlen(s) - 1, j = 0; i >= 0; i--, j++) {
			if (i == 0 && s[i] == '-') {
				X->s = -1;
				break;
			}

			BN_CHECK(bn_get_digit(&d, radix, s[i]));
			X->p[j / (2 * WORD_SIZE)] |= d << ((j % (2 * WORD_SIZE)) << 2);
		}
	} else {
		BN_CHECK(bn_from_udbl(X, 0));

		for (i = 0; i < (int)strlen(s); i++) {
			if (i == 0 && s[i] == '-') {
				X->s = -1;
				continue;
			}

			BN_CHECK(bn_get_digit(&d, radix, s[i]));
			BN_CHECK(bn_mul_sdbl(X, radix, &T));
			BN_CHECK(bn_add_sdbl(&T, d, X));
		}
	}

cleanup:

	bn_zfree(&T, NULL);

	return ret;
}


/* Helper to write the digits high-order first */
static int bn_write_hlp(int radix, char **p, BIGNUM *X)
{
	int ret = 0;
	bn_uint_t r;

	if (radix < 2 || radix > 16)
		return BN_ERR_BAD_INPUT_DATA;

	BN_CHECK(bn_mod_uint(X, radix, &r));
	BN_CHECK(bn_div_sdbl(X, radix, X, NULL));

	if (bn_cmp_sdbl(X, 0) != 0)
		BN_CHECK(bn_write_hlp(radix, p, X));

	if (r < 10)
		*(*p)++ = (char)(r + 0x30);
	else
		*(*p)++ = (char)(r + 0x37);

cleanup:

	return ret;
}

/* Write X to an ASCII string */
int bn_write_string(int radix, char *s, int *slen, const BIGNUM *X)
{
	int ret = 0, n;
	char *p;
	BIGNUM T;

	if (radix < 2 || radix > 16)
		return BN_ERR_BAD_INPUT_DATA;

	n = bn_msb(X);
	if (radix >= 4)
		n >>= 1;
	if (radix == 16)
		n >>= 1;
	n += 3;

	if (*slen < n) {
		*slen = n;
		return BN_ERR_BUFFER_TOO_SMALL;
	}

	p = s;
	bn_init(&T, NULL);

	if (X->s == -1)
		*p++ = '-';

	if (radix == 16) {
		int c, i, j, k;

		for (i = X->n - 1, k = 0; i >= 0; i--) {
			for (j = WORD_SIZE - 1; j >= 0; j--) {
				c = (X->p[i] >> (j << 3)) & 0xFF;

				if (c == 0 && k == 0 && (i + j) != 0)
					continue;

				p += sprintf(p, "%02X", c);
				k = 1;
			}
		}
	} else {
		BN_CHECK(bn_assign(&T, X));
		BN_CHECK(bn_write_hlp(radix, &p, &T));
	}

	*p++ = '\0';
	*slen = p - s;

cleanup:

	bn_zfree(&T, NULL);

	return (ret);
}


/* Copy the content of Y into X (assign X = Y) */
int bn_assign(BIGNUM *X, const BIGNUM *Y)
{
	BN_REQUIRE(X, "X is null");
	BN_REQUIRE(Y, "Y is null");

	int ret = 0, i;

	if (X == Y)
		return 0;

	for (i = Y->n - 1; i > 0; --i) {
		if (Y->p[i] != 0)
			break;
	}
	i++;

	X->s = Y->s;

	BN_CHECK(bn_grow(X, i));

	memset(X->p, 0, X->n * WORD_SIZE);
	memcpy(X->p, Y->p, i * WORD_SIZE);

cleanup:

	return ret;
}


/* Set the least significant bit of X */
inline void bn_set_lsb(BIGNUM *X)
{
	BN_REQUIRE(X, "X is null");
	BN_REQUIRE(X->n > 0, "X is empty");

	X->p[0] |= 1u;
}


/* Set the most significant bit of X */
inline void bn_set_msb(BIGNUM *X)
{
	BN_REQUIRE(X, "X is null");
	BN_REQUIRE(X->n > 0, "X is empty");

	X->p[X->n - 1] |= BN_MSB_MASK;
}


/* Returns the number of most significant bits in X */
inline int bn_msb(const BIGNUM *X)
{
	BN_REQUIRE(X, "X is null");

	int i, j;

	if (X->n == 0)
		return 0;
	
	for (i = X->n - 1; i > 0; --i) {
		if (X->p[i] != 0)
			break;
	}
	for (j = BIW - 1; j >= 0; --j) {
		if (((X->p[i] >> j) & 1) != 0)
			break;
	}

	return (i * BIW) + j + 1;
}


/* Returns the number of least significant trailing zeros in X */
inline int bn_lsb(const BIGNUM *X)
{
	BN_REQUIRE(X, "X is null");

#if defined(__has_builtin)
#if (WORD_SIZE == 4) && __has_builtin(__builtin_ctzl)
	#define bn_uint_ctzl __builtin_ctzl
#endif
#endif

#if defined(bn_uint_ctzl)
	int i;
	
	for (i = 0; i < X->n; ++i) {
		if (X->p[i] != 0)
			return i * BIW + bn_uint_ctzl(X->p[i]);
	}
#else
	int i, j, count = 0;

	for (i = 0; i < X->n; i++) {
		for (j = 0; j < (int)BIW; ++j, ++count) {
			if (((X->p[i] >> j) & 1) != 0)
				return count;
		}
	}
#endif

	return 0;
}


/* Returns 1 if X is even, 0 otherwise */
inline int bn_is_even(const BIGNUM *X)
{
	BN_REQUIRE(X, "X is null");
	BN_REQUIRE(X->n > 0, "X is empty");

	return (X->p[0] & 1u) == 0;
}


/* Returns 1 if X is odd, 0 otherwise */
inline int bn_is_odd(const BIGNUM *X)
{
	BN_REQUIRE(X, "X is null");
	BN_REQUIRE(X->n > 0, "X is empty");

	return (X->p[0] & 1u) == 1;
}


/* Returns 1 if X is positive, 0 otherwise */
inline int bn_is_pos(const BIGNUM *X)
{
	BN_REQUIRE(X, "X is null");
	
	return (X->s == 1);
}


/* Returns 1 if X is negative, 0 otherwise */
inline int bn_is_neg(const BIGNUM *X)
{
	BN_REQUIRE(X, "X is null");
	
	return (X->s == -1);
}


/* Returns 1 if X is zero/unallocated, 0 otherwise */
int bn_is_zero(const BIGNUM *X)
{
	BN_REQUIRE(X, "X is null");

	if (X->n == 0)
		return 1;
	
	for (size_t i = 0; i < X->n; ++i) {
		if (X->p[i] != 0)
			return 0;
	}
	return 1;
}


/* Compare unsigned values. Same as bn_cmp(abs(X), abs(Y)) */
int bn_cmp_abs(const BIGNUM *X, const BIGNUM *Y)
{
	BN_REQUIRE(X, "X is null");
	BN_REQUIRE(Y, "Y is null");
	
	size_t i, j;

	for (i = X->n; i > 0; --i) {
		if (X->p[i - 1] != 0)
			break;
	}

	for (j = Y->n; j > 0; --j) {
		if (Y->p[j - 1] != 0)
			break;
	}

	/* If i == j == 0, i.e. abs(X) == abs(Y),
	   we return 0 at the end of the function */
	if (i > j)
		return 1;
	if (j > i)
		return -1;

	for (; i > 0; --i) {
		if (X->p[i - 1] > Y->p[i - 1])
			return 1;
		if (X->p[i - 1] < Y->p[i - 1])
			return -1;
	}

	return 0; /* abs(X) == abs(Y) */
}


/* Compare signed values */
int bn_cmp(const BIGNUM *X, const BIGNUM *Y)
{
	BN_REQUIRE(X, "X is null");
	BN_REQUIRE(Y, "Y is null");
	
	size_t i, j;
	int X_s = X->s, Y_s = Y->s;

	for (i = X->n; i > 0; --i) {
		if (X->p[i - 1] != 0)
			break;
	}

	for (j = Y->n; j > 0; --j) {
		if (Y->p[j - 1] != 0)
			break;
	}

	if (i == 0 && j == 0)
		return 0;

	if (i > j)
		return X_s;
	if (j > i)
		return -Y_s;

	if (X_s > 0 && Y_s < 0)
		return 1;
	if (Y_s > 0 && X_s < 0)
		return -1;

	for (; i > 0; --i) {
		if (X->p[i - 1] > Y->p[i - 1])
			return X_s;
		if (X->p[i - 1] < Y->p[i - 1])
			return -X_s;
	}

	return 0; /* X == Y */
}


/* Compare unsigned values X and n */
int bn_cmp_udbl(const BIGNUM *X, const bn_udbl_t n)
{
	BN_REQUIRE(X, "X is null");
	
	size_t nw = sizeof(bn_udbl_t) / WORD_SIZE;
	BIGNUM N;
	bn_uint_t PN[nw];
	bn_udbl_t n_cpy = n;

	for (size_t i = 0; i < nw; ++i) {
		PN[i] = (bn_uint_t)n_cpy;
		n_cpy >>= BIW;
	}

	N.p = PN; N.n = nw; N.s = 1;

	return bn_cmp_abs(X, &N);
}


/* Compare signed values X and n */
int bn_cmp_sdbl(const BIGNUM *X, const bn_sdbl_t n)
{
	BN_REQUIRE(X, "X is null");

	size_t nw = sizeof(bn_udbl_t) / WORD_SIZE;
	BIGNUM N;
	bn_uint_t PN[nw];
	bn_udbl_t n_abs = bn_sdbl_abs(n);

	for (size_t i = 0; i < nw; ++i) {
		PN[i] = (bn_uint_t)n_abs;
		n_abs >>= BIW;
	}

	N.p = PN; N.n = nw;
	N.s = BN_DBL_TO_SIGN(n);

	return bn_cmp(X, &N);
}


/* Unsigned addition: X = abs(X) + abs(Y) [HAC 14.7] */
int bn_add_abs(BIGNUM *A, BIGNUM *B, BIGNUM *X)
{
	BN_REQUIRE(A, "A is null");
	BN_REQUIRE(B, "B is null");
	BN_REQUIRE(X, "X is null");

	int ret = 0;
	size_t i, j;
	bn_uint_t c, t;

	if (X == B) {
		BIGNUM *T = A;
		A = X;
		B = T;
	}

	if (X != A)
		BN_CHECK(bn_assign(X, A));

	/* X is always positive as a result of unsigned addition */
	X->s = 1;

	for (i = B->n; i > 0; --i) {
		if (B->p[i - 1] != 0)
			break;
	}

	if (i == 0)
		return 0;
	
	/* At this point we have X == A but it is possible that B->n > A->n,
	   in which case we must expand X to i limbs where i is the number of
	   non-zero limbs of B */
	BN_CHECK(bn_grow(X, i));

	c = 0;
	for (j = 0; j < i; ++j) {
		t = c + X->p[j];
		c = (t < X->p[j]);
		t += B->p[j];
		c += (t < B->p[j]);
		X->p[j] = t;
	}

	/* Propogate the carry */
	while (c) {
		if (i >= X->n)
			BN_CHECK(bn_grow(X, i + 1));

		X->p[i] += c;
		c = (X->p[i] < c);
		i++;
	}

cleanup:

	return ret;
}


/* Helper function for bn_sub */
static void bn_sub_hlp(int n, bn_uint_t *s, bn_uint_t *d)
{
	int i;
	bn_uint_t c, z;

	for (i = c = 0; i < n; ++i, ++s, ++d) {
		z = (*d < c);
		*d -= c;
		c = (*d < *s) + z;
		*d -= *s;
	}

	while (c != 0) {
		z = (*d < c);
		*d -= c;
		c = z;
		i++;
		d++;
	}
}

/* Unsigned subtraction: X = abs(A) - abs(B) [HAC 14.9] */
int bn_sub_abs(BIGNUM *A, BIGNUM *B, BIGNUM *X)
{
	BN_REQUIRE(A, "A is null");
	BN_REQUIRE(B, "B is null");
	BN_REQUIRE(X, "X is null");

	BIGNUM TB;
	int ret = 0, i;

	if (bn_cmp_abs(A, B) < 0)
		return BN_ERR_BAD_INPUT_DATA;

	bn_init(&TB, NULL);

	if (X == B) {
		BN_CHECK(bn_assign(&TB, B));
		B = &TB;
	}

	if (X != A)
		BN_CHECK(bn_assign(X, A));

	for (i = B->n - 1; i >= 0; --i)
		if (B->p[i] != 0)
			break;

	bn_sub_hlp(i + 1, B->p, X->p);

	X->s = 1;

cleanup:

	bn_zfree(&TB, NULL);

	return ret;
}


/* Common function for signed addition and subtraction:
   X = A + B * neg, where neg is 1 or -1 */
static int bn_add_sub(BIGNUM *A, BIGNUM *B, BIGNUM *X, int neg)
{
	BN_REQUIRE(A, "A is null");
	BN_REQUIRE(B, "B is null");
	BN_REQUIRE(X, "X is null");
	
	int ret = 0, s;

	s = A->s;
	if (A->s * B->s * neg < 0) {
		int cmp = bn_cmp_abs(A, B);
		if (cmp >= 0) {
			BN_CHECK(bn_sub_abs(A, B, X));
			/* If abs(A) == abs(B), the result is zero and we must set
			   s to 1, otherwise since abs(A) > abs(B), the sign is the
			   sign of A */
			X->s = (cmp == 0) ? 1 : s;
		} else {
			BN_CHECK(bn_sub_abs(B, A, X));
			X->s = -s;
		}
	} else {
		BN_CHECK(bn_add_abs(A, B, X));
		X->s = s;
	}

cleanup:

	return ret;
}


/* Signed addition: X = A + B */
int bn_add(BIGNUM *A, BIGNUM *B, BIGNUM *X)
{
	return bn_add_sub(A, B, X, 1);
}


/* Signed subtraction: X = A - B */
int bn_sub(BIGNUM *A, BIGNUM *B, BIGNUM *X)
{
	return bn_add_sub(A, B, X, -1);
}


/* Signed addition: X = A + b */
int bn_add_sdbl(BIGNUM *A, const bn_sdbl_t b, BIGNUM *X)
{
	int ret = 0;
	BIGNUM B;

	bn_init(&B, NULL);
	BN_CHECK(bn_from_sdbl(&B, b));

	ret = bn_add(A, &B, X);

cleanup:

	bn_zfree(&B, NULL);

	return ret;
}


/* Signed subtraction: X = A - b */
int bn_sub_sdbl(BIGNUM *A, const bn_sdbl_t b, BIGNUM *X)
{
	int ret = 0;
	BIGNUM B;

	bn_init(&B, NULL);
	BN_CHECK(bn_from_sdbl(&B, b));

	ret = bn_sub(A, &B, X);

cleanup:

	bn_zfree(&B, NULL);

	return ret;
}


/* Left-shift: X = X << count */
int bn_lshift(BIGNUM *X, const int count)
{
	BN_REQUIRE(X, "X is null");

	if (count < 0)
		return BN_ERR_BAD_INPUT_DATA;

	int ret = 0;
	int i, c0, c1;
	bn_uint_t r0 = 0, r1;

	c0 = count / BIW;
	c1 = count & (BIW - 1);

	i = bn_msb(X) + count;

	if (X->n * BIW < i)
		BN_CHECK(bn_grow(X, BN_BITS_TO_LIMBS(i)));

	/* shift by (count / WORD_SIZE) */
	if (c0 > 0) {
		for (i = X->n - 1; i >= c0; --i)
			X->p[i] = X->p[i - c0];

		for (; i >= 0; --i)
			X->p[i] = 0;
	}

	/* shift by (count % WORD_SIZE) */
	if (c1 > 0) {
		for (i = c0; i < X->n; ++i) {
			r1 = X->p[i] >> (BIW - c1);
			X->p[i] <<= c1;
			X->p[i] |= r0;
			r0 = r1;
		}
	}

cleanup:

	return ret;
}


/* Right shift: X = X >> count */
int bn_rshift(BIGNUM *X, const int count)
{
	BN_REQUIRE(X, "X is null");

	if (count < 0)
		return BN_ERR_BAD_INPUT_DATA;

	int n = (int)X->n, i, c0, c1;
	bn_uint_t r0 = 0, r1;

	c0 = count / BIW;
	c1 = count & (BIW - 1);

	if (c0 > n || (c0 == n && c1 > 0)) {
		memset(X, 0, n * WORD_SIZE);
		return 0;
	}

	/* shift by (count / WORD_SIZE) */
	if (c0 > 0) {
		for (i = 0; i < n - c0; ++i)
			X->p[i] = X->p[i + c0];

		for (; i < n; ++i)
			X->p[i] = 0;
	}

	/* shift by (count % WORD_SIZE) */
	if (c1 > 0) {
		for (i = n - 1; i >= 0; --i) {
			r1 = X->p[i] << (BIW - c1);
			X->p[i] >>= c1;
			X->p[i] |= r0;
			r0 = r1;
		}
	}

	return 0;
}


#define BN_KARATSUBA_CUTOFF 80
#define BN_KARATSUBA_SQUARE_CUTOFF 100

#define MLAC                      \
	r   = *(s++) * (bn_udbl_t) b; \
	r0  = r;                      \
	r1  = r >> BIW;               \
	r0 += c;  r1 += (r0 <  c);    \
	r0 += *d; r1 += (r0 < *d);    \
	c = r1; *(d++) = r0;

static inline void bn_mul_1_hlp(int i, bn_uint_t *s, bn_uint_t *d, bn_uint_t b)
{
	bn_uint_t c = 0; /* carry */

	for (; i >= 16; i -= 16) {
		bn_udbl_t r;
		bn_uint_t r0, r1;
		MLAC MLAC
		MLAC MLAC
		MLAC MLAC
		MLAC MLAC
		MLAC MLAC
		MLAC MLAC
		MLAC MLAC
		MLAC MLAC
	}

	for (; i >= 8; i -= 8) {
		bn_udbl_t r;
		bn_uint_t r0, r1;
		MLAC MLAC
		MLAC MLAC
		MLAC MLAC
		MLAC MLAC
	}

	for (; i > 0; i--) {
		bn_udbl_t r;
		bn_uint_t r0, r1;
		MLAC
	}

	do {
		*d += c;
		c = (*d < c);
		d++;
	} while (c != 0);
}

/* Pen-and-paper multiplication [HAC 14.12] */
int bn_mul_1(BIGNUM *A, BIGNUM *B, BIGNUM *X)
{
	int ret = 0, i, j;

	for (i = (int)A->n - 1; i >= 0; i--)
		if (A->p[i] != 0)
			break;

	for (j = (int)B->n - 1; j >= 0; j--)
		if (B->p[j] != 0)
			break;

	BN_CHECK(bn_grow(X, i + j + 2));
	BN_CHECK(bn_from_udbl(X, 0));

	for (i++; j >= 0; j--)
		bn_mul_1_hlp(i, A->p, X->p + j, B->p[j]);

cleanup:

	return ret;
}

int bn_mul_hlp(BIGNUM *A, BIGNUM *B, BIGNUM *X, int alen, int blen);

/* Karatsuba multiplication using three half-size multiplications

   Let R represent the radix (i.e. 2**BIW) and let n represent
   half the number of limbs/digits/words in min(A, B).

   A and B can be represented as:
   A = A1 * R**n + A0
   B = B1 * R**n + B0

   Then,
   A * B =>
   A1B1 * R**2m + ((A1 + A0)(B1 + B0) - (A0B0 + A1B1)) * R**n + A0B0

   Note: Since we only need to compute A0B0, A1B1 and
   (A1 + A0)(B1 + B0) once each, the whole product can be computed
   with only three half-size multiplications, saving 1/4th or 25%
   of the single precision multiplications.

   Note: This function can make a (recursive) call to itself
   - We perform the 'single digit' multiplications by calling 
     back the generic multiply function, which can lead us back
	 into this function if a0, a1, b0 or b1 are above the cutoff.
   - This 'divide-and-conquer' approach results in the famous
     O(n**log(3)) or O(n**1.584) elementary operations, making
	 it asymptotically faster than the O(n**2) grade school 
	algorithm. */
int bn_mul_2(BIGNUM *A, BIGNUM *B, BIGNUM *X)
{
	int ret = 0, alen, blen, a1, a0, b1, b0, R;
	BIGNUM A1, A0, B1, B0, A1B1, A0B0, T;

	alen = A->n; blen = B->n;

	/* half the min # of limbs (we have ensured alen <= blen) */
	R = alen >> 1;

	a0 = R; a1 = alen - R;
	b0 = R; b1 = blen - R;

	bn_init(&A1, &A0, &B1, &B0, &A0B0, &A1B1, &T, NULL);

	/* Allocate memory for temps */
	BN_CHECK(bn_grow(&A0, a0));
	BN_CHECK(bn_grow(&B0, b0));
	BN_CHECK(bn_grow(&A1, a1));
	BN_CHECK(bn_grow(&B1, b1));

	/* We have guaranteed that these temps are big enough,
	   so we populate directly using memcpy */
	memcpy(A0.p, A->p, a0 * WORD_SIZE);
	memcpy(B0.p, B->p, b0 * WORD_SIZE);
	memcpy(A1.p, A->p + a0, a1 * WORD_SIZE);
	memcpy(B1.p, B->p + b0, b1 * WORD_SIZE);

	/* Compute A0*B0 and A1*B1 */
	BN_CHECK(bn_mul_hlp(&A0, &B0, &A0B0, a0, b0));
	BN_CHECK(bn_mul_hlp(&A1, &B1, &A1B1, a1, b1));

	/* A1 = A1 + A0 */
	BN_CHECK(bn_add_abs(&A1, &A0, &A1));
	/* B1 = B1 + B0 */
	BN_CHECK(bn_add_abs(&B1, &B0, &B1));

	/* B1 = (A1 + A0)*(B1 + B0) */
	BN_CHECK(bn_mul_hlp(&A1, &B1, &B1, A1.n, B1.n));
	/* A1 = A1*B1 + A0*B0 */
	BN_CHECK(bn_add_abs(&A1B1, &A0B0, &A1));

	/* T = (A1 + A0)*(B1 + B0) - (A1*B1 + A0*B0) */
	BN_CHECK(bn_sub(&B1, &A1, &T));

	/* T = ((A1 + A0)*(B1 + B0) - (A1*B1 + A0*B0)) << R */
	BN_CHECK(bn_lshift(&T, R * BIW));
	/* A1B1 = A1*B1 << 2R */
	BN_CHECK(bn_lshift(&A1B1, (2 * R) * BIW));

	/* T = A0*B0 + T */
	BN_CHECK(bn_add_abs(&A0B0, &T, &T)); 
	/* X = A0*B0 + T + A1*B1 */
	BN_CHECK(bn_add_abs(&T, &A1B1, X));


cleanup:

	bn_init(&A1, &A0, &B1, &B0, &A0B0, &A1B1, &T, NULL);

	return ret;
}

/* Helper function for generic multiplication */
int bn_mul_hlp(BIGNUM *A, BIGNUM *B, BIGNUM *X, int alen, int blen)
{
	int ret = 0, i;

	if (alen == 0 || blen == 0) {
		BN_CHECK(bn_grow(X, alen + blen));
		memset(X->p, 0, (alen + blen) * WORD_SIZE);
		return 0;
	}

	/* Rearrange so that B is bigger in size than A */
	if (alen > blen) {
		BIGNUM *T = A;
		A = B;
		B = T;

		i = alen;
		alen = blen;
		blen = i;
	}

	/* Check size requirements - use the Karatsuba method if the
	   smaller number is greater in size than BN_KARATSUBA_CUTOFF */
	i = (A == B) ? BN_KARATSUBA_SQUARE_CUTOFF
				 : BN_KARATSUBA_CUTOFF;

	if (alen >= i)
		/* Use Karatsuba multiplication */
		return bn_mul_2(A, B, X);
	else
		/* Use gradeschool multiplication */
		return bn_mul_1(A, B, X);

cleanup:

	return ret;
}

/* Signed multiplication: X = A * B */
int bn_mul(BIGNUM *A, BIGNUM *B, BIGNUM *X)
{
	BN_REQUIRE(A, "A is null");
	BN_REQUIRE(B, "B is null");
	BN_REQUIRE(X, "X is null");

	int ret = 0, alen, blen;
	BIGNUM TA, TB;

	bn_init(&TA, &TB, NULL);

	/* In any case A->n + B->n limbs will always be enough to
	   hold the result, but we keep two extra limbs to prevent
	   a buffer overflow in bn_mul_1_hlp */
	if (A->n + B->n + 2 >= BN_MAX_LIMBS)
		return BN_ERR_NOT_ENOUGH_LIMBS;

	if (bn_is_zero(A) || bn_is_zero(B))
		X->s = 1;
	else
		X->s = A->s * B->s;

	if (X == A) {
		BN_CHECK(bn_assign(&TA, A));
		A = &TA;
	}

	if (X == B) {
		BN_CHECK(bn_assign(&TB, B));
		B = &TB;
	}

	alen = A->n; blen = B->n;

	ret = bn_mul_hlp(A, B, X, alen, blen);

cleanup:

	bn_zfree(&TA, &TB, NULL);
	
	return ret;
}


/* Signed multiplication: X = A * b */
int bn_mul_sdbl(BIGNUM *A, const bn_sdbl_t b, BIGNUM *X)
{
	BN_REQUIRE(A, "A is null");
	BN_REQUIRE(X, "X is null");

	int ret = 0;
	BIGNUM B;

	bn_init(&B, NULL);
	BN_CHECK(bn_from_sdbl(&B, b));

	ret = bn_mul(A, &B, X);

cleanup:

	bn_zfree(&B, NULL);

	return ret;
}


/* Integer square-root: X = isqrt(A) */
int bn_isqrt(BIGNUM *A, BIGNUM *X)
{
	BN_REQUIRE(A, "A is null");
	BN_REQUIRE(X, "X is null");

	int ret = 0;
	BIGNUM L, M, H, T;

	if (bn_is_neg(A))
		return BN_ERR_NEGATIVE_VALUE;

	bn_init(&L, &H, &M, &T, NULL);

	BN_CHECK(bn_assign(&H, A));
	BN_CHECK(bn_assign(&M, A));
	BN_CHECK(bn_rshift(&M, 1));
	BN_CHECK(bn_add_sdbl(&M, 1, &M));

	while (bn_cmp_abs(&H, &L) > 0) {
		BN_CHECK(bn_mul(&M, &M, &T));

		if (bn_cmp_abs(&T, A) > 0) {
			BN_CHECK(bn_assign(&H, &M));
			BN_CHECK(bn_sub_sdbl(&H, 1, &H));
		} else {
			BN_CHECK(bn_assign(&L, &M));
		}

		BN_CHECK(bn_sub(&H, &L, &M));
		BN_CHECK(bn_rshift(&M, 1));
		BN_CHECK(bn_add(&L, &M, &M));
		BN_CHECK(bn_add_sdbl(&M, 1, &M));
	}

	BN_CHECK(bn_assign(X, &L));

cleanup:

	bn_zfree(&L, &H, &M, &T, NULL);

	return ret;
}


/* Division: A = Q * B + R  [HAC 14.20] */
int bn_div(BIGNUM *A, BIGNUM *B, BIGNUM *Q, BIGNUM *R)
{
	BN_REQUIRE(A, "A is null");
	BN_REQUIRE(B, "B is null");
	BN_REQUIRE(Q || R, "both Q and R are null");

	int ret = 0, i, n, t, k;
	BIGNUM X, Y, Z, T1, T2;
	bn_uint_t TP2[3];

	if (bn_is_zero(B))
		return BN_ERR_DIVISION_BY_ZERO;

	bn_init(&X, &Y, &Z, &T1, NULL);

	/* T2 is used for comparison and we will only ever use 3 limbs
	   that are assigned explicitly, hence it is safe to use stack
	   memory since T2 will not grow */
	T2.s = 1;
	T2.n = sizeof(TP2) / sizeof(*TP2);
	T2.p = TP2;

	if (bn_cmp_abs(A, B) < 0) {
		if (Q != NULL)
			BN_CHECK(bn_from_udbl(Q, 0));
		if (R != NULL)
			BN_CHECK(bn_assign(R, A));
		return 0;
	}

	BN_CHECK(bn_assign(&X, A));
	BN_CHECK(bn_assign(&Y, B));
	X.s = Y.s = 1;

	BN_CHECK(bn_grow(&Z, A->n + 2));
	BN_CHECK(bn_from_udbl(&Z, 0));
	BN_CHECK(bn_grow(&T1, A->n + 2));

	k = bn_msb(&Y) % BIW;
	if (k < (int)BIW - 1) {
		k = BIW - 1 - k;
		BN_CHECK(bn_lshift(&X, k));
		BN_CHECK(bn_lshift(&Y, k));
	} else {
		k = 0;
	}

	n = X.n - 1;
	t = Y.n - 1;
	BN_CHECK(bn_lshift(&Y, BIW * (n - t)));

	while (bn_cmp(&X, &Y) >= 0) {
		Z.p[n - t]++;
		BN_CHECK(bn_sub(&X, &Y, &X));
	}
	BN_CHECK(bn_rshift(&Y, BIW * (n - t)));

	for (i = n; i > t; --i) {
		if (X.p[i] >= Y.p[t])
			Z.p[i - t - 1] = ~(bn_uint_t)0u;
		else {
			bn_udbl_t r;
			r = (bn_udbl_t)X.p[i] << BIW;
			r |= (bn_udbl_t)X.p[i - 1];
			r /= Y.p[t];
			if (r > ((bn_udbl_t)1u << BIW) - 1)
				r = ((bn_udbl_t)1u << BIW) - 1;
			Z.p[i - t - 1] = (bn_uint_t)r;
		}

		T2.p[0] = (i < 2) ? 0 : X.p[i - 2];
		T2.p[1] = (i < 1) ? 0 : X.p[i - 1];
		T2.p[2] = X.p[i];

		Z.p[i - t - 1]++;
		do {
			Z.p[i - t - 1]--;

			BN_CHECK(bn_from_udbl(&T1, 0));
			T1.p[0] = (t < 1) ? 0 : Y.p[t - 1];
			T1.p[1] = Y.p[t];
			BN_CHECK(bn_mul_sdbl(&T1, Z.p[i - t - 1], &T1));
		} while (bn_cmp(&T1, &T2) > 0);

		BN_CHECK(bn_mul_sdbl(&Y, Z.p[i - t - 1], &T1));
		BN_CHECK(bn_lshift(&T1, BIW * (i - t - 1)));
		BN_CHECK(bn_sub(&X, &T1, &X));

		if (bn_cmp_sdbl(&X, 0) < 0) {
			BN_CHECK(bn_assign(&T1, &Y));
			BN_CHECK(bn_lshift(&T1, BIW * (i - t - 1)));
			BN_CHECK(bn_add(&X, &T1, &X));
			Z.p[i - t - 1]--;
		}
	}

	if (Q != NULL) {
		BN_CHECK(bn_assign(Q, &Z));
		Q->s = A->s * B->s;
	}

	if (R != NULL) {
		BN_CHECK(bn_rshift(&X, k));
		BN_CHECK(bn_assign(R, &X));

		R->s = A->s;
		if (bn_cmp_sdbl(R, 0))
			R->s = 1;
	}

cleanup:

	bn_zfree(&X, &Y, &Z, &T1, NULL);

	return ret;
}


/* Division: A = Q * b + R */
int bn_div_sdbl(BIGNUM *A, const bn_sdbl_t b, BIGNUM *Q, BIGNUM *R)
{
	BN_REQUIRE(A, "X is null");
	BN_REQUIRE(Q, "Q is null");
	BN_REQUIRE(Q || R, "both Q and R are null");

	int ret = 0;
	BIGNUM B;

	bn_init(&B, NULL);
	BN_CHECK(bn_from_sdbl(&B, b));

	ret = bn_div(A, &B, Q, R);

cleanup:
	bn_zfree(&B, NULL);

	return ret;
}


/* Modulo: R = A (mod B) */
int bn_mod(BIGNUM *A, BIGNUM *B, BIGNUM *R)
{
	BN_REQUIRE(A, "A is null");
	BN_REQUIRE(B, "B is null");
	BN_REQUIRE(R, "R is null");

	int ret = 0;

	if (bn_cmp_sdbl(B, 0) < 0)
		return BN_ERR_NEGATIVE_VALUE;

	BN_CHECK(bn_div(A, B, NULL, R));

	while (bn_cmp_sdbl(R, 0) < 0)
		BN_CHECK(bn_add(R, B, R));

	while (bn_cmp(R, B) >= 0)
		BN_CHECK(bn_sub(R, B, R));

cleanup:

	return ret;
}


/* Integer modulo: r = A (mod b) */
int bn_mod_uint(BIGNUM *A, bn_uint_t b, bn_uint_t *r)
{
	BN_REQUIRE(A, "A is null");
	BN_REQUIRE(r, "r is null");
	BN_REQUIRE(A->n > 0, "A is empty");

	int i;
	bn_uint_t x, y, z;

	if (b == 0)
		return BN_ERR_DIVISION_BY_ZERO;
	
	if (A->n == 0 || bn_is_zero(A)) {
		*r = 0;
		return 0;
	}
	
	if (b == 1) {
		*r = 0;
		return 0;
	}

	if (b == 2) {
		*r = A->p[0] & 1;
		return 0;
	}

	for (i = A->n - 1, y = 0; i >= 0; --i) {
		x = A->p[i];
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


/* Greatest common divisor: G = gcd(A, B) [HAC 14.54] */
int bn_gcd(BIGNUM *A, BIGNUM *B, BIGNUM *G)
{
	BN_REQUIRE(A, "A is null");
	BN_REQUIRE(B, "B is null");
	BN_REQUIRE(G, "G is null");

	int ret = 0, l;
	BIGNUM TG, TA, TB;

	bn_init(&TA, &TB, &TG, NULL);

	BN_CHECK(bn_assign(&TA, A));
	BN_CHECK(bn_assign(&TB, B));

	l = min(bn_lsb(&TA), bn_lsb(&TB));

	BN_CHECK(bn_rshift(&TA, l));
	BN_CHECK(bn_rshift(&TB, l));

	TA.s = TB.s = 1;

	while (bn_cmp_udbl(&TA, 0) != 0) {
		BN_CHECK(bn_rshift(&TA, bn_lsb(&TA)));
		BN_CHECK(bn_rshift(&TB, bn_lsb(&TB)));

		if (bn_cmp(&TA, &TB) >= 0) {
			BN_CHECK(bn_sub_abs(&TA, &TB, &TA));
			BN_CHECK(bn_rshift(&TA, 1));
		} else {
			BN_CHECK(bn_sub_abs(&TB, &TA, &TB));
			BN_CHECK(bn_rshift(&TB, 1));
		}
	}

	BN_CHECK(bn_lshift(&TB, l));
	BN_CHECK(bn_assign(G, &TB));

cleanup:

	bn_zfree(&TA, &TB, &TG, NULL);

	return ret;
}


/* Modular inverse: X = A^-1 mod N  [HAC 14.61 / 14.64] */
int bn_inv_mod(BIGNUM *A, BIGNUM *N, BIGNUM *X)
{
	BN_REQUIRE(A, "A is null");
	BN_REQUIRE(N, "N is null");
	BN_REQUIRE(X, "X is null");

	int ret = 0;
	BIGNUM G, TA, TU, U1, U2, TB, TV, V1, V2;

	if (bn_cmp_sdbl(N, 1) <= 0)
		return BN_ERR_BAD_INPUT_DATA;

	bn_init(&TA, &TU, &U1, &U2, &G, &TB, &TV, &V1, &V2, NULL);

	BN_CHECK(bn_gcd(A, N, &G));

	if (bn_cmp_sdbl(&G, 1) != 0) {
		ret = -1;
		goto cleanup;
	}

	BN_CHECK(bn_mod(A, N, &TA));
	BN_CHECK(bn_assign(&TU, &TA));
	BN_CHECK(bn_assign(&TB, N));
	BN_CHECK(bn_assign(&TV, N));

	BN_CHECK(bn_from_udbl(&U1, 1));
	BN_CHECK(bn_from_udbl(&U2, 0));
	BN_CHECK(bn_from_udbl(&V1, 0));
	BN_CHECK(bn_from_udbl(&V2, 1));

	do {
		while ((TU.p[0] & 1) == 0) {
			BN_CHECK(bn_rshift(&TU, 1));

			if ((U1.p[0] & 1) != 0 || (U2.p[0] & 1) != 0) {
				BN_CHECK(bn_add(&U1, &TB, &U1));
				BN_CHECK(bn_sub(&U2, &TA, &U2));
			}

			BN_CHECK(bn_rshift(&U1, 1));
			BN_CHECK(bn_rshift(&U2, 1));
		}

		while ((TV.p[0] & 1) == 0) {
			BN_CHECK(bn_rshift(&TV, 1));

			if ((V1.p[0] & 1) != 0 || (V2.p[0] & 1) != 0) {
				BN_CHECK(bn_add(&V1, &TB, &V1));
				BN_CHECK(bn_sub(&V2, &TA, &V2));
			}

			BN_CHECK(bn_rshift(&V1, 1));
			BN_CHECK(bn_rshift(&V2, 1));
		}

		if (bn_cmp(&TU, &TV) >= 0) {
			BN_CHECK(bn_sub(&TU, &TV, &TU));
			BN_CHECK(bn_sub(&U1, &V1, &U1));
			BN_CHECK(bn_sub(&U2, &V2, &U2));
		} else {
			BN_CHECK(bn_sub(&TV, &TU, &TV));
			BN_CHECK(bn_sub(&V1, &U1, &V1));
			BN_CHECK(bn_sub(&V2, &U2, &V2));
		}
	} while (bn_cmp_sdbl(&TU, 0) != 0);

	while (bn_cmp_sdbl(&V1, 0) < 0)
		BN_CHECK(bn_add(&V1, N, &V1));

	while (bn_cmp(&V1, N) >= 0)
		BN_CHECK(bn_sub(&V1, N, &V1));

	BN_CHECK(bn_assign(X, &V1));

cleanup:

	bn_zfree(&TA, &TU, &U1, &U2, &G, &TB, &TV, &V1, &V2, NULL);

	return ret;
}


/* Fast Montgomery initialization (thanks to Tom St Denis) */
static void bn_montg_init(bn_uint_t *mm, BIGNUM *N)
{
	bn_uint_t x, m0 = N->p[0];

	x = m0;
	x += ((m0 + 2) & 4) << 1;
	x *= (2 - (m0 * x));

	if (BIW >= 16)
		x *= (2 - (m0 * x));
	if (BIW >= 32)
		x *= (2 - (m0 * x));
	if (BIW >= 64)
		x *= (2 - (m0 * x));

	*mm = ~x + 1;
}


/* Montgomery multiplication: A = A * B * R^-1 (mod N)  [HAC 14.36] */
static void bn_montmul(BIGNUM *A, BIGNUM *B, BIGNUM *N, bn_uint_t mm, BIGNUM *T)
{
	int i, n, m;
	bn_uint_t u0, u1, *d;

	memset(T->p, 0, T->n * WORD_SIZE);

	d = T->p;
	n = N->n;
	m = min(B->n, n);

	for (i = 0; i < n; i++) {
		/* T = (T + u0*B + u1*N) / 2^BIW */
		u0 = A->p[i];
		u1 = (d[0] + u0 * B->p[0]) * mm;

		bn_mul_1_hlp(m, B->p, d, u0);
		bn_mul_1_hlp(n, N->p, d, u1);

		*d++ = u0;
		d[n + 1] = 0;
	}

	memcpy(A->p, d, (n + 1) * WORD_SIZE);

	if (bn_cmp_abs(A, N) >= 0)
		bn_sub_hlp(n, N->p, A->p);
	else
		bn_sub_hlp(n, A->p, T->p);
}


/* Montgomery reduction: A = A * R^-1 (mod N) */
static void bn_montred(BIGNUM *A, BIGNUM *N, bn_uint_t mm, BIGNUM *T)
{
	bn_uint_t z = 1;
	BIGNUM U;

	U.n = U.s = z;
	U.p = &z;

	bn_montmul(A, &U, N, mm, T);
}


/* Sliding-window exponentiation: X = A^E (mod N) [HAC 14.85] */
int bn_exp_mod(BIGNUM *A, BIGNUM *E, BIGNUM *N, BIGNUM *_RR, BIGNUM *X)
{
	BN_REQUIRE(X, "X is null");
	BN_REQUIRE(E, "E is null");
	BN_REQUIRE(N, "N is null");
	BN_REQUIRE(X, "X is null");

	int ret = 0, i, j, wsize, wbits;
	int bufsize, nblimbs, nbits;
	bn_uint_t ei, mm, state;
	BIGNUM RR, T, W[64];

	if (bn_cmp_sdbl(N, 0) < 0 || (N->p[0] & 1u) == 0u)
		return BN_ERR_BAD_INPUT_DATA;

	/* Init temps and window size */
	bn_init(&RR, &T, NULL);
	bn_montg_init(&mm, N);
	memset(W, 0, sizeof(W));

	i = bn_msb(E);
	wsize = (i > 671) ? 6 :
			(i > 239) ? 5 :
			 (i > 79) ? 4 :
			 (i > 23) ? 3 :
						1;

	j = N->n + 1;
	BN_CHECK(bn_grow(X, j));
	BN_CHECK(bn_grow(&W[1], j));
	BN_CHECK(bn_grow(&T, j * 2));

	/* If 1st call, pre-compute R^2 (mod N) */
	if (_RR == NULL || _RR->p == NULL) {
		BN_CHECK(bn_from_udbl(&RR, 1));
		BN_CHECK(bn_lshift(&RR, N->n * 2 * BIW));
		BN_CHECK(bn_mod(&RR, N, &RR));

		if (_RR != NULL)
			memcpy(_RR, &RR, sizeof(BIGNUM));
	} else {
		memcpy(&RR, _RR, sizeof(BIGNUM));
	}

	/* W[1] = A * R^2 * R^-1 (mod N) = A * R (mod N) */
	if (bn_cmp(A, N) >= 0)
		BN_CHECK(bn_mod(A, N, &W[1]));
	else
		BN_CHECK(bn_assign(&W[1], A));

	bn_montmul(&W[1], &RR, N, mm, &T);

	/* X = R^2 * R^-1 (mod N) = R (mod N) */
	BN_CHECK(bn_assign(X, &RR));
	bn_montred(X, N, mm, &T);

	if (wsize > 1) {
		/* W[1 << (wsize - 1)] = W[1] ^ (wsize - 1) */
		j = 1 << (wsize - 1);

		BN_CHECK(bn_grow(&W[j], N->n + 1));
		BN_CHECK(bn_assign(&W[j], &W[1]));

		for (i = 0; i < wsize - 1; i++)
			bn_montmul(&W[j], &W[j], N, mm, &T);

		/* W[i] = W[i - 1] * W[1] */
		for (i = j + 1; i < (1 << wsize); i++) {
			BN_CHECK(bn_grow(&W[i], N->n + 1));
			BN_CHECK(bn_assign(&W[i], &W[i - 1]));

			bn_montmul(&W[i], &W[1], N, mm, &T);
		}
	}

	nblimbs = E->n;
	bufsize = 0;
	nbits = 0;
	wbits = 0;
	state = 0;

	while (1) {
		if (bufsize == 0) {
			if (nblimbs-- == 0)
				break;

			bufsize = sizeof(bn_uint_t) << 3;
		}

		bufsize--;

		ei = (E->p[nblimbs] >> bufsize) & 1;

		/* skip leading 0s */
		if (ei == 0 && state == 0)
			continue;

		if (ei == 0 && state == 1) {
			/* out of window, square X */
			bn_montmul(X, X, N, mm, &T);
			continue;
		}

		/* add ei to current window */
		state = 2;

		nbits++;
		wbits |= (ei << (wsize - nbits));

		if (nbits == wsize) {
			/* X = X^wsize R^-1 (mod N) */
			for (i = 0; i < wsize; i++)
				bn_montmul(X, X, N, mm, &T);

			/* X = X * W[wbits] R^-1 (mod N) */
			bn_montmul(X, &W[wbits], N, mm, &T);

			state--;
			nbits = 0;
			wbits = 0;
		}
	}

	/* process the remaining bits */
	for (i = 0; i < nbits; i++) {
		bn_montmul(X, X, N, mm, &T);

		wbits <<= 1;

		if ((wbits & (1 << wsize)) != 0)
			bn_montmul(X, &W[1], N, mm, &T);
	}

	/* X = A^E * R * R^-1 (mod N) = A^E (mod N) */
	bn_montred(X, N, mm, &T);

cleanup:

	for (i = (1 << (wsize - 1)); i < (1 << wsize); i++)
		bn_zfree(&W[i], NULL);

	if (_RR != NULL)
		bn_zfree(&W[1], &T, NULL);
	else
		bn_zfree(&W[1], &T, &RR, NULL);

	return ret;
}


#define N_PRIMES 1024

static const unsigned short primes[N_PRIMES] = {
	   2u,     3u,     5u,     7u,    11u,    13u,    17u,    19u,
	  23u,    29u,    31u,    37u,    41u,    43u,    47u,    53u,
	  59u,    61u,    67u,    71u,    73u,    79u,    83u,    89u,
	  97u,   101u,   103u,   107u,   109u,   113u,   127u,   131u,
	 137u,   139u,   149u,   151u,   157u,   163u,   167u,   173u,
	 179u,   181u,   191u,   193u,   197u,   199u,   211u,   223u,
	 227u,   229u,   233u,   239u,   241u,   251u,   257u,   263u,
	 269u,   271u,   277u,   281u,   283u,   293u,   307u,   311u,
	 313u,   317u,   331u,   337u,   347u,   349u,   353u,   359u,
	 367u,   373u,   379u,   383u,   389u,   397u,   401u,   409u,
	 419u,   421u,   431u,   433u,   439u,   443u,   449u,   457u,
	 461u,   463u,   467u,   479u,   487u,   491u,   499u,   503u,
	 509u,   521u,   523u,   541u,   547u,   557u,   563u,   569u,
	 571u,   577u,   587u,   593u,   599u,   601u,   607u,   613u,
	 617u,   619u,   631u,   641u,   643u,   647u,   653u,   659u,
	 661u,   673u,   677u,   683u,   691u,   701u,   709u,   719u,
	 727u,   733u,   739u,   743u,   751u,   757u,   761u,   769u,
	 773u,   787u,   797u,   809u,   811u,   821u,   823u,   827u,
	 829u,   839u,   853u,   857u,   859u,   863u,   877u,   881u,
	 883u,   887u,   907u,   911u,   919u,   929u,   937u,   941u,
	 947u,   953u,   967u,   971u,   977u,   983u,   991u,   997u,
	1009u,  1013u,  1019u,  1021u,  1031u,  1033u,  1039u,  1049u,
	1051u,  1061u,  1063u,  1069u,  1087u,  1091u,  1093u,  1097u,
	1103u,  1109u,  1117u,  1123u,  1129u,  1151u,  1153u,  1163u,
	1171u,  1181u,  1187u,  1193u,  1201u,  1213u,  1217u,  1223u,
	1229u,  1231u,  1237u,  1249u,  1259u,  1277u,  1279u,  1283u,
	1289u,  1291u,  1297u,  1301u,  1303u,  1307u,  1319u,  1321u,
	1327u,  1361u,  1367u,  1373u,  1381u,  1399u,  1409u,  1423u,
	1427u,  1429u,  1433u,  1439u,  1447u,  1451u,  1453u,  1459u,
	1471u,  1481u,  1483u,  1487u,  1489u,  1493u,  1499u,  1511u,
	1523u,  1531u,  1543u,  1549u,  1553u,  1559u,  1567u,  1571u,
	1579u,  1583u,  1597u,  1601u,  1607u,  1609u,  1613u,  1619u,
	1621u,  1627u,  1637u,  1657u,  1663u,  1667u,  1669u,  1693u,
	1697u,  1699u,  1709u,  1721u,  1723u,  1733u,  1741u,  1747u,
	1753u,  1759u,  1777u,  1783u,  1787u,  1789u,  1801u,  1811u,
	1823u,  1831u,  1847u,  1861u,  1867u,  1871u,  1873u,  1877u,
	1879u,  1889u,  1901u,  1907u,  1913u,  1931u,  1933u,  1949u,
	1951u,  1973u,  1979u,  1987u,  1993u,  1997u,  1999u,  2003u,
	2011u,  2017u,  2027u,  2029u,  2039u,  2053u,  2063u,  2069u,
	2081u,  2083u,  2087u,  2089u,  2099u,  2111u,  2113u,  2129u,
	2131u,  2137u,  2141u,  2143u,  2153u,  2161u,  2179u,  2203u,
	2207u,  2213u,  2221u,  2237u,  2239u,  2243u,  2251u,  2267u,
	2269u,  2273u,  2281u,  2287u,  2293u,  2297u,  2309u,  2311u,
	2333u,  2339u,  2341u,  2347u,  2351u,  2357u,  2371u,  2377u,
	2381u,  2383u,  2389u,  2393u,  2399u,  2411u,  2417u,  2423u,
	2437u,  2441u,  2447u,  2459u,  2467u,  2473u,  2477u,  2503u,
	2521u,  2531u,  2539u,  2543u,  2549u,  2551u,  2557u,  2579u,
	2591u,  2593u,  2609u,  2617u,  2621u,  2633u,  2647u,  2657u,
	2659u,  2663u,  2671u,  2677u,  2683u,  2687u,  2689u,  2693u,
	2699u,  2707u,  2711u,  2713u,  2719u,  2729u,  2731u,  2741u,
	2749u,  2753u,  2767u,  2777u,  2789u,  2791u,  2797u,  2801u,
	2803u,  2819u,  2833u,  2837u,  2843u,  2851u,  2857u,  2861u,
	2879u,  2887u,  2897u,  2903u,  2909u,  2917u,  2927u,  2939u,
	2953u,  2957u,  2963u,  2969u,  2971u,  2999u,  3001u,  3011u,
	3019u,  3023u,  3037u,  3041u,  3049u,  3061u,  3067u,  3079u,
	3083u,  3089u,  3109u,  3119u,  3121u,  3137u,  3163u,  3167u,
	3169u,  3181u,  3187u,  3191u,  3203u,  3209u,  3217u,  3221u,
	3229u,  3251u,  3253u,  3257u,  3259u,  3271u,  3299u,  3301u,
	3307u,  3313u,  3319u,  3323u,  3329u,  3331u,  3343u,  3347u,
	3359u,  3361u,  3371u,  3373u,  3389u,  3391u,  3407u,  3413u,
	3433u,  3449u,  3457u,  3461u,  3463u,  3467u,  3469u,  3491u,
	3499u,  3511u,  3517u,  3527u,  3529u,  3533u,  3539u,  3541u,
	3547u,  3557u,  3559u,  3571u,  3581u,  3583u,  3593u,  3607u,
	3613u,  3617u,  3623u,  3631u,  3637u,  3643u,  3659u,  3671u,
	3673u,  3677u,  3691u,  3697u,  3701u,  3709u,  3719u,  3727u,
	3733u,  3739u,  3761u,  3767u,  3769u,  3779u,  3793u,  3797u,
	3803u,  3821u,  3823u,  3833u,  3847u,  3851u,  3853u,  3863u,
	3877u,  3881u,  3889u,  3907u,  3911u,  3917u,  3919u,  3923u,
	3929u,  3931u,  3943u,  3947u,  3967u,  3989u,  4001u,  4003u,
	4007u,  4013u,  4019u,  4021u,  4027u,  4049u,  4051u,  4057u,
	4073u,  4079u,  4091u,  4093u,  4099u,  4111u,  4127u,  4129u,
	4133u,  4139u,  4153u,  4157u,  4159u,  4177u,  4201u,  4211u,
	4217u,  4219u,  4229u,  4231u,  4241u,  4243u,  4253u,  4259u,
	4261u,  4271u,  4273u,  4283u,  4289u,  4297u,  4327u,  4337u,
	4339u,  4349u,  4357u,  4363u,  4373u,  4391u,  4397u,  4409u,
	4421u,  4423u,  4441u,  4447u,  4451u,  4457u,  4463u,  4481u,
	4483u,  4493u,  4507u,  4513u,  4517u,  4519u,  4523u,  4547u,
	4549u,  4561u,  4567u,  4583u,  4591u,  4597u,  4603u,  4621u,
	4637u,  4639u,  4643u,  4649u,  4651u,  4657u,  4663u,  4673u,
	4679u,  4691u,  4703u,  4721u,  4723u,  4729u,  4733u,  4751u,
	4759u,  4783u,  4787u,  4789u,  4793u,  4799u,  4801u,  4813u,
	4817u,  4831u,  4861u,  4871u,  4877u,  4889u,  4903u,  4909u,
	4919u,  4931u,  4933u,  4937u,  4943u,  4951u,  4957u,  4967u,
	4969u,  4973u,  4987u,  4993u,  4999u,  5003u,  5009u,  5011u,
	5021u,  5023u,  5039u,  5051u,  5059u,  5077u,  5081u,  5087u,
	5099u,  5101u,  5107u,  5113u,  5119u,  5147u,  5153u,  5167u,
	5171u,  5179u,  5189u,  5197u,  5209u,  5227u,  5231u,  5233u,
	5237u,  5261u,  5273u,  5279u,  5281u,  5297u,  5303u,  5309u,
	5323u,  5333u,  5347u,  5351u,  5381u,  5387u,  5393u,  5399u,
	5407u,  5413u,  5417u,  5419u,  5431u,  5437u,  5441u,  5443u,
	5449u,  5471u,  5477u,  5479u,  5483u,  5501u,  5503u,  5507u,
	5519u,  5521u,  5527u,  5531u,  5557u,  5563u,  5569u,  5573u,
	5581u,  5591u,  5623u,  5639u,  5641u,  5647u,  5651u,  5653u,
	5657u,  5659u,  5669u,  5683u,  5689u,  5693u,  5701u,  5711u,
	5717u,  5737u,  5741u,  5743u,  5749u,  5779u,  5783u,  5791u,
	5801u,  5807u,  5813u,  5821u,  5827u,  5839u,  5843u,  5849u,
	5851u,  5857u,  5861u,  5867u,  5869u,  5879u,  5881u,  5897u,
	5903u,  5923u,  5927u,  5939u,  5953u,  5981u,  5987u,  6007u,
	6011u,  6029u,  6037u,  6043u,  6047u,  6053u,  6067u,  6073u,
	6079u,  6089u,  6091u,  6101u,  6113u,  6121u,  6131u,  6133u,
	6143u,  6151u,  6163u,  6173u,  6197u,  6199u,  6203u,  6211u,
	6217u,  6221u,  6229u,  6247u,  6257u,  6263u,  6269u,  6271u,
	6277u,  6287u,  6299u,  6301u,  6311u,  6317u,  6323u,  6329u,
	6337u,  6343u,  6353u,  6359u,  6361u,  6367u,  6373u,  6379u,
	6389u,  6397u,  6421u,  6427u,  6449u,  6451u,  6469u,  6473u,
	6481u,  6491u,  6521u,  6529u,  6547u,  6551u,  6553u,  6563u,
	6569u,  6571u,  6577u,  6581u,  6599u,  6607u,  6619u,  6637u,
	6653u,  6659u,  6661u,  6673u,  6679u,  6689u,  6691u,  6701u,
	6703u,  6709u,  6719u,  6733u,  6737u,  6761u,  6763u,  6779u,
	6781u,  6791u,  6793u,  6803u,  6823u,  6827u,  6829u,  6833u,
	6841u,  6857u,  6863u,  6869u,  6871u,  6883u,  6899u,  6907u,
	6911u,  6917u,  6947u,  6949u,  6959u,  6961u,  6967u,  6971u,
	6977u,  6983u,  6991u,  6997u,  7001u,  7013u,  7019u,  7027u,
	7039u,  7043u,  7057u,  7069u,  7079u,  7103u,  7109u,  7121u,
	7127u,  7129u,  7151u,  7159u,  7177u,  7187u,  7193u,  7207u,
	7211u,  7213u,  7219u,  7229u,  7237u,  7243u,  7247u,  7253u,
	7283u,  7297u,  7307u,  7309u,  7321u,  7331u,  7333u,  7349u,
	7351u,  7369u,  7393u,  7411u,  7417u,  7433u,  7451u,  7457u,
	7459u,  7477u,  7481u,  7487u,  7489u,  7499u,  7507u,  7517u,
	7523u,  7529u,  7537u,  7541u,  7547u,  7549u,  7559u,  7561u,
	7573u,  7577u,  7583u,  7589u,  7591u,  7603u,  7607u,  7621u,
	7639u,  7643u,  7649u,  7669u,  7673u,  7681u,  7687u,  7691u,
	7699u,  7703u,  7717u,  7723u,  7727u,  7741u,  7753u,  7757u,
	7759u,  7789u,  7793u,  7817u,  7823u,  7829u,  7841u,  7853u,
	7867u,  7873u,  7877u,  7879u,  7883u,  7901u,  7907u,  7919u,
	7927u,  7933u,  7937u,  7949u,  7951u,  7963u,  7993u,  8009u,
	8011u,  8017u,  8039u,  8053u,  8059u,  8069u,  8081u,  8087u,
	8089u,  8093u,  8101u,  8111u,  8117u,  8123u,  8147u,  8161u
};


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


/* Miller-Rabin probabilistic primality test [FIPS 186-5 B.3.1].

   Returns 0 if the number is COMPOSITE, 1 if it is PROBABLY_PRIME,
   and a negative value upon error.
   
   Note: Always explicitly check for the return value of this 
   function being either 0 or 1, since the the function can also
   return with error. */
int bn_check_probable_prime(BIGNUM *W, int iter, void *rng)
{
	BIGNUM Z, M, B, RR, T;
	int ret = -1, a, i, j, wlen;

	if (bn_cmp_udbl(W, 3) < 0)
		return 0;

	if ((W->p[0] & 1u) == 0u)
		return 0;
	
	bn_init(&Z, &M, &B, &RR, &T, NULL);

	BN_CHECK(bn_sub_sdbl(W, 1, &Z));
	BN_CHECK(bn_assign(&M, &Z));

	/* Find the largest 'a' such that 2^a divides W-1 */
	a = bn_lsb(&M);
	BN_CHECK(bn_rshift(&M, a));

	BN_CHECK(bn_grow(&B, W->n));
	wlen = bn_msb(W);

	for (i = 0; i < iter; ++i) {
		/* Pick a random 'B' such that len(B) == wlen and 1 < B < W-1 */
		do {
			if (ctr_drbg_generate(rng, (byte *)B.p, ceil_div(wlen, 8), NULL, 0) != SUCCESS) {
				ret = BN_ERR_INTERNAL_FAILURE;
				goto cleanup;
			}

			int blen = bn_msb(&B);

			if (wlen > blen)
				BN_CHECK(bn_lshift(&B, wlen - blen));
			else
				BN_CHECK(bn_rshift(&B, blen - wlen));

			B.p[0] |= 2;
		} while (bn_cmp_abs(&B, &Z) >= 0);

		/* B = B^M (mod W) */
		BN_CHECK(bn_exp_mod(&B, &M, W, &RR, &B));

		if (bn_cmp_udbl(&B, 1) == 0 || bn_cmp_abs(&B, &Z) == 0)
			continue;
		
		for (j = 1; j < a; ++j) {
			/* B = B^2 (mod W) */
			BN_CHECK(bn_mul(&B, &B, &T));
			BN_CHECK(bn_mod(&T, W, &B));

			/* Composite if B == 1 */
			if (bn_cmp_udbl(&B, 1) == 0)
				break;
			
			if (bn_cmp_abs(&B, &Z) == 0)
				goto next;
		}
		/* Composite if B != W-1 */
		ret = 0;
		goto cleanup;
next:
		continue;
	}
	ret = 1;

cleanup:

	bn_zfree(&Z, &M, &B, &RR, &T, NULL);
	
	return ret;
}


/* Generate a random pseudo-prime number [HAC 4.44].
   
   If dh_flag is set to 1, both X and (X-1)/2 are pseudo-prime.
   
   Returns 0 on success. */
int bn_generate_proabable_prime(BIGNUM *X, int nbits, int dh_flag, void *rng)
{
	BIGNUM Y, TX;
	int ret = 0, i, j;
	bn_uint_t r;

	if (nbits < WORD_SIZE)
		return BN_ERR_BAD_INPUT_DATA;
	if (nbits > BN_MAX_BITS)
		return BN_ERR_NOT_ENOUGH_LIMBS;

	bn_init(&Y, &TX, NULL);
	BN_CHECK(bn_grow(&TX, BN_BITS_TO_LIMBS(nbits)));

generate:
	/* Generate an nbits long odd random number */
	if (ctr_drbg_generate(rng, (byte *)TX.p, ceil_div(nbits, 8), NULL, 0) != SUCCESS) {
		ret = BN_ERR_INTERNAL_FAILURE;
		goto cleanup;
	}

	j = bn_msb(&TX);
	if (j < nbits)
		BN_CHECK(bn_lshift(&TX, nbits - j));
	if (j > nbits)
		BN_CHECK(bn_rshift(&TX, j - nbits));
	
	TX.p[0] |= 1;

	int t1 = num_trial_divisions(nbits);

	/* Calculate the number of rounds of Miller-Rabin which gives
	   a false positive rate of 2^{-80} [HAC Table 4.4] */
	int t2 = (nbits >= 1300) ? 2 :
		(nbits >= 850) ? 3 :
		(nbits >= 550) ? 5 :
		(nbits >= 350) ? 8 :
		(nbits >= 250) ? 12 :
		(nbits >= 150) ? 18 : 27;

	if (dh_flag == 0) {
		for (;;) {
			/* Test with small factors first */
			for (i = 0; i < t1; ++i) {
				if (bn_cmp_udbl(&TX, primes[i]) <= 0 || bn_cmp_udbl(&Y, primes[i]) <= 0)
					continue;
				BN_CHECK(bn_mod_uint(&TX, primes[i], &r));
				if (r == 0)
					continue;
			}

			if ((ret = bn_check_probable_prime(&TX, t2, rng)) < 0)
				goto cleanup;

			if (ret == 1)
				break;
			
			BN_CHECK(bn_add_sdbl(&TX, 2, &TX));
		}

		/* Make sure the number is still nbits long */
		if (bn_msb(&TX) != nbits)
			goto generate;
	} else {
		/* A necessary condition for Y and X = 2Y + 1 to be prime
		   is X = 2 (mod 3) (which is equivalent to Y = 2 (mod 3)).
		   Make sure it is satisfied, while keeping X = 3 (mod 4) */
		TX.p[0] |= 2;

		BN_CHECK(bn_mod_uint(&TX, 3, &r));

		if (r == 0)
			BN_CHECK(bn_add_sdbl(&TX, 8, &TX));
		else if (r == 1)
			BN_CHECK(bn_add_sdbl(&TX, 4, &TX));
		
		/* Set Y = (X-1) / 2, which is X / 2 since X is odd */
		BN_CHECK(bn_assign(&Y, &TX));
		BN_CHECK(bn_rshift(&Y, 1));

		for(;;) {
			/* Test with small factors first */
			for (i = 0; i < t1; ++i) {
				if (bn_cmp_udbl(&TX, primes[i]) <= 0 || bn_cmp_udbl(&Y, primes[i]) <= 0)
					goto next;
				BN_CHECK(bn_mod_uint(&TX, primes[i], &r));
				if (r == 0)
					goto next;
				BN_CHECK(bn_mod_uint(&Y, primes[i], &r));
				if (r == 0)
					goto next;
			}

			/* Do multiple rounds of Miller-Rabin */
			if ((ret = bn_check_probable_prime(&TX, t2, rng)) < 0)
				goto cleanup;
			if (ret == 1)
				break;
			if ((ret = bn_check_probable_prime(&Y, t2, rng)) < 0)
				goto cleanup;
			if (ret == 1)
				break;
next:
			/* We want to preserve Y = (X-1) / 2 and Y = 1 (mod 2) and Y = 2 (mod 3)
			  (eq X = 3 (mod 4) and X = 2 (mod 3)) so we up X by 12 and Y by 6, and
			  test the next candidates */
			BN_CHECK(bn_add_sdbl(&TX, 12, &TX));
			BN_CHECK(bn_add_sdbl(&Y, 6, &Y));
		}

		if (bn_msb(&TX) != nbits)
			goto generate;
	}

	BN_CHECK(bn_assign(X, &TX));

	ret = 0;

cleanup:

	bn_zfree(&Y, &TX, NULL);

	return ret;
}


#define TEST_MSG(v, fp, i, msg, res)                            \
do {                                                            \
	if (v)                                                      \
		fprintf(fp, "Test #%d %40s %s\n", i, msg,               \
		(res) ? "\x1B[92mPASS\x1B[0m" : "\x1B[91mFAIL\x1B[0m"); \
} while (0)


#define N_PRIMES_TVEC 24

static const bn_udbl_t primes_tvec[N_PRIMES_TVEC] = {
	13541837047354514699ull, 11482137299118693707ull, 14287940918865387113ull, 10120279974895627553ull,
	14895576077380784113ull, 12576535594587839761ull, 11549535704659004153ull, 16732162743889269931ull,
	10036021854698400299ull, 12748495651575645193ull, 14192101576074053833ull, 14546590944809174707ull,
	14016092726950390393ull, 12719768151834263519ull, 16729058806973093947ull, 14961602683434188807ull,
	15459199153977669427ull, 15459199153977669427ull, 15459199153977669427ull, 15459199153977669427ull,
	13176432008857319999ull, 12778241984776090871ull, 16429718256786499207ull, 14630459379556164227ull,
};

static const bn_udbl_t composites_tvec[N_PRIMES_TVEC] = {
	10574814068688352009ull, 10574814068688352009ull,  5287861076572492133ull,  8218870243874079947ull,
	11321516760146882137ull,  8352904206657371839ull,  6529615664111464081ull,  7235499105493574221ull,
	 8649229734828310963ull, 16101129338421456491ull, 15604384686487615639ull, 14170715138485288109ull,
	 6836339213695843751ull,  9917718734443855331ull,  6435506140383106139ull,  6420092896969674187ull,
	14326074188423877323ull,  7182496337731210039ull,  7931621731272428183ull,      185984449421681ull,
		 231914319788213ull,      122144845450367ull,      129545555348477ull,      163780048516769ull,
};

#define N_GCD_TVEC 4

static const bn_udbl_t gcd_tvec[N_GCD_TVEC][3] = {
	{  874434ull,    44ull, 22ull},
	{ 4343209ull,  3913ull, 13ull},
	{ 3123291ull,  3213ull, 51ull},
	{39912332ull, 32139ull,  1ull}
};

/* Test routine */
int bn_self_test(void *rng, int verbose, FILE *fp)
{
	int ret = 0, res;
	BIGNUM A, B, C, D, E, F, G, H, M, X, Y, Z;

	bn_init(&A, &B, &C, &D, &E, &F, &G, &H, &M, NULL);

	fp = (fp == NULL) ? stdout : fp;

	BN_CHECK(bn_read_string(16, "79ffb5c63d18fadc6ee85b967401d24b"
								"9a80b683f67e6536a1ba1ecec362a9a0"
								"f8109fe311614c42f7a29b3230c77ee9"
								"560ae7a28ef20d7387c7e8be5c6383fc", &A));

	BN_CHECK(bn_read_string(16, "482430327087ac340c011d003f8980d9"
								"d8d09e2626116baffe49d4ce5d470dc6"
								"4941546382cd387169bcfdf1940b265b"
								"a1b9810affbb8b89dfa03abe47dadb47", &B));

	BN_CHECK(bn_read_string(16, "22612a0d4cb6d1ae162b0ddd6f3c7331"
								"7a445a98518b30b2a29ff1e18d635ddb"
								"7e6c4a91ecb0f7126faa2a91eb2cb4ef"
								"60929467040fa82221724d37b97af5a8"
								"e7202f15767e9393ff665bd4188eac9e"
								"9379269307052ce58a43626da76ccba3"
								"ce8383cbaafaacd878f94ec8702ff8c9"
								"f65ffe75773b6439c989b9360a1a2ee4", &C));

	BN_CHECK(bn_read_string(16, "6765cdb8debf92423588e3aa9ea89c9b"
								"d136fde8640ab7b3812cc7d41e74b5b1"
								"d9a91e6d9d71da4c0f76fad670e63475"
								"515fd7a8c6482b8ec1f90d343eca2faf"
								"6b6bae96f69d3a7738c484b9a96a25a8"
								"3eb1c618ec7ab30b21a043488f89ee61"
								"1257c2eb707fd167dab26e0fc5d4f98f"
								"a61653db4f362e6a46cbb0cb3fc052c6", &D));

	BN_CHECK(bn_read_string(16, "c2abf9c7db931f31b2e8508b1a29d216"
								"c240ccf7f1f9f5f63d236e0cde7b8714"
								"ac1b343bc7921b6a2496331326ef9be9"
								"19c79efc94d60b105a9cef65c086ccea", &E));

	BN_CHECK(bn_read_string(16, "87f8b0bdb7a6638e44f453c94d11c492"
								"12dffc08b11e4c8ecaf100eb1cd1e4af"
								"ea4baa5b7b35695bde34252f79e12ce0"
								"6b33e8e6b2a69f0a3f0e9bc178475b5b", &F));

	BN_CHECK(bn_read_string(16, "2f923fb20198d7d35eb8fbe99eedc493"
								"965a6c4b013884422eba77cffd0fb7cc"
								"d2547b7b1b5f90ab6a62fa249cf06365"
								"d77050404bb49b6da1f3ac5560184d98", &G));
	
	BN_CHECK(bn_read_string(16, "73f62da9eb16525f92778d03db1882f6"
								"6137ef83f201217c3c16af0e7803b3a0"
								"8d1889dd1d0d32bded553b4a352746e6"
								"e31faabd73811885d479441d6e58fa3f", &H));

	BN_CHECK(bn_read_string(16, "1272ea75c263c4591dd33188aac9066"
								"05c65e6a63646570b3b41bf1abf026c"
								"6d94c732f76c142b262d4be8317c769"
								"291923629ab28d2a4d2d4563e738d2c"
														   "5428", &M));
	
	// Multiplication
	bn_init(&X, NULL);
	BN_CHECK(bn_mul(&A, &B, &X));
	TEST_MSG(verbose, fp, 1, "bn_mul", bn_cmp(&X, &C) == 0);
	bn_zfree(&X, NULL);

	// Division
	bn_init(&X, &Y, NULL);
	BN_CHECK(bn_div(&D, &E, &X, &Y));
	TEST_MSG(verbose, fp, 2, "bn_div", bn_cmp(&X, &F) == 0 && bn_cmp(&Y, &G) == 0);
	bn_zfree(&X, &Y, NULL);

	// Modulo
	bn_init(&X, NULL);
	BN_CHECK(bn_mod(&D, &E, &X));
	TEST_MSG(verbose, fp, 3, "bn_mod", bn_cmp(&X, &G) == 0);
	bn_zfree(&X, NULL);

	// Modular exponentiation
	bn_init(&X, NULL);
	BN_CHECK(bn_exp_mod(&A, &B, &F, NULL, &X));
	TEST_MSG(verbose, fp, 4, "bn_exp_mod", bn_cmp(&X, &H) == 0);
	bn_zfree(&X, NULL);

	// Modular inverse
	bn_init(&X, NULL);
	BN_CHECK(bn_inv_mod(&A, &B, &X));
	TEST_MSG(verbose, fp, 5, "bn_inv_mod", bn_cmp(&X, &M) == 0);
	bn_zfree(&X, NULL);
	
	// Greatest common divisor
	res = 0;
	bn_init(&X, &Y, &Z, NULL);
	for (int i = 0; i < N_GCD_TVEC; ++i) {
		bn_from_udbl(&X, gcd_tvec[i][0]);
		bn_from_udbl(&Y, gcd_tvec[i][1]);

		BN_CHECK(bn_gcd(&X, &Y, &Z));

		if ((res = !(bn_cmp_udbl(&Z, gcd_tvec[i][2]) == 0) != 0))
			break;
	}
	TEST_MSG(verbose, fp, 6, "bn_gcd", res == 0);
	bn_zfree(&X, &Y, &Z, NULL);

	// Pseudo-primality test
	if (rng != NULL) {
		res = 0;
		bn_init(&X, NULL);
		for (int i = 0; i < N_PRIMES_TVEC; ++i) {
			bn_from_udbl(&X, primes_tvec[i]);
			if ((res = !(bn_check_probable_prime(&X, 27, rng) == 1)) != 0)
				break;
			bn_from_udbl(&X, composites_tvec[i]);
			if ((res = !(bn_check_probable_prime(&X, 27, rng) == 0)) != 0)
				break;
		}
		TEST_MSG(verbose, fp, 7, "bn_check_probable_prime", res == 0);
		bn_zfree(&X, NULL);
	}

cleanup:

	bn_zfree(&A, &B, &C, &D, &E, &F, &G, &H, &M, NULL);

	return ret;
}
