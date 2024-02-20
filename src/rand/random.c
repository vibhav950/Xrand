/**
 * Copyright (C) 2024-25  Xrand
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "random.h"
#include "common/defs.h"
#include "common/ieee754_format.h"
#include "common/exceptions.h"
#include "trivium.h"
#include <inttypes.h>
#include <string.h>
#include <math.h>

#define _PI 3.141592653589793

#define _sqrt(x) sqrt(x)
#define _log(x) log(x)
#define _exp(x) exp(x)
#define _sin(x) sin(x)
#define _cos(x) cos(x)
#define _pow(x, y) pow(x, y)

static inline uint64_t _ranged(uint64_t a, uint64_t b)
{
    if (a > b)
    {
        return -1;
    }

    return a + RandU64() % ((b - a) + 1);
}

static inline double _uni(void)
{
    ieee754_double_t temp;

    /* Request 64-bit random value from the PRNG */
    uint64_t _rand = RandU64();

    /**
     * Construct a 64-bit positive floating point number in [0.0, 1.0)
     * by distributing the random bits over the 52-bit mantissa.
     */
    temp.fmt.sign = 0;
    temp.fmt.exponent = IEEE754_DOUBLE_PREC_BIAS; /* Exponent bias */
    temp.fmt.mantissa0 = ((_rand & 0xFFF) << 8) | (_rand >> 56);
    temp.fmt.mantissa1 = ((_rand >> 12) & 0xFFFFFFFF) ^ ((_rand >> 44) & 0xFF);

    return temp.d - 1.0;
}

/**
 * Uniform distribution
 * Get random numbers uniformly distributed over the range [a, b]
 */
void uniform(FILE *fp, double a, double b, int iter)
{
    if (fp == NULL)
    {
        fp = stdout;
    }

    double temp, x;

    for (int i = 0; i < iter; ++i)
    {
        temp = _uni();
        x = a + (b - a) * temp;

        fprintf(fp, "%.lf\n", x);
    }
}

/**
 * Normal / Gaussian distribution
 *
 * Get normally distributed random numbers where mu is the mean and
 * sigma is the standard deviation
 *
 * Uses the Box-Muller transform
 * (by George Edward Pelham Box and Mervin Edgar Muller)
 *
 * If u1 and u2 are two independent random variables chosen from
 * the uniform unit interval [0, 1), then
 *
 * x = sqrt(2 * ln(u1)) * cos(2 * pi * u2)
 * y = sqrt(2 * ln(u1)) * sin(2 * pi * u2)
 *
 * are two independent random variables from the standard normal
 * distribution (mu = 0, sigma = 1)
 *
 * (source: https://en.wikipedia.org/wiki/Box%E2%80%93Muller_transform)
 */
void normal(FILE *fp, double mu, double sigma, int iter)
{
    if (sigma < 0)
    {
        Warn("normal : invalid arguments (expected sigma >= 0)",
             WARN_INVALID_PARAM);
        return;
    }

    if (fp == NULL)
    {
        fp = stdout;
    }

    double u1, u2, x, y;
    double *next = NULL;

    for (int i = 0; i < iter; ++i)
    {
        /* Generate two uniform variates uniformly distributed over [0.0, 1.0) */
        u1 = _uni();
        u2 = _uni();
        /* Generate independent normal variates x and y from N(mu, sigma) */
        x = (_sqrt(-2 * _log(u1)) * _cos(2 * _PI * u2)) * sigma + mu;
        y = (_sqrt(-2 * _log(u1)) * _sin(2 * _PI * u2)) * sigma + mu;

        if (next == NULL)
        {
            next = &y;
        }

        else
        {
            fprintf(fp, "%lf\n", y);
            next = NULL;
            continue;
        }

        fprintf(fp, "%lf\n", x);
    }
}

/**
 * Triangular distribution
 *
 * Get random numbers from a continuous probability distribution with
 * lower limit a, upper limit b and mode c, where a < b and a <= c <= b
 *
 * If U is a random number chosen from the uniform unit interval [0, 1),
 * then the variate
 *
 * X = a + sqrt(U * (b - a) * (c - a))         for 0 < U < F
 *   = b + sqrt((1 - U) * (b - a) * (b - c))   for F <= U < 1
 *
 * where F = (c - a) / (b - a), provided (b - a) != 0, has a triangular
 * distribution with parameters a, b and c
 *
 * (source: https://en.wikipedia.org/wiki/Triangular_distribution)
 */
void triangular(FILE *fp, double a, double b, double c, int iter)
{
    if (!(a < b && a <= c && c <= b))
    {
        Warn("triangular : invalid arguments (expected a < b, a <= c <= b)",
             WARN_INVALID_PARAM);
        return;
    }

    if (fp == NULL)
    {
        fp = stdout;
    }

    double U, F, X;

    if (b - a)
    {
        for (int i = 0; i < iter; ++i)
        {
            U = _uni();
            F = (c - a) / (b - a);

            if (U < F)
            {
                X = a + _sqrt(U * (b - a) * (c - a));
            }
            else
            {
                X = b - _sqrt((1.0 - U) * (b - a) * (b - c));
            }

            fprintf(fp, "%lf\n", X);
        }
    }
    else
    {
        X = a;

        for (int i = 0; i < iter; ++i)
        {
            fprintf(fp, "%lf\n", X);
        }
    }
}

/**
 * Poisson distribution
 *
 * Get random numbers from a distribution that expresses the probability
 * of a given number of events occurring in a fixed interval of time or
 * space if these events occur with a known constant mean rate and
 * independently of the time since the last event
 *
 * (source: https://en.wikipedia.org/wiki/Poisson_distribution)
 *
 * Uses the method proposed by C. D. Kemp and Adrienne W. Kemp
 * Kemp, C. D., & Kemp, A. W. (1991). Poisson Random Variate Generation.
 * Journal of the Royal Statistical Society. Series C (Applied Statistics),
 * 40(1), 143–158. https://doi.org/10.2307/2347913
 */
void poisson(FILE *fp, double lambda, int iter)
{
    if (lambda < 0)
    {
        Warn("poisson : invalid arguments (expected lambda > 0)",
             WARN_INVALID_PARAM);
        return;
    }

    if (fp == NULL)
    {
        fp = stdout;
    }

    double u, p, F;
    int x;

    for (int i = 0; i < iter; ++i)
    {
        p = _exp(-lambda);
        F = p;
        u = _uni();
        x = 0;

        while (u > F)
        {
            x = x + 1;
            p = (lambda * p) / x;
            F = F + p;
        }

        fprintf(fp, "%d\n", x);
    }
}

/**
 * Binomial distribution
 *
 * Get random numbers from the discrete probability distribution of the
 * number of successes in a sequence of n independent experiments, each
 * asking a yes–no question, and each with its own Boolean-valued outcome:
 * success (with probability p) or failure (with probability q=1-p)
 * (source: https://en.wikipedia.org/wiki/Binomial_distribution)
 *
 * Uses the method proposed by Voratas Kachitvichyanukul and Bruce W. Schmeiser
 * Voratas Kachitvichyanukul and Bruce W. Schmeiser. 1988. Binomial random
 * variate generation. Commun. ACM 31, 2 (Feb. 1988), 216–222.
 * https://doi.org/10.1145/42372.42381
 */
void binomial(FILE *fp, int n, double p, int iter)
{
    if (n <= 0)
    {
        Warn("binomial : invalid arguments (expected n > 0, 0 <= p <= 1)",
             WARN_INVALID_PARAM);
        return;
    }

    if (fp == NULL)
    {
        fp = stdout;
    }

    double u, s, a, r;
    int x;

    for (int i = 0; i < iter; ++i)
    {
        s = p / (1 - p);
        a = (n + 1) * s;
        r = _pow((1 - p), n);
        u = _uni();
        x = 0;

        while (u > r)
        {
            u = u - r;
            x = x + 1;
            r = ((a / x) - s) * r;
        }

        fprintf(fp, "%d\n", x);
    }
}

/**
 * Random character sequence
 *
 * Get a random string of len characters, based on the selected character set.
 *
 * Set the following flags to define the charset:
 * lc - lowercase characters
 * uc - uppercase characters
 * nc - numeric characters
 * sc - special characters
 */
void randstr(FILE *fp, char lc, char uc, char nc, char sc, int len, int iter)
{
    if (len > 1000)
    {
        Warn("randstr : invalid arguments (expected len <= 1000)",
             WARN_INVALID_PARAM);
        return;
    }

    if (fp == NULL)
    {
        fp = stdout;
    }

    if (!lc && !uc && !nc && !sc)
    {
        Warn("randstr : invalid arguments (expected non-empty charset)",
             WARN_INVALID_PARAM);
        return;
    }

    char charset[92];

    if (lc)
        strcat(charset, "abcdefghijklmnopqrstuvwxyz");
    if (uc)
        strcat(charset, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    if (nc)
        strcat(charset, "0123456789");
    if (sc)
        strcat(charset, "!@#$%^&*()_+-=[]{}|;:,.<>?\\");

    for (int i = 0; i < iter; ++i)
    {
        for (int ch = 0; ch < len; ++ch)
        {
            fprintf(fp, "%c", charset[RandU8() % strlen(charset)]);
        }
        fprintf(fp, "\n");
    }
}