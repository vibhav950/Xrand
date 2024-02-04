/**
 * rdrand.c
 *
 * Based on code written and placed in the public domain by David Johnston;
 * Modified for Xrand by vibhav950 [GitHub].
 *
 * See https://github.com/dj-on-github/djenrandom
 *
 * LICENSE
 * =======
 *
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

#ifndef _WIN32
#error "This file is Windows specific"
#endif

#include "rand/rdrand.h"
#include <string.h>
#include <intrin.h>

int check_is_intel(void)
{
    unsigned int __eax = 0;
    unsigned int __ebx = 0;
    unsigned int __ecx = 0;
    unsigned int __edx = 0;

    __get_cpuid(0, &__eax, &__ebx, &__ecx, &__edx);

    if (memcmp((char *) &__ebx, "Genu", 4) == 0 &&
        memcmp((char *) &__edx, "ineI", 4) == 0 &&
        memcmp((char *) &__ecx, "ntel", 4) == 0)
        return 1;
    return 0;
}

int check_is_amd(void)
{
    unsigned int __eax = 0;
    unsigned int __ebx = 0;
    unsigned int __ecx = 0;
    unsigned int __edx = 0;

    __get_cpuid(0, &__eax, &__ebx, &__ecx, &__edx);

    if (memcmp((char *) &__ebx, "Auth", 4) == 0 &&
        memcmp((char *) &__edx, "enti", 4) == 0 &&
        memcmp((char *) &__ecx, "cAMD", 4) == 0)
        return 1;
    return 0;
}

int check_rdrand(void)
{
    unsigned int __eax = 0;
    unsigned int __ebx = 0;
    unsigned int __ecx = 0;
    unsigned int __edx = 0;

    __get_cpuid(1, &__eax, &__ebx, &__ecx, &__edx);

    if ((__ecx & 0x40000000) == 0x40000000)
        return 1;
    return 0;
}

int check_rdseed(void)
{
    unsigned int __eax = 0;
    unsigned int __ebx = 0;
    unsigned int __ecx = 0;
    unsigned int __edx = 0;

    __get_cpuid_count(7, 0, &__eax, &__ebx, &__ecx, &__edx);

    if ((__ebx & 0x00040000) == 0x00040000)
        return 1;
    return 0;
}

/* Returns 1 if RDRAND is available, 0 otherwise */
int rdrand_check_support(void)
{
    if ((check_is_intel() == 1) || (check_is_amd() == 1))
    {
        if (check_rdrand() == 1)
            return 1;
    }
    return 0;
}

/* Returns 1 if RDSEED is available, 0 otherwise */
int rdseed_check_support(void)
{
    if ((check_is_intel() == 1) || (check_is_amd() == 1))
    {
        if (check_rdseed() == 1)
            return 1;
    }
    return 0;
}

/**
 * Get 16-bit random number with RDRAND
 * and write the value to *therand.
 *
 * Returns 1 on success, 0 on underflow.
 */
inline int rdrand16_step(unsigned short int *therand)
{
    unsigned short int val;
    int cf_error_status;
    asm volatile("\n\
        rdrand %%ax;\n\
        mov $1,%%edx;\n\
        cmovae %%ax,%%dx;\n\
        mov %%edx,%1;\n\
        mov %%ax, %0;" : "=r"(val), "=r"(cf_error_status)::"%ax", "%dx");
    *therand = val;
    return cf_error_status;
}

inline int rdseed16_step(unsigned short int *therand)
{
    unsigned short int val;
    int cf_error_status;
    asm volatile("\n\
        rdseed %%ax;\n\
        mov $1,%%edx;\n\
        cmovae %%ax,%%dx;\n\
        mov %%edx,%1;\n\
        mov %%ax, %0;" : "=r"(val), "=r"(cf_error_status)::"%ax", "%dx");
    *therand = val;
    return cf_error_status;
}

/**
 * Get 32-bit random number with RDRAND
 * and write the value to *therand.
 *
 * Returns 1 on success, 0 on underflow.
 */
inline int rdrand32_step(unsigned int *therand)
{
    int val;
    int cf_error_status;
    asm volatile("\n\
        rdrand %%eax;\n\
        mov $1,%%edx;\n\
        cmovae %%eax,%%edx;\n\
        mov %%edx,%1;\n\
        mov %%eax,%0;" : "=r"(val), "=r"(cf_error_status)::"%eax", "%edx");
    *therand = val;
    return cf_error_status;
}

inline int rdseed32_step(unsigned int *therand)
{
    int val;
    int cf_error_status;
    asm volatile("\n\
        rdseed %%eax;\n\
        mov $1,%%edx;\n\
        cmovae %%eax,%%edx;\n\
        mov %%edx,%1;\n\
        mov %%eax,%0;" : "=r"(val), "=r"(cf_error_status)::"%eax", "%edx");
    *therand = val;
    return cf_error_status;
}

/**
 * Get 64-bit random number using RDRAND
 * and write the value to *therand.
 *
 * Returns 1 on success, 0 on underflow.
 */
inline int rdrand64_step(unsigned long long int *therand)
{
    unsigned long long int val;
    int cf_error_status;
    asm volatile("\n\
        rdrand %%rax;\n\
        mov $1,%%edx;\n\
        cmovae %%rax,%%rdx;\n\
        mov %%edx,%1;\n\
        mov %%rax, %0;" : "=r"(val), "=r"(cf_error_status)::"%rax", "%rdx");
    *therand = val;
    return cf_error_status;
}

inline int rdseed64_step(unsigned long long int *therand)
{
    unsigned long long int val;
    int cf_error_status;
    asm volatile("\n\
        rdseed %%rax;\n\
        mov $1,%%edx;\n\
        cmovae %%rax,%%rdx;\n\
        mov %%edx,%1;\n\
        mov %%rax, %0;" : "=r"(val), "=r"(cf_error_status)::"%rax", "%rdx");
    *therand = val;
    return cf_error_status;
}