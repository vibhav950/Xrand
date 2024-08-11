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

#include "common/defs.h"
#include "rdrand.h"

#if defined(__x86_64__) || defined(_M_X64) || defined(_M_IX86) || defined(__i386)
    #if defined(_MSC_VER)
        // Visual Studio
        #include <intrin.h> // __cpuid, __cpuidex
    #elif defined(__GNUC__)
        // GCC / LLVM (Clang)
        #include <cpuid.h> // __get_cpuid, __get_cpuid_count
    #endif
#endif

int check_is_intel(void)
{
#if defined(__x86_64__) || defined(_M_X64) || defined(_M_IX86) || defined(__i386)
#if defined(_MSC_VER) // Visual Studio
    int cpuid[4] = {-1};
    __cpuid(cpuid, 0);
#else // GCC / LLVM (Clang)
    unsigned int cpuid[4] = {0};
    __get_cpuid(0, &cpuid[0], &cpuid[1], &cpuid[2], &cpuid[3]);
#endif

    // Check against the "GenuineIntel" string
    if ((cpuid[1] /*ebx*/ == 0x756e6547) &&
        (cpuid[2] /*ecx*/ == 0x6c65746e) &&
        (cpuid[3] /*edx*/ == 0x49656e69))
        return 1;
    return 0;
#else // unknown compiler architecture
    return 0;
#endif
}

int check_is_amd(void)
{
#if defined(__x86_64__) || defined(_M_X64) || defined(_M_IX86) || defined(__i386)
#if defined(_MSC_VER) // Visual Studio
    int cpuid[4] = {-1};
    __cpuid(cpuid, 0);
#else // GCC / LLVM (Clang)
    unsigned int cpuid[4] = {0};
    __get_cpuid(0, &cpuid[0], &cpuid[1], &cpuid[2], &cpuid[3]);
#endif

    // Check against the "AuthenticAMD" string
    if ((cpuid[1] /*ebx*/ == 0x68747541) &&
        (cpuid[2] /*ecx*/ == 0x444d4163) &&
        (cpuid[3] /*edx*/ == 0x69746e65))
        return 1;
    return 0;
#else // unknown compiler architecture
    return 0;
#endif
}

int check_rdrand(void)
{
#if defined(__x86_64__) || defined(_M_X64) || defined(_M_IX86) || defined(__i386)
#if defined(_MSC_VER) // Visual Studio
    int cpuid[4] = {-1};
    __cpuid(cpuid, 1);
#else // GCC / LLVM (Clang)
    unsigned int cpuid[4] = {0};
    __get_cpuid(1, &cpuid[0], &cpuid[1], &cpuid[2], &cpuid[3]);
#endif

    if ((cpuid[2] & 0x40000000) == 0x40000000) // rdrand bit (1 << 30)
        return 1;
    return 0;
#else // unknown compiler architecture
    return 0;
#endif
}

int check_rdseed(void)
{
#if defined(__x86_64__) || defined(_M_X64) || defined(_M_IX86) || defined(__i386)
#if defined(_MSC_VER) // Visual Studio
    int cpuid[4] = {-1};
    __cpuidex(cpuid, 7, 0);
#else // GCC / LLVM (Clang)
    unsigned int cpuid[4] = {0};
    __get_cpuid_count(7, 0, &cpuid[0], &cpuid[1], &cpuid[2], &cpuid[3]);
#endif

    if ((cpuid[1] & 0x00040000) == 0x00040000) // rdseed bit (1 << 18)
        return 1;
    return 0;
#else // unknown compiler architecture
    return 0;
#endif
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