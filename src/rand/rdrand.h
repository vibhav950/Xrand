/**
 * rdrand.h
 *
 * Support for RDRAND and RDSEED instructions on x86 processors.
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

int check_is_intel();
int check_is_amd();

int check_rdrand();
int check_rdseed();

int rdrand_check_support();
int rdseed_check_support();

/**
 * Get 16-bit random number with RDRAND
 * and write the value to *therand.
 *
 * Returns 1 on success, 0 on underflow.
 */
extern inline int __attribute__( ( always_inline ) ) rdrand16_step(unsigned short int *therand)
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

extern inline int __attribute__( ( always_inline ) ) rdseed16_step(unsigned short int *therand)
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
extern inline int __attribute__( ( always_inline ) ) rdrand32_step(unsigned int *therand)
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

extern inline int __attribute__( ( always_inline ) ) rdseed32_step(unsigned int *therand)
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
extern inline int __attribute__( ( always_inline ) ) rdrand64_step(unsigned long long int *therand)
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

extern inline int __attribute__( ( always_inline ) ) rdseed64_step(unsigned long long int *therand)
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
