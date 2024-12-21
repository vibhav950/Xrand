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

#ifndef DEFS_H
#define DEFS_H

#include "exceptions.h"

#define XRAND_VERSION "1.0.1"

#if defined(__GNUC__) || defined(__clang__)
#ifndef XR_DEBUG
#define XRAND_UNSTABLE __attribute__((error("Unstable in Xrand v"XRAND_VERSION)))
#else
#define XRAND_UNSTABLE __attribute__((warning("Unstable in Xrand v"XRAND_VERSION)))
#endif
#else
#define XRAND_UNSTABLE
#endif

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

#define INLINE static inline

#define IN
#define OUT

#include <stdint.h>

typedef __int8 s8;
typedef __int16 s16;
typedef __int32 s32;
typedef __int64 s64;

typedef unsigned __int8 byte;
typedef unsigned __int8 u8;
typedef unsigned __int16 u16;
typedef unsigned __int32 u32;
typedef unsigned __int64 u64;

#define Ptrv(_ptr) ((void *)(_ptr))
#define Ptr8(_ptr) ((u8 *)(_ptr))
#define Ptr16(_ptr) ((u16 *)(_ptr))
#define Ptr32(_ptr) ((u32 *)(_ptr))
#define Ptr64(_ptr) ((u64 *)(_ptr))

#ifdef max
#undef max
#endif
#define max(_a, _b) (((_a) > (_b)) ? (_a) : (_b))

#ifdef min
#undef min
#endif
#define min(_a, _b) (((_a) < (_b)) ? (_a) : (_b))

#define count(_arr) (sizeof(_arr) / sizeof((_arr)[0]))
#define ceil_div(_x, _y) ((_x) / (_y) + ((_x) % (_y) ? 1 : 0))
#define floor_div(_x, _y) ((_x) / (_y))

typedef enum { false = 0, true } bool;

typedef enum { SUCCESS = 0, FAILURE } status_t;

#define ASSERT(stmt) Assert(stmt)

#define NOP                                                                    \
  do {                                                                         \
  } while (0)

#ifndef MAX_PATH
#define MAX_PATH 256
#endif

// Securely clear memory containing secrets
#ifdef _WIN32
#define zeroize(ptr, len) RtlSecureZeroMemory(ptr, len)
#else
/**
 * Provide a secure way to clear a block of memory by
 * declaring the pointer to memset volatile so that the
 * compiler must always dereference it, and therefore
 * cannot "optimize away" the call to memset.
 */
#include <string.h>
typedef void *(*memset_t)(void *_p, int _zv, size_t _nc);
static volatile memset_t __memz = memset;
#define zeroize(ptr, len) __memz(ptr, 0, len)
#endif

// The size of the memory to be copied must be a multiple of 32
#define copy32(dst, src, size)                                                 \
  do {                                                                         \
    volatile __int32 *d = (volatile __int32 *)(dst);                           \
    volatile __int32 *s = (volatile __int32 *)(src);                           \
    size_t c = (size / 4);                                                     \
    while (c--)                                                                \
      *d++ = *s++;                                                             \
  } while (0)

#define zcopy32(dst, src, size)                                                \
  do {                                                                         \
    volatile __int32 *d = (volatile __int32 *)(dst);                           \
    volatile __int32 *s = (volatile __int32 *)(src);                           \
    size_t c = (size / 4);                                                     \
    while (c--) {                                                              \
      *d++ = *s;                                                               \
      *s++ = 0;                                                                \
    }                                                                          \
  } while (0)

#define ALIGN(_N) __attribute__((aligned(_N)))

extern volatile void *xr_memset(volatile void *mem, int ch, size_t len);
extern volatile void *xr_memzero(volatile void *mem, size_t len);
extern volatile void *xr_memcpy(volatile void *dst, volatile void *src, size_t len);
extern volatile void *xr_memmove(volatile void *dst, volatile void *src, size_t len);
extern unsigned int xr_memcmp(const void *a, const void *b, size_t len);
extern unsigned int xr_strcmp(const char *str, const char *x);

#include "endianness.h"

#define BSWAP16(_x) bswap16(_x)
#define BSWAP32(_x) bswap32(_x)
#define BSWAP64(_x) bswap64(_x)

#include <intrin.h>

#pragma intrinsic(_rotl8, _rotl16, _rotr8, _rotr16)

#define ROTL8(_x, _s) _rotl8((_x), (_s))
#define ROTL16(_x, _s) _rotl16((_x), (_s))
#define ROTL32(_x, _s) _rotl((_x), (_s))
#define ROTL64(_x, _s) _rotl64((_x), (_s))

#define ROTR8(_x, _s) _rotr8((_x), (_s))
#define ROTR16(_x, _s) _rotr16((_x), (_s))
#define ROTR32(_x, _s) _rotr((_x), (_s))
#define ROTR64(_x, _s) _rotr64((_x), (_s))

#endif /* DEFS_H */
