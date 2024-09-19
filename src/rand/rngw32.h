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

#ifndef GENERATOR_CORE_H
#define GENERATOR_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include "common/defs.h"

/* OpenSSL is required for cryptographic utilities */
#if __has_include(<openssl/sha.h>)
#include <openssl/sha.h>
#else
#error "OpenSSL not found"
#endif

/* RNG basic macros */
#define RNG_POOL_SIZE 384

#if RNG_POOL_SIZE % SHA512_DIGEST_LENGTH
#error "RNG_POOL_SIZE must be a multiple of SHA512_DIGEST_LEN"
#endif 

#define RNG_POOL_CHUNK_SIZE SHA512_DIGEST_LENGTH

#define RNG_POOL_CHUNKS (RNG_POOL_SIZE / RNG_POOL_CHUNK_SIZE)

/* Interval in milliseconds between successive fast polls */
#define RNG_FAST_POLL_INTERVAL 500

/**
 * Call the pool mix function after every RNG_POOL_MIX_INTERVAL
 * bytes added to the pool.
 */
#define RNG_POOL_MIX_INTERVAL 32

BOOL RandPoolInit (void);
void RandCleanStop (void);
BOOL RandFastPoll (void);
BOOL RandSlowPoll (void);
void RandPoolMix (void);
BOOL RandFetchBytes (uint8_t* out, size_t len, int forceSlowPoll);

BOOL CALLBACK EnumWindowsProc (HWND hWnd, LPARAM lParam);
LRESULT CALLBACK MouseProc (int nCode, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK KeyboardProc (int nCode, WPARAM wParam, LPARAM lParam);
static unsigned __stdcall FastPollThreadProc (void *_dummy);

bool RngStart (void);
void RngStop (void);
bool DidRngStart (void);
bool DidRngSlowPoll(void);
void RngMix (void);

/**
 * Fetch len bytes from the randomness pool where len can be any
 * positive value lesser than or equal to RNG_POOL_SIZE.
 *
 * Returns 1 if the bytes were fetched successfully, 0 otherwise.
 */
bool RngFetchBytes (uint8_t* out, size_t len);

extern BOOL bStrictChecksEnabled;
extern BOOL bUserEventsEnabled;
extern BOOL HasRdrand;
extern BOOL HasRdseed;
extern DWORD dwWin32CngLastErr;
extern DWORD dwErrCode;
extern volatile int nUserEventsAdded;

#ifdef __cplusplus
}
#endif

#endif /* GENERATOR_CORE_H */