/** @file exceptions.h
 *  @brief Exception handling for internal use within the library.
 *
 *  This file contains defines for error codes and exception handling
 *  routines for the Xrand core library.
 *
 *  @author Vibhav Tiwari [vibhav950 on GitHub]
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

#ifndef EXCEPTIONS_H
#define EXCEPTIONS_H

#if __has_builtin(__builtin_trap)
#define kill __builtin_trap
#else
#define kill(_) { *(char *)0 = 0; }
#endif

/* ERROR codes */
#define ERR_SUCCESS                     0x00
#define ERR_DEPRECATED                  0x01
#define ERR_NO_MEMORY                   0x02
#define ERR_RAND_INIT                   0x03
#define ERR_REQUEST_TOO_LARGE           0x06
#define ERR_DIGEST_LEN_MISMATCH         0x07
#define ERR_CANNOT_ACCESS_DISK          0x09
#define ERR_JENT_FAILURE                0x0A

// Check debug logs for Win32 system error codes
#define ERR_WINAPI                      0x31
#define ERR_CNG                         0x32

#define ERR_ENTROPY_TOO_LOW             0xE0
#define ERR_INIT_CHECKS_FAILED          0xE1
#define ERR_ASSERTION_FAILED            0xE2

/**
 * WARNING codes
 * 
 * The exception handler will not handle warnings.
 * Every routine that issues a user warning will
 * print a custom warning message to stderr. 
*/
#define WARN_DEPRECATED            0xF0
#define WARN_INVALID_PARAM         0xF1
#define WARN_UNSAFE                0xF2  

typedef int ecode_t;

#define FATAL 1

typedef struct _EXCEPTION_ST
{
    ecode_t err_code;     // Internal error code
    ecode_t err_fatal;    // Trigger a system abort if fatal
    ecode_t err_mswec;    // WIN32 error code for bug reports
    ecode_t err_line;     // Line number of exception
} EXCEPTION;

#include <setjmp.h>

extern jmp_buf ex_buf;
extern EXCEPTION ex;

extern const char *exception_message(ecode_t);
extern void set_exception(ecode_t, ecode_t, ecode_t, ecode_t);
extern void handle_exception(ecode_t, ecode_t, ecode_t, ecode_t);
extern void clear_exception(EXCEPTION*);
extern void dump_log(ecode_t, ecode_t, ecode_t, ecode_t);
extern void warn (char*, int);

#define TRY if (setjmp(ex_buf) == 0)

#define CATCH\
    else {\
        handle_exception(ex.err_code, ex.err_fatal, ex.err_mswec, ex.err_line);\
        clear_exception(&ex);\
    }

#define Throw(code, fatal, mswec, line)\
    handle_exception(code, fatal, mswec, line)

#define Raise(code, fatal, mswec, line)\
    set_exception(code, fatal, mswec, line)

#define Log(code, fatal, mswec, line)\
    dump_log(code, fatal, mswec, line)

#define Warn(warning, warntype)\
    warn(warning, warntype)

#endif /* EXCEPTIONS_H */