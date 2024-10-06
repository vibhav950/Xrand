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

/* Immediate process termination for unrecoverable corruptions */
extern void kill(void);

/* ERROR codes */
#define ERR_SUCCESS 0x00
#define ERR_DEPRECATED 0x01
#define ERR_NO_MEMORY 0x02
#define ERR_RAND_INIT 0x03
#define ERR_REQUEST_TOO_LARGE 0x06
#define ERR_INVALID_POOL_SIZE 0x07
#define ERR_CANNOT_ACCESS_DISK 0x09
#define ERR_JENT_FAILURE 0x0A

// Check debug logs for Win32 system error codes
#define ERR_WIN32_WINAPI 0x31
#define ERR_WIN32_CNG 0x32

#define ERR_ENTROPY_TOO_LOW 0xE0
#define ERR_INIT_CHECKS_FAILED 0xE1
#define ERR_ASSERTION_FAILED 0xE2

/**
 * WARNING codes
 *
 * The exception handler will not handle warnings.
 * Every routine that issues a user warning will
 * print a custom warning message to stderr.
 */
#define WARN_DEPRECATED 0xF0
#define WARN_INVALID_ARGS 0xF1
#define WARN_UNSAFE 0xF2

typedef int ecode_t;

#define FATAL 1

typedef struct _EXCEPTION_ST {
  ecode_t err_code;  // Internal error code
  ecode_t err_fatal; // Trigger a system abort if fatal
  ecode_t err_mswec; // WIN32 error code for bug reports
  ecode_t err_line;  // Line number of exception
} EXCEPTION;

#include <setjmp.h>

extern jmp_buf ex_buf;
extern EXCEPTION ex;

extern const char *exception_message(ecode_t);
extern void set_exception(ecode_t, ecode_t, ecode_t, ecode_t);
extern void handle_exception(ecode_t, ecode_t, ecode_t, ecode_t, int);
extern void clear_exception(EXCEPTION *);
extern void dump_log(ecode_t, ecode_t, ecode_t, ecode_t, int);
extern void assert_expr(char *, int);
extern void warn(char *, int);

#define TRY if (setjmp(ex_buf) == 0)

#if defined(XR_DEBUG)
#define CATCH                                                                  \
  else {                                                                       \
    handle_exception(ex.err_code, ex.err_fatal, ex.err_mswec, ex.err_line, 1); \
    clear_exception(&ex);                                                      \
  }
#else
#define CATCH                                                                  \
  else {                                                                       \
    handle_exception(ex.err_code, ex.err_fatal, ex.err_mswec, ex.err_line, 0); \
    clear_exception(&ex);                                                      \
  }
#endif

#if defined(XR_DEBUG)
#define Throw(code, fatal, mswec, line)                                        \
  handle_exception(code, fatal, mswec, line, 1)
#else
#define Throw(code, fatal, mswec, line)                                        \
  handle_exception(code, fatal, mswec, line, 0)
#endif

#define Raise(code, fatal, mswec, line) set_exception(code, fatal, mswec, line)

#if defined(XR_DEBUG)
#define Log(code, fatal, mswec, line) dump_log(code, fatal, mswec, line, 1)
#else
#define Log(code, fatal, mswec, line) dump_log(code, fatal, mswec, line, 0)
#endif

#if defined(XR_DEBUG)
#define Warn(warning, warntype) warn(warning, warntype)
#else
#define Warn(warning, warntype)                                                \
  {}
#endif

#define Assert(stmt)                                                           \
  do {                                                                         \
    if (!(stmt))                                                               \
      assert_expr(__FILE__, __LINE__);                                         \
  } while (0)

#endif /* EXCEPTIONS_H */
