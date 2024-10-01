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

#include "exceptions.h"
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>

#if defined(_MSC_VER)
    #include <intrin.h> // __fastfail
    #pragma intrinsic(__fastfail)
#endif

__attribute__( ( noreturn ) ) void kill(void)
{
#if defined(__GNUC__) && __has_builtin(__builtin_trap)
    // GCC / LLVM (Clang)
    __builtin_trap();
#elif _MSC_VER >= 1610
    // Visual Studio
    __fastfail(0);
#else
    // Hacky way to trigger a segfault
    *(char *)0 = 0;
#endif
#if __has_builtin(__builtin_unreachable)
    __builtin_unreachable();
#endif
}

jmp_buf ex_buf;

EXCEPTION ex = {
    .err_code = -1,
    .err_fatal = -1,
    .err_mswec = -1,
    .err_line = -1
};

const char *exception_message (ecode_t ecode)
{
    switch (ecode)
    {
        case ERR_SUCCESS:
            return ("No errors detected.");
        case ERR_DEPRECATED:
            return ("This feature is deprecated.");
        case ERR_NO_MEMORY:
            return ("Ran out of memory.");
        case ERR_RAND_INIT:
            return ("Failed to initialize the RNG.");
        case ERR_REQUEST_TOO_LARGE:
            return ("Request exceeded maximum allowed length.");
        case ERR_INVALID_POOL_SIZE:
            return ("Pool size not a multiple of digest length.");
        case ERR_CANNOT_ACCESS_DISK:
            return ("The disk could not be accessed.");
        case ERR_JENT_FAILURE:
            return ("Jitter RNG failure.");
        case ERR_WIN32_WINAPI:
            return ("Win32 API failure (check logs for debug info).");
        case ERR_WIN32_CNG:
            return ("Windows CNG failure (check logs for debug info).");
        case ERR_ENTROPY_TOO_LOW:
            return ("Insufficient system entropy");
        case ERR_INIT_CHECKS_FAILED:
            return ("Did not pass initialization checks.");
        case ERR_ASSERTION_FAILED:
            return ("Assertion failed.");
    }

    return (""); // dummy
}

void set_exception (ecode_t code, ecode_t fatal, ecode_t mswec, ecode_t line)
{
    ex.err_code = code;
    ex.err_fatal = fatal;
    ex.err_mswec = mswec;
    ex.err_line = line;
    longjmp(ex_buf, 1);
}

void handle_exception (ecode_t code, ecode_t fatal, ecode_t mswec, ecode_t line, int verbose)
{
    if (fatal)
    {
#if !defined(XR_NO_CRASH_DUMP)
        time_t _t = time(NULL);
        struct tm _tm = *localtime(&_t);
        FILE* _fpLog = fopen("logs\\crashdebug.log", "at");
        if (_fpLog)
        {
            fprintf(_fpLog, 
                    "[%d %02d %02d %02d:%02d:%02d] [LINE %d] ERR 0x%X (WIN32 ERR 0x%X)\n",
                    _tm.tm_year + 1900, _tm.tm_mon + 1, _tm.tm_mday, _tm.tm_hour, _tm.tm_min, _tm.tm_sec,
                    line,
                    code,
                    mswec
                    );
            fclose(_fpLog);
        }
#endif
        if (verbose)
        {
            fflush(NULL);
            fprintf(stderr, "\x1B[91m[FATAL 0x%X]\x1B[0m Aborting due to previous error.\n", code);
            fflush(stderr);
        }
        kill();
    }
    else if (verbose)
    {
        fflush(NULL);
        fprintf(stderr, "\n\x1B[33m[ERR 0x%X]\x1B[0m %s\n", code, exception_message(code));
        fflush(stderr);
    }
}

void clear_exception (EXCEPTION *pex)
{
    pex->err_code = 0;
    pex->err_fatal = -1;
    pex->err_mswec = 0;
    pex->err_line = -1;
}

void dump_log (ecode_t code, ecode_t fatal, ecode_t mswec, ecode_t line, int verbose)
{
#if !defined(XR_NO_CRASH_DUMP)
    time_t _t = time(NULL);
    struct tm _tm = *localtime(&_t);
    FILE* _fpLog = fopen("logs\\crashdebug.log", "at");
    if (_fpLog)
    {
        fprintf(_fpLog, 
                "[%d %02d %02d %02d:%02d:%02d] [LINE %d] ERR 0x%X (WIN32 ERR 0x%X)\n",
                _tm.tm_year + 1900, _tm.tm_mon + 1, _tm.tm_mday, _tm.tm_hour, _tm.tm_min, _tm.tm_sec,
                line,
                code,
                mswec
                );
        fclose(_fpLog);
    }
#endif
    if (verbose)
    {
        fflush(NULL);
        fprintf(stderr, "\n\x1B[33m[ERR 0x%X]\x1B[0m %s\n", code, exception_message(code));
        fflush(stderr);
    }
}

void warn (char *warning, int warntype)
{
    fprintf(stderr, "\n\x1B[33m[WARN]\x1B[0m %s\n", warning);
}
