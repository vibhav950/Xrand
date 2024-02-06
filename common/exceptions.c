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

#include "common/exceptions.h"
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>

jmp_buf ex_buf;

EXCEPTION ex = {.err_code = -1,
                   .err_fatal = -1,
                   .err_mswec = -1,
                   .err_line = -1
                  };

const char *exception_message (ecode_t ecode)
{
    switch (ecode)
    {
        case ERR_SUCCESS:
            return ("No error.");
        case ERR_DEPRECATED:
            return ("This feature is deprecated.");
        case ERR_NO_MEMORY:
            return ("Memory allocation failure.");
        case ERR_RAND_INIT:
            return ("Failed to init the RNG.");
        case ERR_REQUEST_TOO_LARGE:
            return ("Request exceeded maximum allowed length.");
        case ERR_DIGEST_LEN_MISMATCH:
            return ("Block size does not align with digest length.");
        case ERR_CANNOT_ACCESS_DISK:
            return ("The disk could not be accessed.");
        case ERR_JENT_FAILURE:
            return ("Jitter RNG failure.");
        case ERR_WINAPI:
            return ("Win32 API failure (check logs for debug info).");
        case ERR_CNG:
            return ("Windows CNG failure (check logs for debug info).");
        case ERR_ENTROPY_TOO_LOW:
            return ("Insufficient system entropy");
        case ERR_INIT_CHECKS_FAILED:
            return ("Did not pass init checks.");
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

void handle_exception (ecode_t code, ecode_t fatal, ecode_t mswec, ecode_t line)
{
    if (fatal)
    {
        time_t _t = time(NULL);
        struct tm _tm = *localtime(&_t);
        FILE* _fpLog = fopen("../logs/crashdebug.log", "a+");
        if (_fpLog)
        {
            fprintf(_fpLog, 
                    "[%d %02d %02d %02d:%02d:%02d] [LINE %d] ERR 0x%X (WIN 0x%X)\n",
                    _tm.tm_year + 1900, _tm.tm_mon + 1, _tm.tm_mday, _tm.tm_hour, _tm.tm_min, _tm.tm_sec,
                    line,
                    code,
                    mswec
                    );
            fclose(_fpLog);
        }
        fprintf(stderr, "\x1B[91m[FATAL 0x%X]\x1B[0m Aborting due to previous error.\n", code);
        kill();
    }
    else
    {
        fprintf(stderr, "\n\x1B[33m[ERR 0x%X]\x1B[0m %s\n", code, exception_message(code));
    }
}

void clear_exception (EXCEPTION *pex)
{
    pex->err_code = 0;
    pex->err_fatal = -1;
    pex->err_mswec = 0;
    pex->err_line = -1;
}

void dump_log (ecode_t code, ecode_t fatal, ecode_t mswec, ecode_t line)
{
    time_t _t = time(NULL);
    struct tm _tm = *localtime(&_t);
    FILE* _fpLog = fopen("../logs/crashdebug.log", "a+");
    if (_fpLog)
    {
        fprintf(_fpLog, 
                "[%d %02d %02d %02d:%02d:%02d] [LINE %d] ERR 0x%X (WIN 0x%X)\n",
                _tm.tm_year + 1900, _tm.tm_mon + 1, _tm.tm_mday, _tm.tm_hour, _tm.tm_min, _tm.tm_sec,
                line,
                code,
                mswec
                );
        fclose(_fpLog);
    }
    fprintf(stderr, "\n\x1B[33m[ERR 0x%X]\x1B[0m %s\n", code, exception_message(code));
}

void warn (char *warning, int warntype)
{
    fprintf(stderr, "\n\x1B[33m[WARN]\x1B[0m %s\n", warning);
}