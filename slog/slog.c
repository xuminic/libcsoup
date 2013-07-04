
/*  slog.c - a simple interface for logging/debugging

    Copyright (C) 2011  "Andy Xuming" <xuming@users.sourceforge.net>

    This file is part of CSOUP, Chicken Soup library

    CSOUP is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CSOUP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "slog.h"

static	SMMDBG	*SlogCB = NULL;

void *slog_open(int cword)
{
	if ((SlogCB = calloc(sizeof(SMMDBG), 1)) != NULL) {
		SlogCB->control = (unsigned) cword;
		SlogCB->device  = SLOG_TO_STDOUT;
	}
	return SlogCB;
}

int slog_close(void *control)
{
	SMMDBG	*dbgc = control;

	if (dbgc == NULL) {
		if ((dbgc = SlogCB) == NULL) {
			return 0;
		}
	}

	if (dbgc->device & SLOG_TO_STDOUT) {
		fflush(stdout);
	}
	if (dbgc->device & SLOG_TO_STDERR) {
		fflush(stderr);
	}
	if (dbgc->device & SLOG_TO_FILE) {
		fflush(dbgc->logd);
		fclose(dbgc->logd);
	}

	free(dbgc);
	if (control == NULL) {
		SlogCB = NULL;
	}
	return 0;
}

unsigned slog_control_word_read(void *control)
{
	SMMDBG	*dbgc = control;

	if (dbgc == NULL) {
		if ((dbgc = SlogCB) == NULL) {
			return 0;
		}
	}
	return dbgc->control;
}

unsigned slog_control_word_write(void *control, unsigned cword)
{
	SMMDBG		*dbgc = control;
	unsigned	tmp = 0;

	if (dbgc == NULL) {
		if ((dbgc = SlogCB) == NULL) {
			return 0;
		}
	}

	tmp = dbgc->control;
	dbgc->control = cword;
	return tmp;
}


int slog_level_read(void *control)
{
	SMMDBG	*dbgc = control;

	if (dbgc == NULL) {
		if ((dbgc = SlogCB) == NULL) {
			return 0;
		}
	}
	return SLOG_LEVEL(dbgc->control);
}

int slog_level_write(void *control, int dbg_lvl)
{
	SMMDBG	*dbgc = control;
	int	tmp;

	if (dbgc == NULL) {
		if ((dbgc = SlogCB) == NULL) {
			return 0;
		}
	}

	tmp = slog_level_read(dbgc);
	dbgc->control = SLOG_MODULE(dbgc->control) | SLOG_LEVEL(dbg_lvl);
	return tmp;
}

int slog_bind_stdout(void *control)
{
	SMMDBG	*dbgc = control;

	if (dbgc == NULL) {
		if ((dbgc = SlogCB) == NULL) {
			return -1;
		}
	}
	dbgc->device |= SLOG_TO_STDOUT;
	return 0;
}

int slog_unbind_stdout(void *control)
{
	SMMDBG	*dbgc = control;

	if (dbgc == NULL) {
		if ((dbgc = SlogCB) == NULL) {
			return -1;
		}
	}
	fflush(stdout);
	dbgc->device &= ~SLOG_TO_STDOUT;
	return 0;
}

int slog_bind_stderr(void *control)
{
	SMMDBG	*dbgc = control;

	if (dbgc == NULL) {
		if ((dbgc = SlogCB) == NULL) {
			return -1;
		}
	}
	dbgc->device |= SLOG_TO_STDERR;
	return 0;
}

int slog_unbind_stderr(void *control)
{
	SMMDBG	*dbgc = control;

	if (dbgc == NULL) {
		if ((dbgc = SlogCB) == NULL) {
			return -1;
		}
	}
	fflush(stderr);
	dbgc->device &= ~SLOG_TO_STDERR;
	return 0;
}

int slog_bind_file(void *control, char *fname, int append)
{
	SMMDBG	*dbgc = control;

	if (dbgc == NULL) {
		if ((dbgc = SlogCB) == NULL) {
			return -1;
		}
	}

	if (append) {
		dbgc->logd = fopen(fname, "a+");
	} else {
		dbgc->logd = fopen(fname, "w");
	}
	if (dbgc->logd == NULL) {
		return -2;
	}
	
	dbgc->filename = fname;
	dbgc->device |= SLOG_TO_FILE;
	return 0;
}

int slog_unbind_file(void *control)
{
	SMMDBG	*dbgc = control;

	if (dbgc == NULL) {
		if ((dbgc = SlogCB) == NULL) {
			return -1;
		}
	}

	fflush(dbgc->logd);
	fclose(dbgc->logd);
	dbgc->filename = NULL;
	dbgc->device &= ~SLOG_TO_FILE;
	return 0;
}

int slog_bind_socket(void *control, int socket)
{
	SMMDBG	*dbgc = control;

	if (dbgc == NULL) {
		if ((dbgc = SlogCB) == NULL) {
			return -1;
		}
	}
	return 0;
}

int slog_unbind_socket(void *control)
{
	SMMDBG	*dbgc = control;

	if (dbgc == NULL) {
		if ((dbgc = SlogCB) == NULL) {
			return -1;
		}
	}
	return 0;
}

int slog_bind_window(void *control)
{
	SMMDBG	*dbgc = control;

	if (dbgc == NULL) {
		if ((dbgc = SlogCB) == NULL) {
			return -1;
		}
	}
	return 0;
}

int slog_unbind_window(void *control)
{
	SMMDBG	*dbgc = control;

	if (dbgc == NULL) {
		if ((dbgc = SlogCB) == NULL) {
			return -1;
		}
	}
	return 0;
}

int slog(int cw, char *fmt, ...)
{
	SMMDBG	*dbgc = SlogCB;
	char	logbuf[SLOG_BUFFER];
	int	n;
	va_list	ap;

	if ((SLOG_LEVEL(cw) > SLOG_LVL_ERROR) && (dbgc != NULL))  {
		if (SLOG_LEVEL(cw) > SLOG_LEVEL(dbgc->control)) {
			return 0;
		}
	}

	va_start(ap, fmt);
	n = vsnprintf(logbuf, sizeof(logbuf), fmt, ap);
	va_end(ap);

	if (dbgc == NULL) {	/* ignore the control */
		fwrite(logbuf, n, 1, stdout);
		if (SLOG_LEVEL(cw) <= SLOG_LVL_ERROR) {
			fflush(stdout);
		}
		return n;
	}

	if (dbgc->device & SLOG_TO_STDOUT) {
		fwrite(logbuf, n, 1, stdout);
		if (SLOG_LEVEL(cw) <= SLOG_LVL_ERROR) {
			fflush(stdout);
		}
	}
	if (dbgc->device & SLOG_TO_STDERR) {
		fwrite(logbuf, n, 1, stderr);
		if (SLOG_LEVEL(cw) <= SLOG_LVL_ERROR) {
			fflush(stderr);
		}
	}
	if (dbgc->device & SLOG_TO_FILE) {
		fwrite(logbuf, n, 1, dbgc->logd);
		if (SLOG_LEVEL(cw) <= SLOG_LVL_ERROR) {
			fflush(dbgc->logd);
		}
	}
	return n;
}




