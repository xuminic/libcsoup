
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

static int slog_def_stdout(int flush, char *buf, int len)
{
	if (buf) {
		len = fwrite(buf, len, 1, stdout);
	}
	if (flush) {
		fflush(stdout);
	}
	return len;
}

static int slog_def_stderr(int flush, char *buf, int len)
{
	if (buf) {
		len = fwrite(buf, len, 1, stderr);
	}
	if (flush) {
		fflush(stderr);
	}
	return len;
}



void *slog_open(int cword)
{
	SMMDBG	*dbgc;

	if ((dbgc = calloc(sizeof(SMMDBG), 1)) != NULL) {
		dbgc->control = (unsigned) cword;
		dbgc->device  = SLOG_TO_STDOUT;

		dbgc->stdoutput = slog_def_stdout;
		dbgc->stderrput = slog_def_stderr;
	}

	SlogCB = dbgc;		/* so far so good ... */

	return dbgc;
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
		dbgc->stdoutput(1, NULL, 0);
	}
	if (dbgc->device & SLOG_TO_STDERR) {
		dbgc->stderrput(1, NULL, 0);
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

int slog_bind_stdout(void *control, F_STD func)
{
	SMMDBG	*dbgc = control;

	if (dbgc == NULL) {
		if ((dbgc = SlogCB) == NULL) {
			return -1;
		}
	}

	dbgc->device |= SLOG_TO_STDOUT;
	if (func == (F_STD) -1) {
		dbgc->stdoutput = slog_def_stdout;
	} else if (func) {
		dbgc->stdoutput = func;
	}
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
	
	dbgc->stdoutput(1, NULL, 0);
	dbgc->device &= ~SLOG_TO_STDOUT;
	return 0;
}

int slog_bind_stderr(void *control, F_STD func)
{
	SMMDBG	*dbgc = control;

	if (dbgc == NULL) {
		if ((dbgc = SlogCB) == NULL) {
			return -1;
		}
	}

	dbgc->device |= SLOG_TO_STDERR;
	if (func == (F_STD) -1) {
		dbgc->stderrput = slog_def_stderr;
	} else if (func) {
		dbgc->stderrput = func;
	}
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

	dbgc->stderrput(1, NULL, 0);
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


int slog_output(SMMDBG *dbgc, int cw, char *buf, int len)
{
	if (dbgc == NULL) {	/* ignore the control */
		len = slog_def_stdout(0, buf, len);
		if (SLOG_LEVEL(cw) <= SLOG_LVL_ERROR) {
			slog_def_stdout(1, NULL, 0);
		}
		return len;
	}

	if (dbgc->device & SLOG_TO_STDOUT) {
		len = dbgc->stdoutput(0, buf, len);
		if (SLOG_LEVEL(cw) <= SLOG_LVL_ERROR) {
			dbgc->stdoutput(1, NULL, 0);
		}
	}
	if (dbgc->device & SLOG_TO_STDERR) {
		len = dbgc->stderrput(0, buf, len);
		if (SLOG_LEVEL(cw) <= SLOG_LVL_ERROR) {
			dbgc->stderrput(1, NULL, 0);
		}
	}
	if (dbgc->device & SLOG_TO_FILE) {
		len = fwrite(buf, len, 1, dbgc->logd);
		if (SLOG_LEVEL(cw) <= SLOG_LVL_ERROR) {
			fflush(dbgc->logd);
		}
	}
	return len;
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

	return slog_output(dbgc, cw, logbuf, n);
}

int slogc(void *control, int cw, char *fmt, ...)
{
	SMMDBG	*dbgc = control;
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

	return slog_output(dbgc, cw, logbuf, n);
}


int slogs(void *control, int cw, char *buf, int len)
{
	SMMDBG	*dbgc = control;

	if ((SLOG_LEVEL(cw) > SLOG_LVL_ERROR) && (dbgc != NULL))  {
		if (SLOG_LEVEL(cw) > SLOG_LEVEL(dbgc->control)) {
			return 0;
		}
	}

	return slog_output(dbgc, cw, buf, len);
}




