
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
#include <time.h>
#include "csoup_internal.h"

static char *slog_csoup_prefix(void *self, int cw);

SMMDBG	csoup_debug_control = {
	SLOG_MAGIC,				/* the magic word */
	SLOG_LEVEL_SET(-1, SLOG_LVL_ERROR),	/* control word in host */
	0,					/* option */
	NULL, NULL,				/* file name and FILEP */
	0,					/* socket */
	NULL,					/* standard i/o */
	slog_csoup_prefix			/* generating the prefix */
};

int	csoup_debug_cword = 0;


SMMDBG *slog_csoup_open(FILE *stdio, char *fname, int cword)
{
	if (stdio) {
		slog_bind_stdio(&csoup_debug_control, stdio);
	}
	if (fname) {
		slog_bind_file(&csoup_debug_control, fname);
	}
	csoup_debug_cword = cword;
	return &csoup_debug_control;
}

int slog_csoup_close(void)
{
	return slog_shutdown(&csoup_debug_control);
}

int slog_csoup_puts(SMMDBG *dbgc, int setcw, int cw, char *buf)
{
	if (!slog_validate(dbgc, setcw, cw)) {
		return -1;
	}
	return slog_output(dbgc, cw, buf);
}

/** better use this as an example becuase it's not thread safe */
char *slog_csoup_format(char *fmt, ...)
{
	static	char	logbuf[SLOG_BUFFER];
	va_list ap;

	va_start(ap, fmt);
	SMM_VSNPRINT(logbuf, sizeof(logbuf), fmt, ap);
	va_end(ap);
	return logbuf;
}

static char *slog_csoup_prefix(void *self, int cw)
{
	static	char	buffer[64];
	SMMDBG	*dbgc = self;

	sprintf(buffer, "[%d]", time(NULL));
	if (cw & CSOUP_MOD_SLOG) {
		strcat(buffer, "[SLOG]");
	} else if (cw & CSOUP_MOD_CLI) {
		strcat(buffer, "[CLI]");
	} else  if (cw & CSOUP_MOD_CONFIG) {
		strcat(buffer, "[CONFIG]");
	}
	strcat(buffer, " ");
	return buffer;
}

