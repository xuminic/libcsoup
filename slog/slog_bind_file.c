
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

#include "libcsoup.h"


int slog_bind_file(void *control, char *fname, int append)
{
	SMMDBG	*dbgc;

	if ((dbgc = slog_control(control)) == NULL) {
		return -1;
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
	SMMDBG	*dbgc;

	if ((dbgc = slog_control(control)) == NULL) {
		return -1;
	}

	fflush(dbgc->logd);
	fclose(dbgc->logd);
	dbgc->filename = NULL;
	dbgc->device &= ~SLOG_TO_FILE;
	return 0;
}

