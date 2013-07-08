
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


int slog_output(SMMDBG *dbgc, int cw, char *buf, int len)
{
	if (dbgc == NULL) {	/* ignore the control */
		len = slog_def_stdout(SLOG_BUFFERED, buf, len);
		if (SLOG_LEVEL(cw) <= SLOG_LVL_ERROR) {
			slog_def_stdout(SLOG_NONBUFED, NULL, 0);
		}
		return len;
	}

	if (dbgc->device & SLOG_TO_STDOUT) {
		len = dbgc->stdoutput(SLOG_BUFFERED, buf, len);
		if (SLOG_LEVEL(cw) <= SLOG_LVL_ERROR) {
			dbgc->stdoutput(SLOG_NONBUFED, NULL, 0);
		}
	}
	if (dbgc->device & SLOG_TO_STDERR) {
		len = dbgc->stderrput(SLOG_BUFFERED, buf, len);
		if (SLOG_LEVEL(cw) <= SLOG_LVL_ERROR) {
			dbgc->stderrput(SLOG_NONBUFED, NULL, 0);
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

