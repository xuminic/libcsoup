
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

void slog_init(int cword)
{
	if ((SlogCB = calloc(sizeof(SMMDBG), 1)) != NULL) {
		SlogCB->control = (unsigned) cword;
		SlogCB->device  = SLOG_TO_STDOUT;
	}
}

void slog_destroy(void)
{
	if (SlogCB == NULL) {
		return;
	}
	if (SlogCB->device & SLOG_TO_STDOUT) {
		fflush(stdout);
	}
	if (SlogCB->device & SLOG_TO_STDERR) {
		fflush(stderr);
	}
	if (SlogCB->device & SLOG_TO_FILE) {
		close(SlogCB->logd);
	}

	free(SlogCB);
	SlogCB = NULL;
}

unsigned slog_control_word_read(void)
{
	if (SlogCB) {
		return SlogCB->control;
	}
	return 0;
}

unsigned slog_control_word_write(unsigned cword)
{
	unsigned	tmp = 0;

	if (SlogCB) {
		tmp = SlogCB->control;
		SlogCB->control = cword;
	}
	return tmp;
}


int slog_level_read(void)
{
	if (SlogCB) {
		return SlogCB->control & 7;
	}
	return 0;
}

int slog_level_write(int dbg_lvl)
{
	int	tmp = 0;

	if (SlogCB) {
		tmp = SlogCB->control & 7;
		SlogCB->control = (SlogCB->control & ~7) | 
			(dbg_lvl & 7);
	}
	return tmp;
}

int slog_bind_stdout(void)
{
	if (SlogCB == NULL) {
		return -1;
	}

	SlogCB->device |= SLOG_TO_STDOUT;
	return 0;
}

int slog_unbind_stdout(void)
{
	if (SlogCB == NULL) {
		return -1;
	}

	fflush(stdout);
	SlogCB->device &= ~SLOG_TO_STDOUT;
	return 0;
}

int slog_bind_stderr(void)
{
	if (SlogCB == NULL) {
		return -1;
	}

	SlogCB->device |= SLOG_TO_STDERR;
	return 0;
}

int slog_unbind_stderr(void)
{
	if (SlogCB == NULL) {
		return -1;
	}

	fflush(stderr);
	SlogCB->device &= ~SLOG_TO_STDERR;
	return 0;
}

int slog_bind_file(char *fname, int append)
{
	if (SlogCB == NULL) {
		return -1;
	}

	if (append) {
		SlogCB->logd = open(fname, O_APPEND|O_CREAT|O_RDWR);
	} else {
		SlogCB->logd = open(fname, O_TRUNC|O_CREAT|O_RDWR);
	}
	if (SlogCB->logd < 0) {
		return -2;
	}
	
	SlogCB->filename = fname;
	SlogCB->device |= SLOG_TO_FILE;
	return 0;
}

int slog_unbind_file(void)
{
	if (SlogCB == NULL) {
		return -1;
	}

	close(SlogCB->logd);
	SlogCB->filename = NULL;
	SlogCB->device &= ~SLOG_TO_FILE;
	return 0;
}

int slog_bind_socket(int socket)
{
	return 0;
}

int slog_unbind_socket(void)
{
	return 0;
}

int slog_bind_window(void)
{
	return 0;
}

int slog_unbind_window(void)
{
	return 0;
}

int slog(int cw, char *fmt, ...)
{
	char	logbuf[SLOG_BUFFER];
	int	n;
	va_list	ap;

	va_start(ap, fmt);
	n = vsnprintf(logbuf, sizeof(logbuf), fmt, ap);
	va_end(ap);

	if (SlogCB == NULL) {	/* ignore the control */
		printf("%s", logbuf);
		return n;
	}

	if (SLOG_LEVEL(cw) > SLOG_LVL_ERROR) {
		if (SLOG_LEVEL(cw) > SLOG_LEVEL(SlogCB->control)) {
			return 0;
		}
		if ((SLOG_MODULE(cw) & SLOG_MODULE(SlogCB->control)) 
				!= SLOG_MODULE(cw)) {
			return 0;
		}
	}

	if (SlogCB->device & SLOG_TO_STDOUT) {
		fwrite(logbuf, n, 1, stdout);
		if (SLOG_LEVEL(cw) == SLOG_LVL_SHOWOFF) {
			fflush(stdout);
		}
	}
	if (SlogCB->device & SLOG_TO_STDERR) {
		fwrite(logbuf, n, 1, stderr);
		if (SLOG_LEVEL(cw) == SLOG_LVL_SHOWOFF) {
			fflush(stderr);
		}
	}
	if (SlogCB->device & SLOG_TO_FILE) {
		write(SlogCB->logd, logbuf, n);
	}
	return n;
}




