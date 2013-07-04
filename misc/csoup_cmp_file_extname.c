
/*  csoup_cmp_file_extname.c

    Copyright (C) 2013  "Andy Xuming" <xuming@users.sourceforge.net>

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
#include <string.h>
#include <stdarg.h>

/* if 'fname' has the same extension name to 'ext', it returns 0 
 * (strcmp return protocol)
 * the 'ext' can start with or without the '.'. 
 * for example: "c", ".c" and "*.c" are all right */
int csoup_cmp_file_extname(char *fname, char *ext)
{
	char	*p;
	int	n;

	if (!fname || !ext) {
		if (!fname && !ext) {
			return 0;
		}
		return -2;
	}

	if ((p = strrchr(ext, '.')) != NULL) {
		ext = p + 1;
	}

	if ((n = strlen(fname) - strlen(ext)) <= 0) {
		return -1;
	}
	if (fname[n-1] != '.') {
		return n;
	}
	if (strcasecmp(fname + n, ext)) {
		return n;
	}
	return 0;	/* matched */
}


int csoup_cmp_file_extlist(char *fname, char **ext)
{
	int	i;

	if (!ext || !*ext) {
		return -1;
	}
	for (i = 0; ext[i]; i++) {
		if (!csoup_cmp_file_extname(fname, ext[i])) {
			return 0;
		}
	}
	return i;
}


/* it must end by a NULL, otherwise it goes nasty. 
 * for example:
 * csoup_cmp_file_extargs("my_file_name.ext", ".c", ".h", ".cc", NULL); */
int csoup_cmp_file_extargs(char *fname, char *ext, ...)
{
	va_list	ap;
	char	*s;
	int	n;

	va_start(ap, ext);
	n = 1;
	s = va_arg(ap, char *);
	while (s) {
		if (!csoup_cmp_file_extname(fname, s)) {
			return 0;
		}
		s = va_arg(ap, char *);
		n++;
	}
	va_end(ap);
	return n;
}


