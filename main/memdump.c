/*  memdump.c - test harness of memdump()

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

#include "libcsoup.h"

extern SMMDBG  *tstdbg;

int memdump_main(int argc, char **argv)
{
	char	user[384];
	int	i;

	(void) argc;
	(void) argv;	/* stop the compiler warning */

	for (i = 0; i < (int)sizeof(user); user[i] = i, i++);

	csc_memdump(user, sizeof(user), 16, 7);
	csc_memdump(user, sizeof(user), 8, 16);
	csc_memdump(user, sizeof(user), 6, 32);
	csc_memdump(user, sizeof(user), 3, 64);
	csc_memdump(user+sizeof(user), -(int)(sizeof(user)), 6, 32);
	csc_memdump(user+sizeof(user), -(int)(sizeof(user)), 16, 8);
	slogc(tstdbg, SLINFO, "sizeof int=%ld long=%ld short=%ld long long=%ld long int=%ld\n",
			sizeof(int), sizeof(long), sizeof(short), sizeof(long long), sizeof(long int));
	return 0;
}

