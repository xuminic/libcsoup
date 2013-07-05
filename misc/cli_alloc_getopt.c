
/*  cli_alloc_getopt.c - command line option utility

    Copyright (C) 2011-2013  "Andy Xuming" <xuming@users.sourceforge.net>

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


#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cliopt.h"

struct clirun *cli_alloc_getopt(struct cliopt *optbl)
{
	struct	clirun	*rtbuf;
	int	n, k, rc;

	n  = cli_table_size(optbl) + 1;
	rc = n * (sizeof(struct option) + 4) + sizeof(struct clirun);
	if ((rtbuf = malloc(rc)) == NULL) {
		return NULL;
	}
	memset(rtbuf, 0, rc);

	rtbuf->optarg = (char*) &rtbuf->oplst[n];
	for (n = k = 0; (rc = cli_type(optbl)) != CLI_EOL; optbl++) {
		if (rc & CLI_SHORT) {
			rtbuf->optarg[n++] = optbl->opt_char;
			if (optbl->param > 0) {
				rtbuf->optarg[n++] = ':';
			}
		}
		if (rc & CLI_LONG) {
			rtbuf->oplst[k].name    = optbl->opt_long;
			rtbuf->oplst[k].has_arg = optbl->param > 0 ? 1 : 0;
			rtbuf->oplst[k].val     = optbl->opt_char;
			k++;
		}
	}
	return rtbuf;
}

