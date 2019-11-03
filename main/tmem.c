/*  tmem.c - test harness of csc_tmem functions

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
#include <unistd.h>

#include "libcsoup.h"
#include "libcsoup_debug.h"

#ifdef	CFG_UNIT_TEST
extern int csc_tmem_unittest(void);
#endif
int tmem_main(void *rtime, int argc, char **argv)
{
	(void)rtime; (void)argc; (void)argv;

#ifdef	CFG_UNIT_TEST
	csc_tmem_unittest();
#endif
	return 0;
}

struct	clicmd	tmem_cmd = {
	"tmem", tmem_main, NULL, "Testing the tiny memory management functions"
};

extern  struct  clicmd  tmem_cmd;
