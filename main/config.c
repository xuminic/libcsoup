/*  fontpath.c - test harness of smm_fontpath()

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
#include <stdlib.h>

#include "libcsoup.h"

int config_main(int argc, char **argv)
{
	void	*root;

	while (--argc && (**++argv == '-')) {
		if (!strcmp(*argv, "-h") || !strcmp(*argv, "--help")) {
			slogz("config \n");
			return 0;
		} else {
			slogz("Unknown option. [%s]\n", *argv);
			return -1;
		}
	}
	/*if (argc > 0) {
		fdir = smm_fontpath(*argv, argv+1);
		slogz("%s\n", fdir);
		free(fdir);
	}*/
	root = csc_cfg_open("/home/xum1/.config/ezthumb", "ezthumb.test", 1);
	csc_cfg_dump(root, NULL);
	csc_cfg_close(root);
	return 0;
}

