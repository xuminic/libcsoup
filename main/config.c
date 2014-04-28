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
#include <time.h>

#include "libcsoup.h"

#define	TESTPATH	"/home/xum1/.config/ezthumb"
#define TESTINPUT	"ezthumb.test"
#define TESTOUTPUT	"ezthumb.out"

static int config_open_rdonly(void)
{
	void	*root;

	root = csc_cfg_open(TESTPATH, TESTINPUT, 1);
	csc_cfg_dump(root, NULL);
	if (csc_cfg_save(root) == SMM_ERR_NONE) {
		slogz("FATAL: should be read only\n");
		csc_cfg_abort(root);
		return 0;
	}

	csc_cfg_saveas(root, TESTPATH, TESTOUTPUT);
	csc_cfg_abort(root);
	return 0;
}

static int config_key_test(void)
{
	void	*root;
	int	i;
	char	*val, *key;
	char	nkey[64], mkey[64];
	time_t	tmtick;
	struct	tm	*ltm;
	char	*rdlist[][2] = {
		{ "[hello]", "grid_column" },
		{ "[hello]", "grid_column=4" },
		{ "[hello]", "window_width" },
		{ "[main]", "window_width" },
		{ "[main]", "simple_profile" },
		{ "[what]", "zoom_height" },
		{ "[print]", "last_directory" },
		{ NULL, "window_width" },
		{ NULL, NULL }
	};

	root = csc_cfg_open(TESTPATH, TESTINPUT, 0);
	for (i = 0; rdlist[i][0] || rdlist[i][1]; i++) {
		slogz("READ %s: %s = %s\n", rdlist[i][0], rdlist[i][1],
				csc_cfg_read(root, rdlist[i][0], rdlist[i][1]));
	}

	if ((val = csc_cfg_read_first(root, NULL, &key)) != NULL) {
		slogz("READ NULL: %s = %s\n", key, val);
		while ((val = csc_cfg_read_next(root, &key)) != NULL) {
			slogz("READ NULL: %s = %s\n", key, val);
		}
	}

	if ((val = csc_cfg_read_first(root, "[what]", &key)) != NULL) {
		slogz("READ [what]: %s = %s\n", key, val);
		while ((val = csc_cfg_read_next(root, &key)) != NULL) {
			slogz("READ [what]: %s = %s\n", key, val);
		}
	}

	time(&tmtick);
	ltm = localtime(&tmtick);
	sprintf(mkey, "[%u]", (unsigned) tmtick);
	//sprintf(mkey, "[main]");
	sprintf(nkey, "timestamp");
	csc_cfg_write(root, mkey, nkey, ctime(&tmtick));
	slogz("WRITE %s: %s = %s\n", mkey, nkey, 
			csc_cfg_read(root, mkey, nkey));


	csc_cfg_close(root);
	return 0;
}

int config_main(int argc, char **argv)
{
	while (--argc && (**++argv == '-')) {
		if (!strcmp(*argv, "-h") || !strcmp(*argv, "--help")) {
			slogz("config \n");
			return 0;
		} else if (!strcmp(*argv, "--open-rdonly")) {
			config_open_rdonly();
		} else if (!strcmp(*argv, "--key-test")) {
			config_key_test();
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
	return 0;
}

