
/*  smm_fontpath.c - find the full path of a specified font

    Copyright (C) 2011  "Andy Xuming" <xuming@users.sourceforge.net>

    This file is part of LIBSMM, System Masquerade Module library

    LIBSMM is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    LIBSMM is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libcsoup.h"

struct	FTINF	{
	char	*ftpath;
	char	*ftname;	/* output */
};


#ifdef	CFG_WIN32_API
#define PATHSEP	"\\"
static	char	*def_font_dir[] = {

	NULL
};
#else
#define PATHSEP	"/"
static	char	*def_font_dir[] = {
	"/usr/share/fonts",
	NULL
};
#endif

static int findfont(void *option, char *path, int type, void *info);

char *smm_fontpath(char *ftname, char **userdir)
{
	struct	FTINF	ftinfo;
	char	*home, *bpath;
	int	i;

	/* no need to search fontconfig patterns like "times:bold:italic" */
	if (strchr(ftname, ':')) {
		return strcpy_alloc(ftname, 0);
	}
	/* absolute path */
	if (strchr(ftname, '/')) {
		if (smm_fstat(ftname) != SMM_FSTAT_REGULAR) {
			return NULL;
		}
		return strcpy_alloc(ftname, 0);
	}
	/* try current directory first */
	if (smm_fstat(ftname) == SMM_FSTAT_REGULAR) {
		return strcpy_alloc(ftname, 0);
	}

	/* try the runtime directory */
	if (smm_rt_name && strchr(smm_rt_name, '/')) {
		home = strcpy_alloc(smm_rt_name, strlen(ftname) + 8);
		if (home == NULL) {
			return NULL;
		}
		bpath = strrchr(home, '/') + 1;
		strcpy(bpath, ftname);
		if (smm_fstat(home) == SMM_FSTAT_REGULAR) {
			return home;
		}
		free(home);
	}
	/* try the user specified search path if existed */
	if (userdir) {
		for (i = 0; userdir[i]; i++) {
			ftinfo.ftpath = ftname;
			ftinfo.ftname = NULL;
			smm_pathtrek(userdir[i], 0, findfont, &ftinfo);
			if (ftinfo.ftname) {
				return ftinfo.ftname;
			}
		}
	}
	/* try the user fonts in the home directory (FIXME: unix only?) */
	if ((bpath = getenv("HOME")) != NULL) {
		if ((home = strcpy_alloc(bpath, 16)) == NULL) {
			return NULL;
		}
		strcat(home, "/.fonts");

		ftinfo.ftpath = ftname;
		ftinfo.ftname = NULL;
		smm_pathtrek(home, 0, findfont, &ftinfo);
		if (ftinfo.ftname) {
			free(home);	/* FIXME: produced a memory hole */
			return ftinfo.ftname;
		}
		free(home);
	}
	/* try the default search path */
	for (i = 0; def_font_dir[i]; i++) {
		ftinfo.ftpath = ftname;
		ftinfo.ftname = NULL;
		smm_pathtrek(def_font_dir[i], 0, findfont, &ftinfo);
		if (ftinfo.ftname) {
			return ftinfo.ftname;
		}
	}
	return NULL;
}

static int findfont(void *option, char *path, int type, void *info)
{
	struct	FTINF	*ftinfo = option;

	switch (type) {
	case SMM_MSG_PATH_ENTER:
		slogz("Entering %s:\n", path);
		break;
	case SMM_MSG_PATH_EXEC:
		if (strcasecmp(ftinfo->ftpath, path)) {
			break;
		}
		ftinfo->ftname = smm_cwd_alloc(strlen(path) + 8);
		if (ftinfo->ftname == NULL) {
			break;
		}
		strcat(ftinfo->ftname, PATHSEP);
		strcat(ftinfo->ftname, path);
		slogz("Found %s\n", ftinfo->ftname);
		return SMM_NTF_PATH_EOP;

	case SMM_MSG_PATH_BREAK:
		slog(SLWARN, "Failed to process %s\n", path);
		break;
	case SMM_MSG_PATH_LEAVE:
		slogz("Leaving %s\n", path);
		break;
	}
	return SMM_NTF_PATH_NONE;
}


