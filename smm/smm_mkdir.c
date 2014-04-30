
/*  smm_mkdir.c - make directory

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

#include "libcsoup.h"

#ifdef	CFG_WIN32_API
int smm_mkdir(char *path)
{
	char	**argvs, *root = "\\";
	int	i, rc, argcs;

	if (isalpha(path[0]) && (path[1] == ':')) {
		/* C:/sss/sss/sss */
	} else if (!strcmp(path, "\\\\?\\", 4)) {
		/* \\?\UNC\ComputerName\SharedFolder\Resource
		 * \\?\C:\File */
	} else if (!strcmp(path, "\\\\", 2)) {
		/* \\ComputerName\SharedFolder\Resource */
	}

	argvs = csc_fixtoken_copy(path, "/\\", &argcs);
	if (*argvs[0] == 0) {	/* make up the root directory */
		argvs[0] = root;
	}

	for (i = rc = 0; i < argcs; i++) {
		//printf("[%d] %s\n", i, argvs[i]);
		if (*argvs[i] == 0) {
			continue;
		}
		if ((rc = chdir(argvs[i])) == 0) {
			continue;
		}
		if (errno != ENOENT) {	/* error condition */
			rc = SMM_ERR_CHDIR;
			break;
		}
		if ((rc = mkdir(argvs[i], 0755)) != 0) {
			rc = SMM_ERR_MKDIR;
			break;
		}
		if ((rc = chdir(argvs[i])) != 0) {
			rc = SMM_ERR_CHDIR;
			break;
		}
	}
	free(argvs);
	return smm_errno_update(SMM_ERR_NONE);
}
#endif

#ifdef	CFG_UNIX_API
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

int smm_mkdir(char *path)
{
	char	**argvs, *root = "/";
	int	i, rc, argcs;

	argvs = csc_fixtoken_copy(path, "/", &argcs);
	if (*argvs[0] == 0) {	/* make up the root directory */
		argvs[0] = root;
	}

	for (i = rc = 0; i < argcs; i++) {
		//printf("[%d] %s\n", i, argvs[i]);
		if (*argvs[i] == 0) {
			continue;
		}
		if ((rc = chdir(argvs[i])) == 0) {
			continue;
		}
		if (errno != ENOENT) {	/* error condition */
			rc = SMM_ERR_CHDIR;
			break;
		}
		if ((rc = mkdir(argvs[i], 0755)) != 0) {
			rc = SMM_ERR_MKDIR;
			break;
		}
		if ((rc = chdir(argvs[i])) != 0) {
			rc = SMM_ERR_CHDIR;
			break;
		}
	}
	free(argvs);
	return smm_errno_update(rc);
}
#endif

