
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libcsoup.h"

#ifdef	CFG_WIN32_API
int smm_mkdir(char *path)
{
	TCHAR	*wpath;

	if ((wpath = smm_mbstowcs(path)) == NULL) {
		return smm_errno_update(SMM_ERR_NONE_READ);
	}
	if (CreateDirectory(wpath, NULL)) {
		free(wpath);
		return smm_errno_update(SMM_ERR_NONE);
	}
	free(wpath);
	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		return smm_errno_update(SMM_ERR_NONE);
	}
	return smm_errno_update(SMM_ERR_MKDIR);
}
#endif

#ifdef	CFG_UNIX_API
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

int smm_mkdir(char *path)
{
	//printf("%s\n", path);
	if (mkdir(path, 0755) == 0) {
		return smm_errno_update(SMM_ERR_NONE);
	}
	if (errno == EEXIST) {	/* path name already exists */
		return smm_errno_update(SMM_ERR_NONE);
	}
	return smm_errno_update(SMM_ERR_MKDIR);
}
#endif

int smm_mkpath(char *path)
{
	char	*pco, store;
	int	i;

	if ((pco = csc_strcpy_alloc(csc_strbody(path, NULL), 4)) == NULL) {
		return SMM_ERR_LOWMEM;
	}

	/* remove the tailing whitespaces and keep one delimit */
	for (i = strlen(pco) - 1; i >=0; i--) {
		if (csc_isdelim(SMM_PATH_DELIM " ", pco[i])) {
			pco[i] = 0;
		} else {
			break;
		}
	}
	strcat(pco, SMM_DEF_DELIM);

	for (i = 1; i < (int) strlen(pco); i++) {
		if (!csc_isdelim(SMM_PATH_DELIM, pco[i])) {
			continue;
		}
		store = pco[i];
		pco[i] = 0;
		if (smm_mkdir(pco) != SMM_ERR_NONE) {
			free(pco);
			return smm_errno_update(SMM_ERR_MKDIR);
		}
		pco[i] = store;
	}
	free(pco);
	return smm_errno_update(SMM_ERR_NONE);
}


