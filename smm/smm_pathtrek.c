
/*  smm_pathtrek.c - process directories recursively

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

#include "smm.h"


#define	PATH_STAT_IGNORE	-1
#define PATH_STAT_REGULAR	0
#define PATH_STAT_DIR		1
#define PATH_STAT_SKIP		2


static int dummy_message(void *option, char *path, int type, void *info);
static int path_recur_fifo(struct smmdir *sdir, char *path);
static int path_recur_first(struct smmdir *sdir, char *path);
static int path_recur_last(struct smmdir *sdir, char *path);

int smm_pathtrek(char *path, int flags, F_DIR msg, void *option)
{
	struct	smmdir	sdir;
	void	*cwid;
	int	rc;

	memset(&sdir, 0, sizeof(sdir));
	sdir.message = msg;
	if (sdir.message == NULL) {
		sdir.message = dummy_message;
	}
	sdir.option = option;
	sdir.flags  = flags;
	sdir.depth  = flags & SMM_PATH_DEPTH_MASK;
	sdir.depnow = 0;

	switch (flags & SMM_PATH_DIR_MASK) {
	case SMM_PATH_DIR_FIRST:
		sdir.path_recur = path_recur_first;
		break;
	case SMM_PATH_DIR_LAST:
		sdir.path_recur = path_recur_last;
		break;
	case SMM_PATH_DIR_FIFO:
	default:
		sdir.path_recur = path_recur_fifo;
		break;
	}

	cwid = smm_cwd_push();
	rc = sdir.path_recur(&sdir, path);
	sdir.message(sdir.option, path, SMM_MSG_PATH_STAT, &sdir);
	smm_cwd_pop(cwid);
	return rc;
}


static int dummy_message(void *option, char *path, int type, void *info)
{
	return 0;
}


#ifdef  CFG_WIN32_API
static int wpath_state(TCHAR *wpath)
{
	DWORD	fattr;

	if (!lstrcmp(wpath, TEXT(".")) || !lstrcmp(wpath, TEXT(".."))) {
		return PATH_STAT_SKIP;	/* skip */
	}
	if ((fattr = GetFileAttributes(wpath)) == 0xFFFFFFFF) {
		return PATH_STAT_IGNORE;	/* ignore */
	}
	if (fattr & FILE_ATTRIBUTE_DIRECTORY) {
		return PATH_STAT_DIR;	/* directory */
	}
	return PATH_STAT_REGULAR;	/* regular file */
}

static int wpath_enter(struct smmdir *sdir, TCHAR *wpath, int *rcode)
{
	char	*fname;

	*rcode = smm_errno_update(SMM_ERR_NONE);

	switch (wpath_state(wpath)) {
	case PATH_STAT_IGNORE:
		*rcode = smm_errno_update(SMM_ERR_EOP);	
		return -1;	 /* maybe permission denied */
	case PATH_STAT_REGULAR:
		sdir->stat_files++;
		fname = smm_wcstombs(wpath);
		*rcode = sdir->message(sdir->option, fname, 
				SMM_MSG_PATH_EXEC, sdir);
		free(fname);
		return -2;
	case PATH_STAT_SKIP:	/* go ahead with '.' and '..' */
	case PATH_STAT_DIR:
		break;
	}

	/* check the depth of subdirectories */
	if ((sdir->depth > 0) && (sdir->depnow >= sdir->depth)) {
		fname = smm_wcstombs(wpath);
		sdir->message(sdir->option, fname, SMM_MSG_PATH_FLOOR, sdir);
		free(fname);
		*rcode = smm_errno_update(SMM_ERR_NONE);
		return -3;
	}
	
	if (SetCurrentDirectory(wpath) == 0) {
		*rcode = smm_errno_update(SMM_ERR_CHDIR);
		return -4;
	}
	
	sdir->depnow++;
	sdir->stat_dirs++;
	fname = smm_wcstombs(wpath);
	sdir->message(sdir->option, fname, SMM_MSG_PATH_ENTER, sdir);
	free(fname);
	return 0;
}

static int wpath_leave(struct smmdir *sdir, TCHAR *wpath)
{
	char	*fname;

	SetCurrentDirectory(TEXT(".."));

	fname = smm_wcstombs(wpath);
	sdir->message(sdir->option, fname, SMM_MSG_PATH_LEAVE, sdir);
	free(fname);
	sdir->depnow--;
	return SMM_ERR_NONE;
}

static int win_path_recur_fifo(struct smmdir *sdir, TCHAR *wpath)
{
	WIN32_FIND_DATA	ffdata;
	HANDLE		ffdh;
	char		*fname;
	int		rc;

	if (wpath_enter(sdir, wpath, &rc) < 0) {
		return rc;
	}

	ffdh = FindFirstFile(TEXT("*"), &ffdata);
	if (ffdh == INVALID_HANDLE_VALUE) {
		fname = smm_wcstombs(wpath);
		sdir->message(sdir->option, fname, SMM_MSG_PATH_BREAK, NULL);
		free(fname);
		wpath_leave(sdir, wpath);
		return smm_errno_update(SMM_ERR_OPENDIR);
	}

	do {
		//wprintf(TEXT("> %s\n"), ffdata.cFileName);
		switch (wpath_state(ffdata.cFileName)) {
		case PATH_STAT_SKIP:
		case PATH_STAT_IGNORE:
			continue;
		case PATH_STAT_DIR:
			rc = win_path_recur_fifo(sdir, ffdata.cFileName);
			break;
		case PATH_STAT_REGULAR:
			sdir->stat_files++;
			fname = smm_wcstombs(ffdata.cFileName);
			sdir->message(sdir->option, fname,
					SMM_MSG_PATH_EXEC, sdir);
			free(fname);
			break;
		}
		if (rc != SMM_ERR_NONE) {
			fname = smm_wcstombs(ffdata.cFileName);
			sdir->message(sdir->option, fname,
					SMM_MSG_PATH_BREAK, &rc);
			free(fname);
			break;
		}
	} while (FindNextFile(ffdh, &ffdata));
	FindClose(ffdh);

	wpath_leave(sdir, wpath);
	return rc;
}
	
static int win_path_recur_first(struct smmdir *sdir, TCHAR *wpath)
{
	WIN32_FIND_DATA	ffdata;
	HANDLE		ffdh;
	char		*fname;
	int		rc;

	if (wpath_enter(sdir, wpath, &rc) < 0) {
		return rc;
	}

	ffdh = FindFirstFile(TEXT("*"), &ffdata);
	if (ffdh == INVALID_HANDLE_VALUE) {
		fname = smm_wcstombs(wpath);
		sdir->message(sdir->option, fname, SMM_MSG_PATH_BREAK, NULL);
		free(fname);
		wpath_leave(sdir, wpath);
		return smm_errno_update(SMM_ERR_OPENDIR);
	}

	do {
		if (wpath_state(ffdata.cFileName) != PATH_STAT_DIR) {
			continue;
		}
		rc = win_path_recur_first(sdir, ffdata.cFileName);
		if (rc != SMM_ERR_NONE) {
			fname = smm_wcstombs(ffdata.cFileName);
			sdir->message(sdir->option, fname,
					SMM_MSG_PATH_BREAK, &rc);
			free(fname);
			break;
		}
	} while (FindNextFile(ffdh, &ffdata));
	FindClose(ffdh);

	ffdh = FindFirstFile(TEXT("*"), &ffdata);
	do {
		//wprintf(TEXT("> %s\n"), ffdata.cFileName);
		if (wpath_state(ffdata.cFileName) == PATH_STAT_REGULAR) {
			sdir->stat_files++;
			fname = smm_wcstombs(ffdata.cFileName);
			sdir->message(sdir->option, fname,
					SMM_MSG_PATH_EXEC, sdir);
			free(fname);
		}
	} while (FindNextFile(ffdh, &ffdata));
	FindClose(ffdh);

	wpath_leave(sdir, wpath);
	return rc;
}
	
static int win_path_recur_last(struct smmdir *sdir, TCHAR *wpath)
{
	WIN32_FIND_DATA	ffdata;
	HANDLE		ffdh;
	char		*fname;
	int		rc;

	if (wpath_enter(sdir, wpath, &rc) < 0) {
		return rc;
	}

	ffdh = FindFirstFile(TEXT("*"), &ffdata);
	if (ffdh == INVALID_HANDLE_VALUE) {
		fname = smm_wcstombs(wpath);
		sdir->message(sdir->option, fname, SMM_MSG_PATH_BREAK, NULL);
		free(fname);
		wpath_leave(sdir, wpath);
		return smm_errno_update(SMM_ERR_OPENDIR);
	}

	do {
		if (wpath_state(ffdata.cFileName) == PATH_STAT_REGULAR) {
			sdir->stat_files++;
			fname = smm_wcstombs(ffdata.cFileName);
			sdir->message(sdir->option, fname,
					SMM_MSG_PATH_EXEC, sdir);
			free(fname);
		}
	} while (FindNextFile(ffdh, &ffdata));
	FindClose(ffdh);

	ffdh = FindFirstFile(TEXT("*"), &ffdata);
	do {
		if (wpath_state(ffdata.cFileName) != PATH_STAT_DIR) {
			continue;
		}
		rc = win_path_recur_last(sdir, ffdata.cFileName);
		if (rc != SMM_ERR_NONE) {
			fname = smm_wcstombs(ffdata.cFileName);
			sdir->message(sdir->option, fname,
					SMM_MSG_PATH_BREAK, &rc);
			free(fname);
			break;
		}
	} while (FindNextFile(ffdh, &ffdata));
	FindClose(ffdh);

	wpath_leave(sdir, wpath);
	return rc;
}
	
static int path_recur_fifo(struct smmdir *sdir, char *path)
{
	TCHAR	*wpath;
	int	rc;

	if ((wpath = smm_mbstowcs(path)) == NULL) {
		return smm_errno_update(SMM_ERR_NONE_READ);
	}
	rc = win_path_recur_fifo(sdir, wpath);
	free(wpath);
	return rc;
}

static int path_recur_first(struct smmdir *sdir, char *path)
{
	TCHAR	*wpath;
	int	rc;

	if ((wpath = smm_mbstowcs(path)) == NULL) {
		return smm_errno_update(SMM_ERR_NONE_READ);
	}
	rc = win_path_recur_first(sdir, wpath);
	free(wpath);
	return rc;
}

static int path_recur_last(struct smmdir *sdir, char *path)
{
	TCHAR	*wpath;
	int	rc;

	if ((wpath = smm_mbstowcs(path)) == NULL) {
		return smm_errno_update(SMM_ERR_NONE_READ);
	}
	rc = win_path_recur_last(sdir, wpath);
	free(wpath);
	return rc;
}
#endif	/* CFG_WIN32_API */


#ifdef  CFG_UNIX_API
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

static int path_state(char *path)
{
	struct	stat	fs;

	if (!strcmp(path, ".") || !strcmp(path, "..")) {
		return PATH_STAT_SKIP;	/* skip */
	}
	if (stat(path, &fs) < 0)  {
		return PATH_STAT_IGNORE;	/* ignore */
	}
	if (S_ISDIR(fs.st_mode)) {
		return PATH_STAT_DIR;	/* directory */
	}
	return PATH_STAT_REGULAR;	/* regular file */
}

static int path_enter(struct smmdir *sdir, char *path, int *rcode)
{
	*rcode = smm_errno_update(SMM_ERR_NONE);
	
	switch (path_state(path)) {
	case PATH_STAT_IGNORE:
		*rcode = smm_errno_update(SMM_ERR_EOP);	
		return -1;	 /* maybe permission denied */
	case PATH_STAT_REGULAR:
		sdir->stat_files++;
		*rcode = sdir->message(sdir->option, path, 
				SMM_MSG_PATH_EXEC, sdir);
		return -2;
	case PATH_STAT_SKIP:	/* go ahead with '.' and '..' */
	case PATH_STAT_DIR:
		break;
	}

	/* check the depth of subdirectories */
	if ((sdir->depth > 0) && (sdir->depnow >= sdir->depth)) {
		sdir->message(sdir->option, path, SMM_MSG_PATH_FLOOR, sdir);
		*rcode = smm_errno_update(SMM_ERR_NONE);
		return -3;
	}
	
	if (chdir(path) < 0)  {
		*rcode = smm_errno_update(SMM_ERR_CHDIR);
		return -4;
	}

	sdir->depnow++;
	sdir->stat_dirs++;
	sdir->message(sdir->option, path, SMM_MSG_PATH_ENTER, sdir);
	return 0;
}

static int path_leave(struct smmdir *sdir, char *path)
{
	/*if (chdir("..") < 0) {
		return smm_errno_update(SMM_ERR_CHDIR);
	}*/
	/* absorbbed the possible error by chdir beyond / directory,
	 * which is possible if started the pathtrek(.) or pathtrek(/) */
	chdir("..");

	sdir->message(sdir->option, path, SMM_MSG_PATH_LEAVE, sdir);
	sdir->depnow--;
	return SMM_ERR_NONE;
}

static int path_recur_fifo(struct smmdir *sdir, char *path)
{
	DIR	*dir;
	struct	dirent	*de;
	int	rc;

	if (path_enter(sdir, path, &rc))  {
		return rc;
	}
	if ((dir = opendir(".")) == NULL)  {
		sdir->message(sdir->option, path, SMM_MSG_PATH_BREAK, NULL);
		path_leave(sdir, path);
		return smm_errno_update(SMM_ERR_OPENDIR);
	}
	while ((de = readdir(dir)) != NULL)  {
		switch (path_state(de->d_name)) {
		case PATH_STAT_IGNORE:
		case PATH_STAT_SKIP:
			continue;	/* maybe permission denied */
		case PATH_STAT_DIR:
			rc = sdir->path_recur(sdir, de->d_name);
			break;
		case PATH_STAT_REGULAR:
			sdir->stat_files++;
			sdir->message(sdir->option, de->d_name, 
					SMM_MSG_PATH_EXEC, sdir);
			break;
		}
		if (rc != SMM_ERR_NONE) {
			sdir->message(sdir->option, de->d_name,
					SMM_MSG_PATH_BREAK, NULL);
			break;
		}
	}
	closedir(dir);

	path_leave(sdir, path);
	return rc;
}

static int path_recur_last(struct smmdir *sdir, char *path)
{
	DIR	*dir;
	struct	dirent	*de;
	int	rc;

	if (path_enter(sdir, path, &rc) < 0)  {
		return rc;
	}
	if ((dir = opendir(".")) == NULL)  {
		sdir->message(sdir->option, path, SMM_MSG_PATH_BREAK, NULL);
		path_leave(sdir, path);
		return smm_errno_update(SMM_ERR_OPENDIR);
	}
	while ((de = readdir(dir)) != NULL)  {
		if (path_state(de->d_name) == PATH_STAT_REGULAR) {
			sdir->stat_files++;
			sdir->message(sdir->option, de->d_name,
					SMM_MSG_PATH_EXEC, sdir);
		}
	}

	rewinddir(dir);
	while ((de = readdir(dir)) != NULL)  {
		if (path_state(de->d_name) != PATH_STAT_DIR) {
			continue;
		}
		rc = sdir->path_recur(sdir, de->d_name);
		if (rc != SMM_ERR_NONE) {
			sdir->message(sdir->option, de->d_name, 
					SMM_MSG_PATH_BREAK, NULL);
			break;
		}
	}
	closedir(dir);

	path_leave(sdir, path);
	return rc;
}

static int path_recur_first(struct smmdir *sdir, char *path)
{
	DIR	*dir;
	struct	dirent	*de;
	int	rc;

	if (path_enter(sdir, path, &rc) < 0)  {
		return rc;
	}
	if ((dir = opendir(".")) == NULL)  {
		sdir->message(sdir->option, path, SMM_MSG_PATH_BREAK, NULL);
		path_leave(sdir, path);
		return smm_errno_update(SMM_ERR_OPENDIR);
	}

	while ((de = readdir(dir)) != NULL)  {
		if (path_state(de->d_name) != PATH_STAT_DIR) {
			continue;
		}
		rc = sdir->path_recur(sdir, de->d_name);
		if (rc != SMM_ERR_NONE) {
			sdir->message(sdir->option, de->d_name, 
					SMM_MSG_PATH_BREAK, NULL);
			break;
		}
	}

	rewinddir(dir);
	while ((de = readdir(dir)) != NULL)  {
		if (path_state(de->d_name) == PATH_STAT_REGULAR) {
			sdir->stat_files++;
			sdir->message(sdir->option, de->d_name,
					SMM_MSG_PATH_EXEC, sdir);
		}
	}
	closedir(dir);

	path_leave(sdir, path);
	return rc;
}
#endif	/* CFG_UNIX_API */


