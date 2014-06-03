
/*  smm_config.c - configure parameters management 

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
#include <unistd.h>
#include <errno.h>

#include "libcsoup.h"


struct	KeyDev	{
	FILE	*fp;
	int	mode;
	char	*fpath;		/* full path for the file system */
	char	*kpath;		/* key path for the Win32 registry */
	char	*fname;
#ifdef	CFG_WIN32_API
	HKEY	hSysKey;	/* predefined key like HKEY_CURRENT_USER */
	HKEY	hRootKey;	/* root key points to the entrance */
	int	idx_key[MAX_PATH];	/* index of keys (Win32 values */
	int	idx_dir[MAX_PATH];	/* index of directories (Win32 subkeys) */
	int	idx_no;
#endif
	char	pool[1];
};


static struct KeyDev *smm_config_alloc(int sysdir, char *path, char *fname);
static int smm_config_mem_read(struct KeyDev *cfgd, KEYCB *kp);
static int smm_config_file_read(struct KeyDev *cfgd, KEYCB *kp);
static int smm_config_file_write(struct KeyDev *cfgd, KEYCB *kp);

#ifdef	CFG_WIN32_API
static int smm_config_registry_open(struct KeyDev *cfgd, int mode);
static int smm_config_registry_read(struct KeyDev *cfgd, KEYCB *kp);
static int smm_config_registry_write(struct KeyDev *cfgd, KEYCB *kp);
static int smm_config_registry_delete(struct KeyDev *cfgd, char *fname);
static BOOL RegDelnodeRecurse(HKEY hKeyRoot, LPTSTR lpSubKey, int buflen);
#endif

struct KeyDev *smm_config_open(int sysdir, char *path, char *fname, int mode)
{
	struct	KeyDev	*cfgd;

	/* configure in memory mode */
	if (sysdir == SMM_CFGROOT_MEMPOOL) {
		if ((cfgd = smm_alloc(sizeof(struct KeyDev))) != NULL) {
			cfgd->fpath = path;
		}
		return cfgd;
	}

	if ((cfgd = smm_config_alloc(sysdir, path, fname)) == NULL) {
		return NULL;
	}

	cfgd->mode = mode;
#ifdef	CFG_WIN32_API
	if (smm_config_registry_open(cfgd, mode) == SMM_ERR_NONE) {
		return cfgd;
	}
#endif

	switch (mode) {
	case CSC_CFG_READ:
		cfgd->fp = fopen(cfgd->fpath, "r");
		break;
	case CSC_CFG_RWC:
		if (path) {
			smm_mkpath(path);
		}
		if ((cfgd->fp = fopen(cfgd->fpath, "r+")) == NULL) {
			cfgd->fp = fopen(cfgd->fpath, "w+");
		}
		break;
	default:	/* CSC_CFG_RDWR */
		cfgd->fp = fopen(cfgd->fpath, "r+");
		break;
	}
	if (cfgd->fp == NULL) {
		smm_free(cfgd);
		cfgd = NULL;
	}
	return cfgd;
}

int smm_config_close(struct KeyDev *cfgd)
{
#ifdef	CFG_WIN32_API
	if (cfgd->hRootKey) {
		RegFlushKey(cfgd->hRootKe);
		RegCloseKey(cfgd->hRootKe);
	}
#endif
	if (cfgd->fp) {
		fclose(cfgd->fp);
	}
	return smm_free(cfgd);
}

int smm_config_read(struct KeyDev *cfgd, KEYCB *kp)
{
#ifdef	CFG_WIN32_API
	if (cfgd->hRootKey) {
		return smm_config_registry_read(cfgd, kp);
	}
#endif
	if (cfgd->fp) {
		return smm_config_file_read(cfgd, kp);
	} else {
		return smm_config_mem_read(cfgd, kp);
	}
}

int smm_config_write(struct KeyDev *cfgd, KEYCB *kp)
{
#ifdef	CFG_WIN32_API
	if (cfgd->hRootKey) {
		return smm_config_registry_write(cfgd, kp);
	}
#endif
	if (cfgd->fp || (cfgd->fname == NULL)) {
		return smm_config_file_write(cfgd, kp);
	}
	return 0;
}

int smm_config_delete(int sysdir, char *path, char *fname)
{
	struct	KeyDev	*cfgd;
	int	rc;

	if ((cfgd = smm_config_alloc(sysdir, path, fname)) == NULL) {
		return smm_errno_update(SMM_ERR_NULL);
	}
	
#ifdef	CFG_WIN32_API
	if (cfgd->kpath) {
		rc = smm_config_registry_delete(cfgd);
	} else {
		rc = unlink(cfgd->fpath);
	}
#else
	rc = unlink(cfgd->fpath);
#endif
	smm_free(cfgd);
	if (rc == 0) {
		return smm_errno_update(SMM_ERR_NONE);
	}
	if (errno == EACCES) {
		return smm_errno_update(SMM_ERR_ACCESS);
	}
	return smm_errno_update(SMM_ERR_NULL);
}





static struct KeyDev *smm_config_alloc(int sysdir, char *path, char *fname)
{
	struct	KeyDev	*cfgd;
	char	*home;
	int	tlen;

	if (fname == NULL) {
		return NULL;
	}
	home = getenv("HOME");

	tlen = sizeof(struct KeyDev) + strlen(fname) * 2 + 16;
	if (path) {
		tlen += strlen(path) * 2;
	}
	switch (sysdir) {
	case SMM_CFGROOT_USER:
		if (home) {
			tlen += strlen(home) + 1;
		}
		tlen += 8;	/* size of "CONSOLE\\" */
		break;
	case SMM_CFGROOT_SYSTEM:
		tlen += 4;	/* size of "/etc" */
		tlen += 9;	/* size of "SOFTWARE\\" */
		break;
	case SMM_CFGROOT_DESKTOP:
		if (home == NULL) {
			tlen += 7;	/* size of ".config" */
		} else {
			tlen += strlen(home) + 8;  /* size of "/.config" */
		}
		tlen += 9;	/* size of "SOFTWARE\\" */
		break;
	}

	if ((cfgd = smm_alloc(tlen)) == NULL) {
		smm_errno_update(SMM_ERR_LOWMEM);
		return NULL;
	}

	cfgd->fname = cfgd->pool;
	strcpy(cfgd->fname, fname);
	cfgd->fpath = cfgd->fname + strlen(cfgd->fname) + 1;
	cfgd->fpath[0] = 0;
	
	switch (sysdir) {
	case SMM_CFGROOT_USER:
		if (home) {
			strcat(cfgd->fpath, home);
			strcat(cfgd->fpath, SMM_DEF_DELIM);
		}
		if (path) {
			strcat(cfgd->fpath, path);
			strcat(cfgd->fpath, SMM_DEF_DELIM);
		}
		strcat(cfgd->fpath, fname);

		cfgd->kpath = cfgd->fpath + strlen(cfgd->fpath) + 1;
		strcpy(cfgd->kpath, "CONSOLE\\");
		if (path) {
			strcat(cfgd->kpath, path);
		}
#ifdef	CFG_WIN32_API
		cfgd->hSysKey = HKEY_CURRENT_USER;
#endif
		break;
	case SMM_CFGROOT_SYSTEM:
		strcat(cfgd->fpath, "/etc");	//FIXME
		if (path) {
			strcat(cfgd->fpath, path);
			strcat(cfgd->fpath, SMM_DEF_DELIM);
		}
		strcat(cfgd->fpath, fname);

		cfgd->kpath = cfgd->fpath + strlen(cfgd->fpath) + 1;
		strcpy(cfgd->kpath, "SOFTWARE\\");
		if (path) {
			strcat(cfgd->kpath, path);
		}
#ifdef	CFG_WIN32_API
		cfgd->hSysKey = HKEY_LOCAL_MACHINE;
#endif
		break;
	case SMM_CFGROOT_DESKTOP:
		if (home) {
			strcat(cfgd->fpath, home);
			strcat(cfgd->fpath, SMM_DEF_DELIM);
		}
		strcat(cfgd->fpath, ".config");
		strcat(cfgd->fpath, SMM_DEF_DELIM);
		if (path) {
			strcat(cfgd->fpath, path);
			strcat(cfgd->fpath, SMM_DEF_DELIM);
		}
		strcat(cfgd->fpath, fname);

		cfgd->kpath = cfgd->fpath + strlen(cfgd->fpath) + 1;
		strcpy(cfgd->kpath, "SOFTWARE\\");
		if (path) {
			strcat(cfgd->kpath, path);
		}
#ifdef	CFG_WIN32_API
		cfgd->hSysKey = HKEY_CURRENT_USER;
#endif
		break;
	case SMM_CFGROOT_CURRENT:
	default:
		if (path) {
			strcat(cfgd->fpath, path);
			strcat(cfgd->fpath, SMM_DEF_DELIM);
		}
		strcat(cfgd->fpath, fname);
		break;
	}

	/* check point */
	slogz("smm_config_alloc::fpath = %s\n", cfgd->fpath);
	slogz("smm_config_alloc::kpath = %s\n", cfgd->kpath);
	slogz("smm_config_alloc::fname = %s\n", cfgd->fname);
	return cfgd;
}

static int smm_config_mem_read(struct KeyDev *cfgd, KEYCB *kp)
{
	int	i, cpos;

	if (cfgd->fpath == NULL) {
		return -1;
	}
	if (cfgd->fname != NULL) {
		return -2;
	}
	for (i = 0, cpos = cfgd->mode; cfgd->fpath[cpos]; i++) {
		if (kp) {
			kp->pool[i] = cfgd->fpath[cpos];
			kp->pool[i+1] = 0;
			cfgd->mode++;
		}
		if (cfgd->fpath[cpos++] == '\n') {
			i++;
			break;
		}
	}
	return i;
}

static int smm_config_file_read(struct KeyDev *cfgd, KEYCB *kp)
{
	int	amnt, cpos, ch;

	if (cfgd->fp == NULL) {	
		return -1;
	}

	amnt = 0;
	cpos = ftell(cfgd->fp);
	while ((ch = fgetc(cfgd->fp)) != EOF) {
		if (kp) {
			kp->pool[amnt] = (char) ch;
		}
		amnt++;
		if (ch == '\n') {
			break;
		}
	}
	if (kp == NULL) {	/* rewind to the start position */
		fseek(cfgd->fp, cpos, SEEK_SET);
	} else {
		kp->pool[amnt] = 0;
	}
	return amnt;
}

static int smm_config_file_write(struct KeyDev *cfgd, KEYCB *kp)
{
	FILE	*fout;

	if (kp == NULL) {
		return 0;
	}
	if ((fout = cfgd->fp) == NULL) {
		fout = stdout;
	}

	kp->update = 0;		/* reset the update counter */
	if (kp->key) {
		//if (CFGF_TYPE_GET(kp->flags) == CFGF_TYPE_MASTR) {
		if ((kp->flags & 0xf) == 2) {	//FIXME
			fputc('[', fout);
			fputs(kp->key, fout);
			fputc(']', fout);
		} else {
			fputs(kp->key, fout);
		}
	}
	if (kp->value) {
		fputc('=', fout);
		fputs(kp->value, fout);
	}
	if (kp->comment) {
		fputs(kp->comment, fout);
	}
	fputs("\n", fout);
	return 0;
}



#ifdef	CFG_WIN32_API

static int smm_config_registry_open(struct KeyDev *cfgd, int mode)
{
	HKEY	hPathKey;
	LONG	rc;
	TCHAR	*wkey;
	char	*fpath;

	if (cfgd->kpath == NULL) {
		return SMM_ERR_NULL;
	}
	fpath = csc_strcpy_alloc(cfgd->kpath, strlen(cfgd->fname) + 4);
	if (fpath == NULL) {
		return SMM_ERR_LOWMEM;
	}
	strcat(fpath, SMM_DEF_DELIM);
	strcat(fpath, cfgd->fname);

	slogz("smm_config_registry_open: %s\n", fpath);
	if ((wkey = smm_mbstowcs_alloc(fpath)) == NULL) {
		smm_free(fpath);
		return SMM_ERR_LOWMEM;
	}

	switch (mode) {
	case SMM_CFGMODE_RDONLY:
		rc = RegOpenKeyEx(cfgd->hSysKey, wkey, 0, KEY_READ, 
				&cfgd->hRootKey);
		break;
	case SMM_CFGMODE_RWC:
		/* The good thing of RegCreateKeyEx() is that it can create 
		 * a string of subkeys without creating one by one. 
		 * For example: A\\B\\C */
		rc = RegCreateKeyEx(cfgd->hSysKey, wkey, 0, NULL, 0, 
				KEY_ALL_ACCESS, NULL, &cfgd->hRootKey, NULL);
		break;
	default:	/* SMM_CFGMODE_RDWR */
		rc = RegOpenKeyEx(cfgd->hSysKey, wkey, 0, KEY_ALL_ACCESS, 
				&cfgd->hRootKey);
		break;
	}

	smm_free(wkey);			
	smm_free(fpath);

	if (cfgd->hRootKey && (rc == ERROR_SUCCESS)) {
		return SMM_ERR_NONE;
	}
	return SMM_ERR_ACCESS;
}

static HKEY smm_config_registry_open_dir(struct KeyDev *cfgd)
{
	HKEY	hCurrKey, hTemp;
	TCHAR	szName[MAX_PATH];
	DWORD	dwSize;
	int	i;

	hCurrKey = cfgd->hRootKey;
	for (i = 0; i < cfgd->idx_no; i++) {
		if (RegEnumKeyEx(hCurrKey, cfgd->idx_dir[i], szName, NULL, 
				NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
			if (hCurrKey != cfgd->hRootKey) {
				RegCloseKey(hCurrKey);
			}
			return NULL;
		}
		if (RegOpenKeyEx(hCurrKey, szName, 0, KEY_READ, 
				&hTemp) != ERROR_SUCCESS) {
			if (hCurrKey != cfgd->hRootKey) {
				RegCloseKey(hCurrKey);
			}
			return NULL;
		}
		if (hCurrKey != cfgd->hRootKey) {
			RegCloseKey(hCurrKey);
		}
		hCurrKey = hTemp;
	}
	return hCurrKey;
}

static int smm_config_registry_read(struct KeyDev *cfgd, KEYCB *kp)
{
	HKEY	hCurrKey;
	TCHAR	szName[MAX_PATH];
	DWORD	dwSize, dwDirs, dwKeys;

	if ((hCurrKey = smm_config_registry_open_dir(cfgd)) == NULL) {
		return -1;
	}

	/* get number of keys and values */
	RegQueryInfoKey(hCurrKey, NULL, NULL, NULL, &dwDirs, NULL, NULL, 
			&dwKeys, NULL, NULL, NULL, NULL);

	if (cfgd->idx_key[cfgd->idx_no] < dwKeys) {
		rc = registry_read_content(hCurrKey, cfgd->idx_key[cfgd->idx_no], kp);
		if (kp == NULL) {
			return rc;
		}
		cfgd->idx_key[cfgd->idx_no]++;
		return rc;
	}

	if (cfgd->idx_dir[cfgd->idx_no] < dwDirs) {
		rc = registry_read_directory(hCurrKey, cfgd->idx_dir[cfgd->idx_no], kp);
		if (kp) {
			cfgd->idx_dir[cfgd->idx_no]++;
		}
		return rc;
	}

	if (cfgd->idx_no == 0) {
		return 0;	/* eof */
	}

	cfgd->idx_no--;


}

static int registry_read_content(HKEY hKey, int idx, KEYCB *kp)
{
	TCHAR	szName[MAX_PATH];
	DWORD	dwSize, dwType, dwLeng;
	
	RegEnumValue(hKey, idx, szName, &dwSize, NULL, &dwType, NULL, &dwLeng);
}

static int registry_read_directory(HKEY hKey, int idx, KEYCB *kp)
{
	TCHAR	szName[MAX_PATH];
	DWORD	dwSize, dwType, dwLeng;
	
	if ((RegEnumKeyEx(cfgd->hRootKey, cfgd->index, szName, &dwSize, 
			NULL, NULL, NULL, NULL)) != ERROR_SUCCESS) {
		return 0;	/* EOF */
	}
}

static int smm_config_registry_delete(struct KeyDev *cfgd, char *fname)
{
	HKEY	hPathKey;
	TCHAR	*wkey;
	LONG	rcode;

	if ((wkey = smm_mbstowcs_alloc(cfgd->kpath)) == NULL) {
		return SMM_ERR_LOWMEM;
	}
	if (RegCreateKeyEx(cfgd->hSysKey, wkey, 0, NULL, 0, KEY_ALL_ACCESS, 
				NULL, &hPathKey, NULL) != ERROR_SUCCESS) {
		smm_free(wkey);
		errno = EACCES;
		return SMM_ERR_ACCESS;
	}
	smm_free(wkey);

	/* fabricate the key name */
	if ((wkey = smm_alloc(MAX_PATH * 2 * sizeof(TCHAR))) == NULL) {
		RegCloseKey(hPathKey);
		return SMM_ERR_LOWMEM;
	}
	MultiByteToWideChar(smm_codepage(), 0, cfgd->fname, 
			-1, wkey, MAX_PATH - 1);

	rcode = RegDelnodeRecurse(hPathKey, wkey, MAX_PATH * 2);

	RegCloseKey(hPathKey);
	smm_free(wkey);
       
	if (rcode == TRUE) {
		return SMM_ERR_NONE;
	}
	errno = EACCES;
	return SMM_ERR_ACCESS;
}

/* This code was picked form MSDN, a little modified */
static BOOL RegDelnodeRecurse(HKEY hKeyRoot, LPTSTR lpSubKey, int buflen)
{
	LPTSTR	lpEnd;
	LONG	lResult;
	DWORD	dwSize;
	TCHAR	szName[MAX_PATH];
	HKEY	hKey;

	/* First, see if we can delete the key without having to recurse. */
	if (RegDeleteKey(hKeyRoot, lpSubKey) == ERROR_SUCCESS) {
		return TRUE;
	}

	lResult = RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);
	if (lResult != ERROR_SUCCESS) {
		if (lResult == ERROR_FILE_NOT_FOUND) {
			return TRUE;	/* not guilty */
		} else {
			return FALSE;	/* access denied */
		}
	}

	/* Check for an ending slash and add one if it is missing. */
	if (lstrlen(lpSubKey) >= buflen) {
		return FALSE;	/* low buffer memory */
	}
	lpEnd = lpSubKey + lstrlen(lpSubKey);
	if (*(lpEnd - 1) != TEXT('\\')) {
		*lpEnd++ = TEXT('\\');
		*lpEnd = TEXT('\0');
	}

	/* Enumerate the keys */
	dwSize = MAX_PATH;
	lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL, 
			NULL, NULL, NULL);
	if (lResult == ERROR_SUCCESS) {
		do {
			if (lstrlen(lpSubKey) + lstrlen(szName) >= buflen) {
				break;	/* path is too long */
			}
			lstrcpy(lpEnd, szName);
			if (!RegDelnodeRecurse(hKeyRoot, lpSubKey, buflen)) {
				break;
			}
			dwSize = MAX_PATH;
			lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, 
					NULL, NULL, NULL, NULL);
		} while (lResult == ERROR_SUCCESS);
	}
	lpEnd--;
	*lpEnd = TEXT('\0');
	RegCloseKey (hKey);

	/* Try again to delete the key. */
	if (RegDeleteKey(hKeyRoot, lpSubKey) == ERROR_SUCCESS) {
		return TRUE;
	}
	return FALSE;
}

#endif








#if 0
#ifdef	CFG_WIN32_API
static HKEY RegOpenMainKey(HKEY hRootKey, char *mkey, int mode);
static HKEY RegCreatePath(int sysroot, char *path);
static int RegReadString(HKEY hMainKey, char *skey, char *buf, int blen);
static int RegReadLong(HKEY hMainKey, char *skey, long *val);
static int RegWriteString(HKEY hMainKey, char *skey, char *value);
static int RegWriteLong(HKEY hMainKey, char *skey, long val);
static BOOL RegDelnodeRecurse(HKEY hKeyRoot, LPTSTR lpSubKey, int klen);

void *smm_config_open(int sysroot, int mode, char *path, char *fname)
{
	HKEY	hRootKey, hPathKey;

	if ((hPathKey = RegCreatePath(sysroot, path)) == NULL) {
		return NULL;
	}
	hRootKey = RegOpenMainKey(hPathKey, fname, mode);
	RegCloseKey(hPathKey);
	return hRootKey;
}

int smm_config_flush(void *cfg)
{
	if (RegFlushKey((HKEY) cfg) == ERROR_SUCCESS) {
		return smm_errno_update(SMM_ERR_NONE);
	}
	return smm_errno_update(SMM_ERR_NULL);
}

int smm_config_close(void *cfg)
{
	RegFlushKey((HKEY) cfg);
	if (RegCloseKey((HKEY) cfg) == ERROR_SUCCESS) {
		return smm_errno_update(SMM_ERR_NONE);
	}
	return smm_errno_update(SMM_ERR_NULL);
}

int smm_config_delete(int sysroot, char *path, char *fname)
{
	HKEY	hPathKey;
	TCHAR	*wkey;
	LONG	rcode;

	if (fname == NULL) {
		return smm_errno_update(SMM_ERR_NULL);
	}
	if ((hPathKey = RegCreatePath(sysroot, path)) == NULL) {
		return smm_errno_update(SMM_ERR_ACCESS);
	}

	/* fabricate the key name */
	if ((wkey = smm_alloc(MAX_PATH * 2 * sizeof(TCHAR))) == NULL) {
		RegCloseKey(hPathKey);
		return smm_errno_update(SMM_ERR_LOWMEM);
	}
	MultiByteToWideChar(smm_codepage(), 0, fname, -1, wkey, MAX_PATH - 1);

	rcode = RegDelnodeRecurse(hPathKey, wkey, MAX_PATH * 2);

	RegCloseKey(hPathKey);
	smm_free(wkey);
       
	if (rcode == TRUE) {
		return smm_errno_update(SMM_ERR_NONE);
	}
	return smm_errno_update(SMM_ERR_ACCESS);
}

char *smm_config_read_alloc(void *cfg, char *mkey, char *skey)
{
	HKEY	hMainKey;
	char	*buf;
	int	blen;

	if (skey == NULL) {
		smm_errno_update(SMM_ERR_NULL);
		return NULL;
	}
	hMainKey = RegOpenMainKey(cfg, mkey, SMM_CFGMODE_RDONLY);
	if (hMainKey == NULL) {
		smm_errno_update(SMM_ERR_ACCESS);
		return NULL;
	}

	buf = NULL;
	if ((blen = RegReadString(hMainKey, skey, NULL, 0)) > 0) {
		blen += 2;
		buf = smm_alloc(blen);
		RegReadString(hMainKey, skey, buf, blen);
	}

	if (hMainKey != cfg) {
		RegCloseKey(hMainKey);
	}
	return buf;
}

int smm_config_write(void *cfg, char *mkey, char *skey, char *value)
{
	HKEY	hMainKey;
	int	rc;

	if (!skey || !value) {
		return smm_errno_update(SMM_ERR_NULL);
	}
	if ((hMainKey = RegOpenMainKey(cfg, mkey, SMM_CFGMODE_RWC)) == NULL) {
		return smm_errno_update(SMM_ERR_NULL);
	}
	rc = RegWriteString(hMainKey, skey, value);

	if (hMainKey != cfg) {
		RegCloseKey(hMainKey);
	}
	return rc;
}

int smm_config_read_long(void *cfg, char *mkey, char *skey, long *val)
{
	HKEY	hMainKey;
	int	rc;

	if (skey == NULL) {
		return smm_errno_update(SMM_ERR_NULL);
	}
	hMainKey = RegOpenMainKey(cfg, mkey, SMM_CFGMODE_RDONLY);
	if (hMainKey == NULL) {
		return smm_errno_update(SMM_ERR_ACCESS);
	}
	rc = RegReadLong(hMainKey, skey, val);

	if (hMainKey != cfg) {
		RegCloseKey(hMainKey);
	}
	return rc;
}

int smm_config_write_long(void *cfg, char *mkey, char *skey, long val)
{
	HKEY	hMainKey;
	int	rc;

	if (skey == NULL) {
		return smm_errno_update(SMM_ERR_NULL);
	}
	if ((hMainKey = RegOpenMainKey(cfg, mkey, SMM_CFGMODE_RWC)) == NULL) {
		return smm_errno_update(SMM_ERR_NULL);
	}
	rc = RegWriteLong(hMainKey, skey, val);

	if (hMainKey != cfg) {
		RegCloseKey(hMainKey);
	}
	return rc;
}

static HKEY RegOpenMainKey(HKEY hRootKey, char *mkey, int mode)
{
	HKEY	hMainKey;
	TCHAR	*wkey;
	LONG	rc;

	if (mkey == NULL) {
		return hRootKey;
	}
	if ((wkey = smm_mbstowcs_alloc(mkey)) == NULL) {
		smm_errno_update(SMM_ERR_LOWMEM);
		return NULL;
	}

	switch (mode) {
	case SMM_CFGMODE_RDONLY:
		rc = RegOpenKeyEx(hRootKey, wkey, 0, KEY_READ, &hMainKey);
		break;
	case SMM_CFGMODE_RWC:
		rc = RegCreateKeyEx(hRootKey, wkey, 0, NULL, 0, 
				KEY_ALL_ACCESS, NULL, &hMainKey, NULL);
		break;
	default:	/* SMM_CFGMODE_RDWR */
		rc = RegOpenKeyEx(hRootKey, wkey, 0, KEY_ALL_ACCESS, &hMainKey);
		break;
	}

	smm_free(wkey);			
	if (rc == ERROR_SUCCESS) {
		smm_errno_update(SMM_ERR_NONE);
		return hMainKey;
	}
	smm_errno_update(SMM_ERR_ACCESS);
	return NULL;
}

static HKEY RegCreatePath(int sysroot, char *path)
{
	HKEY	hPathKey, hSysKey;
	LONG	rc;
	TCHAR	*wkey;
	char	*pkey;
	int	extra;

	extra = 4;
	if (path) {
		extra += strlen(path);
	}
	switch (sysroot) {
	case SMM_CFGROOT_USER:
		hSysKey = HKEY_CURRENT_USER;
		pkey = csc_strcpy_alloc("CONSOLE\\", extra);
		break;
	case SMM_CFGROOT_SYSTEM:
		hSysKey = HKEY_LOCAL_MACHINE;
		pkey = csc_strcpy_alloc("SOFTWARE\\", extra);
		break;
	case SMM_CFGROOT_CURRENT:
		/* don't do anything */
		smm_errno_update(SMM_ERR_NONE);
		return NULL;
	default:	/* SMM_CFGROOT_DESKTOP */
		hSysKey = HKEY_CURRENT_USER;
		pkey = csc_strcpy_alloc("SOFTWARE\\", extra);
		break;
	}
	if (pkey == NULL) {
		smm_errno_update(SMM_ERR_LOWMEM);
		return NULL;
	}
	if (path) {
		strcat(pkey, path);
	}

	if ((wkey = smm_mbstowcs_alloc(pkey)) == NULL) {
		smm_free(pkey);
		smm_errno_update(SMM_ERR_LOWMEM);
		return NULL;
	}

	/* The good thing of RegCreateKeyEx() is that it can create a string
	 * of subkeys without creating one by one. For example: A\\B\\C */
	rc = RegCreateKeyEx(hSysKey, wkey, 0, NULL, 0,
			KEY_ALL_ACCESS, NULL, &hPathKey, NULL);

	smm_free(wkey);
	smm_free(pkey);

	if (rc == ERROR_SUCCESS) { 
		return hPathKey;
	}
	return NULL;
}

static int RegReadString(HKEY hMainKey, char *skey, char *buf, int blen)
{
	TCHAR	*wkey, *wval;
	DWORD	slen;
	int	vlen;

	if ((wkey = smm_mbstowcs_alloc(skey)) == NULL) {
		return smm_errno_update(SMM_ERR_LOWMEM);
	}
	if (RegQueryValueEx(hMainKey, wkey, NULL, NULL, NULL, &slen)
			!= ERROR_SUCCESS) {
		smm_free(wkey);
		return smm_errno_update(SMM_ERR_ACCESS);
	}
	slen += 2;
	if ((wval = smm_alloc(slen)) == NULL) {
		smm_free(wkey);
		return smm_errno_update(SMM_ERR_LOWMEM);
	}
	if (RegQueryValueEx(hMainKey, wkey, NULL, NULL, (BYTE*) wval, &slen)
			!= ERROR_SUCCESS) {
		smm_free(wval);
		smm_free(wkey);
		return smm_errno_update(SMM_ERR_ACCESS);
	}

	/* see smm_wcstombs.c for details */
	vlen = WideCharToMultiByte(smm_codepage(), 
			0, wval, -1, NULL, 0, NULL, NULL);
	if (vlen <= 0) {
		smm_free(wval);
		smm_free(wkey);
		return smm_errno_update(SMM_ERR_LENGTH);
	}
	if (buf && (blen > vlen)) {
		WideCharToMultiByte(smm_codepage(), 
				0, wval, -1, buf, blen, NULL, NULL);
	}
	smm_free(wval);
	smm_free(wkey);
	return vlen;
}

static int RegReadLong(HKEY hMainKey, char *skey, long *val)
{
	DWORD	vlen;
	TCHAR	*wkey;

	if ((wkey = smm_mbstowcs_alloc(skey)) == NULL) {
		return smm_errno_update(SMM_ERR_LOWMEM);
	}
	vlen = sizeof(long);
	if (RegQueryValueEx(hMainKey, wkey, NULL, NULL, (BYTE*) val, &vlen)
			== ERROR_SUCCESS) {
		smm_free(wkey);
		return smm_errno_update(SMM_ERR_NONE);
	}
	smm_free(wkey);
	return smm_errno_update(SMM_ERR_ACCESS);
}

static int RegWriteString(HKEY hMainKey, char *skey, char *value)
{
	TCHAR	*wkey, *wval;
	LONG	rc;

	if ((wkey = smm_mbstowcs_alloc(skey)) == NULL) {
		return smm_errno_update(SMM_ERR_LOWMEM);
	}
	if ((wval = smm_mbstowcs_alloc(value)) == NULL) {
		smm_free(wkey);
		return smm_errno_update(SMM_ERR_LOWMEM);
	}

	rc = RegSetValueEx(hMainKey, wkey, 0, REG_SZ, (const BYTE *) wval, 
			(lstrlen(wval)+1) * sizeof(TCHAR));

	smm_free(wval);
	smm_free(wkey);

	if (rc == ERROR_SUCCESS) {
		return smm_errno_update(SMM_ERR_NONE);
	}
	return smm_errno_update(SMM_ERR_ACCESS);
}

static int RegWriteLong(HKEY hMainKey, char *skey, long val)
{
	TCHAR	*wkey;

	if ((wkey = smm_mbstowcs_alloc(skey)) == NULL) {
		return smm_errno_update(SMM_ERR_LOWMEM);
	}

	if (RegSetValueEx(hMainKey, wkey, 0, REG_DWORD, (BYTE *) &val, 
				sizeof(long)) == ERROR_SUCCESS) {
		smm_free(wkey);
		return smm_errno_update(SMM_ERR_NONE);
	}
	smm_free(wkey);
	return smm_errno_update(SMM_ERR_ACCESS);
}


/* This code was picked form MSDN, a little modified */
static BOOL RegDelnodeRecurse(HKEY hKeyRoot, LPTSTR lpSubKey, int buflen)
{
	LPTSTR	lpEnd;
	LONG	lResult;
	DWORD	dwSize;
	TCHAR	szName[MAX_PATH];
	HKEY	hKey;

	/* First, see if we can delete the key without having to recurse. */
	if (RegDeleteKey(hKeyRoot, lpSubKey) == ERROR_SUCCESS) {
		return TRUE;
	}

	lResult = RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);
	if (lResult != ERROR_SUCCESS) {
		if (lResult == ERROR_FILE_NOT_FOUND) {
			return TRUE;	/* not guilty */
		} else {
			return FALSE;	/* access denied */
		}
	}

	/* Check for an ending slash and add one if it is missing. */
	if (lstrlen(lpSubKey) >= buflen) {
		return FALSE;	/* low buffer memory */
	}
	lpEnd = lpSubKey + lstrlen(lpSubKey);
	if (*(lpEnd - 1) != TEXT('\\')) {
		*lpEnd++ = TEXT('\\');
		*lpEnd = TEXT('\0');
	}

	/* Enumerate the keys */
	dwSize = MAX_PATH;
	lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL, 
			NULL, NULL, NULL);
	if (lResult == ERROR_SUCCESS) {
		do {
			if (lstrlen(lpSubKey) + lstrlen(szName) >= buflen) {
				break;	/* path is too long */
			}
			lstrcpy(lpEnd, szName);
			if (!RegDelnodeRecurse(hKeyRoot, lpSubKey, buflen)) {
				break;
			}
			dwSize = MAX_PATH;
			lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, 
					NULL, NULL, NULL, NULL);
		} while (lResult == ERROR_SUCCESS);
	}
	lpEnd--;
	*lpEnd = TEXT('\0');
	RegCloseKey (hKey);

	/* Try again to delete the key. */
	if (RegDeleteKey(hKeyRoot, lpSubKey) == ERROR_SUCCESS) {
		return TRUE;
	}
	return FALSE;
}
#endif

#ifdef	CFG_UNIX_API
#include <unistd.h>
#include <errno.h>

static char *smm_config_mkpath(int sysroot, char *path, int extra);

void *smm_config_open(int sysroot, int mode, char *path, char *fname)
{
	void	*root;

	if ((path = smm_config_mkpath(sysroot, path, 0)) == NULL) {
		return NULL;
	}
	root = csc_cfg_open(path, fname, mode);
	smm_free(path);
	return root;
}

int smm_config_flush(void *cfg)
{
	return csc_cfg_flush(cfg);
}

int smm_config_close(void *cfg)
{
	return csc_cfg_close(cfg);
}

int smm_config_delete(int sysroot, char *path, char *fname)
{
	path = smm_config_mkpath(sysroot, path, strlen(fname) + 4);
	if (path == NULL) {
		return smm_errno_update(SMM_ERR_LOWMEM);
	}
	strcat(path, "/");
	strcat(path, fname);
	
	if (unlink(path) == 0) {
		return smm_errno_update(SMM_ERR_NONE);
	}
	if (errno == EACCES) {
		return smm_errno_update(SMM_ERR_ACCESS);
	}
	return smm_errno_update(SMM_ERR_NULL);
}

char *smm_config_read_alloc(void *cfg, char *mkey, char *skey)
{
	return csc_cfg_copy(cfg, mkey, skey, 4);
}

int smm_config_write(void *cfg, char *mkey, char *skey, char *value)
{
	return csc_cfg_write(cfg, mkey, skey, value);
}

int smm_config_read_long(void *cfg, char *mkey, char *skey, long *val)
{
	return csc_cfg_read_long(cfg, mkey, skey, val);
}

int smm_config_write_long(void *cfg, char *mkey, char *skey, long val)
{
	return csc_cfg_write_longlong(cfg, mkey, skey, (long long) val);
}

static char *smm_config_mkpath(int sysroot, char *path, int extra)
{
	char	*fullpath;

	extra += 4;
	if (path) {
		extra += strlen(path);
	}
	switch (sysroot) {
	case SMM_CFGROOT_USER:
		fullpath = csc_strcpy_alloc(getenv("HOME"), extra);
		break;
	case SMM_CFGROOT_SYSTEM:
		fullpath = csc_strcpy_alloc("/etc", extra);
		break;
	case SMM_CFGROOT_CURRENT:
		fullpath = csc_strcpy_alloc(".", extra);
		break;
	default:	/* SMM_CFGROOT_DESKTOP */
		fullpath = csc_strcpy_alloc(getenv("HOME"), extra + 16);
		if (fullpath) {
			strcat(fullpath, "/.config");
			if (path) {
				strcat(fullpath, "/");
				strcat(fullpath, path);
			}
		}
		break;
	}
	if (fullpath == NULL) {
		smm_errno_update(SMM_ERR_LOWMEM);
		return NULL;
	}
	return fullpath;
}
#endif

int smm_config_read_int(void *cfg, char *mkey, char *skey, int *val)
{
	long	ival;
	int	rc;

	rc = smm_config_read_long(cfg, mkey, skey, &ival);
	if (val && (rc == SMM_ERR_NONE)) {
		*val = (int) ival;
	}
	return rc;
}

int smm_config_write_int(void *cfg, char *mkey, char *skey, int val)
{
	return smm_config_write_long(cfg, mkey, skey, (long) val);
}
#endif	// if 0
