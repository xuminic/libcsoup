
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

/* How to find out the input/output device.
 * Input:
 *   *) Win32 Registry: hRootKey != NULL
 *   *) File system: fp != NULL
 *   *) Memory cache: fname == NULL && fpath == configure (kpath = counter)
 *   *) stdin: fname == NULL && fpath == NULL
 * Input priority: Registry > File > Memory > stdio
 * Output:
 *   *) Win32 Registry: hRootKey != NULL
 *   *) File system: fp != NULL
 *   *) Memory cache: fname == NULL && fpath == configure && mode > 0
 *   *) stdout: fname == NULL && (mode == 0 || fpath == NULL)
 */
struct	KeyDev	{
	FILE	*fp;
	int	mode;
	char	*fpath;		/* full path for the file system */
	char	*kpath;		/* key path for the Win32 registry */
	char	*fname;
#ifdef	CFG_WIN32_API
	HKEY	hSysKey;	/* predefined key like HKEY_CURRENT_USER */
	HKEY	hRootKey;	/* root key points to the entrance */
	TCHAR	cpath[MAX_PATH];
	int	cval;
	int	idx_key[MAX_PATH];	/* index of keys (Win32 values */
	int	idx_dir[MAX_PATH];	/* index of directories (Win32 subkeys) */
	int	idx_no;
#endif
	char	pool[1];
};


static struct KeyDev *smm_config_alloc(int sysdir, char *path, char *fname);
static int smm_config_mem_read(struct KeyDev *cfgd, KEYCB *kp);
static int smm_config_mem_write(struct KeyDev *cfgd, KEYCB *kp);
static int smm_config_file_read(struct KeyDev *cfgd, KEYCB *kp);
static int smm_config_file_write(struct KeyDev *cfgd, KEYCB *kp);

#ifdef	CFG_WIN32_API
static int smm_config_registry_open(struct KeyDev *cfgd, int mode);
//static int smm_config_registry_read(struct KeyDev *cfgd, KEYCB *kp);
static int smm_config_registry_read(struct KeyDev *cfgd, TCHAR *path);
static int smm_config_registry_write(struct KeyDev *cfgd, KEYCB *kp);
static int smm_config_registry_delete(struct KeyDev *cfgd, char *fname);
#endif


/*!\brief Open the input/output device for the configuration manager

   \param[in]  sysdir The identity of system directory. In Win32, the system
   directory normally points to the registry like HKEY_CURRENT_USER\\SOFTWARE.
   In Posix, the configure file is normally stored in the file system like
   $HOME/.config. However it is also possible for Win32 to store the configure
   file like Posix. Current identities of system directory are:

   SMM_CFGROOT_DESKTOP: $HOME/.config in Posix, or HKEY_CURRENT_USER\\SOFTWARE
                        in Windows.
   SMM_CFGROOT_USER: $HOME in Posix, or HKEY_CURRENT_USER\\CONSOLE in Windows.
   SMM_CFGROOT_SYSTEM: /etc in Posix, or HKEY_LOCAL_MACHINE\\SOFTWARE
                       in Windows.
   SMM_CFGROOT_CURRENT: starting from the current directory.
   SMM_CFGROOT_MEMPOOL: the contents of the configuration is stored in the 
         memory buffer pointed by 'path'. 'fname' will be ignored.
	 If 'mode' is 0, the configuration memory buffer is read only and 
	 the output will be written to the stdout. If 'mode' is greater 
	 than 0, which means the size of the configuration memory buffer,
	 the output will be written back to the memory buffer until it's full.
                      
   \param[in]  path Specify the path to the configure file in the file system.
        It can also be the path in Registry of Windows pointing to the parent
	key before the configure key. In SMM_CFGROOT_MEMPOOL mode, the 'path'
	points to the memory buffer where the content of configure holded.

   \param[in]  fname Specify the name of the configure in the file system.
        In Registry of Windows, it's the name of the key to the configures.
	In SMM_CFGROOT_MEMPOOL mode, it should be NULL.

   \param[in]  mode The access mode to the registry or to the file. It can be
        CSC_CFG_READ, which means read only, CSC_CFG_RDWR, which means read
        and write, or CSC_CFG_RWC, which means read/write/create. Note that
	the smm_config module doesn't support random access so the write 
	operation will always over write the previous contents.
	In SMM_CFGROOT_MEMPOOL mode, the 'mode' can be 0, whicn means read 
	only, or be the size of the memory buffer. If the 'mode' specifies
	the size of the memory buffer, the access mode is always be read and
	write.

   \return A pointer to the 'KeyDev' structure if succeed, or NULL if failed.
*/
struct KeyDev *smm_config_open(int sysdir, char *path, char *fname, int mode)
{
	struct	KeyDev	*cfgd;

	/* configure in memory mode.
	 * Note that in memory mode, the 'path' parameter points to the 
	 * contents of the configure and the 'mode' parameter stores the size
	 * of the memory of the configure. In memory mode, the access mode
	 * is always read/write/create. */
	if (sysdir == SMM_CFGROOT_MEMPOOL) {
		if ((cfgd = smm_alloc(sizeof(struct KeyDev))) != NULL) {
			cfgd->fpath = path;
			cfgd->kpath = path;	/* reset the runtime index */
			cfgd->mode  = mode;
		}
		return cfgd;
	}

	if ((cfgd = smm_config_alloc(sysdir, path, fname)) == NULL) {
		return NULL;
	}
	cfgd->mode = mode;
	
	/* debug mode 0xdeadbeef.
	 * In this mode, the function will return by assuming the output
	 * device is available but empty without verify the descriptor */
	if (mode == 0xdeadbeef) {
		return cfgd;
	}

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
	case CSC_CFG_RDWR:
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
		RegFlushKey(cfgd->hRootKey);
		RegCloseKey(cfgd->hRootKey);
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
		//return smm_config_registry_read(cfgd, kp);
		return smm_config_registry_read(cfgd, TEXT(""));
	}
#endif
	if (cfgd->fp) {
		return smm_config_file_read(cfgd, kp);
	}
	if (cfgd->fname == NULL) {
		if (cfgd->fpath) {
			return smm_config_mem_read(cfgd, kp);
		}
		/* stdio has not implemented */
	}
	return -1;
}

int smm_config_write(struct KeyDev *cfgd, KEYCB *kp)
{
#ifdef	CFG_WIN32_API
	if (cfgd->hRootKey) {
		if (cfgd->mode != CSC_CFG_READ) {
			smm_config_registry_write(cfgd, kp);
		}
	}
#endif
	if (cfgd->fname == NULL) {
		if (cfgd->fpath && cfgd->mode) {
			return smm_config_mem_write(cfgd, kp);
		} else {
			return smm_config_file_write(cfgd, kp);
		}
	}
	if (cfgd->mode == CSC_CFG_READ) {
		return smm_errno_update(SMM_ERR_ACCESS);
	}
	return smm_config_file_write(cfgd, kp);
}

int smm_config_delete(int sysdir, char *path, char *fname)
{
	struct	KeyDev	*cfgd;
	int	rc;

	if (sysdir == SMM_CFGROOT_MEMPOOL) {
		return smm_errno_update(SMM_ERR_NULL);
	}
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

void smm_config_dump(struct KeyDev *cfgd)
{
	slogz("Device:    Read from ");
#ifdef	CFG_WIN32_API
	if (cfgd->hRootKey) {
		slogz("Registry");
	} else
#endif
	if (cfgd->fp) {
		slogz("%s", cfgd->fname);
	} else if (cfgd->fname == NULL) {
		if (cfgd->fpath) {
			slogz("%p", cfgd->fpath);
		} else {
			slogz("stdin");
		}
	} else {
		slogz("*%s", cfgd->fname);
	}
	slogz(". Write to ");
#ifdef	CFG_WIN32_API
	if (cfgd->hRootKey) {
		slogz("(Registry)");
	}
#endif
	if (cfgd->fp) {
		slogz("(%s)", cfgd->fname);
	}
	if (cfgd->fname == NULL) {
		if (cfgd->fpath == NULL) {
			slogz("(*stdout)");
		} else if (cfgd->mode) {
			slogz("(%p+%d)", cfgd->fpath, cfgd->mode);
		} else {
			slogz("(stdout)");
		}
	} else {
		slogz("(*%s)", cfgd->fname);
	}
	slogz("\n");

	if (!cfgd->fname && cfgd->fpath) {
		slogz("Memory:    %p %p\n", cfgd->fpath, cfgd->kpath);
	} else {
		slogz("Full Path: %s\n", cfgd->fpath);
		slogz("Reg Path:  %s\n", cfgd->kpath);
	}
	slogz("\n");
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
		strcat(cfgd->fpath, "/etc/");	//FIXME
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
	
	/* convert the '/' to '\\' in the registry path */
	if (cfgd->kpath) {
		for (home = cfgd->kpath; *home; home++) {
			if (*home == '/') {
				*home = '\\';
			}
		}
	}

	/* check point */
	//slogz("smm_config_alloc::fpath = %s\n", cfgd->fpath);
	//slogz("smm_config_alloc::kpath = %s\n", cfgd->kpath);
	//slogz("smm_config_alloc::fname = %s\n", cfgd->fname);
	return cfgd;
}

static int smm_config_mem_read(struct KeyDev *cfgd, KEYCB *kp)
{
	int	i;

	for (i = 0; cfgd->kpath[i]; i++) {
		if (kp) {
			kp->pool[i] = cfgd->kpath[i];
		}
		if (cfgd->kpath[i] == '\n') {
			i++;
			break;
		}
	}
	if (kp) {
		kp->pool[i] = 0;
		cfgd->kpath += i;
	}
	return i;
}

static int mem_update(char **dest, char *s, int *room)
{
	int	n;

	n = strlen(s);
	if (*room > n) {
		strcpy(*dest, s);
	} else if ((n = *room - 1) > 0) {
		strncpy(*dest, s, n);
	}
	*dest += n;
	*room -= n;
	**dest = 0;
	return n;
}

static int smm_config_mem_write(struct KeyDev *cfgd, KEYCB *kp)
{
	int	wtd = 0;

	if (kp == NULL) {
		return 0;
	}
	if (kp->key) {
		if (csc_cfg_isdir(kp)) {
			wtd += mem_update(&cfgd->kpath, "[", &cfgd->mode);
			wtd += mem_update(&cfgd->kpath, kp->key, &cfgd->mode);
			wtd += mem_update(&cfgd->kpath, "]", &cfgd->mode);
		} else {
			wtd += mem_update(&cfgd->kpath, kp->key, &cfgd->mode);
		}
	}
	if (kp->value) {
		wtd += mem_update(&cfgd->kpath, "=", &cfgd->mode);
		wtd += mem_update(&cfgd->kpath, kp->value, &cfgd->mode);
	}
	if (kp->comment) {
		wtd += mem_update(&cfgd->kpath, kp->comment, &cfgd->mode);
	}
	wtd += mem_update(&cfgd->kpath, "\n", &cfgd->mode);
	kp->update = 0;		/* reset the update counter */
	return wtd;
}

static int smm_config_file_read(struct KeyDev *cfgd, KEYCB *kp)
{
	int	amnt, cpos, ch;

	if (cfgd->fp == NULL) {
		return 0;
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
		if (csc_cfg_isdir(kp)) {
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

struct	RegBuf	{
	DWORD	n_keys;		/* number of of keys (directory) */
	DWORD	n_vals;		/* number of values (key/value pairs) */
	TCHAR	*name;		/* to the buffer for name of values/keys */
	DWORD	nm_len;		/* length of the name buffer in unicode */
	TCHAR	*type;		/* to the buffer for value type */
	DWORD	ty_len;		/* length of the type buffer in unicode */
	DWORD	ty_id;
	void	*content;	/* to the buffer for contents of values */
	DWORD	co_len;		/* length of the content buffer in bytes */
	char	pool[1];
};

static struct RegBuf *registry_buffer_alloc(HKEY hKey);
static int registry_buffer_read_value(HKEY hKey, int idx, struct RegBuf *rbuf);
static BOOL RegDelnodeRecurse(HKEY hKeyRoot, LPTSTR lpSubKey, int buflen);


static int smm_config_registry_open(struct KeyDev *cfgd, int mode)
{
	HKEY	hPathKey;
	LONG	rc;
	TCHAR	*wkey;
	char	*mkey;	/* key of main entry */

	if (cfgd->kpath == NULL) {
		return SMM_ERR_NULL;
	}
	mkey = csc_strcpy_alloc(cfgd->kpath, strlen(cfgd->fname) + 4);
	if (mkey == NULL) {
		return SMM_ERR_LOWMEM;
	}
	strcat(mkey, SMM_DEF_DELIM);
	strcat(mkey, cfgd->fname);

	slogz("smm_config_registry_open: %s\n", mkey);
	if ((wkey = smm_mbstowcs_alloc(mkey)) == NULL) {
		smm_free(mkey);
		return SMM_ERR_LOWMEM;
	}

	switch (mode) {
	case CSC_CFG_READ:
		rc = RegOpenKeyEx(cfgd->hSysKey, wkey, 0, KEY_READ, 
				&cfgd->hRootKey);
		break;
	case CSC_CFG_RWC:
		/* The good thing of RegCreateKeyEx() is that it can create 
		 * a string of subkeys without creating one by one. 
		 * For example: A\\B\\C */
		rc = RegCreateKeyEx(cfgd->hSysKey, wkey, 0, NULL, 0, 
				KEY_ALL_ACCESS, NULL, &cfgd->hRootKey, NULL);
		break;
	case CSC_CFG_RDWR:
		rc = RegOpenKeyEx(cfgd->hSysKey, wkey, 0, KEY_ALL_ACCESS, 
				&cfgd->hRootKey);
		break;
	}

	smm_free(wkey);			
	smm_free(mkey);

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

//static int smm_config_registry_read(struct KeyDev *cfgd, KEYCB *kp)

static int smm_config_registry_read(struct KeyDev *cfgd, TCHAR *cpath)
{
	struct	RegBuf	*rbuf;
	HKEY	hCurrKey;
	TCHAR	szName[MAX_PATH], nxPath[MAX_PATH];
	DWORD	i, dwSize;

	if (*cpath == TEXT('\0')) {
		hCurrKey = cfgd->hRootKey;
	} else if (RegOpenKeyEx(cfgd->hRootKey, cpath, 0, KEY_READ, &hCurrKey) != ERROR_SUCCESS) {
		return -1;
	}
	_tprintf(TEXT("Entering %s\n"), cpath);

	/* get number of keys and values */
	if ((rbuf = registry_buffer_alloc(hCurrKey)) == NULL) {
		return -2;
	}
	for (i = 0; i < rbuf->n_vals; i++) {
		if (registry_buffer_read_value(hCurrKey, i, rbuf) < 0) {
			break;
		}
		if (rbuf->ty_id == REG_SZ) {
			_tprintf(TEXT("%s = %s  #%s\n"), rbuf->name, rbuf->content, rbuf->type);
		} else {
			_tprintf(TEXT("%s = %p  #%s\n"), rbuf->name, rbuf->content, rbuf->type);
		}
	}

	dwKeys = rbuf->n_keys;
	smm_free(rbuf);

	for (i = 0; i < dwKeys; i++) {
		dwSize = MAX_PATH * sizeof(TCHAR);
		RegEnumKeyEx(hCurrKey, i, szName, &dwSize, 
				NULL, NULL, NULL, NULL);
		StringCchCopy(nxPath, MAX_PATH, cpath);         /* lstrcpy */
		StringCchCat(nxPath, MAX_PATH, TEXT("\\"));
		StringCchCat(nxPath, MAX_PATH, szName);
		smm_config_registry_read(cfgd, nxPath);
	}

	if (hCurrKey != cfgd->hRootKey) {
		RegCloseKey(hCurrKey);
	}
	return 0;
}

static int smm_config_registry_write(struct KeyDev *cfgd, KEYCB *kp)
{
	return 0;
}

static struct RegBuf *registry_buffer_alloc(HKEY hKey)
{
	struct	RegBuf	*rbuf;
	DWORD	dwKeys, dwKeyLen, dwVals, dwValNmlen, dwValLen, len;

	RegQueryInfoKey(hKey, NULL, NULL, NULL, 
			&dwKeys, &dwKeyLen, NULL,
			&dwVals, &dwValNmlen, &dwValLen, NULL, NULL);

	/* find the longest between name of key and name of value */
	len = dwKeyLen > dwValNmlen ? dwKeyLen : dwValNmlen;
	/* note that name of key and name of value are unicode of Win32 */
	len *= sizeof(TCHAR);
	/* added the longest content of value in byte */
	len += dwValLen;
	/* top up with the structure size and reserve area for type */
	len += sizeof(struct RegBuf) + 64 * sizeof(TCHAR);

	if ((rbuf = smm_alloc((int)len)) == NULL) {
		return NULL;
	}

	rbuf->n_keys = dwKeys;
	rbuf->n_vals = dwVals;
	rbuf->name   = rbuf->pool;
	rbuf->nm_len = (dwKeyLen > dwValNmlen ? dwKeyLen : dwValNmlen) + 1;
	rbuf->type   = &rbuf->name[rbuf->nm_len];
	rbuf->ty_len = 60;
	rbuf->content = (void*) &rbuf->type[rbuf->ty_len];
	rbuf->co_len = dwValLen + 1;
	return rbuf;
}

static int registry_buffer_read_value(HKEY hKey, int idx, struct RegBuf *rbuf)
{
	DWORD	dwSize, dwLeng, dwType;

	dwSize = rbuf->nm_len;
	dwLeng = rbuf->co_len;
	if (RegEnumValue(hKey, idx, rbuf->name, &dwSize, NULL, &dwType, 
				&rbuf->content, &dwLeng) != ERROR_SUCCESS) {
		return -1;
	}

	rbuf->ty_id = dwType;
	switch (dwType) {
	case REG_BINARY:
		StringCchCopy(rbuf->type, rbuf->ty_len, TEXT("REG_BINARY"));
		break;
	case REG_DWORD:
		StringCchCopy(rbuf->type, rbuf->ty_len, TEXT("REG_DWORD"));
		break;
	case REG_DWORD_LITTLE_ENDIAN:
		StringCchCopy(rbuf->type, rbuf->ty_len, TEXT("REG_DWORD_LITTLE_ENDIAN"));
		break;
	case REG_DWORD_BIG_ENDIAN:
		StringCchCopy(rbuf->type, rbuf->ty_len, TEXT("REG_DWORD_BIG_ENDIAN"));
		break;
	case REG_EXPAND_SZ:
		StringCchCopy(rbuf->type, rbuf->ty_len, TEXT("REG_EXPAND_SZ"));
		break;
	case REG_LINK:
		StringCchCopy(rbuf->type, rbuf->ty_len, TEXT("REG_LINK"));
		break;
	case REG_MULTI_SZ:
		StringCchCopy(rbuf->type, rbuf->ty_len, TEXT("REG_MULTI_SZ"));
		break;
	case REG_NONE:
		StringCchCopy(rbuf->type, rbuf->ty_len, TEXT("REG_NONE"));
		break;
	case REG_QWORD:
		StringCchCopy(rbuf->type, rbuf->ty_len, TEXT("REG_QWORD"));
		break;
	case REG_QWORD_LITTLE_ENDIAN:
		StringCchCopy(rbuf->type, rbuf->ty_len, TEXT("REG_QWORD_LITTLE_ENDIAN"));
		break;
	case REG_SZ:
		StringCchCopy(rbuf->type, rbuf->ty_len, TEXT("REG_SZ"));
		break;
	default:
		StringCchCopy(rbuf->type, rbuf->ty_len, TEXT("REG_UNKNOWN"));
		break;
	}
	return 0;	//FIXME
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
