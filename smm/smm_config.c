
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
	HKEY	hSaveKey;	/* used to save contents */

	int	idx;
	struct	{
		HKEY	hKey;
		DWORD	n_keys;
		DWORD	n_vals;
		DWORD	l_key;
		DWORD	l_vname;
		DWORD	l_value;
		int	i_val;
		int	i_key;
	} reg[CFGF_MAX_DEPTH];
#endif
	char	pool[1];
};


static struct KeyDev *smm_config_alloc(int sysdir, char *path, char *fname);
static KEYCB *smm_config_mem_read(struct KeyDev *cfgd);
static int smm_config_mem_write(struct KeyDev *cfgd, KEYCB *kp);
static KEYCB *smm_config_file_read(struct KeyDev *cfgd);
static int smm_config_file_write(struct KeyDev *cfgd, KEYCB *kp);
static int str_substitue_char(char *s, int len, char src, char dst);

#ifdef	CFG_WIN32_API
static int smm_config_registry_open(struct KeyDev *cfgd, int mode);
static KEYCB *smm_config_registry_read(struct KeyDev *cfgd);
static int smm_config_registry_write(struct KeyDev *cfgd, KEYCB *kp);
static int smm_config_registry_delete(struct KeyDev *cfgd, char *fname);
extern int csc_cfg_binary_to_hex(char *src, int slen, char *buf, int blen);
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
	if (mode == (int) 0xdeadbeef) {
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

KEYCB *smm_config_read_alloc(struct KeyDev *cfgd)
{
#ifdef	CFG_WIN32_API
	if (cfgd->hRootKey) {
		return smm_config_registry_read(cfgd);
	}
#endif
	if (cfgd->fp) {
		return smm_config_file_read(cfgd);
	}
	if (cfgd->fname == NULL) {
		if (cfgd->fpath) {
			return smm_config_mem_read(cfgd);
		}
		/* stdio has not implemented */
	}
	return NULL;
}

int smm_config_write(struct KeyDev *cfgd, KEYCB *kp)
{
#ifdef	CFG_WIN32_API
	if (cfgd->hRootKey) {
		if (cfgd->mode != CSC_CFG_READ) {
			return smm_config_registry_write(cfgd, kp);
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
		rc = smm_config_registry_delete(cfgd, fname);
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
		str_substitue_char(cfgd->kpath, -1, '/', '\\');
	}

	/* check point */
	//slogz("smm_config_alloc::fpath = %s\n", cfgd->fpath);
	//slogz("smm_config_alloc::kpath = %s\n", cfgd->kpath);
	//slogz("smm_config_alloc::fname = %s\n", cfgd->fname);
	return cfgd;
}

static KEYCB *smm_config_mem_read(struct KeyDev *cfgd)
{
	KEYCB	*kp;
	int	n;

	for (n = 0; cfgd->kpath[n]; n++) {
		if (cfgd->kpath[n] == '\n') {
			n++;
			break;
		}
	}

	if ((n == 0) || ((kp = csc_cfg_kcb_alloc(n+1)) == NULL)) {
		return NULL;
	}
	memcpy(kp->pool, cfgd->kpath, n);
	kp->pool[n] = 0;
	cfgd->kpath += n;
	return kp;
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
		if (CFGF_TYPE_GET(kp->flags) == CFGF_TYPE_DIR) {
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

static KEYCB *smm_config_file_read(struct KeyDev *cfgd)
{
	KEYCB	*kp;
	int	amnt, cpos, ch;

	if (cfgd->fp == NULL) {
		return NULL;
	}

	amnt = 0;
	cpos = ftell(cfgd->fp);
	while ((ch = fgetc(cfgd->fp)) != EOF) {
		amnt++;
		if (ch == '\n') {
			break;
		}
	}

	if ((amnt == 0) || ((kp = csc_cfg_kcb_alloc(amnt+1)) == NULL)) {
		return NULL;
	}

	/* rewind to the start position */
	fseek(cfgd->fp, cpos, SEEK_SET);
	amnt = 0;
	while ((ch = fgetc(cfgd->fp)) != EOF) {
		kp->pool[amnt++] = (char) ch;
		if (ch == '\n') {
			break;
		}
	}
	kp->pool[amnt] = 0;
	return kp;
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
		if (CFGF_TYPE_GET(kp->flags) == CFGF_TYPE_DIR) {
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

static int str_substitue_char(char *s, int len, char src, char dst)
{
	int	i, n = 0;

	if (len < 0) {
		len = strlen(s);
	}
	for (i = n = 0; i < len; i++) {
		if (s[i] == src) {
			s[i] = dst;
			n++;
		}
	}
	return n;
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

#define RREF(d)		((d)->reg[(d)->idx])

static int smm_config_registry_eof(struct KeyDev *cfgd);
static DWORD smm_config_registry_load_info(struct KeyDev *cfgd, HKEY hKey);
static DWORD smm_config_registry_open_subkey(struct KeyDev *cfgd);
static KEYCB *smm_config_registry_key_alloc(struct KeyDev *cfgd, int idx);
static KEYCB *smm_config_registry_path_alloc(struct KeyDev *cfgd);
static HKEY RegKeyFromDir(HKEY hRoot, char *dkey);
static DWORD RegWriteString(HKEY hKey, TCHAR *key, DWORD dwType, char *val);
static BOOL RegDelnodeRecurse(HKEY hKeyRoot, LPTSTR lpSubKey, int buflen);


static int smm_config_registry_open(struct KeyDev *cfgd, int mode)
{
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
		RegOpenKeyEx(cfgd->hSysKey, wkey, 0, KEY_READ, 
				&cfgd->hRootKey);
		break;
	case CSC_CFG_RWC:
		/* The good thing of RegCreateKeyEx() is that it can create 
		 * a string of subkeys without creating one by one. 
		 * For example: A\\B\\C */
		RegCreateKeyEx(cfgd->hSysKey, wkey, 0, NULL, 0, 
				KEY_ALL_ACCESS, NULL, &cfgd->hRootKey, NULL);
		break;
	case CSC_CFG_RDWR:
		RegOpenKeyEx(cfgd->hSysKey, wkey, 0, KEY_ALL_ACCESS, 
				&cfgd->hRootKey);
		break;
	}

	smm_free(wkey);			
	smm_free(mkey);

	if (cfgd->hRootKey == NULL) {
		return SMM_ERR_ACCESS;
	}
	/* load the reg[0] with the root key */
	smm_config_registry_load_info(cfgd, cfgd->hRootKey);
	/* initialize the key for saving */
	cfgd->hSaveKey = cfgd->hRootKey;
	return SMM_ERR_NONE;
}


/* Note that the reg[0] must be loaded with root key prior to this call. */
static KEYCB *smm_config_registry_read(struct KeyDev *cfgd)
{
	while (!smm_config_registry_eof(cfgd)) {
		/*slogz("smm_config_registry_read: %d I(%d/%u) V(%d/%u)\n", 
				cfgd->idx, RREF(cfgd).i_key, RREF(cfgd).n_keys,
				RREF(cfgd).i_val, RREF(cfgd).n_vals);*/
		if (RREF(cfgd).i_val < (int)RREF(cfgd).n_vals) {
			return smm_config_registry_key_alloc(cfgd, 
					RREF(cfgd).i_val++);
		}

		if (RREF(cfgd).i_key == (int)RREF(cfgd).n_keys) {
			if (cfgd->idx) {
				RegCloseKey(RREF(cfgd).hKey);
				RREF(cfgd).hKey = NULL;
				RREF(cfgd).n_keys = RREF(cfgd).n_vals = 0;
				RREF(cfgd).i_key = RREF(cfgd).i_val = 0;
				cfgd->idx--;
			}
			continue;
		}

		/* move to the subkey; cfgd->idx mostly increased here */
		if (smm_config_registry_open_subkey(cfgd) == ERROR_SUCCESS) {
			/* the first time entering the current path */
			if (RREF(cfgd).n_vals) {
				return smm_config_registry_path_alloc(cfgd);
			}
		}
	}
	return NULL;
}


static int smm_config_registry_write(struct KeyDev *cfgd, KEYCB *kp)
{
	TCHAR	*wpath;
	DWORD	dwErr;
	
	if (CFGF_TYPE_GET(kp->flags) == CFGF_TYPE_DIR) {
		if (cfgd->hSaveKey && (cfgd->hSaveKey != cfgd->hRootKey)) {
			RegCloseKey(cfgd->hSaveKey);
		}

		cfgd->hSaveKey = RegKeyFromDir(cfgd->hRootKey, kp->key);
		if (cfgd->hSaveKey == NULL) {
			return SMM_ERR_ACCESS;
		}
		return SMM_ERR_NONE;
	}

	if (cfgd->hSaveKey == NULL) {
		return SMM_ERR_ACCESS;
	}
	if ((wpath = smm_mbstowcs_alloc(kp->key)) == NULL) {
		return SMM_ERR_LOWMEM;
	}
	if (kp->comment == NULL) {
		dwErr = RegWriteString(cfgd->hSaveKey, wpath, 
				REG_SZ, kp->value);
	} else if (!strcmp(kp->comment, "##REG_BINARY")) {
		dwErr = RegSetValueEx(cfgd->hSaveKey, wpath, 0, 
				REG_BINARY, (void*)kp->value, kp->vsize);
	} else if (!strcmp(kp->comment, "##REG_DWORD")) {
		DWORD	dwData = (DWORD) strtol(kp->value, NULL, 0);
		dwErr = RegSetValueEx(cfgd->hSaveKey, wpath, 0,
				REG_DWORD, (void*)&dwData, sizeof(dwData));
	} else if (!strcmp(kp->comment, "##REG_DWORD_BIG_ENDIAN")) {
		DWORD	dwData = (DWORD) strtol(kp->value, NULL, 0);
		dwErr = RegSetValueEx(cfgd->hSaveKey, wpath, 0,
			REG_DWORD_BIG_ENDIAN, (void*)&dwData, sizeof(dwData));
	} else if (!strcmp(kp->comment, "##REG_EXPAND_SZ")) {
		dwErr = RegWriteString(cfgd->hSaveKey, wpath, 
				REG_EXPAND_SZ, kp->value);
	} else if (!strcmp(kp->comment, "##REG_LINK")) {
		dwErr = RegWriteString(cfgd->hSaveKey, wpath, 
				REG_LINK, kp->value);
	} else if (!strcmp(kp->comment, "##REG_MULTI_SZ")) {
		dwErr = RegWriteString(cfgd->hSaveKey, wpath, 
				REG_MULTI_SZ, kp->value);
	} else if (!strcmp(kp->comment, "##REG_NONE") ||
			!strcmp(kp->comment, "##REG_UNKNOWN")) {
		dwErr = RegSetValueEx(cfgd->hSaveKey, wpath, 0, 
				REG_NONE, (void*)kp->value, kp->vsize);
	} else if (!strcmp(kp->comment, "##REG_QWORD")) {
		DWORD64	dqData = (DWORD64) strtoll(kp->value, NULL, 0);
		dwErr = RegSetValueEx(cfgd->hSaveKey, wpath, 0,
				REG_QWORD, (void*)&dqData, sizeof(dqData));
	} else {
		dwErr = RegWriteString(cfgd->hSaveKey, wpath, 
				REG_SZ, kp->value);
	}
	smm_free(wpath);
	return dwErr;
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
	MultiByteToWideChar(smm_codepage(), 0, fname, -1, wkey, MAX_PATH);

	rcode = RegDelnodeRecurse(hPathKey, wkey, MAX_PATH * 2);

	RegCloseKey(hPathKey);
	smm_free(wkey);
       
	if (rcode == TRUE) {
		return SMM_ERR_NONE;
	}
	errno = EACCES;
	return SMM_ERR_ACCESS;
}


static int smm_config_registry_eof(struct KeyDev *cfgd)
{
	return (cfgd->idx == 0) && 
		(RREF(cfgd).i_key == (int) RREF(cfgd).n_keys) &&
		(RREF(cfgd).i_val == (int) RREF(cfgd).n_vals);
}

static DWORD smm_config_registry_load_info(struct KeyDev *cfgd, HKEY hKey)
{
	RREF(cfgd).hKey  = hKey;
	RREF(cfgd).i_val = 0;
	RREF(cfgd).i_key = 0;

	return RegQueryInfoKey(hKey, NULL, NULL, NULL, 
			&RREF(cfgd).n_keys, &RREF(cfgd).l_key, NULL,
			&RREF(cfgd).n_vals, &RREF(cfgd).l_vname, 
			&RREF(cfgd).l_value, NULL, NULL);
}

static DWORD smm_config_registry_open_subkey(struct KeyDev *cfgd)
{
	HKEY	hSubKey;
	TCHAR	szName[MAX_PATH];
	DWORD	dwSize, dwErro;

	dwSize = MAX_PATH * sizeof(TCHAR);
	dwErro = RegEnumKeyEx(RREF(cfgd).hKey, RREF(cfgd).i_key++, 
			szName, &dwSize, NULL, NULL, NULL, NULL);
	if (dwErro != ERROR_SUCCESS) {
		return dwErro;
	}

	dwErro = RegOpenKeyEx(RREF(cfgd).hKey, szName, 0, KEY_READ, &hSubKey);
	if (dwErro != ERROR_SUCCESS) {
		return dwErro;
	}

	cfgd->idx++;
	if (cfgd->idx >= CFGF_MAX_DEPTH) {
		cfgd->idx--;
		RegCloseKey(hSubKey);
		return ERROR_INVALID_LEVEL;
	}

	dwErro = smm_config_registry_load_info(cfgd, hSubKey);
	if (dwErro != ERROR_SUCCESS) {
		cfgd->idx--;
		RegCloseKey(hSubKey);
	}
	return dwErro;
}

static KEYCB *smm_config_registry_key_alloc(struct KeyDev *cfgd, int idx)
{
	TCHAR	*tbuf;
	DWORD	dwSize, dwLeng, dwType, len;
	char 	*content;
	KEYCB	*kp;

	/* allocate a buffer for reading the registry */
	len = RREF(cfgd).l_vname * sizeof(TCHAR) + RREF(cfgd).l_value + 16;
	if ((tbuf = smm_alloc((int)len)) == NULL) {
		return NULL;
	}
	content = (void*) &tbuf[RREF(cfgd).l_vname + 1];

	dwSize = RREF(cfgd).l_vname * sizeof(TCHAR);
	dwLeng = RREF(cfgd).l_value;
	if (RegEnumValue(RREF(cfgd).hKey, idx, tbuf, &dwSize, NULL, &dwType,
				(BYTE*)content, &dwLeng) != ERROR_SUCCESS) {
		smm_free(tbuf);
		return NULL;
	}

	/* estimate the total length of the entry according to RFC3629,
	 * the longest UTF-8 character should be 4 bytes */
	len = (dwSize + dwLeng) * 4 + 64;
	if ((kp = csc_cfg_kcb_alloc((int)len)) == NULL) {
		smm_free(tbuf);
		return NULL;
	}

	kp->key = kp->pool;
	WideCharToMultiByte(smm_codepage(), 0, tbuf, -1, 
			kp->key, len, NULL, NULL);
	/* it is possible that '#' appears inside so has it replaced by '_' */
	str_substitue_char(kp->key, -1, '#', '_');
	
	
	kp->value = kp->key + strlen(kp->key) + 1;
	len -= strlen(kp->key) + 1;
	kp->comment = kp->value + len - 64;

	switch (dwType) {
	case REG_BINARY:
		memcpy(kp->value, content, dwLeng);
		strcpy(kp->comment, "##REG_BINARY");
		kp->vsize = (int) dwLeng;
		break;
	case REG_DWORD:		/* == REG_DWORD_LITTLE_ENDIAN */
		dwSize = *((DWORD *) content);
		sprintf(kp->value, "%lu", dwSize);
		strcpy(kp->comment, "##REG_DWORD");
		break;
	case REG_DWORD_BIG_ENDIAN:
		dwSize = *((DWORD *) content);
		sprintf(kp->value, "%lu", dwSize);
		strcpy(kp->comment, "##REG_DWORD_BIG_ENDIAN");
		break;
	case REG_EXPAND_SZ:
		WideCharToMultiByte(smm_codepage(), 0, (TCHAR*)content, -1,
				kp->value, len, NULL, NULL);
		str_substitue_char(kp->value, -1, '#', '_');
		strcpy(kp->comment, "##REG_EXPAND_SZ");
		break;
	case REG_LINK:
		WideCharToMultiByte(smm_codepage(), 0, (TCHAR*)content, -1,
				kp->value, len, NULL, NULL);
		str_substitue_char(kp->value, -1, '#', '_');
		strcpy(kp->comment, "##REG_LINK");
		break;
	case REG_MULTI_SZ:
		len = WideCharToMultiByte(smm_codepage(), 0, (TCHAR*)content, 
				dwLeng / sizeof(TCHAR),
				kp->value, len, NULL, NULL);
		str_substitue_char(kp->value, len - 1, 0, '~');
		str_substitue_char(kp->value, -1, '#', '_');
		strcpy(kp->comment, "##REG_MULTI_SZ");
		break;
	case REG_NONE:
		memcpy(kp->value, content, dwLeng);
		strcpy(kp->comment, "##REG_NONE");
		kp->vsize = (int) dwLeng;
		break;
	case REG_QWORD:		/* == REG_QWORD_LITTLE_ENDIAN */
		SMM_SPRINT(kp->value, "%llu", 
				*((unsigned long long *)content));
		strcpy(kp->comment, "##REG_QWORD");
		break;
	case REG_SZ:
		WideCharToMultiByte(smm_codepage(), 0, (TCHAR*)content, -1,
				kp->value, len, NULL, NULL);
		str_substitue_char(kp->value, -1, '#', '_');
		strcpy(kp->comment, "##REG_SZ");
		break;
	default:
		memcpy(kp->value, content, dwLeng);
		strcpy(kp->comment, "##REG_UNKNOWN");
		kp->vsize = (int) dwLeng;
		break;
	}
	smm_free(tbuf);
	kp->flags = CFGF_TYPE_SET(kp->flags, CFGF_TYPE_KEY);

	return kp;
}

static KEYCB *smm_config_registry_path_alloc(struct KeyDev *cfgd)
{
	TCHAR	*path, szName[MAX_PATH];
	DWORD	dwSize;
	KEYCB	*kp;
	int	i;

	dwSize = 48;
	for (i = 0; i < cfgd->idx; i++) {
		dwSize += cfgd->reg[i].l_key + 1;
	}

	if ((path = smm_alloc(dwSize * sizeof(TCHAR))) == NULL) {
		return NULL;
	}

	/* estimated the total length of the entry according to RFC3629,
	 * the longest UTF-8 character should be 4 bytes */
	dwSize *= 4;
	if ((kp = csc_cfg_kcb_alloc((int)dwSize)) == NULL) {
		smm_free(path);
		return NULL;
	}
	kp->key = kp->pool;
	kp->comment = kp->key + dwSize - 48;
	kp->update = (int)(dwSize - 48);	/* borrow it for a while */

	path[0] = TEXT('\0');
	for (i = 0; i < cfgd->idx; i++) {
		dwSize = MAX_PATH * sizeof(TCHAR);
		if (RegEnumKeyEx(cfgd->reg[i].hKey, cfgd->reg[i].i_key - 1, 
				szName, &dwSize, NULL, NULL, NULL, NULL) 
				== ERROR_SUCCESS) {
			if (i != 0) {
				lstrcat(path, TEXT("/"));
			}
			lstrcat(path, szName);
		}
	}
	//wprintf(TEXT("%s\n"), path);

	/* convert the UTF-16 string to UTF-8 and stored */
	WideCharToMultiByte(smm_codepage(), 0, path, -1,
			kp->key, kp->update, NULL, NULL);
	kp->update = 0;
	kp->flags = CFGF_TYPE_SET(kp->flags, CFGF_TYPE_DIR);

	sprintf(kp->comment, "## DIR=%lu KEY=%lu",
			RREF(cfgd).n_keys, RREF(cfgd).n_vals);
	smm_free(path);
	return kp;
}

static HKEY RegKeyFromDir(HKEY hRoot, char *dkey)
{
	HKEY	hKey;
	TCHAR	*wpath;
	char	*path;
	int	len;

	len = strlen(dkey) + 1;
	if ((wpath = smm_alloc(len * (sizeof(TCHAR) + 1))) == NULL) {
		return NULL;
	}
	path = (char*) &wpath[len];
	strcpy(path, dkey);
	str_substitue_char(path, -1, '/', '\\');
	MultiByteToWideChar(smm_codepage(), 0, path, -1, wpath, len);

	if (RegCreateKeyEx(hRoot, wpath, 0, NULL, 0, KEY_ALL_ACCESS, NULL, 
				&hKey, NULL) != ERROR_SUCCESS) {
		smm_free(wpath);
		return NULL;
	}
	smm_free(wpath);
	return hKey;
}

static DWORD RegWriteString(HKEY hKey, TCHAR *key, DWORD dwType, char *val)
{
	TCHAR	*wval;
	DWORD	dwErr;

	if (val == NULL) {
		return RegSetValueEx(hKey, key, 0, dwType, NULL, 0);
	}
	if (dwType == REG_MULTI_SZ) {
		char	*content;
		int	len = strlen(val) + 1;
		if ((wval = smm_alloc(len * (sizeof(TCHAR) + 1))) == NULL) {
			return ERROR_NOT_ENOUGH_MEMORY;
		}
		content = (char*) &wval[len];
		strcpy(content, val);
		str_substitue_char(content, -1, '~', 0);
		len = MultiByteToWideChar(smm_codepage(), 0, content, len, 
				wval, len);
		dwErr = RegSetValueEx(hKey, key, 0, dwType, 
				(void*) wval, len * sizeof(TCHAR));
		smm_free(wval);
	} else 	{
		if ((wval = smm_mbstowcs_alloc(val)) == NULL) {
			return ERROR_NOT_ENOUGH_MEMORY;
		}
		dwErr = RegSetValueEx(hKey, key, 0, dwType, 
			(void*)wval, (lstrlen(wval)+1) * sizeof(TCHAR));
		smm_free(wval);
	}
	return dwErr;
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
	/* Original code bugges here. According to MSDN, the size should be
	 * "specified by the lpName parameter, in characters". Therefore
	 * it should be multiplied by the size of TCHAR */
	dwSize = MAX_PATH * sizeof(TCHAR);
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
			dwSize = MAX_PATH * sizeof(TCHAR);
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
/*
	if (cfgd->hRootKey) {
		return smm_config_registry_read(cfgd->hRootKey);
	}
*/
static int smm_config_registry_read(HKEY hKey)
{
	struct	RegBuf	*rbuf;
	HKEY	hNextKey;
	TCHAR	szName[MAX_PATH];
	DWORD	i, dwSize, dwKeys;

	/* get number of keys and values */
	if ((rbuf = registry_buffer_alloc(hKey)) == NULL) {
		return -2;
	}
	for (i = 0; i < rbuf->n_vals; i++) {
		if (registry_buffer_read_value(hKey, i, rbuf) < 0) {
			break;
		}
		if (rbuf->ty_id == REG_SZ) {
			wprintf(TEXT("%s = %s  #%s\n"), 
					rbuf->name, rbuf->content, rbuf->type);
		} else {
			wprintf(TEXT("%s = %p  #%s\n"), 
					rbuf->name, rbuf->content, rbuf->type);
		}
	}

	dwKeys = rbuf->n_keys;
	smm_free(rbuf);

	for (i = 0; i < dwKeys; i++) {
		dwSize = MAX_PATH;	//FIXME confused by MSDN
		if (RegEnumKeyEx(hKey, i, szName, &dwSize, NULL, NULL, 
					NULL, NULL) != ERROR_SUCCESS) {
			continue;
		}
		if (RegOpenKeyEx(hKey, szName, 0, KEY_READ, &hNextKey) 
				== ERROR_SUCCESS) {
			wprintf(TEXT("Entering %s\n"), szName);
			smm_config_registry_read(hNextKey);
			RegCloseKey(hNextKey);
		}
	}
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
	rbuf->name   = (TCHAR*) rbuf->pool;
	rbuf->nm_len = (dwKeyLen > dwValNmlen ? dwKeyLen : dwValNmlen) + 1;
	rbuf->type   = &rbuf->name[rbuf->nm_len];
	rbuf->ty_len = 60;
	rbuf->content = (void*) &rbuf->type[rbuf->ty_len];
	rbuf->co_len = dwValLen + 1;
	wprintf(TEXT("registry_buffer_alloc: (%u/%u)(%u/%u)\n"),
				 dwKeys, dwKeyLen, dwVals, dwValNmlen);
	return rbuf;
}
#endif

