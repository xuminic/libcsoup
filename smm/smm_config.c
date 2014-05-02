
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

#include "libcsoup.h"

#ifdef	CFG_WIN32_API
static HKEY RegCreateMainKey(HKEY hRootKey, char *mkey);
static HKEY RegOpenMainKey(HKEY hRootKey, char *mkey);
static HKEY RegCreatePath(int sysroot, char *path);
static BOOL RegDelnodeRecurse(HKEY hKeyRoot, LPTSTR lpSubKey);

void *smm_config_open(int sysroot, char *path, char *fname)
{
	HKEY	hRootKey, hPathKey;
	LONG	rc;
	TCHAR	*wkey;

	if ((hPathKey = RegCreatePath(sysroot, path)) == NULL) {
		return NULL;
	}

	if ((wkey = smm_mbstowcs(fname)) == NULL) {
		smm_errno_update(SMM_ERR_LOWMEM);
		RegCloseKey(hPathKey);
		return NULL;
	}

	rc = RegCreateKeyEx(hPathKey, wkey, 0, NULL, 0,
			KEY_ALL_ACCESS, NULL, &hRootKey, NULL);
	
	free(wkey);
	RegCloseKey(hPathKey);
	
	if (rc == ERROR_SUCCESS) { 
		return hRootKey;
	}
	return NULL;
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

	if ((hPathKey = RegCreatePath(sysroot, path)) == NULL) {
		return smm_errno_update(SMM_ERR_ACCESS);
	}

	/* fabricate the key name */
	if ((wkey = malloc(MAX_PATH * 2 * sizeof(TCHAR))) == NULL) {
		RegCloseKey(hPathKey);
		return smm_errno_update(SMM_ERR_LOWMEM);
	}
	MultiByteToWideChar(smm_codepage(), 0, fname, -1, wkey, MAX_PATH - 1);

	rcode = RegDelnodeRecurse(hPathKey, wkey);

	RegCloseKey(hPathKey);
	free(wkey);
       
	if (rcode == TRUE) {
		return smm_errno_update(SMM_ERR_NONE);
	}
	return smm_errno_update(SMM_ERR_ACCESS);
}

//FIXME: memory hole
long smm_config_read(void *cfg, char *mkey, char *skey, char *buf, int blen)
{
}

char *smm_config_copy(void *cfg, char *mkey, char *skey)
{
	HKEY	hMainKey;
	LONG	rc;
	DWORD	slen;
	TCHAR	*wkey, *wval;
	char	*rtval;

	if ((wkey = smm_mbstowcs(skey)) == NULL) {
		smm_errno_update(SMM_ERR_LOWMEM);
		return NULL;
	}
	if ((hMainKey = RegOpenMainKey(cfg, mkey)) == NULL) {
		free(wkey);
		smm_errno_update(SMM_ERR_ACCESS);
		return NULL;
	}

	rtval = NULL;
	rc = RegQueryValueEx(hMainKey, wkey, NULL, NULL, NULL, &slen);
	if (rc == ERROR_SUCCESS) {
		if ((wval = malloc(slen)) != NULL) {
			rc = RegQueryValueEx(hMainKey, wkey, NULL, NULL,
					(BYTE*) wval, &slen);
			if (rc == ERROR_SUCCESS) {
				rtval = smm_wcstombs(wval);
			}
			free(wval);
		}
	}
	if (hMainKey != cfg) {
		RegCloseKey(hMainKey);
	}
	free(wkey);

	if (rc == ERROR_SUCCESS) {
		smm_errno_update(SMM_ERR_NONE);
		return rtval;
	}
	smm_errno_update(SMM_ERR_ACCESS);
	return rtval;
}

int smm_config_write(void *cfg, char *mkey, char *skey, char *value)
{
	HKEY	hMainKey;
	LONG	rc;
	TCHAR	*wkey, *wval;

	if ((wkey = smm_mbstowcs(skey)) == NULL) {
		return smm_errno_update(SMM_ERR_LOWMEM);
	}
	if ((wval = smm_mbstowcs(value)) == NULL) {
		free(wkey);
		return smm_errno_update(SMM_ERR_LOWMEM);
	}
	if ((hMainKey = RegCreateMainKey(cfg, mkey)) == NULL) {
		free(wval);
		free(wkey);
		return smm_errno_update(SMM_ERR_NULL);
	}

	rc = RegSetValueEx(hMainKey, wkey, 0, REG_SZ, (const BYTE *) wval, 
			(lstrlen(wval)+1) * sizeof(TCHAR));

	if (hMainKey != cfg) {
		RegCloseKey(hMainKey);
	}
	free(wval);
	free(wkey);

	if (rc == ERROR_SUCCESS) {
		return smm_errno_update(SMM_ERR_NONE);
	}
	return smm_errno_update(SMM_ERR_ACCESS);

}

int smm_config_read_long(void *cfg, char *mkey, char *skey, long *val)
{
	HKEY	hMainKey;
	LONG	rc;
	DWORD	vlen;
	TCHAR	*wkey;

	if ((wkey = smm_mbstowcs(skey)) == NULL) {
		return smm_errno_update(SMM_ERR_LOWMEM);
	}
	if ((hMainKey = RegOpenMainKey(cfg, mkey)) == NULL) {
		free(wkey);
		return smm_errno_update(SMM_ERR_ACCESS);
	}

	vlen = sizeof(long);
	rc = RegQueryValueEx(hMainKey, wkey, NULL, NULL, (BYTE*) val, &vlen);

	if (hMainKey != cfg) {
		RegCloseKey(hMainKey);
	}
	free(wkey);

	if (rc == ERROR_SUCCESS) {
		return smm_errno_update(SMM_ERR_NONE);
	}
	return smm_errno_update(SMM_ERR_ACCESS);
}

int smm_config_write_long(void *cfg, char *mkey, char *skey, long val)
{
	HKEY	hMainKey;
	LONG	rc;
	TCHAR	*wkey;

	if ((wkey = smm_mbstowcs(skey)) == NULL) {
		return smm_errno_update(SMM_ERR_LOWMEM);
	}
	if ((hMainKey = RegCreateMainKey(cfg, mkey)) == NULL) {
		free(wkey);
		return smm_errno_update(SMM_ERR_NULL);
	}

	rc = RegSetValueEx(hMainKey, wkey, 0, REG_DWORD, 
			(const BYTE *) &val, sizeof(long));

	if (hMainKey != cfg) {
		RegCloseKey(hMainKey);
	}
	free(wkey);

	if (rc == ERROR_SUCCESS) {
		return smm_errno_update(SMM_ERR_NONE);
	}
	return smm_errno_update(SMM_ERR_ACCESS);
}

static HKEY RegCreateMainKey(HKEY hRootKey, char *mkey)
{
	HKEY	hMainKey;
	TCHAR	*wkey;
	LONG	rc;

	if (mkey == NULL) {
		return hRootKey;
	}
	if ((wkey = smm_mbstowcs(mkey)) == NULL) {
		smm_errno_update(SMM_ERR_LOWMEM);
		return NULL;
	}

	rc = RegCreateKeyEx(hRootKey, wkey, 0, NULL, 0, KEY_ALL_ACCESS, 
			NULL, &hMainKey, NULL);

	free(wkey);			
	if (rc == ERROR_SUCCESS) {
		smm_errno_update(SMM_ERR_NONE);
		return hMainKey;
	}
	smm_errno_update(SMM_ERR_ACCESS);
	return NULL;
}

static HKEY RegOpenMainKey(HKEY hRootKey, char *mkey)
{
	HKEY	hMainKey;
	TCHAR	*wkey;
	LONG	rc;

	if (mkey == NULL) {
		return hRootKey;
	}
	if ((wkey = smm_mbstowcs(mkey)) == NULL) {
		smm_errno_update(SMM_ERR_LOWMEM);
		return NULL;
	}

	rc = RegOpenKeyEx(hRootKey, wkey, 0, KEY_READ, &hMainKey);

	free(wkey);			
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

	switch (sysroot) {
	case SMM_CFGROOT_USER:
		hSysKey = HKEY_CURRENT_USER;
		pkey = csc_strcpy_alloc("CONSOLE\\", strlen(path) + 4);
		break;
	case SMM_CFGROOT_SYSTEM:
		hSysKey = HKEY_LOCAL_MACHINE;
		pkey = csc_strcpy_alloc("SOFTWARE\\", strlen(path) + 4);
		break;
	default:	/* SMM_CFGROOT_DESKTOP */
		hSysKey = HKEY_CURRENT_USER;
		pkey = csc_strcpy_alloc("SOFTWARE\\", strlen(path) + 4);
		break;
	}
	if (pkey == NULL) {
		smm_errno_update(SMM_ERR_LOWMEM);
		return NULL;
	}
	strcat(pkey, path);

	if ((wkey = smm_mbstowcs(pkey)) == NULL) {
		free(pkey);
		smm_errno_update(SMM_ERR_LOWMEM);
		return NULL;
	}

	/* The good thing of RegCreateKeyEx() is that it can create a string
	 * of subkeys without creating one by one. For example: A\\B\\C */
	rc = RegCreateKeyEx(hSysKey, wkey, 0, NULL, 0,
			KEY_ALL_ACCESS, NULL, &hPathKey, NULL);

	free(wkey);
	free(pkey);

	if (rc == ERROR_SUCCESS) { 
		return hPathKey;
	}
	return NULL;
}


/* This code was picked form MSDN, a little modified */
static BOOL RegDelnodeRecurse(HKEY hKeyRoot, LPTSTR lpSubKey)
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
			//StringCchCopy (lpEnd, MAX_PATH*2, szName);
			lstrcpy(lpEnd, szName);
			if (!RegDelnodeRecurse(hKeyRoot, lpSubKey)) {
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

void *smm_config_open(int sysroot, char *path, char *fname)
{
}

int smm_config_flush(void *cfg)
{
}

int smm_config_close(void *cfg)
{
}

int smm_config_delete(void *cfg)
{
}

char *smm_config_read(void *cfg, char *mkey, char *skey)
{
}

int smm_config_write(void *cfg, char *mkey, char *skey, char *value)
{
}

int smm_config_read_long(void *cfg, char *mkey, char *skey, long *val)
{
}

int smm_config_write_long(void *cfg, char *mkey, char *skey, long val)
{
}

#endif

