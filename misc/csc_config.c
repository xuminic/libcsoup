/*  csc_config.c - simple interface of configure file access
 
    This is a simplified configure file interface so it only supports
    a flat level configure file, which means the subkey structure is
    not supported. For example:

    [main]
    key A=value a
    key B=value b
    [subkey1]
    key A=value a
    key B=value b
    [subkey2]
    key A=value a
    key B=value b
    ...

    or

    key A=value a
    key B=value b
    key C=value c
    ...

    are all okey. But it doesn't support

    [main]
    key A=value a
    key B=value b
    [main/subkey1]
    key A=value a
    key B=value b
    [main/subkey1/subkey2]
    key A=value a
    key B=value b
    ...

    Anything starts with '#' are all treated as comments.

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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "libcsoup.h"

#define CFGF_CB_COMM	0	/* comment */
#define CFGF_CB_ROOT	1	/* root control block (only one) */
#define CFGF_CB_MAIN	2	/* main key control block (under root) */
#define CFGF_CB_KEY	3	/* common key */
#define CFGF_CB_PART	4	/* partial key */
#define CFGF_CB_MASK	0xf
#define CFGF_CB_SET(f,t)	((((KEYCB*)(f))->flags & ~CFGF_CB_MASK) | (t))
#define CFGF_CB_GET(f)		(((KEYCB*)(f))->flags & CFGF_CB_MASK)

#define CFGF_RDONLY	0x10
#define CFGF_UPDATED	0x20



typedef	struct	_KEYCB	{
	/* CSCLNK compatible head */
	void	*next;
	void	*prev;

	/* key and value are matching pairs. 
	 * If value is NULL, the key points to a main key and anchor points
	 * to the sub-key chain */
	char	*key;
	char	*value;
	char	*comment;
	CSCLNK	*anchor;
	char	store[4];	/* storing the boundary character */

	int	flags;
	int	size;
	char	pool[1];
} KEYCB;


static KEYCB *csc_cfg_kcb_alloc(int psize);
static int csc_cfg_kcb_fillup(KEYCB *kp);
static FILE *csc_cfg_open_configure(char *path, char *fname, int rdflag);
static int csc_cfg_read_next_line(FILE *fp, char *buf);
static int csc_cfg_write_next_line(FILE *fp, KEYCB *kp);


void *csc_cfg_open(char *path, char *filename, int rdflag)
{
	KEYCB	*root, *ckey, *kp;
	FILE	*fp;
	int	len;


	/* try to open the configure file. If the file doesn't exist 
	 * while it's the read/write mode, then create it */
	if ((fp = csc_cfg_open_configure(path, filename, rdflag)) == NULL) {
		return NULL;
	}

	/* create the root control block */
	if ((root = csc_cfg_kcb_alloc(strlen(path) + strlen(filename))) == NULL) {
		fclose(fp);
		return NULL;
	}

	/* initialize the root control block */
	root->flags = rdflag ? CFGF_RDONLY : 0;
	root->flags = CFGF_CB_SET(root, CFGF_CB_ROOT);
	root->key = root->pool;
	strcpy(root->key, path);
	root->value = root->pool + strlen(root->key) + 1;
	strcpy(root->value, filename);

	ckey = root;
	while (!feof(fp)) {
		if ((len = csc_cfg_read_next_line(fp, NULL)) <= 0) {
			break;
		}
		if ((kp = csc_cfg_kcb_alloc(len)) == NULL) {
			break;
		}
		csc_cfg_read_next_line(fp, kp->pool);

		csc_cfg_kcb_fillup(kp);
	
		if (CFGF_CB_GET(kp) == CFGF_CB_MAIN) {
			root->anchor = csc_cdl_insert_tail(root->anchor, 
					(CSCLNK*)kp);
			ckey = kp;
		} else {
			ckey->anchor = csc_cdl_insert_tail(ckey->anchor,
					(CSCLNK*)kp);
		}
	}
	fclose(fp);
	return root;
}

int csc_cfg_abort(void *cfg)
{
	KEYCB	*root, *ckey;
	CSCLNK	*p;

	root = cfg;
	for (p = root->anchor; p != NULL; p = csc_cdl_next(root->anchor, p)) {
		ckey = (KEYCB *)p;
		if (ckey->anchor) {
			csc_cdl_destroy(&ckey->anchor);
		}
	}
	csc_cdl_destroy(&root->anchor);
	return 0;
}

int csc_cfg_save(void *cfg)
{
	KEYCB	*mkey, *root = cfg;
	CSCLNK	*mp, *sp;
	FILE	*fp;

	if (root->flags & CFGF_RDONLY) {
		return SMM_ERR_ACCESS;
	}
	if ((fp = csc_cfg_open_configure(root->key, root->value,0)) == NULL) {
		return SMM_ERR_ACCESS;
	}

	for (mp = root->anchor; mp != NULL; mp = csc_cdl_next(root->anchor, mp)) {
		mkey = (KEYCB *)mp;
		csc_cfg_write_next_line(fp, mkey);

		if (CFGF_CB_GET(mkey) == CFGF_CB_MAIN) {
			for (sp = mkey->anchor; sp != NULL; sp = csc_cdl_next(mkey->anchor, sp)) {
				csc_cfg_write_next_line(fp, (KEYCB *)sp);
			}
		}
	}
	return SMM_ERR_NONE;
}

int csc_cfg_flush(void *cfg)
{
	KEYCB	*root = cfg;

	if (root->flags & CFGF_UPDATED) {
		root->flags &= ~CFGF_UPDATED;
		return csc_cfg_save(cfg);
	}
	return SMM_ERR_NONE;
}

int csc_cfg_close(void *cfg)
{
	csc_cfg_flush(cfg);
	csc_cfg_abort(cfg);
	return SMM_ERR_NONE;
}


char *csc_cfg_read(void *cfg, char *mkey, char *skey)
{
}

char *csc_cfg_copy(void *cfg, char *mkey, char *skey, int extra)
{
}

int csc_cfg_write(void *cfg, char *mkey, char *skey, char *value)
{
}

int csc_cfg_read_long(void *cfg, char *mkey, char *skey, long *val)
{
}

int csc_cfg_write_long(void *cfg, char *mkey, char *skey, long val)
{
}

int csc_cfg_read_longlong(void *cfg, char *mkey, char *skey, long long *val)
{       
}

int csc_cfg_write_longlong(void *cfg, char *mkey, char *skey, long long val)
{
}

void *csc_cfg_copy_bin(void *cfg, char *mkey, char *skey, int *bsize)
{
}

int csc_cfg_save_bin(void *cfg, char *mkey, char *skey, void *bin, int bsize)
{
}

int csc_cfg_dump_contrl(void *cfg)
{
	KEYCB	*kp = cfg;

	switch (CFGF_CB_GET(kp)) {
	case CFGF_CB_COMM:
		*(kp->comment) = kp->store[1];	/* restore the content */
		slogz("COMM: %s", kp->comment);
		*(kp->comment) = 0;
		break;
	case CFGF_CB_MAIN:
		*(kp->comment) = kp->store[1];	/* restore the content */
		if (kp->value) {
			slogz("MAIN: %s | %s", kp->key, kp->value + 1);
		} else {
			slogz("MAIN: %s", kp->key);
		}
		*(kp->comment) = 0;
		break;
	case CFGF_CB_KEY:
		*(kp->comment) = kp->store[1];	/* restore the content */
		slogz("KEYP: %s = %s", kp->key, kp->value + 1);
		*(kp->comment) = 0;
		break;
	case CFGF_CB_PART:
		*(kp->comment) = kp->store[1];	/* restore the content */
		slogz("PART: %s", kp->key);
		*(kp->comment) = 0;
		break;
	case CFGF_CB_ROOT:
		slogz("ROOT: %s/%s\n", kp->key, kp->value);
		break;
	default:
		slogz("BOOM!\n");
		break;
	}
	return 0;
}

int csc_cfg_dump(void *cfg, char *mkey)
{
	KEYCB	*root, *ckey;
	CSCLNK	*p, *k;

	csc_cfg_dump_contrl(cfg);

	root = cfg;
	for (p = root->anchor; p != NULL; p = csc_cdl_next(root->anchor, p)) {
		ckey = (KEYCB *)p;
		csc_cfg_dump_contrl(ckey);
		if (CFGF_CB_GET(ckey) == CFGF_CB_MAIN) {
			for (k = ckey->anchor; k != NULL; k = csc_cdl_next(ckey->anchor, k)) {
				csc_cfg_dump_contrl(k);
			}
		}
	}
	return 0;
}


static KEYCB *csc_cfg_kcb_alloc(int psize)
{
	KEYCB	*kp;

	psize += sizeof(KEYCB) + 4;
	psize = (psize + 3) / 4 * 4;	/* round up to 32-bit boundry */
	if ((kp = malloc(psize)) == NULL) {
		return NULL;
	}

	memset(kp, 0, psize);
	kp->size   = psize;
	return kp;
}


/* tricky part is, after this call, the key will point to the start address 
 * of it contents. however the value and comment will point to  a '\0', 
 * which content has been saved in store[] */
static int csc_cfg_kcb_fillup(KEYCB *kp)
{
	int	i;

	/* first scan to locate the comments */
	for (i = 0; kp->pool[i]; i++) {
		if ((kp->pool[i] == '#') || (kp->pool[i] == '\n')) {
			break;
		}
	}
	/* 'i' should be indicating either '#', '\n' or '\0' now */
	for (i--; i >= 0; i--) {
		if (!isspace(kp->pool[i])) {
			break;
		}
	}

	i++;
	kp->store[1] = kp->pool[i];
	kp->pool[i] = 0;
	kp->comment = &kp->pool[i];	/* this is NOT a bug */
	kp->flags = CFGF_CB_SET(kp, CFGF_CB_COMM);

	if (kp->pool[0] == 0) {		/* empty line is kind of comments */
		return CFGF_CB_COMM;
	}

	/* second scan to locate the value */
	for (i = 0; kp->pool[i]; i++) {
		if (kp->pool[i] == '=') {
			break;
		}
	}
	
	/* it could be a partial key or a main key if no '=' appear */
	kp->key = kp->pool;
	kp->flags = CFGF_CB_SET(kp, CFGF_CB_PART);

	if (kp->pool[i] == '=') {
		/* otherwise it could be a common key or a main key */
		kp->store[0] = kp->pool[i];
		kp->pool[i] = 0;
		kp->value = &kp->pool[i];	/* this is NOT a bug */
		kp->flags = CFGF_CB_SET(kp, CFGF_CB_KEY);
	}

	/* another scan to decide if it is a main key */
	for (i = 0; kp->key[i]; i++) {
		if (kp->key[i] == '[') {
			kp->flags = CFGF_CB_SET(kp, CFGF_CB_MAIN);
			break;
		}
	}
	return CFGF_CB_GET(kp);
}

static FILE *csc_cfg_open_configure(char *path, char *fname, int rdflag)
{
	FILE	*fp;

	if (rdflag) {
		if (smm_chdir(path) != SMM_ERR_NONE) {
			perror("smm_chdir");
			return NULL;	/* path doesn't exist */
		}
		if ((fp = fopen(fname, "r")) == NULL) {
			perror("fopen");
			return NULL;	/* file doesn't exist */
		}
	} else {
		if (smm_chdir(path) != SMM_ERR_NONE) {
			printf("FIXME! create %s\n", path);
			return NULL;
		}
		if (smm_chdir(path) != SMM_ERR_NONE) {
			return NULL;	/* permittion denied */
		}
		if ((fp = fopen(fname, "r+")) == NULL) {
			fp = fopen(fname, "w+");
		}
		if (fp == NULL) {
			return NULL;	/* permittion denied */
		}
	}
	return fp;
}

static int csc_cfg_read_next_line(FILE *fp, char *buf)
{
	int	amnt, cpos, ch;

	amnt = 0;
	cpos = ftell(fp);
	while ((ch = fgetc(fp)) != EOF) {
		if (buf) {
			*buf++ = (char) ch;
		}
		amnt++;
		if (ch == '\n') {
			break;
		}
	}
	if (buf == NULL) {	/* rewind to the start position */
		fseek(fp, cpos, SEEK_SET);
	} else {
		*buf++ = 0;
	}
	return amnt;
}

static int csc_cfg_write_next_line(FILE *fp, KEYCB *kp)
{
	if (kp->value == NULL) {
		fputs(kp->key, fp);
	} else {
		*(kp->value) = kp->store[0];
		fputs(kp->key, fp);
		*(kp->value) = 0;
	}
	
	*(kp->comment) = kp->store[1];
	fputs(kp->comment, fp);
	*(kp->comment) = 0;
	return 0;
}

