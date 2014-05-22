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

#define CFGF_TYPE_UNKWN	0	/* comment */
#define CFGF_TYPE_ROOT	1	/* root control block (only one) */
#define CFGF_TYPE_MAIN	2	/* main key control block (under root) */
#define CFGF_TYPE_KEY	3	/* common key */
#define CFGF_TYPE_PART	4	/* partial key */
#define CFGF_TYPE_COMM	5	/* comment */
#define CFGF_TYPE_MASK	0xf
#define CFGF_TYPE_SET(f,n)	(((f) & ~CFGF_TYPE_MASK) | (n))
#define CFGF_TYPE_GET(f)	((f) & CFGF_TYPE_MASK)

#define CFGF_MODE_MASK	0xf0	/* mask of CSC_CFG_RDONLY,CSC_CFG_RDWR,... */
#define CFGF_MODE_SET(f,n)	(((f) & ~CFGF_MODE_MASK) | (n))
#define CFGF_MODE_GET(f)	((f) & CFGF_MODE_MASK)


#define	CFGF_BLOCK_WID		48
#define CFGF_BLOCK_MAGIC	"BINARY"


/* KEYCB extension for the root structure */
struct	KEYROOT	{
	KEYCB	*mkey;	/* latest accessed main key */
	KEYCB	*skey;	/* latest accessed sub key */
	int	mode;
	char	pool[1];
};

static KEYCB *csc_cfg_kcb_alloc(int psize);
static KEYCB *csc_cfg_root_alloc(char *path, char *filename, int mode);
static KEYCB *csc_cfg_kcb_create(int mk, char *skey, char *value, char *comm);
static int csc_cfg_kcb_fillup(KEYCB *kp);
static KEYCB *csc_cfg_find_key(KEYCB *cfg, char *key, int type);
static int csc_cfg_access_setup(KEYCB *cfg, KEYCB *mkey, KEYCB *kcb);
static KEYCB *csc_cfg_access_update(KEYCB *cfg, int type);
static FILE *_smm_config_open(char *path, char *fname, int mode);
static int _smm_config_read(FILE *fp, KEYCB *kp);
static int _smm_config_write(FILE *fp, KEYCB *kp);
static int csc_cfg_strcmp(char *sour, char *dest);
static int csc_cfg_binary_to_hex(char *src, int slen, char *buf, int blen);
static int csc_cfg_hex_to_binary(char *src, char *buf, int blen);

static inline KEYCB *CFGF_GETOBJ(CSCLNK *self)
{
	KEYCB   *kcb = (KEYCB *) &self[1];

	switch (CFGF_TYPE_GET(kcb->flags)) {
	case CFGF_TYPE_ROOT:
	case CFGF_TYPE_MAIN:
	case CFGF_TYPE_KEY:
	case CFGF_TYPE_PART:
	case CFGF_TYPE_COMM:
		return kcb;
	}
	slogz("CFGF_GETOBJ: unknown object\n");
	return NULL;
}

KEYCB *csc_cfg_open(char *path, char *filename, int mode)
{
	KEYCB	*root, *ckey, *kp;
	FILE	*fp;
	int	len;

	/* try to open the configure file. If the file doesn't exist 
	 * while it's the read/write mode, then create it */
	if ((fp = _smm_config_open(path, filename, mode)) == NULL) {
		return NULL;
	}

	/* create the root control block */
	if ((root = csc_cfg_root_alloc(path, filename, mode)) == NULL) {
		fclose(fp);
		return NULL;
	}

	ckey = root;
	while (!feof(fp)) {
		if ((len = _smm_config_read(fp, NULL)) <= 0) {
			break;
		}
		if ((kp = csc_cfg_kcb_alloc(len)) == NULL) {
			break;
		}
		_smm_config_read(fp, kp);

		csc_cfg_kcb_fillup(kp);
	
		if (CFGF_TYPE_GET(kp->flags) == CFGF_TYPE_MAIN) {
			csc_cdl_list_insert(&root->anchor, 
					kp->self, CSC_CDLL_TAIL);
			ckey = kp;
		} else {
			csc_cdl_list_insert(&ckey->anchor, 
					kp->self, CSC_CDLL_TAIL);
		}
	}
	fclose(fp);
	return root;
}

int csc_cfg_abort(KEYCB *cfg)
{
	KEYCB	*ckey;
	CSCLNK	*p;

	if (cfg == NULL) {
		return SMM_ERR_NULL;
	}
	for (p = cfg->anchor; p; p = csc_cdl_next(cfg->anchor, p)) {
		if ((ckey = CFGF_GETOBJ(p)) == NULL) {
			break;
		}
		if (ckey->anchor) {
			csc_cdl_list_destroy(&ckey->anchor);
		}
	}
	csc_cdl_list_destroy(&cfg->anchor);
	return SMM_ERR_NONE;
}

int csc_cfg_save(KEYCB *cfg)
{
	KEYCB	*mkey;
	CSCLNK	*mp, *sp;
	FILE	*fp;

	if (cfg == NULL) {
		return SMM_ERR_NULL;
	}
	if (CFGF_TYPE_GET(cfg->flags) != CFGF_TYPE_ROOT) {
		return SMM_ERR_ACCESS;
	}
	if (CFGF_MODE_GET(cfg->flags) == CSC_CFG_RDONLY) {
		return SMM_ERR_ACCESS;
	}

	fp = _smm_config_open(cfg->key, cfg->value, CSC_CFG_RWC);
	if (fp == NULL) {
		return SMM_ERR_ACCESS;
	}

	for (mp = cfg->anchor; mp; mp = csc_cdl_next(cfg->anchor, mp)) {
		if ((mkey = CFGF_GETOBJ(mp)) == NULL) {
			break;
		}
		if (CFGF_TYPE_GET(mkey->flags) != CFGF_TYPE_MAIN) {
			_smm_config_write(fp, mkey);
		}
	}

	for (mp = cfg->anchor; mp; mp = csc_cdl_next(cfg->anchor, mp)) {
		if ((mkey = CFGF_GETOBJ(mp)) == NULL) {
			break;
		}
		if (CFGF_TYPE_GET(mkey->flags) != CFGF_TYPE_MAIN) {
			continue;
		}

		_smm_config_write(fp, mkey);
		for (sp = mkey->anchor; sp; 
				sp = csc_cdl_next(mkey->anchor, sp)) {
			_smm_config_write(fp, CFGF_GETOBJ(sp));
		}
	}
	fclose(fp);
	cfg->update = 0;	/* reset the update counter */
	return SMM_ERR_NONE;
}

int csc_cfg_saveas(KEYCB *cfg, char *path, char *filename)
{
	KEYCB	*newc;
	CSCLNK	*tmp;
	int	rc;

	if (cfg == NULL) {
		return SMM_ERR_NULL;
	}
	if ((newc = csc_cfg_open(path, filename, 0)) == NULL) {
		return SMM_ERR_OPEN;
	}
	tmp = newc->anchor;
	newc->anchor = cfg->anchor;
	newc->update = cfg->update + 1;
	cfg->update  = 0;

	if ((rc = csc_cfg_save(newc)) != SMM_ERR_NONE) {
		return rc;
	}
	newc->anchor = tmp;
	return csc_cfg_close(newc);
}

int csc_cfg_flush(KEYCB *cfg)
{
	if (cfg == NULL) {
		return SMM_ERR_NULL;
	}
	if (cfg->update) {
		return csc_cfg_save(cfg);
	}
	return SMM_ERR_NONE;
}

int csc_cfg_close(KEYCB *cfg)
{
	csc_cfg_flush(cfg);
	csc_cfg_abort(cfg);
	return SMM_ERR_NONE;
}


char *csc_cfg_read(KEYCB *cfg, char *mkey, char *skey)
{
	KEYCB	*mcb, *scb;

	if (cfg == NULL) {
		return NULL;
	}
	if ((mcb = csc_cfg_find_key(cfg, mkey, CFGF_TYPE_MAIN)) == NULL) {
		return NULL;
	}
	if ((scb = csc_cfg_find_key(mcb, skey, CFGF_TYPE_KEY)) == NULL) {
		return NULL;
	}
	csc_cfg_access_setup(cfg, mcb, scb);
	return scb->value;
}

char *csc_cfg_read_first(KEYCB *cfg, char *mkey, char **key)
{
	struct	KEYROOT	*rext;

	if (csc_cfg_read(cfg, mkey, NULL) == NULL) {
		return NULL;
	}

	rext = (struct KEYROOT *)cfg->pool;
	if (key) {
		*key = rext->skey->key;
	}
	return rext->skey->value;
}

char *csc_cfg_read_next(KEYCB *cfg, char **key)
{
	KEYCB	*scb;

	if ((scb = csc_cfg_access_update(cfg, CFGF_TYPE_KEY)) == NULL) {
		return NULL;
	}
	if (key) {
		*key = scb->key;
	}
	return scb->value;
}

char *csc_cfg_copy(KEYCB *cfg, char *mkey, char *skey, int extra)
{
	char	*value;

	if ((value = csc_cfg_read(cfg, mkey, skey)) == NULL) {
		return NULL;
	}
	return csc_strcpy_alloc(value, extra);
}

int csc_cfg_write(KEYCB *cfg, char *mkey, char *skey, char *value)
{
	KEYCB	*mcb, *scb, *ncb;
	int	olen, nlen;

	if ((value == NULL) || (skey == NULL) || (cfg == NULL)) {
		return SMM_ERR_NULL;
	}

	if ((mcb = csc_cfg_find_key(cfg, mkey, CFGF_TYPE_MAIN)) == NULL) {
		/* if the main key doesn't exist, create a new key and
		 * insert to the tail */
		if ((mcb = csc_cfg_kcb_create(1, mkey, NULL, NULL)) == NULL) {
			return SMM_ERR_NULL;
		}
		cfg->update++;
		csc_cdl_list_insert(&cfg->anchor, mcb->self, CSC_CDLL_TAIL);
	}
	if ((scb = csc_cfg_find_key(mcb, skey, CFGF_TYPE_KEY)) == NULL) {
		/* if the key doesn't exist, it'll create a new key and
		 * insert to the tail. To tail shows a more natural way
		 * of display. But there is no white space line in the head.
		 */
		if ((ncb = csc_cfg_kcb_create(0, skey, value, NULL)) != NULL) {
			ncb->update++;
			mcb->update++;
			cfg->update++;
			csc_cdl_list_insert(&mcb->anchor, 
					ncb->self, CSC_CDLL_TAIL);
			csc_cfg_access_setup(cfg, mcb, ncb);
		}
		return SMM_ERR_NONE;
	}

	csc_cfg_access_setup(cfg, mcb, scb);
	olen = strlen(scb->value);
	nlen = strlen(value);
	if (!csc_cfg_strcmp(value, scb->value)) {
		/* same value so do nothing */
		return SMM_ERR_NONE;
	} else if (nlen <= olen) {
		/* If the new value is smaller than or same to the original 
		 * value, it'll replace the original value directly. */
		strcpy(scb->value, value);
	} else {
		/* If the new value is larger than the original value, it'll
		 * create a new key to replace the old key structure */
		ncb = csc_cfg_kcb_create(0, skey, value, scb->comment);
		if (ncb == NULL) {
			return SMM_ERR_LOWMEM;
		}
		ncb->update = scb->update;
		csc_cdl_insert_after(scb->self, ncb->self);
		csc_cdl_list_free(&mcb->anchor, scb->self);
		scb = ncb;
	}
	scb->update++;
	if (scb->update == 1) {
		mcb->update++;
		cfg->update++;
	}
	return SMM_ERR_NONE;
}

int csc_cfg_read_long(KEYCB *cfg, char *mkey, char *skey, long *val)
{
	char 	*value;

	if ((value = csc_cfg_read(cfg, mkey, skey)) == NULL) {
		return SMM_ERR_NULL;
	}
	if (val) {
		*val = strtol(value, NULL, 0);
	}
	return SMM_ERR_NONE;
}

int csc_cfg_write_long(KEYCB *cfg, char *mkey, char *skey, long val)
{
	char	buf[32];

	sprintf(buf, "%ld", val);
	return csc_cfg_write(cfg, mkey, skey, buf);
}

int csc_cfg_read_longlong(KEYCB *cfg, char *mkey, char *skey, long long *val)
{ 
	char	*value;

	if ((value = csc_cfg_read(cfg, mkey, skey)) == NULL) {
		return SMM_ERR_NULL;
	}
	if (val) {
		*val = strtoll(value, NULL, 0);
	}
	return SMM_ERR_NONE;
}

int csc_cfg_write_longlong(KEYCB *cfg, char *mkey, char *skey, long long val)
{
	char	buf[32];

	SMM_SPRINT(buf, "%lld", val);
	return csc_cfg_write(cfg, mkey, skey, buf);
}

int csc_cfg_read_bin(KEYCB *cfg, char *mkey, char *skey, char *buf, int blen)
{
	char	*src, *value;
	int	len;

	if ((value = csc_cfg_read(cfg, mkey, skey)) == NULL) {
		return SMM_ERR_NULL;
	}

	src = csc_strbody(value, NULL);	/* strip the white space */
	len = csc_cfg_hex_to_binary(src, buf, blen);
	return len;
}

void *csc_cfg_copy_bin(KEYCB *cfg, char *mkey, char *skey, int *bsize)
{
	char	*buf;
	int	len;

	if ((len = csc_cfg_read_bin(cfg, mkey, skey, NULL, 0)) <= 0) {
		return NULL;
	}
	if ((buf = smm_alloc(len)) == NULL) {
		return NULL;
	}
	if (bsize) {
		*bsize = len;
	}
	csc_cfg_read_bin(cfg, mkey, skey, buf, len);
	return buf;
}

int csc_cfg_write_bin(KEYCB *cfg, char *mkey, char *skey, void *bin, int bsize)
{
	char	*buf;

	if (!bin || !bsize) {
		return SMM_ERR_NULL;
	}
	if ((buf = smm_alloc((bsize+1)*2)) == NULL) {
		return SMM_ERR_LOWMEM;
	}
	csc_cfg_binary_to_hex(bin, bsize, buf, (bsize+1)*2);
	bsize = csc_cfg_write(cfg, mkey, skey, buf);
	smm_free(buf);
	return bsize;
}

int csc_cfg_read_block(KEYCB *cfg, char *mkey, char *buf, int blen)
{
	KEYCB	*mcb, *scb;
	char	*src, tmp[256];
	int	len, amnt;

	if ((mcb = csc_cfg_find_key(cfg, mkey, CFGF_TYPE_MAIN)) == NULL) {
		return -1;
	}
	if (strcmp(mcb->value, CFGF_BLOCK_MAGIC)) {
		return -2;
	}
	if ((scb = csc_cfg_find_key(mcb, NULL, CFGF_TYPE_PART)) == NULL) {
		return 0;	/* empty block */
	}
	csc_cfg_access_setup(cfg, mcb, scb);

	amnt = 0;
	do {
		/* convert ASC to binary */
		src = csc_strbody(scb->key, NULL); /* strip the space */
		len = csc_cfg_hex_to_binary(src, tmp, sizeof(tmp));

		/* store to the buffer */
		if (blen && (blen < (amnt + len))) {
			break;
		}
		if (buf) {
			memcpy(buf + amnt, tmp, len);
		}
		amnt += len;
	} while ((scb = csc_cfg_access_update(cfg, CFGF_TYPE_PART)) != NULL);
	return amnt;
}

void *csc_cfg_copy_block(KEYCB *cfg, char *mkey, int *bsize)
{
	char	*buf;
	int	len;

	if ((len = csc_cfg_read_block(cfg, mkey, NULL, 0)) <= 0) {
		return NULL;
	}
	if ((buf = smm_alloc(len)) == NULL) {
		return NULL;
	}
	csc_cfg_read_block(cfg, mkey, buf, len);
	if (bsize) {
		*bsize = len;
	}
	return buf;
}

int csc_cfg_write_block(KEYCB *cfg, char *mkey, void *bin, int bsize)
{
	KEYCB	*mcb, *scb;
	char	*src, tmp[256];
	int	len, rest;

	if (!bin || !bsize || !cfg) {
		return SMM_ERR_NULL;
	}
	if ((mcb = csc_cfg_find_key(cfg, mkey, CFGF_TYPE_MAIN)) == NULL) {
		/* if the main key doesn't exist, create a new key and
		 * insert to the tail */
		mcb = csc_cfg_kcb_create(1, mkey, CFGF_BLOCK_MAGIC, NULL);
		if (mcb == NULL) {
			return SMM_ERR_LOWMEM;
		}
		csc_cdl_list_insert(&cfg->anchor, mcb->self, CSC_CDLL_TAIL);
	} else  if (strcmp(mcb->value, CFGF_BLOCK_MAGIC)) {
		/* you can't write blocks into other types of main keys */
		return SMM_ERR_ACCESS;
	} else {
		/* if the main key does exist, destory its contents */
		csc_cdl_list_destroy(&mcb->anchor);
		mcb->update = 0;
	}
	cfg->update++;

	for (src = bin, rest = bsize; rest > 0; rest -= CFGF_BLOCK_WID) {
		/* convert the binary to hex codes */
		len = rest > CFGF_BLOCK_WID ? CFGF_BLOCK_WID : rest;
		csc_cfg_binary_to_hex(src, len, tmp, sizeof(tmp));
		src += len;

		/* insert to the tail */
		if ((scb = csc_cfg_kcb_create(0, tmp, NULL, NULL)) == NULL) {
			return SMM_ERR_LOWMEM;
		}
		scb->update++;
		mcb->update++;
		csc_cdl_list_insert(&mcb->anchor, scb->self, CSC_CDLL_TAIL);
		csc_cfg_access_setup(cfg, mcb, scb);
	}
	return bsize;
}

int csc_cfg_dump_kcb(KEYCB *kp)
{
	switch (CFGF_TYPE_GET(kp->flags)) {
	case CFGF_TYPE_COMM:
		slogz("COMM_%d: %s\n", kp->update, kp->comment);
		break;
	case CFGF_TYPE_MAIN:
		if (kp->value) {
			slogz("MAIN_%d: [%s] = %s %s\n", kp->update, 
					kp->key, kp->value, kp->comment);
		} else {
			slogz("MAIN_%d: [%s] %s\n", kp->update, kp->key);
		}
		break;
	case CFGF_TYPE_KEY:
		slogz("KEYP_%d: %s = %s %s\n", kp->update, 
				kp->key, kp->value, kp->comment);
		break;
	case CFGF_TYPE_PART:
		slogz("PART_%d: %s %s %s\n", kp->update,
				kp->key, kp->value, kp->comment);
		break;
	case CFGF_TYPE_ROOT:
		slogz("ROOT: %s/%s\n", kp->key, kp->value);
		break;
	default:
		slogz("BOOM!\n");
		return 0;
	}
	return 0;
}

int csc_cfg_dump(KEYCB *cfg, char *mkey)
{
	KEYCB	*ckey;
	CSCLNK	*p, *k;

	csc_cfg_dump_kcb(cfg);

	if (mkey == NULL) {
		for (p = cfg->anchor; p; p = csc_cdl_next(cfg->anchor, p)) {
			ckey = CFGF_GETOBJ(p);
			if (CFGF_TYPE_GET(ckey->flags) != CFGF_TYPE_MAIN) {
				csc_cfg_dump_kcb(ckey);
			}
		}
	}

	for (p = cfg->anchor; p; p = csc_cdl_next(cfg->anchor, p)) {
		ckey = CFGF_GETOBJ(p);
		if (mkey && strcmp(ckey->key, mkey)) {
			continue;
		}
		if (CFGF_TYPE_GET(ckey->flags) != CFGF_TYPE_MAIN) {
			continue;
		}

		csc_cfg_dump_kcb(ckey);
		for (k = ckey->anchor; k; k = csc_cdl_next(ckey->anchor, k)) {
			csc_cfg_dump_kcb(CFGF_GETOBJ(k));
		}
	}
	return 0;
}


static KEYCB *csc_cfg_kcb_alloc(int psize)
{
	CSCLNK	*node;
	KEYCB	*kp;

	psize += sizeof(KEYCB) + 8;	/* reserved 8 bytes */
	psize = (psize + 3) / 4 * 4;	/* round up to 32-bit boundry */

	if ((node = csc_cdl_list_alloc(psize)) == NULL) {
		return NULL;
	}
	kp = (KEYCB*) &node[1];
	kp->self = node;
	return kp;
}

static KEYCB *csc_cfg_root_alloc(char *path, char *filename, int mode)
{
	struct	KEYROOT	*rext;
	KEYCB	*root;
	int	len;

	len = sizeof(struct KEYROOT) + 8;	/* reserve 8 bytes */
	if (path) {
		len += strlen(path);
	}
	if (filename) {
		len += strlen(filename);
	}

	if ((root = csc_cfg_kcb_alloc(len)) == NULL) {
		return NULL;
	}
	root->flags = CFGF_MODE_SET(root->flags, mode);
	root->flags = CFGF_TYPE_SET(root->flags, CFGF_TYPE_ROOT);

	rext = (struct KEYROOT *) root->pool;
	if (path) {
		root->key = rext->pool;
		strcpy(root->key, path);
	}
	if (filename) {
		root->value = rext->pool;
		if (root->key) {
			root->value += strlen(root->key) + 1;
		}
		strcpy(root->value, filename);
	}
	return root;
}

static KEYCB *csc_cfg_kcb_create(int mk, char *skey, char *value, char *comm)
{
	KEYCB	*kp;
	int	len;

	if (!skey && !value && !comm) {
		return NULL;	/* foolproof */
	}

	len = 8;	/* given some extra bytes */
	if (skey) {
		len += strlen(skey);
	}
	if (value) {
		len += strlen(value);
	}
	if (comm) {
		len += strlen(comm);
	}
	if ((kp = csc_cfg_kcb_alloc(len)) == NULL) {
		return NULL;
	}

	len = 0;	/* it's safe to reuse the 'len' */
	if (skey) {
		kp->key = kp->pool + len;
		len += sprintf(kp->key, "%s", skey) + 1;
	}
	if (value) {
		kp->value = kp->pool + len;
		len += sprintf(kp->value, "%s", value) + 1;
	}
	kp->comment = kp->pool + len;
	if (comm == NULL) {
		strcpy(kp->comment, "");	//FIXME
	} else if (*comm == '#') {
		sprintf(kp->comment, "%s", comm);
	} else {
		sprintf(kp->comment, "#%s", comm);
	}

	if (skey) {
		if (mk) {
			kp->flags = CFGF_TYPE_SET(kp->flags, CFGF_TYPE_MAIN);
		} else if (value) {
			kp->flags = CFGF_TYPE_SET(kp->flags, CFGF_TYPE_KEY);
		} else {
			kp->flags = CFGF_TYPE_SET(kp->flags, CFGF_TYPE_PART);
		}
	} else if (value) {
		kp->flags = CFGF_TYPE_SET(kp->flags, CFGF_TYPE_PART);
	} else {
		kp->flags = CFGF_TYPE_SET(kp->flags, CFGF_TYPE_COMM);
	}
	return kp;
}


/* tricky part is, after this call, the key will point to the start address 
 * of it contents. however the value and comment will point to  a '\0', 
 * which content has been saved in store[] */
static int csc_cfg_kcb_fillup(KEYCB *kp)
{
	char	*p;
	int	i;

	/* first scan to locate the comments */
	for (i = 0; kp->pool[i]; i++) {
		if ((kp->pool[i] == '#') || (kp->pool[i] == '\n')) {
			break;
		}
	}
	/* after the last loop, 'i' should be indicating either '#', '\n' 
	 * or '\0' now */
	/* starts another loop to include tailing whitespace into comments */
	for (i--; i >= 0; i--) {
		if (!SMM_ISSPACE(kp->pool[i])) {
			break;
		}
	}

	i++;
	memmove(&kp->pool[i+1], &kp->pool[i], strlen(&kp->pool[i])+1);
	kp->pool[i] = 0;
	kp->comment = &kp->pool[i+1];
	if ((p = strchr(kp->comment, '\n')) != NULL) {
		*p = 0;
	}
	if ((p = strchr(kp->comment, '\r')) != NULL) {
		*p = 0;
	}
	kp->flags = CFGF_TYPE_SET(kp->flags, CFGF_TYPE_COMM);

	if (kp->pool[0] == 0) {		/* empty line is kind of comments */
		return CFGF_TYPE_COMM;
	}

	/* Another scan to locate the key and value.
	 * It could be a partial key or a main key if no '=' appear */
	kp->key = kp->pool;
	kp->flags = CFGF_TYPE_SET(kp->flags, CFGF_TYPE_PART);

	if ((p = strchr(kp->key, '=')) != NULL) {
		/* otherwise it could be a common key or a main key */
		*p++ = 0;
		kp->value = p;
		kp->flags = CFGF_TYPE_SET(kp->flags, CFGF_TYPE_KEY);
	}

	/* Last scan to decide if it is a main key */
	p = csc_strbody(kp->key, NULL);
	if ((*p == '[') && strchr(p + 2, ']')) {  /* found the main key */
		kp->key = p + 1;	/* strip the '[]' pair */
		p = strchr(p + 2, ']');
		*p = 0;
		kp->flags = CFGF_TYPE_SET(kp->flags, CFGF_TYPE_MAIN);
	}
	return CFGF_TYPE_GET(kp->flags);
}

static KEYCB *csc_cfg_find_key(KEYCB *cfg, char *key, int type)
{
	KEYCB	*kcb;
	CSCLNK	*mp;

	if (cfg == NULL) {
		return NULL;
	}
	if ((key == NULL) && (type == CFGF_TYPE_MAIN)) {
		return cfg;
	}
	for (mp = cfg->anchor; mp; mp = csc_cdl_next(cfg->anchor, mp)) {
		if ((kcb = CFGF_GETOBJ(mp)) == NULL) {
			break;
		}
		if (CFGF_TYPE_GET(kcb->flags) != type) {
			continue;
		}
		if (key == NULL) {
			/* if the key is not specified, it'll return the first
			 * available key control */
			return kcb;
		}
		if (kcb->key == NULL) {
			continue;
		}
		if (!csc_cfg_strcmp(kcb->key, key)) {
			return kcb;
		}
	}
	return NULL;	/* main key doesn't exist */
}

static int csc_cfg_access_setup(KEYCB *cfg, KEYCB *mkey, KEYCB *kcb)
{
	struct	KEYROOT	*rext;

	if (cfg == NULL) {
		return SMM_ERR_OBJECT;
	}
	if (CFGF_TYPE_GET(cfg->flags) != CFGF_TYPE_ROOT) {
		return SMM_ERR_OBJECT;
	}

	rext = (struct KEYROOT *)cfg->pool;
	rext->mkey = mkey;
	rext->skey = kcb;
	return SMM_ERR_NONE;
}

static KEYCB *csc_cfg_access_update(KEYCB *cfg, int type)
{
	struct	KEYROOT	*rext;
	KEYCB	*kcb;
	CSCLNK	*mp;

	if (cfg == NULL) {
		return NULL;
	}
	if (CFGF_TYPE_GET(cfg->flags) != CFGF_TYPE_ROOT) {
		return NULL;
	}

	rext = (struct KEYROOT *)cfg->pool;
	if ((rext->mkey == NULL) || (rext->skey == NULL)) {
		return NULL;
	}

	mp = csc_cdl_next(rext->mkey->anchor, rext->skey->self);
	while (mp) {
		if ((kcb = CFGF_GETOBJ(mp)) == NULL) {
			break;
		}
		if (CFGF_TYPE_GET(kcb->flags) == type) {
			rext->skey = kcb;
			return kcb;
		}
		mp = csc_cdl_next(rext->mkey->anchor, mp);
	}
	return NULL;
}

static FILE *_smm_config_open(char *path, char *fname, int mode)
{
	FILE	*fp;
	char	*fullpath;

	if ((fullpath = csc_strcpy_alloc(path, strlen(fname)+4)) == NULL) {
		return NULL;
	}
	strcat(fullpath, SMM_DEF_DELIM);
	strcat(fullpath, fname);

	switch (mode) {
	case CSC_CFG_RDONLY:
		fp = fopen(fullpath, "r");
		break;
	case CSC_CFG_RWC:
		smm_mkpath(path);
		if ((fp = fopen(fullpath, "r+")) == NULL) {
			fp = fopen(fullpath, "w+");
		}
		break;
	default:	/* CSC_CFG_RDWR */
		fp = fopen(fullpath, "r+");
		break;
	}
	smm_free(fullpath);
	return fp;
}

static int _smm_config_read(FILE *fp, KEYCB *kp)
{
	int	amnt, cpos, ch;

	amnt = 0;
	cpos = ftell(fp);
	while ((ch = fgetc(fp)) != EOF) {
		if (kp) {
			kp->pool[amnt] = (char) ch;
		}
		amnt++;
		if (ch == '\n') {
			break;
		}
	}
	if (kp == NULL) {	/* rewind to the start position */
		fseek(fp, cpos, SEEK_SET);
	} else {
		kp->pool[amnt] = 0;
	}
	return amnt;
}

static int _smm_config_write(FILE *fp, KEYCB *kp)
{
	if (kp == NULL) {
		return 0;
	}

	kp->update = 0;		/* reset the update counter */
	if (kp->key) {
		if (CFGF_TYPE_GET(kp->flags) == CFGF_TYPE_MAIN) {
			fprintf(fp, "[%s]", kp->key);
		} else {
			fputs(kp->key, fp);
		}
	}
	if (kp->value) {
		if (kp->key) {
			fputc('=', fp);
		}
		fputs(kp->value, fp);
	}
	if (kp->comment) {
		fputs(kp->comment, fp);
	}
	fputs("\n", fp);	//FIXME: DOS format \r\n 
	return 0;
}

/* strcmp() without comparing the head and tail white spaces */
static int csc_cfg_strcmp(char *sour, char *dest)
{
	int	slen, dlen;

	/* skip the heading white spaces */
	sour = csc_strbody(sour, &slen);
	dest = csc_strbody(dest, &dlen);

	/* comparing the body content */
	if (slen == dlen) {
		return strncmp(sour, dest, slen);
	}
	return slen - dlen;
}

static int csc_cfg_binary_to_hex(char *src, int slen, char *buf, int blen)
{
	char	temp[4];
	int	i;

	for (i = 0; i < slen; i++) {
		sprintf(temp, "%02X", (unsigned char) *src++);
		if (buf && (blen > 1)) {
			blen -= 2;
			*buf++ = temp[0];
			*buf++ = temp[1];
		}
	}
	if (buf && (blen > 0)) {
		*buf++ = 0;
	}
	return slen * 2;	/* return the length of the hex string */
}

static int csc_cfg_hex_to_binary(char *src, char *buf, int blen)
{
	char	temp[4];
	int	amnt = 0;

	while (*src) {
		if (isxdigit(*src)) {
			temp[0] = *src++;
		}
		if (isxdigit(*src)) {
			temp[1] = *src++;
		} else {
			break;
		}
		temp[2] = 0;

		if (buf && blen) {
			*buf++ = (char)strtol(temp, 0, 16);
			blen--;
		}
		amnt++;
	}
	return amnt;
}

