/*!\file       csc_bmem.c
   \brief      bitmap memory allocation plan

   The file supports a set of dynamic memory managed by bitmap

   \author     "Andy Xuming" <xuming@users.sourceforge.net>
   \date       2019
*/
/* Copyright (C) 1998-2019  "Andy Xuming" <xuming@users.sourceforge.net>

   This file is part of CSOUP library, Chicken Soup for the C

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
/*
 Blank memory:
  |-------------------------------------------------------------------------|
 After initialized:
  |----------------------------------------------------------------[BMMCB***]
 Allocated:
  [BMMPC*][PAGES]----[BMMPC*][PAGES]-------------------------------[BMMCB***]
 [BMMCB***]:
  [BMMCB+bitmp][bitmap][bitmap]...
 [BMMPC*][PAGES]:
  [BMMPC+frontpad][extra pages][guards][page1][page2]...[pageN+backpad][guards]
  - backpad is always part of guards; 
  - frontpad is always part of extra page
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libcsoup.h"


/* page has 12 setting: 32/64/128/256/512/1k/2k/4k/8k/16k/32k/64k
 * so that the padding size can be limited in 64k */

#define BMEM_GUARD		0	/* 0: Miniman GUARD; 1: 1 PAGE OF GUARD */
#define BMEM_MAGIC		0xAC

#define BMEM_DIR_CLIENT		0
#define BMEM_DIR_EXTRA		1
#define BMEM_DIR_FRONTGRD	2
#define BMEM_DIR_BACKGRD	3
#define BMEM_DIR_BMMPC		4


static	unsigned char	bmtab[8] = { 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80 };
#define BM_CK_PAGE(bm, idx)	((bm)[(idx)/8] & bmtab[(idx)&7])
#define BM_SET_PAGE(bm, idx)	((bm)[(idx)/8] |= bmtab[(idx)&7])
#define BM_CLR_PAGE(bm, idx)	((bm)[(idx)/8] &= ~bmtab[(idx)&7])


/* Bitmap Memory Manager Page Controller */
typedef struct	_BMMPC	{
	unsigned char	magic[4];	/* CRC8 + MAGIC + PAD1 + PAD2 */
	uint	pages;		/* occupied pages, includes BMMPC and guards */
} BMMPC;

/* Bitmap Memory Manager Control Block */
typedef	struct	_BMMCB	{
	unsigned char	magic[4];	/* CRC8 + MAGIC + CONFIG1 + CONFIG2 */
	uint	pages;		/* control block used pages, inc. BMMCB and bitmap */

	char	*trunk;		/* point to the head of the page array */
	uint	total;		/* number of allocable pages */
	uint	avail;		/* number of available pages */

	unsigned char	bitmap[1];
} BMMCB;

typedef int (*BMap_F)(BMMPC *mpc, uint index, uint pages);

/*
static int bmem_validing(BMMCB *bmc);
static int bmem_verify(BMMPC *mpc);
static uint bmem_page_finder(BMMCB *bmc, uint pages);
static void bmem_page_take(BMMCB *bmc, uint idx, uint pages);
static void bmem_page_free(BMMCB *bmc, uint idx, uint pages);
static uint bmem_page_index(BMMCB *bmc, void *mem);
static void *bmem_find_front_guard(BMMPC *mpc, int *len);
static void *bmem_find_back_guard(BMMPC *mpc, int *len);
static int bmem_guard_setup(BMMPC *mpc);
static long bmem_guard_verify(BMMPC *mpc);
*/

static size_t bmem_page_to_size(BMMCB *bmc, uint page);
static uint bmem_size_to_page(BMMCB *bmc, size_t size);
static void *bmem_directory(BMMCB *bmc, BMMPC *mpc, int cmd, size_t *osize);

static inline void bmem_set_crc(void *mb, int len)
{
	register char   *p = mb;
	p[1] = (char) BMEM_MAGIC;
	p[0] = (char) csc_crc8(0, p+1, len-1);
}

static inline int bmem_check(void *mb, int len)
{
	register char   *p = mb;
	return (p[1] == (char) BMEM_MAGIC) &&
		(p[0] == (char) csc_crc8(0, p+1, len-1));
}

static inline void bmem_config_set(BMMCB *bmc, int config)
{
	bmc->magic[2] = (unsigned char)(config & 0xff);
	bmc->magic[3] = (unsigned char)((config >> 8) & 0xff);
}

static inline int bmem_config_get(BMMCB *bmc)
{
	return (int)((bmc->magic[3] << 8) | bmc->magic[2]);
}

static inline void bmem_pad_set(BMMPC *mpc, int padding)
{
	mpc->magic[2] = (unsigned char)(padding & 0xff);
	mpc->magic[3] = (unsigned char)((padding >> 8) & 0xff);
}

static inline int bmem_pad_get(BMMPC *mpc)
{
	return (int)((mpc->magic[3] << 8) | mpc->magic[2]);
}

void *csc_bmem_init(void *mem, size_t mlen, int flags)
{
	BMMCB	*bmc;
	uint	bmlen, pages;
	size_t	extra;

	if (mem == NULL) {
		return NULL;	/* CSC_MERR_INIT */
	}

	bmc = (BMMCB*) mem;
	bmem_config_set(bmc, flags);

	/* estimate how many page are there */
	pages = (uint)(mlen / bmem_page_to_size(bmc, 1));

	/* based on page numbers calculate the pages of the control block */
	bmlen = bmem_size_to_page(bmc, sizeof(BMMCB) + pages / 8);

	/* minimum pool size depends on the minimum pages can be allocated */
	bmem_directory(bmc, NULL, BMEM_DIR_BMMPC, &extra);
	if (pages < extra + bmlen) {
		return NULL;	/* CSC_MERR_LOWMEM */
	}

	/* reduce the page numbers to fit in the control block */
	pages -= bmlen;
	if ((pages == 0) && ((flags & CSC_MEM_ZERO) == 0)) {
		return NULL;	/* CSC_MERR_LOWMEM */
	}

	/* set up the control block in the end of the memory block in page boundry */
	bmc = (BMMCB*) ((char*)mem + bmem_page_to_size(mem, pages));
	memset((void*)bmc, 0, bmem_page_to_size(mem, bmlen));
	bmem_config_set(bmc, flags);
	bmc->pages = bmlen;
	bmc->trunk = mem;
	bmc->total = bmc->avail = pages;
	bmem_set_crc(bmc, bmem_page_to_size(bmc, bmc->pages));
	return bmc;
}

void *csc_bmem_alloc(void *heap, size_t size)
{
	BMMCB	*bmc = heap;
	BMMPC	*mpc;
	uint	idx, pages;
	size_t	extra;

	if (bmem_verify(bmc, (void*)-1)) {
		return NULL;
	}

	/* front guard is BMEM_GUARD - 1 because BMMPC plays as guard too */
	bmem_directory(bmc, NULL, BMEM_DIR_BMMPC, &extra)l
	pages = bmem_size_to_page(bmc, size) + extra;
	if (pages > bmc->avail) {
		return NULL;	/* CSC_MERR_RANGE */
	}

	if ((idx = bmem_page_finder(bmc, pages)) == (uint) -1) {
		return NULL;	/* CSC_MERR_RANGE */
	}

	/* take the free pages */
	bmem_page_take(bmc, idx, pages);
	bmc->avail -= pages;
	bmem_set_crc(bmc, bmem_page_to_size(bmc, bmc->pages));
	
	/* setup the Bitmap Memory Manager Page Controller */
	mpc = (BMMPC*)(bmc->trunk + bmem_page_to_size(bmc, idx));
	memset(mpc, 0, sizeof(BMMPC));
	mpc->pages = pages;
	bmem_pad_set(mpc, bmem_page_to_size(bmc, pages - extra) - size);
	bmem_set_crc(mpc, sizeof(BMMPC));

	/* setup guards */
	//bmem_guard_setup(mpc);
	return bmem_directory(bmc, mpc, 0, NULL);
}

int bmem_free(void *heap, void *mem)
{
	BMMCB	*bmc = *heap;
	BMMPC	*mpc;
	uint	idx;

	if ((rc = bmem_verify(bmc, mem)) < 0) {
		return rc;	/* invalided memory management */
	}

	mpc = bmem_directory(bmc, mem, BMEM_DIR_BMMPC, NULL);

	/* set free of these pages */
	idx = bmem_page_index(bmc, mpc);
	bmem_page_free(bmc, idx, mpc->pages);
	bmc->avail += mpc->pages;
	bmem_set_crc(bmc, bmem_page_to_size(bmc, bmc->pages));
	return 0;
}


static int bmem_verify(BMMCB *bmc, void *mem)
{
	if (bmc == NULL) {
		return CSC_MERR_INIT;	/* heap not created */
	}
	if (!bmem_check(bmc, bmem_page_to_size(bmc, bmc->pages))) {
		return CSC_MERR_BROKEN;
	}

	if (mem == (void*) -1) {
		return 0;
	}
	if ((mem < bmc->trunk) || (mem > bmc->trunk + bmem_page_to_size(bmc, bmc->total))) {
		return CSC_MERR_RANGE;	/* memory out of range */
	}

	mem = bmem_directory(bmc, mem, BMEM_DIR_BMMPC, NULL);
	if (!bmem_check(mem, sizeof(BMMPC))) {
		return CSC_MERR_BROKEN; /* broken memory controller */
	}
	return 0;
}

static size_t bmem_page_to_size(BMMCB *bmc, uint page)
{
	int n = (((int)bmc->magic[2] & CSC_MEM_PAGEMASK) >> 4);
	if (n > 11) n = 11;	/* no more than 64KB per page */
	return (size_t)page * (32<<n);
}

static uint bmem_size_to_page(BMMCB *bmc, size_t size)
{
	int n = (((int)bmc->magic[2] & CSC_MEM_PAGEMASK) >> 4);
	if (n > 11) n = 11;	/* no more than 64KB per page */
	n = 32<<n;
	return (uint)((size + n - 1) / n);
}

static void *bmem_directory(BMMCB *bmc, BMMPC *mpc, int cmd, size_t *osize)
{
	char	*p = NULL;
	int	pages, config = bmem_config_get(bmc);

	switch (cmd) {
	case BMEM_DIR_CLIENT:		/* find client area */
		pages = 1 + ((config & CSC_MEM_EXTRMASK) >> 8);	/* head and extra */
		pages += (config & CSC_MEM_GURDMASK) >> 12;	/* front guard */
		p = (char*)mpc + bmem_page_to_size(bmc, pages);
		if (osize) {
			pages += (config & CSC_MEM_GURDMASK) >> 12;	/* back guard */
			*osize = bmem_page_to_size(bmc, mpc->pages - pages);
			*osize -= bmem_pad_get(mpc);
		}
		break;

	case BMEM_DIR_EXTRA:		/* find extra pages */
		p = (char*)(mpc + 1);
		if (osize) {
			pages = 1 + ((config & CSC_MEM_EXTRMASK) >> 8);	/* head and extra */
			*osize = bmem_page_to_size(bmc, pages) - sizeof(BMMPC);
		}
		break;

	case BMEM_DIR_FRONTGRD:		/* find front guard */
		cmd = (config & CSC_MEM_GURDMASK) >> 12;	/* reuse the variable for guard */
		if (cmd) {
			pages = 1 + ((config & CSC_MEM_EXTRMASK) >> 8);	/* head and extra */
			p = (char*)mpc + bmem_page_to_size(bmc, pages);
		}
		if (osize) {
			*osize = bmem_page_to_size(bmc, cmd);
		}
		break;

	case BMEM_DIR_BACKGRD:		/* find back guard */
		pages = mpc->pages - ((config & CSC_MEM_GURDMASK) >> 12);
		p = (char*)mpc + bmem_page_to_size(bmc, pages) - bmem_pad_get(mpc);
		if (osize) {
			pages = (config & CSC_MEM_GURDMASK) >> 12;
			*osize = bmem_page_to_size(bmc, pages) + bmem_pad_get(mpc);
		}
		break;

	case BMEM_DIR_BMMPC:		/* find BMMPC from client memory address and return extra pages */
		pages = 1 + ((config & CSC_MEM_EXTRMASK) >> 8);	/* head and extra pages */
		pages += (config & CSC_MEM_GURDMASK) >> 12;	/* front guards */
		if (mpc) {
			p = (char*)mpc - bmem_page_to_size(bmc, pages);
		}
		if (osize) {
			*osize = pages + ((config & CSC_MEM_GURDMASK) >> 12);
		}
		break;
	}
	return p;
}

#ifdef	CFG_UNIT_TEST
#include "libcsoup_debug.h"

#define	BMEM_CFG_GUARD	1
#define BMEM_CFG_EXTRA	1
#define BMEM_CFG_PAGE	1	/* 0=32,1=64,2=128,3=256,... */
#define	BMEM_CONFIG	(CSC_MEM_DEFAULT | (BMEM_CFG_PAGE << 4) | (BMEM_CFG_EXTRA << 8) | (BMEM_CFG_GUARD << 12))

static void csc_bmem_function_test(char *buf, int len);


int csc_bmem_unittest(void)
{
	BMMCB	*bmc;
	char	buf[32*1024];

	csc_bmem_function_test(buf, sizeof(buf));

	/* create the minimum heap */
	bmc = csc_bmem_init(buf, sizeof(buf), BMEM_CONFIG);
	cclog(bmc!=NULL, "Create Bitmap heap: %p %x\n", bmc, bmem_config_get(bmc));
	return 0;
}

static void csc_bmem_function_test(char *buf, int len)
{
	BMMCB	*bmc;
	BMMPC	*mpc;
	int	i, k;
	char	*p;
	size_t	msize, mpage;

	/* function tests */
	cclog(-1, "Testing internal functions.\n");
	bmc = (BMMCB*) buf;
	memset(bmc, 0, sizeof(BMMCB));
	bmem_config_set(bmc, 0xc1c2c3c4);
	cclog(bmc->magic[2] == 0xc4 && bmc->magic[3] == 0xc3, 
			"bmem_config_set: %x %x %x %x\n",
			bmc->magic[0], bmc->magic[1], bmc->magic[2], bmc->magic[3]);
	msize = (size_t)bmem_config_get(bmc);
	cclog(msize == 0xc3c4, "bmem_config_get: %x\n", (int)msize);
	bmem_set_crc(bmc, sizeof(BMMCB));
	cclog(bmc->magic[0] == 0x67, "bmem_set_crc: %x %x\n", bmc->magic[0], bmc->magic[1]);
	cclog(bmem_check(bmc, sizeof(BMMCB)), "bmem_check: %d %x\n", 
			bmc->magic[0], bmem_check(bmc, sizeof(BMMCB)));

	mpc = (BMMPC*)buf;
	memset(mpc, 0, sizeof(BMMPC));
	bmem_pad_set(mpc, 0xf1f2f3f4);
	cclog(mpc->magic[2] == 0xf4 && mpc->magic[3] == 0xf3, 
			"bmem_pad_set: %x %x %x %x\n",
			mpc->magic[0], mpc->magic[1], mpc->magic[2], mpc->magic[3]);
	msize = (size_t)bmem_pad_get(mpc);
	cclog(msize==0xf3f4, "bmem_pad_get: %x\n", (int)msize);

	for (i = 0; i < 16; i++) {
		bmem_config_set(bmc, i << 4);
		msize = bmem_page_to_size(bmc, 1);
		mpage = bmem_size_to_page(bmc, 128 * 1024);
		if (i < 12) {
			cclog(msize == (size_t)(32 << i), "bmem_page_to_size: %d -> %d %d pages\n", i, msize, mpage);
		} else {
			cclog(msize == 65536, "bmem_page_to_size: %d -> %d %d pages\n", i, msize, mpage);
		}
	}

	/* testing the bmem_directory() function */
	cclog(-1, "Testing bmem_directory():\n");
	bmc = (BMMCB*) buf;
	memset(bmc, 0, sizeof(BMMCB));
	mpc = (BMMPC*)(bmc + 1);
	memset(mpc, 0, sizeof(BMMPC));
	bmem_pad_set(mpc, 260);
	mpc->pages = 24;
	for (i = 0; i < 4; i++) {	/* guarding pages */
		for (k = 0; k < 4; k++) {	/* extra pages */
			bmem_config_set(bmc, (1<<4)|(k<<8)|(i<<12));
			p = bmem_directory(bmc, mpc, BMEM_DIR_CLIENT, &msize);
			cclog(p!=NULL, "PSize=64 Extra=%d Guard=%d - Client=+%ld:%ld ", 
					k, i, (long)(p - (char*)mpc), msize);
			p = bmem_directory(bmc, mpc, BMEM_DIR_EXTRA, &msize);
			cslog("Extra=+%ld:%ld ", (long)(p - (char*)mpc), msize);
			p = bmem_directory(bmc, mpc, BMEM_DIR_FRONTGRD, &msize);
			if (p == NULL) p = (char*)mpc;
			cslog("FrontG=+%ld:%ld ", (long)(p - (char*)mpc), msize);
			p = bmem_directory(bmc, mpc, BMEM_DIR_BACKGRD, &msize);
			cslog("BackG=+%ld:%ld ", (long)(p - (char*)mpc), msize);

			p = bmem_directory(bmc, mpc, BMEM_DIR_CLIENT, &msize);
			p = bmem_directory(bmc, (BMMPC*)p, BMEM_DIR_BMMPC, &msize);
			if (p == NULL) p = (char*)mpc;
			cslog("BMMPC=+%ld:%ld\n", (long)(p - (char*)mpc), msize);
		}
	}
}
#endif


#if 0

int bmem_scan(BMMCB *bmc, BMap_F bm_alloc, BMap_F bm_freed, BMap_F bm_error)
{
	BMMPC	*mpc;
	uint	i, total, last_free;
	int	err = 0;

	if (bmem_validing(bmc)) {
		return -1;	/* invalided memory management */
	}

	last_free = (uint) -1;
	for (i = total = 0; i < bmc->total; i++) {
		if (!BM_CK_PAGE(bmc->bitmap, i)) {
			if (last_free == (uint)-1) {
				last_free = i;
			}
			continue;
		}

		/* for inspecting the freed pages */
		if (last_free != (uint)-1) {
			if (bm_freed) {
				mpc = (BMMPC *)(bmc->trunk + bmem_page_to_size(bmc, last_free));
				bm_freed(mpc, last_free, i - last_free);
			}
			last_free = (uint) -1;
		}

		/* found an allocated memory block */
		mpc = (BMMPC *)(bmc->trunk + bmem_page_to_size(bmc, i));
		if (mpc->magic != BMEM_MAGIC_USED) {
			if (bm_error) {
				bm_error(mpc, i, 0);
			}
			err++;
		} else {
			if (bm_alloc) {
				bm_alloc(mpc, i, mpc->pages);
			}
			/* skip the allocated pages */
			i += mpc->pages - 1;
		}
	}

	/* if rest pages are free */
	if (last_free != (uint)-1) {
		if (bm_freed) {
			mpc = (BMMPC *)(bmc->trunk + bmem_page_to_size(bmc, last_free));
			bm_freed(mpc, last_free, i - last_free);
		}
	}
	return err;
}

static uint bmem_page_finder(BMMCB *bmc, uint pages)
{
	uint	i, n;

	for (i = 0; i <= bmc->total - pages; i++) {
		for (n = 0; n < pages; n++) {
			if (BM_CK_PAGE(bmc->bitmap, i + n)) {
				break;
			}
		}
		if (n == pages) {	/* found the free space */
			return i;
		}
	}
	return (uint) -1;	/* no enough pages */
}

static void bmem_page_take(BMMCB *bmc, uint idx, uint pages)
{
	uint	i;

	//printf("bmem_page_take: %d %d\n", idx, pages);
	for (i = 0; i < pages; i++) {
		BM_SET_PAGE(bmc->bitmap, idx + i);
	}
}

static void bmem_page_free(BMMCB *bmc, uint idx, uint pages)
{
	uint	i;

	for (i = 0; i < pages; i++) {
		BM_CLR_PAGE(bmc->bitmap, idx + i);
	}
}

static uint bmem_page_index(BMMCB *bmc, void *mem)
{
	ulong	off;
	uint	idx;

	if ((char*)mem < bmc->trunk) {
		return (uint) -1;	/* memory out of low boundry */
	}

	off = (ulong)((char*)mem - bmc->trunk);
	if (off % bmem_page_to_size(bmc, 1) != 0) {
		return (uint) -1;	/* unaligned memory */
	}

	idx = (uint)(off / bmem_page_to_size(bmc, 1));
	if (idx >= bmc->total) {
		return (uint) -1;	/* memory out of high boundry */
	}
	return idx;
}


static int bmem_guard_setup(BMMPC *mpc)
{
	char	*p;
	int	len;

	p = bmem_find_front_guard(mpc, &len);
	memset(p, BMEM_MAGIC, len);
	p = bmem_find_back_guard(mpc, &len);
	memset(p, BMEM_MAGIC, len);
	return 0;
}

/* return the offset of the violation address aginst the memory address,
 * not the page controller's address. 
 * so it returns a negative number if violation in front guard */
static long bmem_guard_verify(BMMPC *mpc)
{
	unsigned char	*p;
	int	i, len;

	p = bmem_find_front_guard(mpc, &len);
	for (i = 0; i < len; i++) {
		if (p[i] != BMEM_MAGIC) {
			return (long)&p[i] - (long)bmem_directory(bmc, mpc, 0, NULL);
		}
	}

	p = bmem_find_back_guard(mpc, &len);
	for (i = 0; i < len; i++) {
		if (p[i] != BMEM_MAGIC) {
			return (long)&p[i] - (long)bmem_directory(bmc, mpc, 0, NULL);
		}
	}
	return 0;
}
#endif


