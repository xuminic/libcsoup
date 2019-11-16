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


static	unsigned char	bmtab[8] = { 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80 };
#define BM_CK_PAGE(bm, idx)	((bm)[(idx)/8] & bmtab[(idx)&7])
#define BM_SET_PAGE(bm, idx)	((bm)[(idx)/8] |= bmtab[(idx)&7])
#define BM_CLR_PAGE(bm, idx)	((bm)[(idx)/8] &= ~bmtab[(idx)&7])

#define BMEM_SPAN(f,t)		((size_t)((char*)(f) - (char*)(t)))
#define BMEM_CFG_PAGE(n)	((((n)>>4)&0xf)%12)
#define BMEM_CFG_EXTRA(n)	(((n)>>8)&0xf)
#define BMEM_CFG_GUARD(n)	(((n)>>12)&0xf)




/* Bitmap Memory Manager Page Controller */
typedef struct	_BMMPC	{
	unsigned char	magic[4];	/* CRC8 + MAGIC + PAD1 + PAD2 */
	int	pages;		/* occupied pages, includes BMMPC and guards */
} BMMPC;

/* Bitmap Memory Manager Control Block */
typedef	struct	_BMMCB	{
	unsigned char	magic[4];	/* CRC8 + MAGIC + CONFIG1 + CONFIG2 */
	int	pages;		/* control block used pages, inc. BMMCB and bitmap */

	char	*trunk;		/* point to the head of the page array */
	int	total;		/* number of allocable pages */
	int	avail;		/* number of available pages */

	unsigned char	bitmap[1];
} BMMCB;

typedef int (*BMap_F)(BMMPC *mpc, int index, int pages);


static int bmem_verify(BMMCB *bmc, void *mem);
static int bmem_guard_setup(BMMCB *bmc, BMMPC *mpc);
static void *bmem_guard_verify(BMMCB *bmc, BMMPC *mpc);
static void bmem_page_take(BMMCB *bmc, int idx, int pages);
static void bmem_page_free(BMMCB *bmc, int idx, int pages);
static size_t bmem_page_to_size(BMMCB *bmc, int page);
static int bmem_size_to_page(BMMCB *bmc, size_t size);
static int bmem_size_to_index(BMMCB *bmc, size_t size);
static void *bmem_find_client(BMMCB *bmc, BMMPC *mpc, size_t *osize);
static void *bmem_find_extradata(BMMCB *bmc, BMMPC *mpc, int *osize);
static void *bmem_find_front_guard(BMMCB *bmc, BMMPC *mpc, int *osize);
static void *bmem_find_back_guard(BMMCB *bmc, BMMPC *mpc, int *osize);
static BMMPC *bmem_find_control(BMMCB *bmc, void *mem);

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

static inline int bmem_service_pages(BMMCB *bmc)
{
	register int	config = (int)((bmc->magic[3] << 8) | bmc->magic[2]);

	/* head + extra pages + front and back guards */
	return 1 + BMEM_CFG_EXTRA(config) + BMEM_CFG_GUARD(config) + BMEM_CFG_GUARD(config);
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
	int	bmlen, pages;

	if (mem == NULL) {
		return NULL;	/* CSC_MERR_INIT */
	}

	bmc = (BMMCB*) mem;
	bmem_config_set(bmc, flags);

	/* estimate how many page are there */
	pages = bmem_size_to_index(bmc, mlen);

	/* based on page numbers calculate the pages of the control block */
	bmlen = bmem_size_to_page(bmc, sizeof(BMMCB) + pages / 8);

	/* minimum pool size depends on the minimum pages can be allocated */
	if (pages < bmlen + bmem_service_pages(bmc)) {
		return NULL;	/* CSC_MERR_LOWMEM */
	}

	/* reduce the page numbers to fit in the control block */
	pages -= bmlen;
	if ((pages == bmem_service_pages(bmc)) && ((flags & CSC_MEM_ZERO) == 0)) {
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
	int	pages, config, padding;
	int	fnd_idx, fnd_pages = -1;

	int loose(void *mem, int freepages)
	{
		/* when it's been called, the "pages" should've been set */
		if (freepages >= pages) {
			if (fnd_pages == -1) {
				fnd_pages = freepages;
				fnd_idx = bmem_size_to_index(bmc, BMEM_SPAN(mem, bmc->trunk));
			}
			switch (config & CSC_MEM_FITMASK) {
			case CSC_MEM_BEST_FIT:
				if (fnd_pages > freepages) {
					fnd_pages = freepages;
					fnd_idx = bmem_size_to_index(bmc, BMEM_SPAN(mem, bmc->trunk));
				}
				break;
			case CSC_MEM_WORST_FIT:
				if (fnd_pages < freepages) {
					fnd_pages = freepages;
					fnd_idx = bmem_size_to_index(bmc, BMEM_SPAN(mem, bmc->trunk));
				}
				break;
			default:	/* CSC_MEM_FIRST_FIT */
				return 1;
			}
		}
		return 0;
	}

	if (bmem_verify(bmc, (void*)-1) < 0) {
		puts("1");
		return NULL;
	}
	config = (int)bmem_config_get(bmc);

	pages = bmem_size_to_page(bmc, size);
	if (!pages && !(config & CSC_MEM_ZERO)) {
		puts("2");
		return NULL;	/* CSC_MERR_RANGE: not allow empty allocation */
	}

	/* find the size of the tail padding */
	padding = bmem_page_to_size(bmc, pages) - size;

	/* add up the service pages: the BMMPC, extra page, front and back guards */
	pages += bmem_service_pages(bmc);
	if (pages > bmc->avail) {
		puts("3");
		return NULL;	/* CSC_MERR_RANGE */
	}

	/* find a group of free pages where meets the requirement */
	fnd_pages = -1;
	if (csc_bmem_scan(heap, NULL, loose)) {
		puts("4");
		return NULL;	/* CSC_MERR_BROKEN: chain broken */
	}
	if (fnd_pages == -1) {
		puts("5");
		return NULL;	/* CSC_MERR_LOWMEM */
	}

	/* take the free pages */
	bmem_page_take(bmc, fnd_idx, pages);
	bmc->avail -= pages;
	bmem_set_crc(bmc, bmem_page_to_size(bmc, bmc->pages));
	
	/* setup the Bitmap Memory Manager Page Controller */
	mpc = (BMMPC*)(bmc->trunk + bmem_page_to_size(bmc, fnd_idx));
	memset(mpc, 0, sizeof(BMMPC));
	mpc->pages = pages;
	bmem_pad_set(mpc, padding);
	bmem_guard_setup(bmc, mpc);
	bmem_set_crc(mpc, sizeof(BMMPC));

	/* initial the memory */
	heap = bmem_find_client(bmc, mpc, NULL);	/* find client area */
	if (config & CSC_MEM_CLEAN) {
		memset(heap, 0, size);
	}
	return heap;
}

int csc_bmem_free(void *heap, void *mem)
{
	BMMCB	*bmc = heap;
	BMMPC	*mpc;
	size_t	idx;
	int	rc;

	if ((rc = bmem_verify(bmc, mem)) < 0) {
		return rc;	/* invalided memory management */
	}

	mpc = bmem_find_control(bmc, mem);

	/* set free of these pages */
	idx = bmem_size_to_index(bmc, BMEM_SPAN(mpc, bmc->trunk));
	bmem_page_free(bmc, idx, mpc->pages);
	mpc->magic[0] = 0;	/* destroy the page controller */
	bmc->avail += mpc->pages;
	bmem_set_crc(bmc, bmem_page_to_size(bmc, bmc->pages));
	return 0;
}

void *csc_bmem_scan(void *heap, int (*used)(void*, int), int (*loose)(void*, int))
{
	BMMCB	*bmc = heap;
	BMMPC	*mpc;
	int	i, last_free;

	if (bmem_verify(bmc, (void*)-1) < 0) {
		return bmc;	/* invalided memory management */
	}

	last_free = (int) -1;
	for (i = 0; i < bmc->total; i++) {
		if (!BM_CK_PAGE(bmc->bitmap, i)) {
			if (last_free == (int)-1) {
				last_free = i;
			}
			continue;
		}

		/* for inspecting the freed pages */
		if (last_free != (int)-1) {
			mpc = (BMMPC *)(bmc->trunk + bmem_page_to_size(bmc, last_free));
			if (loose && loose(mpc, i - last_free)) {
				return NULL;
			}
			last_free = (int) -1;
		}

		/* found an allocated memory block */
		mpc = (BMMPC *)(bmc->trunk + bmem_page_to_size(bmc, i));
		if (bmem_verify(bmc, bmem_find_client(bmc, mpc, NULL)) < 0) {
			return mpc;
		}

		if (used && used(mpc, mpc->pages)) {
			return NULL;
		}
		i += mpc->pages - 1; /* skip the allocated pages */
	}

	/* if rest pages are free */
	if (last_free != (int)-1) {
		if (loose) {
			mpc = (BMMPC *)(bmc->trunk + bmem_page_to_size(bmc, last_free));
			loose(mpc, i - last_free);
		}
	}
	return NULL;
}

size_t csc_bmem_attrib(void *heap, void *mem, int *state)
{
	BMMCB	*bmc = heap;
	BMMPC	*mpc;
	int	i, idx;

	if (bmem_verify(bmc, mem) < 0) {
		return (size_t) -1;	/* invalided memory management */
	}

	mpc = bmem_find_control(bmc, mem);
	idx = bmem_size_to_index(bmc, BMEM_SPAN(mpc, bmc->trunk));

	if (BM_CK_PAGE(bmc->bitmap, idx)) {
		if (state) {
			*state = 1;
		}
	
		idx = mpc->pages - bmem_service_pages(bmc);
		return bmem_page_to_size(bmc, idx) - bmem_pad_get(mpc);
	}

	/* search for free pages */
	for (i = idx; i < bmc->total; i++) {
		if (BM_CK_PAGE(bmc->bitmap, i)) {
			break;
		}
	}
	if (state) {
		*state = 0;
	}
	return bmem_page_to_size(bmc, i - idx);
}

void *csc_bmem_extra(void *heap, void *mem, int *xsize)
{
	BMMCB	*bmc = heap;

	if (bmem_verify(bmc, mem) < 0) {
		return NULL;	/* invalided memory management */
	}
	return bmem_find_extradata(bmc, bmem_find_control(bmc, mem), xsize);
}

static int bmem_verify(BMMCB *bmc, void *mem)
{
	int	idx;

	if (bmc == NULL) {
		return CSC_MERR_INIT;	/* heap not created */
	}
	if (!bmem_check(bmc, bmem_page_to_size(bmc, bmc->pages))) {
		return CSC_MERR_BROKEN;
	}

	if (mem == (void*) -1) {
		return 0;
	}
	if (((char*)mem < bmc->trunk) || ((char*)mem > bmc->trunk + 
				bmem_page_to_size(bmc, bmc->total))) {
		return CSC_MERR_RANGE;	/* memory out of range */
	}

	mem = bmem_find_control(bmc, mem);
	idx = bmem_size_to_index(bmc, BMEM_SPAN(mem, bmc->trunk));
	if (!BM_CK_PAGE(bmc->bitmap, idx)) {
		return 0;	/* free page: no need to verify */
	}

	if (!bmem_check(mem, sizeof(BMMPC))) {
		return CSC_MERR_BROKEN; /* broken memory controller */
	}

	if (bmem_guard_verify(bmc, (BMMPC *)mem) != NULL) {
		return 1;	/* a warning that memory may be violated */
	}
	return 0;
}

static int bmem_guard_setup(BMMCB *bmc, BMMPC *mpc)
{
	char	*p;
	int	len;

	if ((p = bmem_find_front_guard(bmc, mpc, &len)) != NULL) {
		memset(p, ~BMEM_MAGIC, len);
	}
	if ((p = bmem_find_back_guard(bmc, mpc, &len)) != NULL) {
		memset(p, ~BMEM_MAGIC, len);
	}
	return 0;
}

static void *bmem_guard_verify(BMMCB *bmc, BMMPC *mpc)
{
	char	*p;
	int	len;

	if ((p = bmem_find_front_guard(bmc, mpc, &len)) != NULL) {
		for ( ; len > 0; len--, p++) {
			if (*p != (char) ~BMEM_MAGIC) {
				return p;
			}
		}
	}
	if ((p = bmem_find_back_guard(bmc, mpc, &len)) != NULL) {
		for ( ; len > 0; len--, p++) {
			if (*p != (char) ~BMEM_MAGIC) {
				return p;
			}
		}
	}
	return NULL;
}

static void bmem_page_take(BMMCB *bmc, int idx, int pages)
{
	int	i;

	//printf("bmem_page_take: %d %d\n", idx, pages);
	for (i = 0; i < pages; i++) {
		BM_SET_PAGE(bmc->bitmap, idx + i);
	}
}

static void bmem_page_free(BMMCB *bmc, int idx, int pages)
{
	int	i;

	for (i = 0; i < pages; i++) {
		BM_CLR_PAGE(bmc->bitmap, idx + i);
	}
}

static size_t bmem_page_to_size(BMMCB *bmc, int page)
{
	/* no more than 64KB per page */
	int n = BMEM_CFG_PAGE(bmem_config_get(bmc));
	return (size_t)page * (32<<n);
}

static int bmem_size_to_page(BMMCB *bmc, size_t size)
{
	/* no more than 64KB per page */
	int n = 32 << BMEM_CFG_PAGE(bmem_config_get(bmc));
	return (int)((size + n - 1) / n);
}

static int bmem_size_to_index(BMMCB *bmc, size_t size)
{
	/* no more than 64KB per page */
	int n = 32 << BMEM_CFG_PAGE(bmem_config_get(bmc));
	return (int)(size / n);
}

static void *bmem_find_client(BMMCB *bmc, BMMPC *mpc, size_t *osize)
{
	int	idx, pages, config = bmem_config_get(bmc);

	/* service pages are head, extra pages and front guards */
	idx = 1 + BMEM_CFG_EXTRA(config) + BMEM_CFG_GUARD(config);
	if (osize) {
		pages = mpc->pages - idx - BMEM_CFG_GUARD(config);	/* back guard */
		*osize = bmem_page_to_size(bmc, pages) - bmem_pad_get(mpc); 
	}
	return (char*)mpc + bmem_page_to_size(bmc, idx);
}

static void *bmem_find_extradata(BMMCB *bmc, BMMPC *mpc, int *osize)
{
	int	pages, config = bmem_config_get(bmc);

	if (osize) {
		pages = 1 + BMEM_CFG_EXTRA(config);	/* head and extra */
		*osize = (int)(bmem_page_to_size(bmc, pages) - sizeof(BMMPC));
	}
	return mpc + 1;
}

static void *bmem_find_front_guard(BMMCB *bmc, BMMPC *mpc, int *osize)
{
	int	guard, config = bmem_config_get(bmc);

	if ((guard = BMEM_CFG_GUARD(config)) > 0) {
		if (osize) {
			*osize = (int)bmem_page_to_size(bmc, guard);
		}
		guard = 1 + BMEM_CFG_EXTRA(config);	/* head and extra */
		return (char*)mpc + bmem_page_to_size(bmc, guard);
	}
	return NULL;
}

static void *bmem_find_back_guard(BMMCB *bmc, BMMPC *mpc, int *osize)
{
	int	pages, config = bmem_config_get(bmc);

	pages = BMEM_CFG_GUARD(config);
	if (osize) {
		*osize = (int)bmem_page_to_size(bmc, pages) + bmem_pad_get(mpc);
	}
	pages = mpc->pages - pages;
	return (char*)mpc + bmem_page_to_size(bmc, pages) - bmem_pad_get(mpc);
}

static BMMPC *bmem_find_control(BMMCB *bmc, void *mem)
{
	int	pages, config = bmem_config_get(bmc);

	/* find head, extra pages and front guards */
	pages = 1 + BMEM_CFG_EXTRA(config) + BMEM_CFG_GUARD(config);
	return (BMMPC*)((char*)mem - bmem_page_to_size(bmc, pages));
}


#ifdef	CFG_UNIT_TEST
#include "libcsoup_debug.h"

static void csc_bmem_function_test(char *buf, int blen);
static void csc_bmem_minimum_test(char *buf, int blen);

int csc_bmem_unittest(void)
{
	char	buf[32*1024];

	csc_bmem_function_test(buf, sizeof(buf));
	csc_bmem_minimum_test(buf, sizeof(buf));
	return 0;
}

static void csc_bmem_function_test(char *buf, int blen)
{
	BMMCB	*bmc;
	BMMPC	*mpc;
	int	i, k, len;
	char	*p, *tmp;
	size_t	msize, mpage;

	return;

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
		cclog(msize == (size_t)(32 << (i%12)), 
				"bmem_page_to_size: %d -> %d %d pages\n", i, msize, mpage);
	}

	/* testing the bmem_find_xxx() function */
	cclog(-1, "Testing bmem_find_xxx():\n");
	bmc = (BMMCB*)(buf + blen - sizeof(BMMCB));
	memset(bmc, 0, sizeof(BMMCB));
	bmc->trunk = buf;
	mpc = (BMMPC*)bmc->trunk;
	memset(mpc, 0, sizeof(BMMPC));
	bmem_pad_set(mpc, 260);
	mpc->pages = 24;
	for (i = 0; i < 4; i++) {	/* guarding pages */
		for (k = 0; k < 4; k++) {	/* extra pages */
			bmem_config_set(bmc, (1<<4)|(k<<8)|(i<<12));
			p = bmem_find_client(bmc, mpc, &msize);
			cclog(!!p, "PSize=64 Extra=%d Guard=%d - Client=+%ld:%ld ", 
					k, i, BMEM_SPAN(p, mpc), msize);
			p = bmem_find_extradata(bmc, mpc, &len);
			cslog("Extra=+%ld:%d ", BMEM_SPAN(p, mpc), len);
			p = bmem_find_front_guard(bmc, mpc, &len);
			if (p == NULL) p = (char*)mpc, len = 0;
			cslog("FrontG=+%ld:%d ", BMEM_SPAN(p, mpc), len);
			p = bmem_find_back_guard(bmc, mpc, &len);
			cslog("BackG=+%ld:%d ", BMEM_SPAN(p, mpc), len);

			p = bmem_find_client(bmc, mpc, &msize);
			p = (char*)bmem_find_control(bmc, p);
			msize = bmem_service_pages(bmc);
			cslog("BMMPC=+%ld:%ld\n", BMEM_SPAN(p, mpc), msize);
		}
	}
	tmp = buf + bmem_page_to_size(bmc, 10) + 12;
	msize = (size_t) bmem_size_to_index(bmc, BMEM_SPAN(tmp, bmc->trunk));
	cclog(msize==10, "Found page index %ld at +%ld\n", msize, BMEM_SPAN(tmp, bmc->trunk));
}

static void csc_bmem_minimum_test(char *buf, int blen)
{
	BMMCB	*bmc;
	int	config, rc[4];
	char	*p[4];
	
	(void) blen;

	/* create the minimum heap: bmc=1 mpc=1 extra=1 guard=1x2 */
	config = CSC_MEM_DEFAULT | CSC_MEM_XCFG(1,1,1);
	bmc = csc_bmem_init(buf, 5*(32<<BMEM_CFG_PAGE(config)), config);
	cclog(!bmc, "Create heap with empty allocation disabled: 5 pages\n");

	config |= CSC_MEM_ZERO;
	bmc = csc_bmem_init(buf, 5*(32<<BMEM_CFG_PAGE(config)), config);
	cclog(!!bmc, "Create heap with empty allocation enabled: 5 pages\n");
	if (!bmc) return;
	cclog(-1, "Created Heap: bmc=%d pages=%d free=%d map=%02x%02x%02x%02x\n",
			bmc->pages, bmc->total, bmc->avail, bmc->bitmap[0],
			bmc->bitmap[1], bmc->bitmap[2], bmc->bitmap[3]);

	p[0] = csc_bmem_alloc(bmc, 1);
	cclog(!p[0], "Failed to allocate from empty heap. [%02x]\n", bmc->bitmap[0]);

	p[0] = csc_bmem_alloc(bmc, 0);
	cclog(!!p[0], "Allocated an empty memory block. [%02x]\n", bmc->bitmap[0]); 
	rc[1] = (int)csc_bmem_attrib(bmc, p[0], rc);
	cclog(!rc[1], "Memory attribution: size=%d state=%d pad=%d\n", rc[1], rc[0],
			bmem_pad_get(bmem_find_control(bmc, p[0])));

	rc[0] = csc_bmem_free(bmc, p[0]);
	cclog(rc[0] >= 0, "Freed the empty memory block. [%02x]\n", bmc->bitmap[0]);
	rc[1] = (int)csc_bmem_attrib(bmc, p[0], rc);
	cclog(rc[1] == (int)bmem_page_to_size(bmc, 4), "Memory destroied: pages=%d %d\n", 
			bmem_find_control(bmc, p[0])->pages, rc[1]);

}

#endif


