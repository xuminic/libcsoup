/*!\file       csc_bmem.c
   \brief      dynamic memory management based on bitmaps

   The file supports a group of functions of dynamic memory 
   management based on bitmaps.

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
  [BMMCB***]----------------------------------------------------------------|
 Allocated:
  [BMMCB***][BMMPC*][PAGES]----[BMMPC*][PAGES]------------------------------|
 [BMMCB***]:
  [BMMCB+bitmap][bitmap][bitmap]...
 [BMMPC*][PAGES]:
  [BMMPC+frontpad][guards][page1][page2]...[pageN+backpad][guards]
  - frontpad and backpad are always part of guards; 
 In [BMMCB], page has 12 setting: 32/64/128/256/512/1k/2k/4k/8k/16k/32k/64k
   so that the padding size can be limited in 64k 
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libcsoup.h"

#define BMEM_MAGPIE		0xCA

static	unsigned char	bmtab[8] = { 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80 };
#define BM_CK_PAGE(bm, idx)	((bm)[(idx)/8] & bmtab[(idx)&7])
#define BM_SET_PAGE(bm, idx)	((bm)[(idx)/8] |= bmtab[(idx)&7])
#define BM_CLR_PAGE(bm, idx)	((bm)[(idx)/8] &= ~bmtab[(idx)&7])

#define BMEM_SPAN(f,t)		((size_t)((char*)(f) - (char*)(t)))


/* Bitmap Memory Manager Page Controller */
typedef struct	_BMMPC	{
	unsigned char	magic[4];	/* CRC8 + MAGIC + PAD1 + PAD2 */
	int	pages;		/* occupied pages, includes BMMPC and guards */
} BMMPC;

/* Bitmap Memory Manager Control Block */
typedef	struct	_BMMCB	{
	unsigned char	magic[4];	/* CRC8 + MAGIC + CONFIG1 + CONFIG2 */
	int	pages;		/* control block used pages, inc. BMMCB and bitmap */

	//char	*trunk;		/* point to the head of the page array */
	int	total;		/* number of allocable pages */
	int	avail;		/* number of available pages */

	unsigned char	bitmap[1];
} BMMCB;


static int bmem_verify(BMMCB *bmc, void *mem);
static void bmem_page_take(BMMCB *bmc, int idx, int pages);
static void bmem_page_free(BMMCB *bmc, int idx, int pages);
static void *bmem_find_client(BMMCB *bmc, BMMPC *mpc, size_t *osize);
static void *bmem_find_front_guard(BMMCB *bmc, BMMPC *mpc, int *osize);
static void *bmem_find_back_guard(BMMCB *bmc, BMMPC *mpc, int *osize);
static BMMPC *bmem_find_control(BMMCB *bmc, void *mem);

static inline void bmem_set_crc(void *mb, int len)
{
	register char   *p = mb;
	p[1] = (char) CSC_MEM_MAGIC_BITMAP;
	p[0] = (char) csc_crc8(0, p+1, len-1);
}

static inline int bmem_check(void *mb, int len)
{
	register char   *p = mb;
	return (p[1] == (char) CSC_MEM_MAGIC_BITMAP) &&
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
	register int	config = bmem_config_get(bmc);

	/* MemCB + front and back guards */
	return 1 + CSC_MEM_XCFG_GUARD(config) + CSC_MEM_XCFG_GUARD(config);
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

static inline size_t bmem_page_to_size(BMMCB *bmc, int page)
{
	/* no more than 64KB per page */
	return (size_t)page * CSC_MEM_XCFG_PAGE(bmem_config_get(bmc));
}

static inline int bmem_size_to_page(BMMCB *bmc, size_t size)
{
	/* no more than 64KB per page */
	register int n = CSC_MEM_XCFG_PAGE(bmem_config_get(bmc));
	return (int)((size + n - 1) / n);
}

static inline int bmem_addr_to_index(BMMCB *bmc, void *mem)
{
	/* no more than 64KB per page */
	return (int)(((char*)mem - (char*)bmc) / 
			CSC_MEM_XCFG_PAGE(bmem_config_get(bmc)));
}

static inline void *bmem_index_to_addr(BMMCB *bmc, int idx)
{
	return (char*)bmc + idx * CSC_MEM_XCFG_PAGE(bmem_config_get(bmc));
}

void *csc_bmem_init(void *mem, size_t mlen, int flags)
{
	BMMCB	*bmc;
	int	bmpage, allpage, minpage;

	if ((bmc = mem) == NULL) {
		return NULL;	/* CSC_MERR_INIT */
	}

	/* estimate how many page are there in total */
	allpage = (int)(mlen / CSC_MEM_XCFG_PAGE(flags));

	/* based on page numbers calculate the pages of the heap control block */
	bmpage = (int)(sizeof(BMMCB) + allpage / 8) / CSC_MEM_XCFG_PAGE(flags);

	/* minimum required pages: HeapCB + MemCB + FrontGUARD + BackGUARD */
	minpage = bmpage + 1 + CSC_MEM_XCFG_GUARD(flags) + CSC_MEM_XCFG_GUARD(flags);

	/* minimum pool size depends on the minimum pages can be allocated */
	if (allpage < minpage) {
		return NULL;	/* CSC_MERR_LOWMEM */
	}
	if ((allpage == minpage) && ((flags & CSC_MEM_ZERO) == 0)) {
		return NULL;	/* CSC_MERR_LOWMEM */
	}

	/* set up the control block.  Note that the control block is also part of 
	 * the memory scheme so it will take some bits in the bitmap. */
	memset((void*)bmc, 0, bmpage * CSC_MEM_XCFG_PAGE(flags));
	bmem_config_set(bmc, flags);
	bmc->pages = bmpage;
	bmc->total = allpage;
	bmc->avail = allpage - bmpage;
	bmem_page_take(bmc, 0, bmpage);		/* set the bitmap */	
	bmem_set_crc(bmc, bmem_page_to_size(bmc, bmc->pages));
	return bmc;
}

void *csc_bmem_alloc(void *heap, size_t size)
{
	BMMCB	*bmc = heap;
	BMMPC	*mpc;
	int	pages, config, padding;
	int	fnd_idx, fnd_pages = -1;

	int loose(void *mem)
	{
		mpc = mem;

		/* when it's been called, the "pages" should've been set */
		if (mpc->pages >= pages) {
			if (fnd_pages == -1) {
				fnd_pages = mpc->pages;
				fnd_idx = bmem_addr_to_index(bmc, mem);
			}
			switch (config & CSC_MEM_FITMASK) {
			case CSC_MEM_BEST_FIT:
				if (fnd_pages > mpc->pages) {
					fnd_pages = mpc->pages;
					fnd_idx = bmem_addr_to_index(bmc, mem);
				}
				break;
			case CSC_MEM_WORST_FIT:
				if (fnd_pages < mpc->pages) {
					fnd_pages = mpc->pages;
					fnd_idx = bmem_addr_to_index(bmc, mem);
				}
				break;
			default:	/* CSC_MEM_FIRST_FIT */
				/*printf("goose: now=%d prev=%d\n",  mpc->pages, pages);*/
				return 1;
			}
			/*printf("loose: now=%d prev=%d found=%d\n", mpc->pages, pages, fnd_pages);*/
		}
		return 0;
	}

	if (bmem_verify(bmc, (void*)-1) < 0) {
		return NULL;
	}
	config = (int)bmem_config_get(bmc);

	pages = bmem_size_to_page(bmc, size);
	if (!pages && !(config & CSC_MEM_ZERO)) {
		return NULL;	/* CSC_MERR_RANGE: not allow empty allocation */
	}

	/* find the size of the tail padding */
	padding = bmem_page_to_size(bmc, pages) - size;

	/* add up the service pages: the BMMPC, front and back guards */
	pages += bmem_service_pages(bmc);
	if (pages > bmc->avail) {
		return NULL;	/* CSC_MERR_RANGE */
	}

	/* find a group of free pages where meets the requirement */
	fnd_pages = -1;
	if (csc_bmem_scan(heap, NULL, loose)) {
		return NULL;	/* CSC_MERR_BROKEN: chain broken */
	}
	if (fnd_pages == -1) {
		return NULL;	/* CSC_MERR_LOWMEM */
	}

	/* take the free pages */
	bmem_page_take(bmc, fnd_idx, pages);
	bmc->avail -= pages;
	bmem_set_crc(bmc, bmem_page_to_size(bmc, bmc->pages));
	
	/* setup the Bitmap Memory Manager Page Controller */
	mpc = (BMMPC*)bmem_index_to_addr(bmc, fnd_idx);
	memset(mpc, 0, sizeof(BMMPC));
	mpc->pages = pages;
	bmem_pad_set(mpc, padding);
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
	idx = bmem_addr_to_index(bmc, mpc);
	bmem_page_free(bmc, idx, mpc->pages);
	mpc->magic[1] = (unsigned char) ~CSC_MEM_MAGIC_BITMAP;	/* set free of the page controller */
	bmem_set_crc(mpc, sizeof(BMMPC));

	bmc->avail += mpc->pages;
	bmem_set_crc(bmc, bmem_page_to_size(bmc, bmc->pages));
	return 0;
}

void *csc_bmem_scan(void *heap, int (*used)(void*), int (*loose)(void*))
{
	BMMCB	*bmc = heap;
	BMMPC	*mpc;
	int	i, last_free;

	/* setup a BMMPC structure for the free pages */
	BMMPC *make_free_mpc(int idx, int pages)
	{
		BMMPC *mpc = (BMMPC *) bmem_index_to_addr(bmc, idx);
		memset(mpc, 0, sizeof(BMMPC));
		mpc->pages = pages;
		bmem_set_crc(mpc, sizeof(BMMPC));
		return mpc;
	}

	if (bmem_verify(bmc, (void*)-1) < 0) {
		return bmc;	/* invalided memory management */
	}

	last_free = (int) -1;
	for (i = bmc->pages; i < bmc->total; i++) {
		if (!BM_CK_PAGE(bmc->bitmap, i)) {
			if (last_free == (int)-1) {
				last_free = i;
			}
			continue;
		}

		/* for inspecting the freed pages */
		if (last_free != (int)-1) {
			if (loose && loose(make_free_mpc(last_free, i - last_free))) {
				return NULL;
			}
			last_free = (int) -1;
		}

		/* found an allocated memory block */
		mpc = (BMMPC *) bmem_index_to_addr(bmc, i);
		if (bmem_verify(bmc, bmem_find_client(bmc, mpc, NULL)) < 0) {
			return mpc;
		}

		if (used && used(mpc)) {
			return NULL;
		}
		i += mpc->pages - 1; /* skip the allocated pages */
	}

	/* if rest pages are free */
	if ((last_free != (int)-1) && loose) {
		loose(make_free_mpc(last_free, i - last_free));
	}
	return NULL;
}

void *csc_bmem_scan_mapper(void *heap, void *smem)
{
	return bmem_find_client(heap, smem, NULL);
}

size_t csc_bmem_attrib(void *heap, void *mem, int *state)
{
	BMMCB	*bmc = heap;
	BMMPC	*mpc;
	int	i, idx;

	i = bmem_verify(bmc, mem);
	if (i == CSC_MERR_BROKEN) {	/* probably in the uninitially free area */
		idx = bmem_addr_to_index(bmc, mem);
		/* search for free pages */
		for (i = idx; i < bmc->total; i++) {
			if (BM_CK_PAGE(bmc->bitmap, i)) {
				break;
			}
		}
		if (i == idx) {		/* not found free pages */
			return (size_t) -1;	/* memory block corrupted */
		}
		if (state) {
			*state = -1;	/* uninitialized */
		}
		return bmem_page_to_size(bmc, i - idx);
	}
	if (i < 0) {
		return (size_t) -1;	/* invalided memory management */
	}

	mpc = bmem_find_control(bmc, mem);
	idx = bmem_addr_to_index(bmc, mpc);

	if (BM_CK_PAGE(bmc->bitmap, idx)) {
		if (state) {
			*state = 1;
		}
	
		idx = mpc->pages - bmem_service_pages(bmc);
		return bmem_page_to_size(bmc, idx) - bmem_pad_get(mpc);
	}

	if (state) {
		*state = 0;
	}
	return bmem_page_to_size(bmc, mpc->pages);
}

void *csc_bmem_extra(void *heap, void *mem, int *xsize)
{
	BMMCB	*bmc = heap;

	if (bmem_verify(bmc, mem) < 0) {
		return NULL;	/* invalided memory management */
	}

	if (xsize) {
		int pages, config = bmem_config_get(bmc);
		pages = 1 + CSC_MEM_XCFG_EXTRA(config);	/* head and extra */
		*xsize = (int)(bmem_page_to_size(bmc, pages) - sizeof(BMMPC));
	}
	return bmem_find_control(bmc, mem) + 1;
}

void *csc_bmem_front_guard(void *heap, void *mem, int *xsize)
{
	BMMCB	*bmc = heap;

	if (bmem_verify(bmc, mem) < 0) {
		return NULL;	/* invalided memory management */
	}
	return bmem_find_front_guard(bmc, bmem_find_control(bmc, mem), xsize);
}

void *csc_bmem_back_guard(void *heap, void *mem, int *xsize)
{
	BMMCB	*bmc = heap;

	if (bmem_verify(bmc, mem) < 0) {
		return NULL;	/* invalided memory management */
	}
	return bmem_find_back_guard(bmc, bmem_find_control(bmc, mem), xsize);
}


static int bmem_verify(BMMCB *bmc, void *mem)
{
	if (bmc == NULL) {
		return CSC_MERR_INIT;	/* heap not created */
	}
	if (!bmem_check(bmc, bmem_page_to_size(bmc, bmc->pages))) {
		return CSC_MERR_BROKEN;
	}

	/* Only verify the BMMCB. 
	 * Not using NULL because NULL can be a to-be-verified pointer */
	if (mem == (void*) -1) {
		return 0;
	}

	/* make sure the client memory is in range */
	if ((mem < bmem_index_to_addr(bmc, bmc->pages)) ||
			(mem > bmem_index_to_addr(bmc, bmc->total))) {
		return CSC_MERR_RANGE;	/* memory out of range */
	}

	/* Note that bmem_verify() only verify the memory blocks which have
	 * a BMMPC structure. Uninitialized will be treated as broken */
	mem = bmem_find_control(bmc, mem);	/* mem become mpc */
	if (!bmem_check(mem, sizeof(BMMPC))) {
		return CSC_MERR_BROKEN; /* broken memory controller */
	}
	return 0;
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

static void *bmem_find_client(BMMCB *bmc, BMMPC *mpc, size_t *osize)
{
	int	idx, pages, config = bmem_config_get(bmc);

	/* service pages are head, extra pages and front guards */
	idx = 1 + CSC_MEM_XCFG_EXTRA(config) + CSC_MEM_XCFG_GUARD(config);
	if (osize) {
		pages = mpc->pages - idx - CSC_MEM_XCFG_GUARD(config);	/* back guard */
		*osize = bmem_page_to_size(bmc, pages) - bmem_pad_get(mpc); 
	}
	return (char*)mpc + bmem_page_to_size(bmc, idx);
}


static void *bmem_find_front_guard(BMMCB *bmc, BMMPC *mpc, int *osize)
{
	int	guard, config = bmem_config_get(bmc);

	if ((guard = CSC_MEM_XCFG_GUARD(config)) > 0) {
		if (osize) {
			*osize = (int)bmem_page_to_size(bmc, guard);
		}
		guard = 1 + CSC_MEM_XCFG_EXTRA(config);	/* head and extra */
		return (char*)mpc + bmem_page_to_size(bmc, guard);
	}
	return NULL;
}

static void *bmem_find_back_guard(BMMCB *bmc, BMMPC *mpc, int *osize)
{
	int	pages, config = bmem_config_get(bmc);

	pages = CSC_MEM_XCFG_GUARD(config);	/* get the pages of memory guards */
	config = (int)bmem_page_to_size(bmc, pages) + bmem_pad_get(mpc);
	if (config <= 0) {
		return NULL;
	}
	if (osize) {
		*osize = config;
	}
	return (char*)mpc + bmem_page_to_size(bmc, mpc->pages) - config;
}

static BMMPC *bmem_find_control(BMMCB *bmc, void *mem)
{
	int	pages, config = bmem_config_get(bmc);

	/* find head, extra pages and front guards */
	pages = 1 + CSC_MEM_XCFG_EXTRA(config) + CSC_MEM_XCFG_GUARD(config);
	return (BMMPC*)((char*)mem - bmem_page_to_size(bmc, pages));
}


#ifdef	CFG_UNIT_TEST
#include "libcsoup_debug.h"

static void csc_bmem_function_test(char *buf, int blen);
static void csc_bmem_minimum_test(char *buf, int blen);
static void csc_bmem_fitness_test(char *buf, int blen);

int csc_bmem_unittest(void)
{
	char	buf[32*1024];

	csc_bmem_function_test(buf, sizeof(buf));
	csc_bmem_minimum_test(buf, sizeof(buf));
	csc_bmem_fitness_test(buf, sizeof(buf));
	return 0;
}

static void csc_bmem_function_test(char *buf, int blen)
{
	BMMCB	*bmc;
	BMMPC	*mpc;
	int	i, k, len;
	char	*p, *tmp;
	size_t	msize, mpage;

	/* function tests: bmem_config_set() and bmem_config_get() */
	cclog(-1, "Testing internal functions.\n");
	bmc = (BMMCB*) buf;
	memset(bmc, 0, sizeof(BMMCB));
	bmem_config_set(bmc, 0xc1c2c3c4);
	cclog(bmc->magic[2] == 0xc4 && bmc->magic[3] == 0xc3, 
			"bmem_config_set: %x %x %x %x\n",
			bmc->magic[0], bmc->magic[1], bmc->magic[2], bmc->magic[3]);
	msize = (size_t)bmem_config_get(bmc);
	cclog(msize == 0xc3c4, "bmem_config_get: %x\n", (int)msize);

	/* bmem_set_crc() and bmem_check() */
	bmem_set_crc(bmc, sizeof(BMMCB));
	cclog(bmc->magic[0] == 0x67, "bmem_set_crc: %x %x\n", bmc->magic[0], bmc->magic[1]);
	cclog(bmem_check(bmc, sizeof(BMMCB)), "bmem_check: %d %x\n", 
			bmc->magic[0], bmem_check(bmc, sizeof(BMMCB)));

	/* bmem_pad_set() and bmem_pad_get() */
	mpc = (BMMPC*)buf;
	memset(mpc, 0, sizeof(BMMPC));
	bmem_pad_set(mpc, 0xf1f2f3f4);
	cclog(mpc->magic[2] == 0xf4 && mpc->magic[3] == 0xf3, 
			"bmem_pad_set: %x %x %x %x\n",
			mpc->magic[0], mpc->magic[1], mpc->magic[2], mpc->magic[3]);
	msize = (size_t)bmem_pad_get(mpc);
	cclog(msize==0xf3f4, "bmem_pad_get: %x\n", (int)msize);

	/* page size test: bmem_page_to_size() and bmem_size_to_page() */
	for (i = 0; i < 16; i++) {
		bmem_config_set(bmc, i << 4);
		msize = bmem_page_to_size(bmc, 1);
		mpage = bmem_size_to_page(bmc, 128 * 1024);
		cclog(msize == (size_t)(32 << (i%12)), 
				"bmem_page_to_size: %d -> %d %d pages\n", i, msize, mpage);
	}

	/* bmem_find_xxx() family: bmem_find_client(), bmem_find_control(), 
	 * bmem_find_front_guard(), bmem_find_back_guard(), csc_bmem_extra() 
	 * and bmem_service_pages() */
	cclog(-1, "Testing bmem_find_xxx():\n");
	bmc = (BMMCB*)buf;
	memset(bmc, 0, sizeof(BMMCB));
	mpc = (BMMPC*)(bmc+1);
	memset(mpc, 0, sizeof(BMMPC));
	bmem_pad_set(mpc, 260);
	mpc->pages = 24;
	for (i = 0; i < 4; i++) {	/* guarding pages */
		for (k = 0; k < 4; k++) {	/* extra pages */
			bmem_config_set(bmc, (1<<4)|(k<<8)|(i<<12));
			p = bmem_find_client(bmc, mpc, &msize);
			cclog(!!p, "PSize=64 Extra=%d Guard=%d - Client=+%ld:%ld ", 
					k, i, BMEM_SPAN(p, mpc), msize);
			p = csc_bmem_extra(bmc, bmem_find_client(bmc, mpc, NULL), &len);
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

	/* testing how to find the page index in the bitmap */
	tmp = buf + bmem_page_to_size(bmc, 10) + 12;
	msize = (size_t) bmem_addr_to_index(bmc, tmp);
	cclog(msize==10, "Found page index %ld at +%ld\n", msize, BMEM_SPAN(tmp, bmc));
}

static void csc_bmem_minimum_test(char *buf, int blen)
{
	BMMCB	*bmc;
	int	config, rc[4];
	char	*p[4];
	
	(void) blen;

	/* failed to create the minimum heap: bmc=1 mpc=1 extra=0 guard=0 */
	config = CSC_MEM_DEFAULT | CSC_MEM_XCFG_SET(1,0,0);
	bmc = csc_bmem_init(buf, 2*CSC_MEM_XCFG_PAGE(config), config);
	cclog(!bmc, "Create heap with empty allocation disabled: null 2 pages\n");

	/* successful to create the minimum heap: bmc=1 mpc=1 extra=0 guard=0 */
	config |= CSC_MEM_ZERO;
	bmc = csc_bmem_init(buf, 2*CSC_MEM_XCFG_PAGE(config), config);
	if (!bmc) return;
	cclog(-1, "Created Heap(%d,%d,%d) with empty allocation enabled: bmc=%d free=%d map=%02x%02x%02x%02x\n",
			CSC_MEM_XCFG_PAGE(config), CSC_MEM_XCFG_EXTRA(config), 
			CSC_MEM_XCFG_GUARD(config), bmc->pages, bmc->avail, 
			bmc->bitmap[0], bmc->bitmap[1], bmc->bitmap[2], bmc->bitmap[3]);

	/* failed to allocate 1 byte from the empty heap */
	p[0] = csc_bmem_alloc(bmc, 1);
	cclog(!p[0], "Failed to allocate 1 byte from empty heap. [%02x]\n", bmc->bitmap[0]);

	/* succeeded to allocate 0 byte from the empty heap */
	p[0] = csc_bmem_alloc(bmc, 0);
	cclog(!!p[0], "Allocated an empty memory block. [%02x]\n", bmc->bitmap[0]); 
	rc[1] = (int)csc_bmem_attrib(bmc, p[0], rc);
	cclog(!rc[1], "Memory attribution: size=%d state=%d pad=%d\n", rc[1], rc[0],
			bmem_pad_get(bmem_find_control(bmc, p[0])));

	/* succeeded to find the extra data in the empty memory block */
	p[1] = csc_bmem_extra(bmc, p[0], rc);
	cclog(!!p[1], "The extra data: offset=+%d size=%d\n",
			BMEM_SPAN(p[1], bmem_find_control(bmc, p[0])), rc[0]);

	/* failed to find the memory guards */
	p[1] = csc_bmem_front_guard(bmc, p[0], NULL);
	p[2] = csc_bmem_back_guard(bmc, p[0], NULL);
	cclog(!p[1]&&!p[2], "Memory guards were not allocated. %p/%p\n", p[1], p[2]);

	/* free the empty memory block */
	rc[0] = csc_bmem_free(bmc, p[0]);
	cclog(rc[0] >= 0, "Freed the empty memory block. [%02x]\n", bmc->bitmap[0]);
	rc[1] = (int)csc_bmem_attrib(bmc, p[0], rc);
	cclog(rc[1] == (int)bmem_page_to_size(bmc, 1), "Memory destroied: pages=%d %d\n", 
			bmem_find_control(bmc, p[0])->pages, rc[1]);

	/* create the minimum heap: bmc=1 mpc=1 extra=1 guard=1x2 */
	config = CSC_MEM_DEFAULT | CSC_MEM_XCFG_SET(1,1,1);
	bmc = csc_bmem_init(buf, 5*CSC_MEM_XCFG_PAGE(config), config);
	cclog(!bmc, "Create heap with empty allocation disabled: null 5 pages\n");

	config |= CSC_MEM_ZERO;
	bmc = csc_bmem_init(buf, 5*CSC_MEM_XCFG_PAGE(config), config);
	if (!bmc) return;
	cclog(-1, "Created Heap(%d,%d,%d): bmc=%d free=%d map=%02x%02x%02x%02x\n",
			CSC_MEM_XCFG_PAGE(config), CSC_MEM_XCFG_EXTRA(config), 
			CSC_MEM_XCFG_GUARD(config), bmc->pages, bmc->avail, 
			bmc->bitmap[0], bmc->bitmap[1], bmc->bitmap[2], bmc->bitmap[3]);

	/* failed to allocate 1 byte from the empty heap */
	p[0] = csc_bmem_alloc(bmc, 1);
	cclog(!p[0], "Failed to allocate 1 byte from empty heap. [%02x]\n", bmc->bitmap[0]);

	/* allocated an empty memory block from the empty heap */
	p[0] = csc_bmem_alloc(bmc, 0);
	cclog(!!p[0], "Allocated an empty memory block. [%02x]\n", bmc->bitmap[0]); 
	rc[1] = (int)csc_bmem_attrib(bmc, p[0], rc);
	cclog(!rc[1], "Memory attribution: size=%d state=%d pad=%d\n", rc[1], rc[0],
			bmem_pad_get(bmem_find_control(bmc, p[0])));

	/* free the empty memory block */
	rc[0] = csc_bmem_free(bmc, p[0]);
	cclog(rc[0] >= 0, "Freed the empty memory block. [%02x]\n", bmc->bitmap[0]);
	rc[1] = (int)csc_bmem_attrib(bmc, p[0], rc);
	cclog(rc[1] == (int)bmem_page_to_size(bmc, 4), "Memory destroied: pages=%d %d\n", 
			bmem_find_control(bmc, p[0])->pages, rc[1]);

	/* create the small heap: bmc=1 mpc=1 extra=0 guard=0 */
	config = CSC_MEM_DEFAULT | CSC_MEM_XCFG_SET(1,0,0);
	bmc = csc_bmem_init(buf, 12*CSC_MEM_XCFG_PAGE(config), config);
	if (!bmc) return;
	cclog(-1, "Created Heap(%d,%d,%d): bmc=%d free=%d map=%02x%02x%02x%02x\n",
			CSC_MEM_XCFG_PAGE(config), CSC_MEM_XCFG_EXTRA(config), 
			CSC_MEM_XCFG_GUARD(config), bmc->pages, bmc->avail, 
			bmc->bitmap[0], bmc->bitmap[1], bmc->bitmap[2], bmc->bitmap[3]);

	/* allocating test */
	p[0] = csc_bmem_alloc(bmc, 1);
	p[1] = csc_bmem_alloc(bmc, CSC_MEM_XCFG_PAGE(config) + 2);
	p[2] = csc_bmem_alloc(bmc, CSC_MEM_XCFG_PAGE(config)*2 + 3);
	cclog(p[0]&&p[1]&&p[2], "Allocated 3 memory blocks: free=%d map=%02x%02x%02x%02x\n",
			bmc->avail, bmc->bitmap[0], bmc->bitmap[1], bmc->bitmap[2], bmc->bitmap[3]);
	rc[1] = (int)csc_bmem_attrib(bmc, p[0], rc);
	cclog(rc[0], "Memory attribution: off=+%d size=%d state=%d pad=%d\n", 
			BMEM_SPAN(p[0], bmc), rc[1], rc[0],
			bmem_pad_get(bmem_find_control(bmc, p[0])));
	rc[1] = (int)csc_bmem_attrib(bmc, p[1], rc);
	cclog(rc[0], "Memory attribution: off=+%d size=%d state=%d pad=%d\n",
			BMEM_SPAN(p[1], bmc), rc[1], rc[0],
			bmem_pad_get(bmem_find_control(bmc, p[1])));
	rc[1] = (int)csc_bmem_attrib(bmc, p[2], rc);
	cclog(rc[0], "Memory attribution: off=+%d size=%d state=%d pad=%d\n",
			BMEM_SPAN(p[2], bmc), rc[1], rc[0],
			bmem_pad_get(bmem_find_control(bmc, p[2])));

	/* free memory test */
	rc[0] = csc_bmem_free(bmc, p[1]);
	cclog(rc[0] >= 0, "Freed the memory block in middle: free=%d map=%02x%02x%02x%02x\n", 
			bmc->avail, bmc->bitmap[0], bmc->bitmap[1], bmc->bitmap[2], bmc->bitmap[3]);
	rc[1] = (int)csc_bmem_attrib(bmc, p[1], rc);
	cclog(!rc[0], "Memory destroied: pages=%d %d\n", 
			bmem_find_control(bmc, p[1])->pages, rc[1]);
}

static void csc_bmem_fitness_test(char *buf, int blen)
{
	BMMCB	*bmc;
	int	config, rc[4];
	char	*p[8];
	
	(void) blen;

	/* successful to create the minimum heap: bmc=2 page=32 extra=0 guard=0 */
	config = CSC_MEM_DEFAULT | CSC_MEM_XCFG_SET(0,0,0);
	bmc = csc_bmem_init(buf, 30*CSC_MEM_XCFG_PAGE(config), config);
	if (!bmc) return;
	cclog(-1, "Created Heap(%d,%d,%d): bmc=%d free=%d map=%02x%02x%02x%02x\n",
			CSC_MEM_XCFG_PAGE(config), CSC_MEM_XCFG_EXTRA(config), 
			CSC_MEM_XCFG_GUARD(config), bmc->pages, bmc->avail, 
			bmc->bitmap[0], bmc->bitmap[1], bmc->bitmap[2], bmc->bitmap[3]);

	/* create memory pattern: P2+P8+P2+P4+P2+P10 */
	p[0] = csc_bmem_alloc(bmc, 1);
	p[1] = csc_bmem_alloc(bmc, CSC_MEM_XCFG_PAGE(config)*7);
	p[2] = csc_bmem_alloc(bmc, 1);
	p[3] = csc_bmem_alloc(bmc, CSC_MEM_XCFG_PAGE(config)*3);
	p[4] = csc_bmem_alloc(bmc, 1);
	cclog(p[1]&&p[3], "Allocated 5 memory blocks: free=%d map=%02x%02x%02x%02x\n",
			bmc->avail, bmc->bitmap[0], bmc->bitmap[1], bmc->bitmap[2], bmc->bitmap[3]);

	/* create memory holes */
	csc_bmem_free(bmc, p[1]);
	csc_bmem_free(bmc, p[3]);

	/* list all candidators */
	rc[1] = (int)csc_bmem_attrib(bmc, p[1], rc);
	cclog(!rc[0], "Candidator 1: off=+%d size=%d state=%d\n", BMEM_SPAN(p[1], bmc), rc[1], rc[0]);
	rc[1] = (int)csc_bmem_attrib(bmc, p[3], rc);
	cclog(!rc[0], "Candidator 2: off=+%d size=%d state=%d\n", BMEM_SPAN(p[3], bmc), rc[1], rc[0]);
	/* manully set the next candidator because it's inside untouched area */
	p[5] = p[4] + CSC_MEM_XCFG_PAGE(config);	
	rc[1] = (int)csc_bmem_attrib(bmc, p[5], rc);
	p[5] += CSC_MEM_XCFG_PAGE(config);
	cclog(rc[0]<0, "Candidator 3: off=+%d size=%d state=%d\n", BMEM_SPAN(p[5], bmc), rc[1], rc[0]);
	cclog(bmc->avail==22, "Created 3 memory holes: free=%d map=%02x%02x%02x%02x\n",
			bmc->avail, bmc->bitmap[0], bmc->bitmap[1], bmc->bitmap[2], bmc->bitmap[3]);

	/* testing first fit */
	p[6] = csc_bmem_alloc(bmc, CSC_MEM_XCFG_PAGE(config)*3);
	if (!p[6]) return;
	rc[1] = (int)csc_bmem_attrib(bmc, p[6], rc);
	cclog(p[6]==p[1], "First Fit: off=+%d size=%d -- free=%d map=%02x%02x%02x%02x\n", 
			BMEM_SPAN(p[6], bmc), rc[1], bmc->avail, 
			bmc->bitmap[0], bmc->bitmap[1], bmc->bitmap[2], bmc->bitmap[3]);

	/* testing best fit */
	csc_bmem_free(bmc, p[6]);
	cclog(bmc->avail==22, "Created 3 memory holes: free=%d map=%02x%02x%02x%02x\n",
			bmc->avail, bmc->bitmap[0], bmc->bitmap[1], bmc->bitmap[2], bmc->bitmap[3]);

	config = (config & ~CSC_MEM_FITMASK) | CSC_MEM_BEST_FIT;
	bmem_config_set(bmc, config);
	bmem_set_crc(bmc, bmem_page_to_size(bmc, bmc->pages));

	p[6] = csc_bmem_alloc(bmc, CSC_MEM_XCFG_PAGE(config)*3);
	if (!p[6]) return;
	rc[1] = (int)csc_bmem_attrib(bmc, p[6], rc);
	cclog(p[6]==p[3], "Best Fit: off=+%d size=%d -- free=%d map=%02x%02x%02x%02x\n", 
			BMEM_SPAN(p[6], bmc), rc[1], bmc->avail, 
			bmc->bitmap[0], bmc->bitmap[1], bmc->bitmap[2], bmc->bitmap[3]);

	/* testing worst fit */
	csc_bmem_free(bmc, p[6]);
	cclog(bmc->avail==22, "Created 3 memory holes: free=%d map=%02x%02x%02x%02x\n",
			bmc->avail, bmc->bitmap[0], bmc->bitmap[1], bmc->bitmap[2], bmc->bitmap[3]);

	config = (config & ~CSC_MEM_FITMASK) | CSC_MEM_WORST_FIT;
	bmem_config_set(bmc, config);
	bmem_set_crc(bmc, bmem_page_to_size(bmc, bmc->pages));

	p[6] = csc_bmem_alloc(bmc, CSC_MEM_XCFG_PAGE(config)*3);
	if (!p[6]) return;
	rc[1] = (int)csc_bmem_attrib(bmc, p[6], rc);
	cclog(p[6]==p[5], "Worst Fit: off=+%d size=%d -- free=%d map=%02x%02x%02x%02x\n", 
			BMEM_SPAN(p[6], bmc), rc[1], bmc->avail, 
			bmc->bitmap[0], bmc->bitmap[1], bmc->bitmap[2], bmc->bitmap[3]);
}

#endif

#if 0
static int bmem_guard_setup(BMMCB *bmc, BMMPC *mpc)
{
	char	*p;
	int	len;

	if ((p = bmem_find_front_guard(bmc, mpc, &len)) != NULL) {
		memset(p, BMEM_MAGPIE, len);
	}
	if ((p = bmem_find_back_guard(bmc, mpc, &len)) != NULL) {
		memset(p, BMEM_MAGPIE, len);
	}
	return 0;
}

static void *bmem_guard_verify(BMMCB *bmc, BMMPC *mpc)
{
	char	*p;
	int	len;

	if ((p = bmem_find_front_guard(bmc, mpc, &len)) != NULL) {
		for ( ; len > 0; len--, p++) {
			if (*p != (char) BMEM_MAGPIE) {
				return p;
			}
		}
	}
	if ((p = bmem_find_back_guard(bmc, mpc, &len)) != NULL) {
		for ( ; len > 0; len--, p++) {
			if (*p != (char) BMEM_MAGPIE) {
				return p;
			}
		}
	}
	return NULL;
}
#endif
