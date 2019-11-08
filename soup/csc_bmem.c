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
  [BMMPC+padding][page1][page2]...[pageN]
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libcsoup.h"


/* page has 12 setting: 32/64/128/256/512/1k/2k/4k/8k/16k/32k/64k
 * so that the padding size can be limited in 64k */

#define BMEM_GUARD	0	/* 0: Miniman GUARD; 1: 1 PAGE OF GUARD */
#define	BMEM_GU_MAGIC	0xaa
#define BMEM_MAGIC	0xAC

#define	MKMAGIC(n)		((n)[0]|(n)[1]<<8|(n)[2]<<16|(n)[3]<<24)
#define BMEM_MAGIC_CB		MKMAGIC("BMMC")
#define	BMEM_MAGIC_USED		MKMAGIC("BMMU")
#define BMEM_MAGIC_FREE		MKMAGIC("BMMF")


#define BMPAGE(n)		(((n) + bmem_page_size(bmc) - 1) / bmem_page_size(bmc))

static	unsigned char	bmtab[8] = { 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80 };
#define BM_CK_PAGE(bm, idx)	((bm)[(idx)/8] & bmtab[(idx)&7])
#define BM_SET_PAGE(bm, idx)	((bm)[(idx)/8] |= bmtab[(idx)&7])
#define BM_CLR_PAGE(bm, idx)	((bm)[(idx)/8] &= ~bmtab[(idx)&7])

#if	BMEM_GUARD == 0
#define BMEM_PC_TO_MEM(p)	(void*)((char*)(p) + bmem_page_size(bmc))
#define BMEM_MEM_TO_PC(p)	(void*)((char*)(p) - bmem_page_size(bmc))
#define bmem_extra_page(bmc)		1
#else
#define BMEM_PC_TO_MEM(p)	(void*)((char*)(p) + BMEM_GUARD * bmem_page_size(bmc))
#define BMEM_MEM_TO_PC(p)	(void*)((char*)(p) - BMEM_GUARD * bmem_page_size(bmc))
#define bmem_extra_page(bmc)		(BMEM_GUARD + BMEM_GUARD)
#endif
#define BMEM_PC_SIZE(p)		(((p)->pages - bmem_extra_page(bmc)) * bmem_page_size(bmc) - (p)->pad)



/* Bitmap Memory Manager Page Controller */
typedef struct	_BMMPC	{
	char	magic[4];	/* CRC8 + MAGIC + PAD1 + PAD2 */
	uint	pages;		/* occupied pages, includes BMMPC and guards */
} BMMPC;

/* Bitmap Memory Manager Control Block */
typedef	struct	_BMMCB	{
	char	magic[4];	/* CRC8 + MAGIC + CONFIG1 + CONFIG2 */
	uint	pages;		/* control block used pages, inc. BMMCB and bitmap */

	char	*trunk;		/* point to the head of the page array */
	uint	total;		/* number of allocable pages */
	uint	avail;		/* number of available pages */

	unsigned char	bitmap[1];
} BMMCB;

typedef int (*BMap_F)(BMMPC *mpc, uint index, uint pages);

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


void *csc_bmem_init(void *mem, size_t mlen, int flags)
{
	BMMCB	*bmc;
	uint	bmlen, pages;
	int	psize = bmem_get_page_size(flags);

	if (mem == NULL) {
		return NULL;	/* CSC_MERR_INIT */
	}

	/* estimate how many page are there */
	pages = (uint)(mlen / psize);

	/* based on page numbers calculate the pages of the control block */
	bmlen = sizeof(BMMCB) + pages / 8;
	bmlen = (bmlen + psize -1) / psize;

	/* minimum pool size depends on the minimum pages can be allocated, 
	 * which depends on BMEM_GUARD:
	 * BMEM_GUARD = 0: minimum pool = 1
	 * BMEM_GUARD = 1: minimum pool = 2
	 * BMEM_GUARD = 2: minimum pool = 4
	 * BMEM_GUARD = 3: minimum pool = 6
	 */
	if (pages < bmem_extra_page(bmc) + bmlen) {
		return NULL;	/* CSC_MERR_LOWMEM */
	}

	/* reduce the page numbers to fit in the control block */
	pages -= bmlen;
	if ((pages == 0) && ((config & CSC_MEM_ZERO) == 0)) {
		return NULL;	/* CSC_MERR_LOWMEM */
	}

	/* set up the control block in the end of the memory block in page boundry */
	bmc = (BMMCB*) ((char*)mem + pages * psize);
	memset((void*)bmc, 0, bmlen * psize);
	bmc->magic[2] = (char)(flags & 0xff);
	bmc->magic[3] = (char)((flags >> 8) & 0xff);
	bmc->pages = bmlen;
	bmc->trunk = mem;
	bmc->total = bmc->avail = pages;
	bmem_set_crc(bmc, bmlen*psize);
	return bmc;
}

void *csc_bmem_alloc(BMMCB *bmc, size_t size)
{
	BMMPC	*mpc;
	uint	idx, pages;

	if (bmem_validing(bmc)) {
		return NULL;
	}

	/* front guard is BMEM_GUARD - 1 because BMMPC plays as guard too */
	pages = BMPAGE(size) + bmem_extra_page(bmc);
	if (pages > bmc->avail) {
		//printf("bmem_alloc: %d %d\n", pages, bmc->avail);
		return NULL;
	}

	if ((idx = bmem_page_finder(bmc, pages)) == (uint) -1) {
		//printf("bmem_alloc: not found.\n");
		return NULL;
	}

	/* take the free pages */
	bmem_page_take(bmc, idx, pages);
	bmc->avail -= pages;
	
	/* setup the Bitmap Memory Manager Page Controller */
	mpc = (BMMPC*)(bmc->trunk + idx * bmem_page_size(bmc));
	memset(mpc, 0, sizeof(BMMPC));
	mpc->magic = BMEM_MAGIC_USED;
	mpc->pages = pages;
	mpc->pad  = (int)(BMPAGE(size) * bmem_page_size(bmc) - size);

	/* setup guards */
	bmem_guard_setup(mpc);
	return BMEM_PC_TO_MEM(mpc);
}

int bmem_free(BMMCB *bmc, void *mem)
{
	BMMPC	*mpc;
	uint	idx;

	if (bmem_validing(bmc)) {
		return -1;	/* invalided memory management */
	}
	if ((char*)mem < bmc->trunk + bmem_page_size(bmc)) {
		return -2;	/* memory out of boundry */
	}
	if ((char*)mem > bmc->trunk + bmc->total * bmem_page_size(bmc)) {
		return -2;	/* memory out of boundry */
	}

	mpc = BMEM_MEM_TO_PC(mem);
	if (bmem_verify(mpc) < 0) {
		return -3;	/* invalid memory block */
	}
	if (mpc->magic == BMEM_MAGIC_FREE) {
		return 0;	/* already been freed */
	}

	/* set free of these pages */
	idx = bmem_page_index(bmc, mpc);
	bmem_page_free(bmc, idx, mpc->pages);
	mpc->magic = BMEM_MAGIC_FREE;
	bmc->avail += mpc->pages;
	return 0;
}


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
				mpc = (BMMPC *)(bmc->trunk + last_free * bmem_page_size(bmc));
				bm_freed(mpc, last_free, i - last_free);
			}
			last_free = (uint) -1;
		}

		/* found an allocated memory block */
		mpc = (BMMPC *)(bmc->trunk + i * bmem_page_size(bmc));
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
			mpc = (BMMPC *)(bmc->trunk + last_free * bmem_page_size(bmc));
			bm_freed(mpc, last_free, i - last_free);
		}
	}
	return err;
}

static int bmem_get_page_size(int flags)
{
	int	n = ((flags & CSC_MEM_PAGEMASK) >> 4);

	if (n > 12) n = 12;
	return 32<<n;
}

static int bmem_page_size(BMMCB *bmc)
{
	int	n = (((int)bmc->magic[2] & CSC_MEM_PAGEMASK) >> 4);
	if (n > 12) n = 12;
	return 32<<n;
}

static int bmem_extra_page(BMMCB *bmc)
{
	int	flags = (bmc->magic[3] << 8) | bmc->magic[2];
	int	guard = (flags & CSC_MEM_GURDMASK) >> 12;
	
	if (guard == 0) {
		guard = 1;
	} else {
		guard += guard;
	}
	guard += (flags & CSC_MEM_EXTRMASK) >> 8;
	return guard;
}

static int bmem_validing(BMMCB *bmc)
{
	if (bmc->magic != BMEM_MAGIC_CB) {
		return -1;
	}
	return 0;
}

static int bmem_verify(BMMPC *mpc)
{
	if (mpc->magic == BMEM_MAGIC_FREE) {
		return 1;	/* WARNING: already been freed */
	}
	if (mpc->magic != BMEM_MAGIC_USED) {
		return -1;	/* ERROR: invalid memory block */
	}
	
	/* verify the memory */
	if (bmem_guard_verify(mpc) != 0) {
		return 2;	/* WARNING: memory overflowed */
	}
	return 0;
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
	if (off % bmem_page_size(bmc) != 0) {
		return (uint) -1;	/* unaligned memory */
	}

	idx = (uint)(off / bmem_page_size(bmc));
	if (idx >= bmc->total) {
		return (uint) -1;	/* memory out of high boundry */
	}
	return idx;
}

static void *bmem_find_front_guard(BMMPC *mpc, int *len)
{
	if (len) {
		*len = (bmem_extra_page(bmc) - BMEM_GUARD) * bmem_page_size(bmc) - sizeof(BMMPC);
	}
	return &mpc[1];
}

static void *bmem_find_back_guard(BMMPC *mpc, int *len)
{
	if (len) {
		*len = BMEM_GUARD * bmem_page_size(bmc) + mpc->pad;
	}
	return (char*)mpc + (mpc->pages - BMEM_GUARD) * bmem_page_size(bmc) - mpc->pad;
}

static int bmem_guard_setup(BMMPC *mpc)
{
	char	*p;
	int	len;

	p = bmem_find_front_guard(mpc, &len);
	memset(p, BMEM_GU_MAGIC, len);
	p = bmem_find_back_guard(mpc, &len);
	memset(p, BMEM_GU_MAGIC, len);
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
		if (p[i] != BMEM_GU_MAGIC) {
			return (long)&p[i] - (long)BMEM_PC_TO_MEM(mpc);
		}
	}

	p = bmem_find_back_guard(mpc, &len);
	for (i = 0; i < len; i++) {
		if (p[i] != BMEM_GU_MAGIC) {
			return (long)&p[i] - (long)BMEM_PC_TO_MEM(mpc);
		}
	}
	return 0;
}
