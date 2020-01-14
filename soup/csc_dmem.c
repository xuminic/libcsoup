
/*!\file       csc_dmem.c
   \brief      dynamic memory management based on doubly linked list

   The file supports a group of functions of dynamic memory 
   management based on doubly linked list. 

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

#include <stdio.h>
#include <limits.h>
#include <string.h>

#include "libcsoup.h"

#define DMEM_FREE	0
#define DMEM_USED	0x80
#define DMEM_PAD_MASK	0x7f

#define DMEM_OWNED(n)	((((DMEM*)(n))->magic[2]) & DMEM_USED)
#define DMEM_PADDED(n)	((((DMEM*)(n))->magic[2]) & DMEM_PAD_MASK)

#define DMEM_GUARD(c)	(CSC_MEM_GETPG(c) * 2)

typedef	struct	_DMEM	{
	unsigned char	magic[4];	/* CRC8 + MAGIC + USAGE|PAD + RSV */
	struct	_DMEM	*prev;
	struct	_DMEM	*next;
	size_t	size;		/* size of the payload in bytes, includes paddings */
} DMEM;

typedef	struct	_DMHEAP	{
	unsigned char	magic[4];	/* CRC8 + MAGIC + CONFIG1 + CONFIG2 */
	struct	_DMEM	*prev;	/* point to the first memory block */
	struct	_DMEM	*next;	/* point to the last memory block */
	size_t	al_size;	/* total allocated size */
	size_t	al_num;		/* number of allocated blocks */
	size_t	fr_size;	/* total free size */
	size_t	fr_num;		/* number of free blocks */
} DMHEAP;

static int dmem_verify(void *heap, DMEM *cm);
static void *dmem_find_client(void *heap, DMEM *cm, size_t *osize);
static DMEM *dmem_find_control(void *heap, void *mem);


static inline void dmem_set_crc(void *mb, int len)
{
	register char	*p = mb;
	p[1] = (char) CSC_MEM_MAGIC_DLINK;
	p[0] = (char) csc_crc8(0, p+1, len-1);
}

static inline int dmem_check(void *mb, int len)
{
	register char	*p = mb;
	return (p[1] == (char) CSC_MEM_MAGIC_DLINK) && 
		(p[0] == (char) csc_crc8(0, p+1, len-1));
}

static inline void dmem_config_set(DMHEAP *hman, int config)
{
	hman->magic[2] = (unsigned char)(config & 0xff);
	hman->magic[3] = (unsigned char)((config >> 8) & 0xff);
}

static inline int dmem_config_get(DMHEAP *hman)
{
	return (int)((hman->magic[3] << 8) | hman->magic[2]);
}

void *csc_dmem_init(void *heap, size_t len, int flags)
{
	DMHEAP	*hman;
	DMEM	*cm;
	int	min;

	if (heap == NULL) {
		return heap;	/* CSC_MERR_INIT */
	}

	/* round up the len to int boundary */
	len = len / sizeof(int) * sizeof(int);
	min = sizeof(DMHEAP) + sizeof(DMEM) + DMEM_GUARD(flags);

	if ((int)len < min) {
		return NULL;	/* CSC_MERR_LOWMEM */
	} else if (((int)len == min) && !(flags & CSC_MEM_ZERO)) {
		return NULL;	/* CSC_MERR_RANGE: not allow empty allocation */
	}

	/* create the first block and set it free */
	hman = (DMHEAP*)heap;	/* set ready the management block */
	cm = (DMEM*)&hman[1];	/* right after the management block */
	cm->prev = cm->next = NULL;
	cm->size = len - sizeof(DMHEAP) - sizeof(DMEM);
	cm->magic[2] = (char) DMEM_FREE;
	cm->magic[3] = 0;
	dmem_set_crc(cm, sizeof(DMEM));

	/* create the heap management block */
	hman->prev = hman->next = cm;
	hman->al_size = 0;
	hman->al_num  = 0;
	hman->fr_size = cm->size;
	hman->fr_num  = 1;
	dmem_config_set(hman, flags);
	dmem_set_crc(hman, sizeof(DMHEAP));
	return heap;
}

void *csc_dmem_scan(void *heap, int (*used)(void*), int (*loose)(void*))
{
	DMEM	*cm;

	for (cm = ((DMHEAP*)heap)->prev; cm != NULL; cm = cm->next) {
		if (dmem_verify(heap, cm) < 0) {
			return cm;
		}
		if (DMEM_OWNED(cm)) {
			if (used && used(dmem_find_client(heap, cm, NULL))) {
				break;
			}
		} else {
			if (loose && loose(dmem_find_client(heap, cm, NULL))) {
				break;
			}
		}
	}
	return NULL;
}

void *csc_dmem_alloc(void *heap, size_t n)
{
	DMHEAP	*hman;
	DMEM	*found, *next;
	size_t	realn, nextlen, min;
	char	*mem;
	int	config;

	int loose(void *mem)
	{
		DMEM	*cm = dmem_find_control(heap, mem);

		if (cm->size >= n) {
			found = (found == NULL) ? cm : found;
			switch (config & CSC_MEM_FITMASK) {
			case CSC_MEM_BEST_FIT:
				if (found->size > cm->size) {
					found = cm;
				}
				break;
			case CSC_MEM_WORST_FIT:
				if (found->size < cm->size) {
					found = cm;
				}
				break;
			default:	/* CSC_MEM_FIRST_FIT */
				return 1;
			}
		}
		return 0;
	}

	if (dmem_verify(heap, (void*)-1) < 0) {
		return NULL;
	}

	hman = heap;
	config = dmem_config_get(hman);

	realn = (n + sizeof(int) - 1) / sizeof(int) * sizeof(int); /* round up */
	realn += DMEM_GUARD(config);	/* add up the guarding area */

	if (realn > hman->fr_size) {
		return NULL;	/* CSC_MERR_LOWMEM */
	} else if (((int)realn == DMEM_GUARD(config)) && !(config & CSC_MEM_ZERO)) {
		return NULL;	/* CSC_MERR_RANGE: not allow empty allocation */
	}

	found = NULL;
	if (csc_dmem_scan(heap, NULL, loose)) {
		return NULL;	/* CSC_MERR_BROKEN: chain broken */
	}
	if (found == NULL) {
		return NULL;	/* CSC_MERR_LOWMEM */
	}

	nextlen = found->size - realn;
	min = sizeof(DMEM) + DMEM_GUARD(config);

	if ((nextlen > min) || ((nextlen == min) && (config & CSC_MEM_ZERO))) {
		/* go split */
		next = (DMEM*)((char*)found + sizeof(DMEM) + realn);
		next->prev = found;
		next->next = found->next;
		next->size = nextlen - sizeof(DMEM);
		next->magic[2] = (char) DMEM_FREE;
		next->magic[3] = 0;
		dmem_set_crc(next, sizeof(DMEM));

		found->next = next;
		found->size -= nextlen;

		hman->fr_size -= found->size + sizeof(DMEM);
		hman->next = hman->next < next ? next : hman->next;
	} else {
		hman->fr_size -= found->size;
		hman->fr_num--;
	}

	found->magic[2] = (unsigned char)(realn - DMEM_GUARD(config) - n);
	found->magic[2] |= DMEM_USED;
	dmem_set_crc(found, sizeof(DMEM));

	hman->al_size += found->size;
	hman->al_num++;
	dmem_set_crc(hman, sizeof(DMHEAP));

	mem = (char*)(found+1) + CSC_MEM_GETPG(config);
	if (config & CSC_MEM_CLEAN) {
		memset(mem, 0, n);
	}
	return mem;
}

int csc_dmem_free(void *heap, void *mem)
{
	DMHEAP	*hman;
	DMEM	*cm, *other;
	int	rc;

	if (mem == NULL) {
		return CSC_MERR_RANGE;
	}

	cm = dmem_find_control(heap, mem);
	if ((rc = dmem_verify(heap, cm)) < 0) {
		return rc;
	}

	if (!DMEM_OWNED(cm)) {
		return 0;	/* freeing a freed memory */
	}

	/* update the freed size */
	cm->magic[2] = DMEM_FREE;
	hman = (DMHEAP*) heap;
	hman->al_size -= cm->size;
	hman->al_num--;
	hman->fr_size += cm->size;
	hman->fr_num++;

	/* try to down merge the free block */
	other = cm->next;
	if (other && !DMEM_OWNED(other)) {
		cm->size += other->size + sizeof(DMEM);
		cm->next = other->next;
		if (other->next) {
			other->next->prev = cm;
			dmem_set_crc(other->next, sizeof(DMEM));
		}
		other->magic[0] = other->magic[1] = 0;	/* liquidate the control block */
		hman->fr_size += sizeof(DMEM);
		hman->fr_num--;
		if (hman->next == other) {
			hman->next = cm;
		}
	}

	/* try to up merge the free block */
	other = cm->prev;
	if (other && !DMEM_OWNED(other)) {
		other->size += cm->size + sizeof(DMEM);
		other->next = cm->next;
		if (cm->next) {
			cm->next->prev = other;
			dmem_set_crc(cm->next, sizeof(DMEM));
		}
		cm->magic[0] = cm->magic[1] = 0;	/* liquidate the control block */
		hman->fr_size += sizeof(DMEM);
		hman->fr_num--;
		if (hman->next == cm) {
			hman->next = other;
		}
		cm = other;
	}
	dmem_set_crc(hman, sizeof(DMHEAP));
	dmem_set_crc(cm, sizeof(DMEM));
	return 0;
}

size_t csc_dmem_attrib(void *heap, void *mem, int *state)
{
	DMEM	*cm;
	int	rc;
	size_t	len;

	if (state == NULL) {
		state = &rc;
	}

	if (mem == NULL) {
		*state = CSC_MERR_RANGE;
		return (size_t) -1;
	}

	cm = dmem_find_control(heap, mem);
	if ((rc = dmem_verify(heap, cm)) < 0) {
		*state = rc;
		return (size_t)-1;
	}
	
	*state = DMEM_OWNED(cm) ? 1 : 0;

	/* should not happen in theory: the remain memory is smaller than
	 * the guarding area. It should've been sorted out in the allocation 
	 * function already */
	len = cm->size - DMEM_PADDED(cm) - DMEM_GUARD(dmem_config_get(heap));
	if (cm->size < (size_t)DMEM_PADDED(cm) + DMEM_GUARD(dmem_config_get(heap))) {
		*state = (int) len;
		return (size_t) -1;
	}
	return len;
}


void *csc_dmem_front_guard(void *heap, void *mem, int *xsize)
{
	DMEM	*cm;
	int	rc;

	if (xsize == NULL) {
		xsize = &rc;
	}
	
	if (mem == NULL) {
		*xsize = CSC_MERR_RANGE;
		return NULL;
	}
	
	cm = dmem_find_control(heap, mem);
	if ((rc = dmem_verify(heap, cm)) < 0) {
		*xsize = rc;
		return NULL;    /* memory heap not available */
	}

	/* make sure the memory block was allocated. pointless to guard a free block */
	if (!DMEM_OWNED(cm)) {
		*xsize = 0;
		return NULL;
	}

	*xsize = CSC_MEM_GETPG(dmem_config_get(heap));
	return (void*)(cm + 1);
}

void *csc_dmem_back_guard(void *heap, void *mem, int *xsize)
{
	DMEM	*cm;
	int	rc;

	if (xsize == NULL) {
		xsize = &rc;
	}
	
	if (mem == NULL) {
		*xsize = CSC_MERR_RANGE;
		return NULL;
	}
	
	cm = dmem_find_control(heap, mem);
	if ((rc = dmem_verify(heap, cm)) < 0) {
		*xsize = rc;
		return NULL;    /* memory heap not available */
	}

	/* make sure the memory block was allocated. pointless to guard a free block */
	if (!DMEM_OWNED(cm)) {
		*xsize = 0;
		return NULL;
	}

	*xsize = CSC_MEM_GETPG(dmem_config_get(heap)) + DMEM_PADDED(cm);
	return (char*)mem + sizeof(DMEM) + cm->size - *xsize;
}

static int dmem_verify(void *heap, DMEM *mblock)
{
	if (heap == NULL) {
		return CSC_MERR_INIT;	/* heap not created */
	}
	if (!dmem_check(heap, sizeof(DMHEAP))) {
		return CSC_MERR_BROKEN;
	}

	/* Only verify the heap; not using NULL because NULL is valid */
	if (mblock == (DMEM*) -1) {
		return 0;
	}

	if ((mblock < ((DMHEAP*)heap)->prev) || (mblock > ((DMHEAP*)heap)->next)) {
		return CSC_MERR_RANGE;	/* memory out of range */
	}
	if (!dmem_check(mblock, sizeof(DMEM))) {
		return CSC_MERR_BROKEN;	/* broken memory controller */
	}
	return 0;
}

static void *dmem_find_client(void *heap, DMEM *cm, size_t *osize)
{
	char	*p;
	int	config = dmem_config_get(heap);

	p = (char*)(cm + 1) + CSC_MEM_GETPG(config);
	if (osize) {
		*osize = cm->size - DMEM_PADDED(cm) - DMEM_GUARD(config);
	}
	return p;
}

static DMEM *dmem_find_control(void *heap, void *mem)
{
	register int	config = dmem_config_get(heap);

	return (DMEM*) ((char*)mem - sizeof(DMEM) - CSC_MEM_GETPG(config));
}

#ifdef	CFG_UNIT_TEST
#include "libcsoup_debug.h"

#define BMEM_SPAN(f,t)		((size_t)((char*)(t) - (char*)(f)))
#define DMEM_MDATA(n,k)		(unsigned char)(((DMEM*)(n))->magic[k])

static int dmem_test_function(void *buf, int len);
static int dmem_test_empty(void *buf, int len);
static int dmem_test_minimum(void *buf, int len);
static void dmem_heap_status(DMHEAP *hman, size_t used, size_t freed);

int csc_dmem_unittest(void)
{
	char     buf[40960];
	
	dmem_test_function(buf, sizeof(buf));
	dmem_test_empty(buf, sizeof(buf));
	dmem_test_minimum(buf, sizeof(buf));
	return 0;
}

static int dmem_test_function(void *buf, int len)
{
	unsigned char   *p, *q;
	DMEM	*cm;
	size_t	msize;

	cclog(-1, "Size of Heap manager: %d; size of memory manager: %d\n", 
			sizeof(DMHEAP), sizeof(DMEM));

	memset(buf, 0, 4);
        p = buf;
        dmem_config_set(buf, 0xc1c2c3c4);
        cclog(p[2] == 0xc4 && p[3] == 0xc3, "dmem_config_set: %x %x %x %x\n",
                        p[0], p[1], p[2], p[3]);
	len = dmem_config_get(buf);
        cclog(len == 0xc3c4, "dmem_config_get: %x\n", len);

	dmem_set_crc(buf, sizeof(DMEM));
	p[3]++;
	len = csc_crc8(0, ((char*)buf) + 1, sizeof(DMEM) - 1);
	cclog(!dmem_check(buf, sizeof(DMEM)), "dmem_set_crc: %x %x vs %x\n", p[0], p[1], len);

	msize = 1024;
	len = CSC_MEM_DEFAULT | CSC_MEM_SETPG(1,2);
	p = csc_dmem_init(buf, msize, len);
	cclog(!!p, "Create heap(%d,%d) with %ld bytes: %p.\n",
			CSC_MEM_PAGE(len), CSC_MEM_GUARD(len), msize, p);

	cm = (DMEM*)(p + sizeof(DMHEAP));	/* move to the first block */
	cclog(!dmem_verify(buf, (DMEM*)cm), "First memory block at: +%d\n", BMEM_SPAN(buf, cm));
	if (dmem_verify(buf, cm)) return -1;

	p = dmem_find_client(buf, cm, &msize);
	cclog(BMEM_SPAN(cm, p) == CSC_MEM_GETPG(len) + sizeof(DMEM), 
		"Client of the first memory block: +%d (%u)\n", BMEM_SPAN(buf, p), msize);

	p = (void*) dmem_find_control(buf, p);
	cclog(p == (void*)cm, "Managing block at: +%d\n", BMEM_SPAN(buf, p));
	dmem_heap_status(buf, 0, 1);

	p = csc_dmem_alloc(buf, 29);
	dmem_heap_status(buf, 1, 1);

	cm = dmem_find_control(buf, p);
	cclog(!!p, "Allocated a memory at: +%d (%u)\n", BMEM_SPAN(buf, p), cm->size);

	msize = csc_dmem_attrib(buf, p, NULL);
	cclog(msize == 29, "Allocated size: %u  Pad=%d\n", msize, DMEM_PADDED(cm));

	q = csc_dmem_front_guard(buf, p, &len);
	cclog(!!q, "Front guard at: +%d (%d)\n", BMEM_SPAN(buf, q), len);
	q = csc_dmem_back_guard(buf, p, &len);
	cclog(!!q, "Back guard at: +%d (%d)\n", BMEM_SPAN(buf, q), len);

	if ((cm = cm->next) == NULL) return -1;
	cclog(!dmem_verify(buf, cm), 
			"The next memory block is free: +%d (%x) %u\n", 
			BMEM_SPAN(buf, cm), cm->magic[2], cm->size);

	q = dmem_find_client(buf, cm, &msize);
	cclog(!!q, "The client area of the free block: +%d (%u)\n", 
			BMEM_SPAN(buf, q), msize);

	msize = csc_dmem_attrib(buf, q, &len);
	cclog(len == 0, "The size of the free block: %u\n", msize);

	csc_dmem_free(buf, p);
	msize = csc_dmem_attrib(buf, p, &len);
	cclog(len == 0, "Free the allocated memory: %u\n", msize);
	dmem_heap_status(buf, 0, 1);

	len = csc_dmem_free(buf, p);
	cclog(len == 0, "Double free is Okey.\n");
	return 0;
}

static int dmem_test_empty(void *buf, int len)
{
	DMHEAP	*hman;
	size_t	msize;
	char	*mem;

	/********************************************************************
	 * testing the empty heap
	 *******************************************************************/
	msize = sizeof(DMHEAP) + sizeof(DMEM);
	hman = csc_dmem_init(buf, msize, CSC_MEM_DEFAULT);
	cclog(!hman, "Mmeory pool is too small to create a heap: %d\n", msize);

	hman = csc_dmem_init(buf, msize, CSC_MEM_DEFAULT | CSC_MEM_ZERO);
	cclog(-1, "Created an empty heap: %d\n", msize);
	if (hman == NULL) return -1;
	dmem_heap_status(hman, 0, 1);

	mem = csc_dmem_alloc(hman, 1);
	cclog(!mem, "Can not allocate 1 byte from the empty heap\n");
	mem = csc_dmem_alloc(hman, 0);
	cclog(!!mem, "Allocated 0 byte from the empty heap: +%d\n", BMEM_SPAN(hman, mem));
	dmem_heap_status(hman, 1, 0);

	len = csc_dmem_free(hman, mem);
	cclog(len == 0, "Free 0 byte from the empty heap: +%d\n", BMEM_SPAN(hman, mem));
	dmem_heap_status(hman, 0, 1);
	return 0;
}

static int dmem_test_minimum(void *buf, int len)
{
	DMEM	*cm;
	DMHEAP	*hman;
	size_t	msize;
	char	*p[8];
	int	s[4];

	/********************************************************************
	 * testing the minimum heap
	 *******************************************************************/
	msize = sizeof(DMHEAP) + sizeof(DMEM) + sizeof(int);
	hman = csc_dmem_init(buf, msize, CSC_MEM_DEFAULT);
	cclog(!!hman, "The minimum heap is created: %u\n", msize);
	if (hman == NULL) return -1;
	cclog(-1, "The minimum heap size: %u\n", hman->fr_size);
	dmem_heap_status(hman, 0, 1);

	cm = (DMEM *)(hman + 1);
	p[0] = dmem_find_client(hman, cm, NULL);
	msize = csc_dmem_attrib(hman, p[0], &s[0]);
	cclog(!s[0]&&(msize==sizeof(int)), "Memory attribute: Memory %s %u\n", 
			s[0] ? "used" : "free", msize);

	p[0] = csc_dmem_alloc(hman, 0);
	cclog(!p[0], "Not allow to allocate empty memory: %p\n", p[0]);

	p[0] = csc_dmem_alloc(hman, 3);
	msize = csc_dmem_attrib(hman, p[0], &s[0]);
	cclog(!!p[0] && s[0], "Try to allocate %u byte at: +%d\n", msize, BMEM_SPAN(hman, p[0]));
	cm = dmem_find_control(hman, p[0]);
	cclog(DMEM_PADDED(cm) == 1, "Usage Flags and paddning size: %x\n", cm->magic[2]);
	dmem_heap_status(hman, 1, 0);

	s[0] = csc_dmem_free(hman, p[0]);
	msize = csc_dmem_attrib(hman, p[0], &s[1]);
	cclog(!s[0] && !s[1], "Free the memory gets %u bytes\n", msize);
	dmem_heap_status(hman, 0, 1);

#if 0
	/********************************************************************
	 * testing the free function in minimum heap
	 *******************************************************************/
	cm = csc_dmem_init(buf, sizeof(buf), CSC_MEM_DEFAULT);
	if (cm == NULL) return 0;
	hman = (DMHEAP*)(cm+1);
	cclog(-1, "The test heap is created: %p %d\n", cm, (int)hman->fr_size);

	/* testing down-merge the free space */
	p[0] = csc_dmem_alloc(cm, 12);
	cclog(p[0] != NULL, "Allocated %p: %ld\n", p[0], csc_dmem_attrib(cm, p[0], NULL));
	p[1] = csc_dmem_alloc(cm, 24);
	cclog(p[1] != NULL, "Allocated %p: %ld\n", p[1], csc_dmem_attrib(cm, p[1], NULL));
	p[2] = csc_dmem_alloc(cm, 36);
	cclog(p[2] != NULL, "Allocated %p: %ld\n", p[2], csc_dmem_attrib(cm, p[2], NULL));
	p[3] = csc_dmem_alloc(cm, 16);
	cclog(p[3] != NULL, "Allocated %p: %ld\n", p[3], csc_dmem_attrib(cm, p[3], NULL));
	cclog(dmem_heap_state(cm, 5, 1), "End=%p used=%ld usize=%ld freed=%ld fsize=%ld\n", 
			hman->next, hman->al_num, hman->al_size, hman->fr_num, hman->fr_size);


	/* create a hole: USED FREE USED USED FREE */
	s[0] = csc_dmem_free(cm, p[1]);
	msize = csc_dmem_attrib(cm, p[1], &s[1]);
	cclog(s[0] == 0 && s[1] == 0, "Freed %p: %ld (%s)\n", p[1], msize, s[1]?"used":"free");
	cclog(dmem_heap_state(cm, 4, 2), "End=%p used=%ld usize=%ld freed=%ld fsize=%ld\n", 
			hman->next, hman->al_num, hman->al_size, hman->fr_num, hman->fr_size);

	/* down merge the first two memory: (FREE FREE) USED USED FREE */
	s[0] = csc_dmem_free(cm, p[0]);
	msize = csc_dmem_attrib(cm, p[0], &s[1]);
	cclog(s[0] == 0 && s[1] == 0, "Down merge %p: %ld (%s)\n", p[0], msize, s[1]?"used":"free");
	cclog(dmem_heap_state(cm, 3, 2), "End=%p used=%ld usize=%ld freed=%ld fsize=%ld\n", 
			hman->next, hman->al_num, hman->al_size, hman->fr_num, hman->fr_size);

	/* up merge the three memories: (FREE FREE FREE) USED FREE */
	s[0] = csc_dmem_free(cm, p[2]);
	msize = csc_dmem_attrib(cm, p[0], &s[1]);
	cclog(s[0] == 0 && s[1] == 0, "Up merge %p: %ld (%s)\n", p[2], msize, s[1]?"used":"free");
	cclog(dmem_heap_state(cm, 2, 2), "End=%p used=%ld usize=%ld freed=%ld fsize=%ld\n", 
			hman->next, hman->al_num, hman->al_size, hman->fr_num, hman->fr_size);

	/* run a scanner to verify the result */
	memset(s, 0, sizeof(s));
	csc_dmem_scan(cm, used, loose);
	cclog(s[0]==2 && s[2]==2, "Scanned: used=%d usize=%d free=%d fsize=%d\n", s[0], s[1], s[2], s[3]);

	/* tri-merge all memories: (FREE FREE FREE FREE FREE) */
	s[0] = csc_dmem_free(cm, p[3]);
	msize = csc_dmem_attrib(cm, p[0], &s[1]);
	cclog(s[0] == 0 && s[1] == 0, "Tri-merge %p: %ld (%s)\n", p[0], msize, s[1]?"used":"free");
	cclog(dmem_heap_state(cm, 1, 1), "End=%p used=%ld usize=%ld freed=%ld fsize=%ld\n", 
			hman->next, hman->al_num, hman->al_size, hman->fr_num, hman->fr_size);
#endif
	return 0;
}

static void dmem_heap_status(DMHEAP *hman, size_t used, size_t freed)
{
	size_t	s[4];
	int	cond;

	int f_used(void *mem)
	{
		DMEM *cm = dmem_find_control(hman, mem);
		s[0]++; s[1] += ((DMEM*)cm)->size; return 0;
	}
	
	int f_loose(void *mem)
	{
		DMEM *cm = dmem_find_control(hman, mem);
		s[2]++; s[3] += ((DMEM*)cm)->size; return 0;
	}

	memset(s, 0, sizeof(s));
	csc_dmem_scan(hman, f_used, f_loose);

	cond = ((hman->al_num == used) && (hman->fr_num == freed) &&
			(hman->al_num == s[0]) && (hman->al_size == s[1]) &&
			(hman->fr_num == s[2]) && (hman->fr_size == s[3]));

	cclog(cond, "Heap:Scan: used=%u:%d usize=%u:%d freed=%u:%d fsize=%u:%d endp=+%d\n",
			hman->al_num, s[0], hman->al_size, s[1],
			hman->fr_num, s[2], hman->fr_size, s[3],
			BMEM_SPAN(hman, hman->next));
}


#if 0
int dmem_unittest(void)
{
	int	buf[256], s[4];
	DMEM	*cm;
	DMHEAP	*hman;
	size_t	msize;
	char	*p[8];

	/* maximum test */
	msize = hman->fr_size + 1;
	p[0] = csc_dmem_alloc(cm, msize);
	cclog(p[0] == NULL, "Allocating %d: %p\n", msize, p[0]);
	msize = hman->fr_size;
	p[0] = csc_dmem_alloc(cm, msize);
	cclog(p[0] != NULL, "Allocating %d: %p\n", msize, p[0]);
	s[0] = csc_dmem_free(cm, p[0]);
	cclog(dmem_heap_state(cm, 1, 1), "End=%p used=%ld usize=%ld freed=%ld fsize=%ld\n",
			hman->next, hman->al_num, hman->al_size, hman->fr_num, hman->fr_size);

	/* general allocating and freeing */
	p[0] = csc_dmem_alloc(cm, 12);
	cclog(p[0] != NULL, "Allocated %p: %ld\n", p[0], csc_dmem_attrib(cm, p[0], NULL));
	p[1] = csc_dmem_alloc(cm, 24);
	cclog(p[1] != NULL, "Allocated %p: %ld\n", p[1], csc_dmem_attrib(cm, p[1], NULL));
	p[2] = csc_dmem_alloc(cm, 36);
	cclog(p[2] != NULL, "Allocated %p: %ld\n", p[2], csc_dmem_attrib(cm, p[2], NULL));
	p[3] = csc_dmem_alloc(cm, 16);
	cclog(p[3] != NULL, "Allocated %p: %ld\n", p[3], csc_dmem_attrib(cm, p[3], NULL));
	p[4] = csc_dmem_alloc(cm, 12);
	cclog(p[4] != NULL, "Allocated %p: %ld\n", p[4], csc_dmem_attrib(cm, p[4], NULL));
	p[5] = csc_dmem_alloc(cm, 24);
	cclog(p[5] != NULL, "Allocated %p: %ld\n", p[5], csc_dmem_attrib(cm, p[5], NULL));
	p[6] = csc_dmem_alloc(cm, 36);
	cclog(p[6] != NULL, "Allocated %p: %ld\n", p[6], csc_dmem_attrib(cm, p[6], NULL));
	p[7] = csc_dmem_alloc(cm, 16);
	cclog(p[7] != NULL, "Allocated %p: %ld\n", p[7], csc_dmem_attrib(cm, p[7], NULL));

	/* run a scanner to verify the result */
	memset(s, 0, sizeof(s));
	csc_dmem_scan(cm, used, loose);
	cclog(s[0]==9 && s[2]==1, "Scanned: used=%d usize=%d free=%d fsize=%d\n", s[0], s[1], s[2], s[3]);

	/* free half of them */
	s[0] = csc_dmem_free(cm, p[0]);
	s[0] += csc_dmem_free(cm, p[2]);
	s[0] += csc_dmem_free(cm, p[4]);
	s[0] += csc_dmem_free(cm, p[6]);
	cclog(s[0] == 0, "Free half of them\n");

	/* run a scanner to verify the result */
	memset(s, 0, sizeof(s));
	csc_dmem_scan(cm, used, loose);
	cclog(s[0]==5 && s[2]==5, "Scanned: used=%d usize=%d free=%d fsize=%d\n", s[0], s[1], s[2], s[3]);

	/* free rest of them */
	s[0] = csc_dmem_free(cm, p[1]);
	s[0] += csc_dmem_free(cm, p[3]);
	s[0] += csc_dmem_free(cm, p[5]);
	s[0] += csc_dmem_free(cm, p[7]);
	cclog(s[0] == 0, "Free rest of them\n");
	cclog(dmem_heap_state(cm, 1, 1), "End=%p used=%ld usize=%ld freed=%ld fsize=%ld\n",
			hman->next, hman->al_num, hman->al_size, hman->fr_num, hman->fr_size);

	/* run a scanner to verify the result */
	memset(s, 0, sizeof(s));
	csc_dmem_scan(cm, used, loose);
	cclog(s[0]==1 && s[2]==1, "Scanned: used=%d usize=%d free=%d fsize=%d\n", s[0], s[1], s[2], s[3]);
	return 0;
}
#endif
#endif	/* CFG_UNIT_TEST */

