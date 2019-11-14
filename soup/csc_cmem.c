
/*!\file       csc_cmem.c
   \brief      chained memory allocation plan

   The file supports a set of dynamic memory management in doubly linked list. 

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

#define CMEM_MAGIC	0xA6

#define CMEM_FREE	0
#define CMEM_USED	0x80
#define CMEM_PAD_MASK	0x7f

#define CMEM_OWNED(n)	((((CMEM*)(n))->magic[2]) & CMEM_USED)
#define CMEM_CONFIG(n)	(((CMEM*)(n))->magic[3])
#define CMEM_PADDED(n)	((((CMEM*)(n))->magic[2]) & CMEM_PAD_MASK)

typedef	struct	_CMEM	{
	char	magic[4];	/* CRC8 + MAGIC + USAGE|PAD + CONFIG1 */
	struct	_CMEM	*prev;
	struct	_CMEM	*next;
	size_t	size;		/* size of the payload in bytes */
} CMEM;

typedef	struct	_CMHEAP	{
	char	magic[4];	/* CRC8 + MAGIC + RSV + CONFIG2 */
	struct	_CMEM	*prev;	/* point to the first memory block */
	struct	_CMEM	*next;	/* point to the last memory block */
	size_t	al_size;	/* total allocated size */
	size_t	al_num;		/* number of allocated blocks */
	size_t	fr_size;	/* total free size */
	size_t	fr_num;		/* number of free blocks */
} CMHEAP;

static CMEM *cmeme_alloc(CMEM *cm, size_t size, int config);
static int cmem_verify(void *heap, CMEM *cm);



static inline void cmem_set_crc(void *mb, int len)
{
	register char	*p = mb;
	p[1] = (char) CMEM_MAGIC;
	p[0] = (char) csc_crc8(0, p+1, len-1);
}

static inline int cmem_check(void *mb, int len)
{
	register char	*p = mb;
	return (p[1] == (char) CMEM_MAGIC) && 
		(p[0] == (char) csc_crc8(0, p+1, len-1));
}



void *csc_cmem_init(void *heap, size_t len, int flags)
{
	CMHEAP	*hman;
	CMEM	*cm;

	if (heap == NULL) {
		return heap;	/* CSC_MERR_INIT */
	}

	/* round up the len to int boundary */
	len = len / sizeof(int) * sizeof(int);
	if (len < sizeof(CMHEAP) + sizeof(CMEM)) {
		return NULL;	/* CSC_MERR_LOWMEM */
	}

	/* create the first block and set it free */
	cm = (CMEM *)heap;
	cm->prev = cm->next = NULL;
	cm->size = len - sizeof(CMEM);
	cm->magic[2] = (char) CMEM_FREE;
	cm->magic[3] = (char) flags;
	cmem_set_crc(cm, sizeof(CMEM));
	/* allocate the hman management structure */
	hman = (CMHEAP*)(cm + 1);
	if ((cm = cmeme_alloc(cm, sizeof(CMHEAP), flags)) == NULL) {
		return NULL;	/* CSC_MERR_RANGE: not support the empty allocation */
	}

	hman->prev = heap;
	hman->next = cm;
	hman->al_size = sizeof(CMHEAP);
	hman->al_num  = 1;
	hman->fr_size = cm->size;
	hman->fr_num  = 1;
	hman->magic[2] = hman->magic[3] = 0;
	cmem_set_crc(hman, sizeof(CMHEAP));
	return heap;
}

void *csc_cmem_scan(void *heap, int (*used)(void*), int (*loose)(void*))
{
	CMEM	*cm;

	for (cm = heap; cm != NULL; cm = cm->next) {
		if (cmem_verify(heap, cm) < 0) {
			return cm;
		}
		if (CMEM_OWNED(cm)) {
			if (used && used(cm)) {
				break;
			}
		} else {
			if (loose && loose(cm)) {
				break;
			}
		}
	}
	return NULL;
}

void *csc_cmem_alloc(void *heap, size_t n)
{
	CMHEAP	*hman;
	CMEM	*found, *next;
	int	config = (int)CMEM_CONFIG(heap);

	int loose(void *mman)
	{
		if (((CMEM*)mman)->size >= n) {
			found = (found == NULL) ? mman : found;
			switch (config & CSC_MEM_FITMASK) {
			case CSC_MEM_BEST_FIT:
				if (found->size > ((CMEM*)mman)->size) {
					found = mman;
				}
				break;
			case CSC_MEM_WORST_FIT:
				if (found->size < ((CMEM*)mman)->size) {
					found = mman;
				}
				break;
			default:	/* CSC_MEM_FIRST_FIT */
				return 1;
			}
		}
		return 0;
	}

	if (cmem_verify(heap, heap) < 0) {
		return NULL;
	}

	hman = (CMHEAP*)(((CMEM*)heap) + 1);
	if (n > hman->fr_size) {
		return NULL;	/* CSC_MERR_LOWMEM */
	} else if ((n == 0) && !(config & CSC_MEM_ZERO)) {
		return NULL;	/* CSC_MERR_RANGE: not allow empty allocation */
	}

	found = NULL;
	if (csc_cmem_scan(heap, NULL, loose)) {
		return NULL;	/* CSC_MERR_BROKEN: chain broken */
	}
	if (found == NULL) {
		return NULL;	/* CSC_MERR_LOWMEM */
	}

	if ((next = cmeme_alloc(found, n, config)) == NULL) {	/* no splitting */
		hman->al_size += found->size;
		hman->al_num++;
		hman->fr_size -= found->size;
		hman->fr_num--;
	} else {
		hman->al_size += found->size;
		hman->al_num++;
		hman->fr_size -= found->size + sizeof(CMEM);
		hman->next = hman->next < next ? next : hman->next;
	}
	cmem_set_crc(hman, sizeof(CMHEAP));

	if (config & CSC_MEM_CLEAN) {
		memset(found + 1, 0, n);
	}
	return (void*)(found+1);
}

int csc_cmem_free(void *heap, void *mem)
{
	CMHEAP	*hman;
	CMEM	*cm, *other;
	int	rc;

	cm = mem ? ((CMEM*)mem) -1 : NULL; 
	if ((rc = cmem_verify(heap, cm)) < 0) {
		return rc;
	}

	/* update the freed size */
	cm->magic[2] = CMEM_FREE;
	hman = (CMHEAP*)(((CMEM*)heap) + 1);
	hman->al_size -= cm->size;
	hman->al_num--;
	hman->fr_size += cm->size;
	hman->fr_num++;

	/* try to down merge the free block */
	other = cm->next;
	if (other && !CMEM_OWNED(other)) {
		cm->size += other->size + sizeof(CMEM);
		cm->next = other->next;
		if (other->next) {
			other->next->prev = cm;
			cmem_set_crc(other->next, sizeof(CMEM));
		}
		hman->fr_size += sizeof(CMEM);
		hman->fr_num--;
		if (hman->next == other) {
			hman->next = cm;
		}
	}

	/* try to up merge the free block */
	other = cm->prev;
	if (other && !CMEM_OWNED(other)) {
		other->size += cm->size + sizeof(CMEM);
		other->next = cm->next;
		if (cm->next) {
			cm->next->prev = other;
			cmem_set_crc(cm->next, sizeof(CMEM));
		}
		hman->fr_size += sizeof(CMEM);
		hman->fr_num--;
		if (hman->next == cm) {
			hman->next = other;
		}
		cm = other;
	}
	cmem_set_crc(hman, sizeof(CMHEAP));
	cmem_set_crc(cm, sizeof(CMEM));
	return 0;
}

size_t csc_cmem_attrib(void *heap, void *mem, int *state)
{
	CMEM	*cm;
	int	rc;

	cm = mem ? ((CMEM*)mem) -1 : NULL;
	if ((rc = cmem_verify(heap, cm)) < 0) {
		if (state) {
			*state = rc;
		}
		return (size_t)-1;
	}
	if (state) {
		*state = CMEM_OWNED(cm) ? 1 : 0;
	}
	return cm->size - CMEM_PADDED(cm);
}

/* when calling cmeme_alloc(), assume cm is valid and cm->size >= size 
 * and cm->size is always int aligned */
/* size = 0 should be up-wrapper's problem */
static CMEM *cmeme_alloc(CMEM *cm, size_t size, int config)
{
	CMEM	*nb = NULL;
	size_t	rlen, nlen;

	/* round up the 'size' to int boundary */
	rlen = (size + sizeof(int) - 1) / sizeof(int) * sizeof(int);
	nlen = cm->size - rlen;		/* the size of the next whole block */

	if ((nlen > sizeof(CMEM)) ||
			((nlen == sizeof(CMEM)) && (config & CSC_MEM_ZERO))) {
		/* go split */
		nb = (CMEM*)((char*)cm + sizeof(CMEM) + rlen);
		nb->prev = cm;
		nb->next = cm->next;
		nb->size = nlen - sizeof(CMEM);
		nb->magic[2] = (char) CMEM_FREE;
		nb->magic[3] = 0;
		cmem_set_crc(nb, sizeof(CMEM));

		cm->next = nb;
		cm->size -= nlen;
	}
	cm->magic[2] = CMEM_USED | (char)(cm->size - size);
	cmem_set_crc(cm, sizeof(CMEM));
	return nb;
}

static int cmem_verify(void *heap, CMEM *mblock)
{
	CMEM	*cm;
	
	if ((cm = heap) == NULL) {
		return CSC_MERR_INIT;	/* heap not created */
	}
	if (!cmem_check(cm, sizeof(CMEM))) {
		return CSC_MERR_BROKEN;
	}
	if (CMEM_OWNED(cm) == 0) {
		return CSC_MERR_TYPE;
	}
	
	cm++;
	if (!cmem_check(cm, sizeof(CMHEAP))) {
		return CSC_MERR_BROKEN;
	}

	if ((mblock < cm->prev) || (mblock > cm->next)) {
		return CSC_MERR_RANGE;	/* memory out of range */
	}
	if (!cmem_check(mblock, sizeof(CMEM))) {
		return CSC_MERR_BROKEN;	/* broken memory controller */
	}
	return 0;
}

#ifdef	CFG_UNIT_TEST
#include "libcsoup_debug.h"

#define CMEM_MDATA(n,k)	(unsigned char)(((CMEM*)(n))->magic[k])

static int cmem_heap_state(void *heap, int used, int freed)
{
	CMHEAP	*hman = (CMHEAP*)(((CMEM*)heap) + 1);

	if ((hman->prev == heap) && ((int)hman->al_num == used) 
			&& ((int)hman->fr_num == freed)) {
		return 1;
	}
	return 0;
}

int csc_cmem_unittest(void)
{
	int	buf[256], s[4];
	CMEM	*cm;
	CMHEAP	*hman;
	size_t	msize;
	char	*p[8];

	int used(void *cm)
	{
		s[0]++; s[1] += ((CMEM*)cm)->size; return 0;
	}
	
	int loose(void *cm)
	{
		s[2]++; s[3] += ((CMEM*)cm)->size; return 0;
	}

	/********************************************************************
	 * testing the empty heap
	 *******************************************************************/
	cclog(-1, "Size of Heap manager: %d; size of memory manager: %d\n", 
			sizeof(CMHEAP), sizeof(CMEM));

	msize = sizeof(CMHEAP) + sizeof(CMEM);
	cm = csc_cmem_init(buf, msize, CSC_MEM_DEFAULT);
	cclog(cm == NULL, "Too small memory to create a heap: %d\n", msize);
	cclog(cmem_check((CMEM*)buf, sizeof(CMEM)), "The heap was partially initialized.\n");

	msize = sizeof(CMHEAP) + sizeof(CMEM) + sizeof(CMEM) + 1;
	cm = csc_cmem_init(buf, msize, CSC_MEM_ZERO);
	cclog(cm != NULL, "Emtpy allocation is enabled: %d\n", msize);
	if (cm == NULL) return 0;
	hman = (CMHEAP*)(cm+1);
	cclog(-1, "Emtpy heap created: %p %d\n", cm, (int)hman->fr_size);

	s[0] = cmem_verify(cm, cm);
	cclog(s[0] == 0, "Verification Heap only: %d\n", s[0]);
	s[0] = cmem_verify(cm, cm->next);
	cclog(s[0] == 0, "Verification Heap and memory: %d\n", s[0]);
	s[0] = cmem_verify(cm->next, cm->next);
	cclog(s[0] != 0, "Verification Heap error: %d\n", s[0]);

	p[0] = csc_cmem_alloc(cm, 0);
	cclog(p[0]!=NULL, "Allocated 0 byte from the empty heap: %p\n", p[0]);
	cclog(cmem_heap_state(cm, 2, 0), "End=%p used=%ld usize=%ld freed=%ld fsize=%ld\n", 
			hman->next, hman->al_num, hman->al_size, hman->fr_num, hman->fr_size);

	s[0] = csc_cmem_free(cm, p[0]);
	cclog(s[0] == 0, "Free 0 byte from the empty heap: %d\n", s[0]);
	cclog(cmem_heap_state(cm, 1, 1), "End=%p used=%ld usize=%ld freed=%ld fsize=%ld\n", 
			hman->next, hman->al_num, hman->al_size, hman->fr_num, hman->fr_size);

	msize = sizeof(CMHEAP) + sizeof(CMEM) + sizeof(CMEM) + 1;
	cm = csc_cmem_init(buf, msize, CSC_MEM_DEFAULT);
	cclog(cm == NULL, "Emtpy allocation is disabled: %d\n", msize);

	/********************************************************************
	 * testing the minimum heap
	 *******************************************************************/
	msize = sizeof(CMHEAP) + sizeof(CMEM) + sizeof(CMEM) + sizeof(int);
	cm = csc_cmem_init(buf, msize, CSC_MEM_DEFAULT);
	cclog(cm != NULL, "The minimum heap is created: %d\n", msize);
	if (cm == NULL) return 0;
	hman = (CMHEAP*)(cm+1);
	cclog(-1, "The minimum heap size: %d\n", (int)hman->fr_size);

	memset(s, 0, sizeof(s));
	csc_cmem_scan(cm, used, loose);
	cclog(s[0]==1 && s[2]==1, "Scanned: used=%d usize=%d free=%d fsize=%d\n", s[0], s[1], s[2], s[3]);
	cclog(cmem_heap_state(cm, 1, 1), "End=%p used=%ld usize=%ld freed=%ld fsize=%ld\n", 
			hman->next, hman->al_num, hman->al_size, hman->fr_num, hman->fr_size);

	msize = csc_cmem_attrib(cm, cm+1, s);
	cclog(s[0]&&(msize==sizeof(CMHEAP)), "Memory attribute: Heap %s %d\n", s[0]?"used":"free", msize);
	msize = csc_cmem_attrib(cm, cm->next+1, s);
	cclog(!s[0]&&(msize==sizeof(int)), "Memory attribute: Memory %s %d\n", s[0]?"used":"free", msize);

	p[0] = csc_cmem_alloc(cm, 0);
	cclog(p[0] == NULL, "Not allow to allocate empty memory: %p\n", p[0]);

	p[0] = csc_cmem_alloc(cm, 1);
	cclog(p[0] != NULL, "Try to allocate 1 byte: %p\n", p[0]);
	msize = csc_cmem_attrib(cm, p[0], s);
	cclog(s[0]&&(msize==1), "Memory attribute: Memory %s %d\n", s[0]?"used":"free", msize);

	p[1] = p[0] - sizeof(CMEM);
	cclog(CMEM_PADDED(p[1]) == 3, "Usage Flags and paddning size: %x\n", CMEM_MDATA(p[1], 2));
	cclog(cmem_heap_state(cm, 2, 0), "End=%p used=%ld usize=%ld freed=%ld fsize=%ld\n", 
			hman->next, hman->al_num, hman->al_size, hman->fr_num, hman->fr_size);

	s[0] = csc_cmem_free(cm, p[0]);
	cclog(s[0] == 0, "Free the 1 byte memory: %d\n", s[0]);
	cclog(cmem_heap_state(cm, 1, 1), "End=%p used=%ld usize=%ld freed=%ld fsize=%ld\n", 
			hman->next, hman->al_num, hman->al_size, hman->fr_num, hman->fr_size);

	/********************************************************************
	 * testing the free function in minimum heap
	 *******************************************************************/
	cm = csc_cmem_init(buf, sizeof(buf), CSC_MEM_DEFAULT);
	if (cm == NULL) return 0;
	hman = (CMHEAP*)(cm+1);
	cclog(-1, "The test heap is created: %p %d\n", cm, (int)hman->fr_size);

	/* testing down-merge the free space */
	p[0] = csc_cmem_alloc(cm, 12);
	cclog(p[0] != NULL, "Allocated %p: %ld\n", p[0], csc_cmem_attrib(cm, p[0], NULL));
	p[1] = csc_cmem_alloc(cm, 24);
	cclog(p[1] != NULL, "Allocated %p: %ld\n", p[1], csc_cmem_attrib(cm, p[1], NULL));
	p[2] = csc_cmem_alloc(cm, 36);
	cclog(p[2] != NULL, "Allocated %p: %ld\n", p[2], csc_cmem_attrib(cm, p[2], NULL));
	p[3] = csc_cmem_alloc(cm, 16);
	cclog(p[3] != NULL, "Allocated %p: %ld\n", p[3], csc_cmem_attrib(cm, p[3], NULL));
	cclog(cmem_heap_state(cm, 5, 1), "End=%p used=%ld usize=%ld freed=%ld fsize=%ld\n", 
			hman->next, hman->al_num, hman->al_size, hman->fr_num, hman->fr_size);


	/* create a hole: USED FREE USED USED FREE */
	s[0] = csc_cmem_free(cm, p[1]);
	msize = csc_cmem_attrib(cm, p[1], &s[1]);
	cclog(s[0] == 0 && s[1] == 0, "Freed %p: %ld (%s)\n", p[1], msize, s[1]?"used":"free");
	cclog(cmem_heap_state(cm, 4, 2), "End=%p used=%ld usize=%ld freed=%ld fsize=%ld\n", 
			hman->next, hman->al_num, hman->al_size, hman->fr_num, hman->fr_size);

	/* down merge the first two memory: (FREE FREE) USED USED FREE */
	s[0] = csc_cmem_free(cm, p[0]);
	msize = csc_cmem_attrib(cm, p[0], &s[1]);
	cclog(s[0] == 0 && s[1] == 0, "Down merge %p: %ld (%s)\n", p[0], msize, s[1]?"used":"free");
	cclog(cmem_heap_state(cm, 3, 2), "End=%p used=%ld usize=%ld freed=%ld fsize=%ld\n", 
			hman->next, hman->al_num, hman->al_size, hman->fr_num, hman->fr_size);

	/* up merge the three memories: (FREE FREE FREE) USED FREE */
	s[0] = csc_cmem_free(cm, p[2]);
	msize = csc_cmem_attrib(cm, p[0], &s[1]);
	cclog(s[0] == 0 && s[1] == 0, "Up merge %p: %ld (%s)\n", p[2], msize, s[1]?"used":"free");
	cclog(cmem_heap_state(cm, 2, 2), "End=%p used=%ld usize=%ld freed=%ld fsize=%ld\n", 
			hman->next, hman->al_num, hman->al_size, hman->fr_num, hman->fr_size);

	/* run a scanner to verify the result */
	memset(s, 0, sizeof(s));
	csc_cmem_scan(cm, used, loose);
	cclog(s[0]==2 && s[2]==2, "Scanned: used=%d usize=%d free=%d fsize=%d\n", s[0], s[1], s[2], s[3]);

	/* tri-merge all memories: (FREE FREE FREE FREE FREE) */
	s[0] = csc_cmem_free(cm, p[3]);
	msize = csc_cmem_attrib(cm, p[0], &s[1]);
	cclog(s[0] == 0 && s[1] == 0, "Tri-merge %p: %ld (%s)\n", p[0], msize, s[1]?"used":"free");
	cclog(cmem_heap_state(cm, 1, 1), "End=%p used=%ld usize=%ld freed=%ld fsize=%ld\n", 
			hman->next, hman->al_num, hman->al_size, hman->fr_num, hman->fr_size);

	/* maximum test */
	msize = hman->fr_size + 1;
	p[0] = csc_cmem_alloc(cm, msize);
	cclog(p[0] == NULL, "Allocating %d: %p\n", msize, p[0]);
	msize = hman->fr_size;
	p[0] = csc_cmem_alloc(cm, msize);
	cclog(p[0] != NULL, "Allocating %d: %p\n", msize, p[0]);
	s[0] = csc_cmem_free(cm, p[0]);
	cclog(cmem_heap_state(cm, 1, 1), "End=%p used=%ld usize=%ld freed=%ld fsize=%ld\n",
			hman->next, hman->al_num, hman->al_size, hman->fr_num, hman->fr_size);

	/* general allocating and freeing */
	p[0] = csc_cmem_alloc(cm, 12);
	cclog(p[0] != NULL, "Allocated %p: %ld\n", p[0], csc_cmem_attrib(cm, p[0], NULL));
	p[1] = csc_cmem_alloc(cm, 24);
	cclog(p[1] != NULL, "Allocated %p: %ld\n", p[1], csc_cmem_attrib(cm, p[1], NULL));
	p[2] = csc_cmem_alloc(cm, 36);
	cclog(p[2] != NULL, "Allocated %p: %ld\n", p[2], csc_cmem_attrib(cm, p[2], NULL));
	p[3] = csc_cmem_alloc(cm, 16);
	cclog(p[3] != NULL, "Allocated %p: %ld\n", p[3], csc_cmem_attrib(cm, p[3], NULL));
	p[4] = csc_cmem_alloc(cm, 12);
	cclog(p[4] != NULL, "Allocated %p: %ld\n", p[4], csc_cmem_attrib(cm, p[4], NULL));
	p[5] = csc_cmem_alloc(cm, 24);
	cclog(p[5] != NULL, "Allocated %p: %ld\n", p[5], csc_cmem_attrib(cm, p[5], NULL));
	p[6] = csc_cmem_alloc(cm, 36);
	cclog(p[6] != NULL, "Allocated %p: %ld\n", p[6], csc_cmem_attrib(cm, p[6], NULL));
	p[7] = csc_cmem_alloc(cm, 16);
	cclog(p[7] != NULL, "Allocated %p: %ld\n", p[7], csc_cmem_attrib(cm, p[7], NULL));

	/* run a scanner to verify the result */
	memset(s, 0, sizeof(s));
	csc_cmem_scan(cm, used, loose);
	cclog(s[0]==9 && s[2]==1, "Scanned: used=%d usize=%d free=%d fsize=%d\n", s[0], s[1], s[2], s[3]);

	/* free half of them */
	s[0] = csc_cmem_free(cm, p[0]);
	s[0] += csc_cmem_free(cm, p[2]);
	s[0] += csc_cmem_free(cm, p[4]);
	s[0] += csc_cmem_free(cm, p[6]);
	cclog(s[0] == 0, "Free half of them\n");

	/* run a scanner to verify the result */
	memset(s, 0, sizeof(s));
	csc_cmem_scan(cm, used, loose);
	cclog(s[0]==5 && s[2]==5, "Scanned: used=%d usize=%d free=%d fsize=%d\n", s[0], s[1], s[2], s[3]);

	/* free rest of them */
	s[0] = csc_cmem_free(cm, p[1]);
	s[0] += csc_cmem_free(cm, p[3]);
	s[0] += csc_cmem_free(cm, p[5]);
	s[0] += csc_cmem_free(cm, p[7]);
	cclog(s[0] == 0, "Free rest of them\n");
	cclog(cmem_heap_state(cm, 1, 1), "End=%p used=%ld usize=%ld freed=%ld fsize=%ld\n",
			hman->next, hman->al_num, hman->al_size, hman->fr_num, hman->fr_size);

	/* run a scanner to verify the result */
	memset(s, 0, sizeof(s));
	csc_cmem_scan(cm, used, loose);
	cclog(s[0]==1 && s[2]==1, "Scanned: used=%d usize=%d free=%d fsize=%d\n", s[0], s[1], s[2], s[3]);
	return 0;
}

#endif	/* CFG_UNIT_TEST */

