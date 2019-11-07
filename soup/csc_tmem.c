
/*!\file       csc_tmem.c
   \brief      Tiny memory allocation agent

   The file supports a set of extreme light weight dynamic memory management.
   It would be quite easy to use with a small memory pool in stack.
   The overhead is the smallest as far as I know, only one standard integer,
   which can be 4 bytes in 32-bit system or 2 byte in 8-bit system.
   It uses single chain list so not so good for high frequent allocating 
   and freeing; please use it wisely.

   \author     "Andy Xuming" <xuming@users.sourceforge.net>
   \date       2013-2014
*/
/* Copyright (C) 1998-2018  "Andy Xuming" <xuming@users.sourceforge.net>

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

/* Control Word for managing block:
 *   MSB+0: parity bit
 *   MSB+1: magic bit (always 1=used)
 *   MSB+2...n: whole memory minus the Control Word for managing block
 * Control Word for memory block:
 *   MSB+0: parity bit
 *   MSB+1: usable bit (0=free 1=used)
 *   MSB+2...n: block size 
 * Memory Sight:
 *   [Managing Block][Memory Block][Memory Block]...
 */
#if	(UINT_MAX == 0xFFFFFFFFU)
#define TMEM_MASK_PARITY	0x80000000U
#define TMEM_MASK_USED		0x40000000U
#else
#define TMEM_MASK_PARITY	0x8000U
#define TMEM_MASK_USED		0x4000U
#endif
#define TMEM_MASK_USIZE		((int)(UINT_MAX >> 2))

#define TMEM_SIZE(n)		((n) & TMEM_MASK_USIZE)
#define TMEM_BYTES(n)		(TMEM_SIZE(n) * sizeof(int))
#define TMEM_NEXT(p)		((int*)(p) + TMEM_SIZE(*(int*)(p)) + 1)

#define TMEM_SET_USED(n)	((n) | TMEM_MASK_USED)
#define	TMEM_CLR_USED(n)	((n) & ~TMEM_MASK_USED)
#define	TMEM_TEST_USED(n)	((n) & TMEM_MASK_USED)

#ifdef	CFG_UNIT_TEST
static		int	tmem_config = CSC_MEM_DEFAULT;
#else
static	const	int	tmem_config = CSC_MEM_DEFAULT;
#endif

static int tmem_parity(int cw);
static int tmem_verify(void *heap, int *mb);
static int tmem_cword(int uflag, int size);


/*!\brief Initialize the memory heap to be allocable.

   \param[in]  hmem the memory heap for allocation.
   \param[in]  len the size of the memory heap.

   \return    The pointer to the memory heap object, or NULL if failed.

   \remark The given memory pool must be started at 'int' boundry.
   The minimum allocation unit is 'int'. Therefore the maximum managable 
   memory is 4GB in 32/64-bit system, or 32KB in 8/16-bit system.
*/
void *csc_tmem_init(void *hmem, size_t len)
{
	int	*heap = (int*) hmem;

	if (hmem == NULL) {
		return hmem;	/* CSC_MERR_INIT */
	}

	/* change size unit to per-int; the remains will be cut off  */
	len /= sizeof(int);	

	/* save one unit for heap managing  */
	len--;
	
	/* make sure the size is not out of range */
	/* Though CSC_MEM_ZERO is practically useless, supporting CSC_MEM_ZERO
	 * in program is for the integrity of the memory logic */
	if ((len < 1) || (len > (UINT_MAX >> 2))) {
		return NULL;	/* CSC_MERR_RANGE */
	}
	if ((len == 1) && !(tmem_config & CSC_MEM_ZERO)) {
		return NULL;	/* CSC_MERR_RANGE: no support empty allocation */
	}

	/* create the heap management */
	*heap++ = tmem_cword(1, (int)len--);
	
	/* create the first memory block */
	*heap = tmem_cword(0, (int)len);
	return hmem;
}


/*!\brief scan the memory chain to process every piece of memory block.

   \param[in]  heap the memory heap for allocation.
   \param[in]  used the callback function when find a piece of used memory
   \param[in]  loose the callback function when find a piece of free memory

   \return     NULL if successfully scanned the memory chain. If the memory
               chain is corrupted, it returns a pointer to the broken point.

   \remark The prototype of the callback functions are: int func(int *)
           The scan process can be broken if func() returns non-zero.
*/
void *csc_tmem_scan(void *heap, int (*used)(int*), int (*loose)(int*))
{
	int	*mb;

	if (tmem_verify(heap, heap) < 0) {
		return heap;	/* memory heap not available */
	}
	for (mb = ((int*)heap)+1; mb < TMEM_NEXT(heap); mb = TMEM_NEXT(mb)) {
		if (tmem_verify(heap, mb) < 0) {
			return (void*)mb;	/* chain broken */
		}
		if (TMEM_TEST_USED(*mb)) {
			if (used && used(mb)) {
				break;
			}
		} else {
			if (loose && loose(mb)) {
				break;
			}
		}
	}
	return NULL;
}

/*!\brief allocate a piece of dynamic memory block inside the specified 
   memory heap.

   \param[in]  heap the memory heap for allocation.
   \param[in]  n the size of the expecting allocated memory block.

   \return    point to the allocated memory block in the memory heap. 
              or NULL if not enough space for allocating.

   \remark The strategy of allocation is defined by CSC_MEM_FITNESS
           in libcsoup.h

*/
void *csc_tmem_alloc(void *heap, size_t n)
{
	int	 *found, *next;
	int	unum = (int)((n + sizeof(int) - 1) / sizeof(int));
	
	int loose(int *mb)
	{
		if (TMEM_SIZE(*mb) >= unum) {
			if (found == NULL) {
				found = mb;
			}
			switch (tmem_config & CSC_MEM_FITMASK) {
			case CSC_MEM_BEST_FIT:
				if (TMEM_SIZE(*found) > TMEM_SIZE(*mb)) {
					found = mb;
				}
				break;
			case CSC_MEM_WORST_FIT:
				if (TMEM_SIZE(*found) < TMEM_SIZE(*mb)) {
					found = mb;
				}
				break;
			default:	/* CSC_MEM_FIRST_FIT */
				return 1;
			}
		}
		return 0;
	}

	if (tmem_verify(heap, heap) < 0) {
		return NULL;	/* CSC_MERR_INIT: memory heap not available */
	}

	/* make sure the request is NOT out of size */
	if (unum > TMEM_SIZE(*((int*)heap))) {
		return NULL;	/* CSC_MERR_LOWMEM */
	} else if (!unum && !(tmem_config & CSC_MEM_ZERO)) {
		return NULL;	/* CSC_MERR_RANGE: not allow empty allocation */
	}

	found = next = NULL;
	if (csc_tmem_scan(heap, NULL, loose)) {
		return NULL;	/* CSC_MERR_BROKEN: chain broken */
	}
	if (found == NULL) {
		return NULL;	/* CSC_MERR_LOWMEM: out of memory */
	}

	n = tmem_config & CSC_MEM_ZERO ? 0 : 1;	/* reuse the 'n' for size test */
	if (TMEM_SIZE(*found) <= unum + n) {	
		/* not worth to split this block */
		*found = tmem_cword(1, *found);
	} else {
		/* split this memory block */
		next = found + unum + 1;
		*next = tmem_cword(0, TMEM_SIZE(*found) - unum - 1);
		*found = tmem_cword(1, unum);
	}
	found++;
	if (tmem_config & CSC_MEM_CLEAN) {
		memset(found, 0, TMEM_BYTES(*(found-1)));
	}
	return (void*)found;
}

/*!\brief free the allocated memory block.

   \param[in]  heap the memory heap for allocation.
   \param[in]  mem the memory block.

   \return    0 if freed successfully 
              -1 memory heap not initialized
	      -2 memory chain broken
	      -3 memory not found

   \remark If using csc_tmem_free() to free a free memory block, it returns -3.
*/
int csc_tmem_free(void *heap, void *mem)
{
	int	*last, *found, rc;

	int used(int *mb)
	{
		if ((void*)(mb+1) == mem) {
			found = mb;
			*found = tmem_cword(0, *found);	/* free itself */
			
			/* try to down-merge the next memory block */
			mb = TMEM_NEXT(mb);
			if (tmem_verify(heap, mb) < 0) {
				return 1;
			}
			if (!TMEM_TEST_USED(*mb)) {
				*found = tmem_cword(0, TMEM_SIZE(*found + *mb + 1));
			}
			return 1;
		}
		return 0;
	}
	int loose(int *mb)
	{
		last = mb; return 0;
	}

	found = (int*)mem;
	found -= found ? 1 : 0;
	if ((rc = tmem_verify(heap, found)) < 0) {
		return rc;	/* memory heap not available */
	}

	last = found = NULL;
	if (csc_tmem_scan(heap, used, loose)) {
		return CSC_MERR_BROKEN;	/* memory chain broken */
	}

	if (found == NULL) {
		/* BE WARE: To free a free memory returns -3 "not found" */
		return CSC_MERR_RANGE;	/* memory not found */
	}

	/* try to up-merge the previous memory block */
	if (last && (TMEM_NEXT(last) == found)) {
		*last = tmem_cword(0, TMEM_SIZE(*last + *found + 1));
	}
	return 0;
}

/*!\brief find the attribution of an allocated memory.

   \param[in]  heap the memory heap for allocation.
   \param[in]  mem the memory block.
   \param[out] msize the size of the memory block

   \return    0 free memory block
              1 used memory block
              -1 memory heap not initialized
	      -2 memory block corrupted
	      -3 memory out of range
*/
int csc_tmem_attrib(void *heap, void *mem, size_t *msize)
{
	int	rc, *mb = (int*) mem;

	mb -= mb ? 1 : 0;
	if ((rc = tmem_verify(heap, mb)) < 0) {
		return rc;	/* memory heap not available */
	}
	
	if (msize) {
		*msize = (size_t)TMEM_BYTES(*mb);
	}

	if (TMEM_TEST_USED(*mb)) {
		return 1;	/* used memory block */
	}
	return 0;		/* free memory block */
}

/* applying odd parity so 15 (16-bit) or 31 (32-bit) 1-bits makes MSB[1]=0,
 * which can easily sorting out -1 as an illegal word. */
/* https://stackoverflow.com/questions/109023/how-to-count-the-number-of-set-bits-in-a-32-bit-integer
 * https://stackoverflow.com/questions/30688465/how-to-check-the-number-of-set-bits-in-an-8-bit-unsigned-char
 */
#if	UINT_MAX == 0xFFFFFFFFU
static int tmem_parity(int cw)
{
	unsigned  x = (unsigned)cw & ~TMEM_MASK_PARITY;

	x = x - ((x >> 1) & 0x55555555);
	x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
	x = (x + (x >> 4)) & 0x0F0F0F0F;
	x = x + (x >> 8);
	x = x + (x >> 16);
	x &= 0x0000003F;
	x++;	/* make odd bit even */
	return (cw & ~TMEM_MASK_PARITY) | (x << 31);
}
#else
static int tmem_parity(int cw)
{
	unsigned  x = (unsigned)cw & ~TMEM_MASK_PARITY;

	x = x - ((x >> 1) & 0x5555);
	x = (x & 0x3333) + ((x >> 2) & 0x3333);
	x = (x + (x >> 4)) & 0x0F0F;
	x = x + (x >> 8);
	x &= 0x7;
	x++;	/* make odd bit even */
	return (cw & ~TMEM_MASK_PARITY) | (x << 15);
}
#endif

static int tmem_verify(void *heap, int *mb)
{
	if (heap == NULL) {
		return CSC_MERR_INIT;
	}
	if (*((int*)heap) != tmem_parity(*((int*)heap))) {
		return CSC_MERR_INIT;	/* memory heap not available */
	}
	if (((void*)mb < heap) || (mb >= TMEM_NEXT(heap))) {
		return CSC_MERR_RANGE;	/* memory out of range */
	}
	if (*mb != tmem_parity(*mb)) {
		return CSC_MERR_BROKEN;	/* memory block corrupted */
	}
	return 0;
}

static int tmem_cword(int uflag, int size)
{
	if (uflag) {
		size = TMEM_SET_USED(size);
	} else {
		size = TMEM_CLR_USED(size);
	}
	return tmem_parity(size);
}


#ifdef	CFG_UNIT_TEST

#include "libcsoup_debug.h"

static short tmem_parity16(short cw)
{
	unsigned short  x = (unsigned short)cw & ~0x8000;

	x = x - ((x >> 1) & 0x5555);
	x = (x & 0x3333) + ((x >> 2) & 0x3333);
	x = (x + (x >> 4)) & 0x0F0F;
	x = x + (x >> 8);
	x &= 0x1f;
	x++;	/* make odd bit even */
	return (cw & ~0x8000) | (x << 15);
}

static int tmem_unittest_empty_memory(int *buf)
{
	int	n, *p;
	size_t	msize;
	
	int memc(int *mb)
	{
		cslog("(%p:%d:%lu)", mb, TMEM_TEST_USED(*mb)?1:0, TMEM_BYTES(*mb));
		return 0;
	}

	/* create a smallest heap where has only one heap control and 
	 * one block control */
	p = csc_tmem_init(buf, sizeof(int)*2+1);
	cclog(p == buf, "Create heap with %d bytes\n", sizeof(int)*2+1);
	if (p == NULL) return 0;
	
	n = TMEM_SIZE(*buf);
	cclog(n == 1, "TMEM_SIZE of the heap: %p %d\n", buf, n);
	p = TMEM_NEXT(buf);
	cclog(p == buf+2, "TMEM_NEXT of the heap: %p\n", p);
	n = TMEM_SIZE(buf[1]);
	cclog(n == 0, "TMEM_SIZE of the first block: %d\n", n);
	p = TMEM_NEXT(buf+1);
	cclog(p == TMEM_NEXT(buf), "TMEM_NEXT of the first block: %p\n", p);

	p = csc_tmem_alloc(buf, 1);
	cclog(p == NULL, "Can not allocate 1 byte from the full heap\n");

	p = csc_tmem_alloc(buf, 0);
	cclog(p != NULL, "Can allocate 0 byte from the full heap %p\n", p);
	cclog(TMEM_SIZE(buf[1]) == 0, "TMEM_SIZE of the first block: %d\n", TMEM_SIZE(buf[1]));

	n = csc_tmem_attrib(buf, buf+1, &msize);
	cclog((n == 1) && (msize == sizeof(int)), "Attribution of the heap: %d %ld\n", n, msize);
	n = csc_tmem_attrib(buf, p, &msize);
	cclog((n == 1) && (msize == 0), "Attribution of the first block: %d %ld\n", n, msize);

	csc_tmem_free(buf, p);
	n = csc_tmem_attrib(buf, p, &msize);
	cclog((n == 0) && (msize == 0), "Attribution of the freed block: %d %ld\n", n, msize);

	/* create heap with 3 empty block: HEAP+MB0+MB1+MB2 */
	p = csc_tmem_init(buf, sizeof(int)*4+1);
	cclog(p == buf, "Create heap with %d bytes\n", sizeof(int)*4+1);
	if (p == NULL) return 0;

	p = csc_tmem_alloc(buf, 1);
	cclog(p == buf+2, "Allocated memory %p %x\n", p, buf[1]);
	cclog(TMEM_NEXT(buf+1) == buf+3, "Next memory %p\n", TMEM_NEXT(buf+1));
	cclog(TMEM_NEXT(buf+3) == TMEM_NEXT(buf), "End of the memory %p\n", TMEM_NEXT(buf+3));
	n = csc_tmem_attrib(buf, buf+1, &msize);
	cclog((n == 1) && (msize == sizeof(int)*3), "Attribution of the heap: %d %ld\n", n, msize);
	n = csc_tmem_attrib(buf, p, &msize);
	cclog((n ==1) && (msize == sizeof(int)), "Attribution of the allocated memory: %d %ld\n", n, msize);
	n = csc_tmem_attrib(buf, buf+4, &msize);
	cclog((n == 0) && (msize == 0), "Attribution of the free memory: %d %ld\n", n, msize);

	csc_tmem_free(buf, p);
	n = csc_tmem_attrib(buf, p, &msize);
	cclog((n == 0) && (msize == sizeof(int)*2), "Attribution of the freed memory: %d %ld\n", n, msize);
	cclog(TMEM_NEXT(buf+1) == TMEM_NEXT(buf), "The next address of the freed memory: %p\n", TMEM_NEXT(buf+1));

	n = csc_tmem_alloc(buf, 0) ? 1 : 0;
	n += csc_tmem_alloc(buf, 0) ? 1 : 0;
	n += csc_tmem_alloc(buf, 0) ? 1 : 0;
	cclog(n == 3, "Allocated 3 empty memories: ");
	csc_tmem_free(buf, buf+3);
	csc_tmem_scan(buf, memc, memc);
	cslog("\n");
	return 0;
}

static int tmem_unittest_nonempty_memory(int *buf)
{
	int	n, *p;
	size_t	msize;

	p = csc_tmem_init(buf, sizeof(int)*2+1);
	cclog(p == NULL, "Create heap with %d bytes (%p): %d minimum.\n", 
			sizeof(int)*2+1, p, sizeof(int)*3);

	/* create heap with 1 memory block: HEAP+MB0+PL0 */
	p = csc_tmem_init(buf, sizeof(int)*3+1);
	cclog(p == buf, "Create heap with %d bytes (%p)\n", sizeof(int)*3+1, p);
	if (p == NULL) return 0;

	n = TMEM_SIZE(*buf);
	cclog(n == 2, "TMEM_SIZE of the heap: %p %d\n", buf, n);
	p = TMEM_NEXT(buf);
	cclog(p == buf+3, "TMEM_NEXT of the heap: %p\n", p);
	n = TMEM_SIZE(buf[1]);
	cclog(n == 1, "TMEM_SIZE of the first block: %d\n", n);
	p = TMEM_NEXT(buf+1);
	cclog(p == TMEM_NEXT(buf), "TMEM_NEXT of the first block: %p\n", p);

	p = csc_tmem_alloc(buf, 0);
	cclog(p == NULL, "Allocating 0 byte from the heap: %p\n", p);

	p = csc_tmem_alloc(buf, 1);
	cclog(p != NULL, "Allocating 1 byte from the heap: %p\n", p);
	n = csc_tmem_attrib(buf, p, &msize);
	cclog((n == 1) && (msize == sizeof(int)), 
			"Verify memory %p: %s %ld bytes\n", p, n?"used":"free", msize);
	cclog(TMEM_NEXT(buf) == TMEM_NEXT(buf+1), "Verify the end of the heap: %p\n", TMEM_NEXT(buf+1));

	csc_tmem_free(buf, p);
	n = csc_tmem_attrib(buf, p, &msize);
	cclog((n == 0) && (msize == 4), "Attribution of the freed block: %d %ld\n", n, msize);

	/* create heap with 3 memory block: HEAP+MB0+PL0+MB1+PL1+MB2+PL2 */
	p = csc_tmem_init(buf, sizeof(int)*7+1);
	cclog(p == buf, "Create heap with %d bytes\n", sizeof(int)*7+1);
	if (p == NULL) return 0;

	/* testing merging: create a hole in middle  */
	n = csc_tmem_alloc(buf, 1) ? 1 : 0;
	n += csc_tmem_alloc(buf, 1) ? 1 : 0;
	n += csc_tmem_alloc(buf, 1) ? 1 : 0;
	csc_tmem_free(buf, buf+4);
	cclog((n == 3) && !TMEM_TEST_USED(buf[3]), "Create a memory hole in the middle\n");

	csc_tmem_free(buf, buf+2);
	n = csc_tmem_attrib(buf, buf+2, &msize);
	cclog((n == 0) && TMEM_SIZE(buf[1]) == 3, "Freed: down-merged the memory hole. [%d]\n", TMEM_SIZE(buf[1]));
	csc_tmem_free(buf, buf+6);
	n = csc_tmem_attrib(buf, buf+2, &msize);
	cclog((n == 0) && TMEM_SIZE(buf[1]) == 5, "Freed: up-merged the memory hole. [%d]\n", TMEM_SIZE(buf[1]));

	/* testing merging: create a hole in middle  */
	n = csc_tmem_alloc(buf, 1) ? 1 : 0;
	n += csc_tmem_alloc(buf, 1) ? 1 : 0;
	n += csc_tmem_alloc(buf, 1) ? 1 : 0;
	csc_tmem_free(buf, buf+4);
	cclog((n == 3) && !TMEM_TEST_USED(buf[3]), "Create a memory hole in the middle\n");

	csc_tmem_free(buf, buf+6);
	n = csc_tmem_attrib(buf, buf+4, &msize);
	cclog((n == 0) && TMEM_SIZE(buf[3]) == 3, "Freed: up-merged the memory hole. [%d]\n", TMEM_SIZE(buf[3]));
	csc_tmem_free(buf, buf+2);
	n = csc_tmem_attrib(buf, buf+2, &msize);
	cclog((n == 0) && TMEM_SIZE(buf[1]) == 5, "Freed: down-merged the memory hole. [%d]\n", TMEM_SIZE(buf[1]));

	/* testing merging: create a hole in middle  */
	n = csc_tmem_alloc(buf, 1) ? 1 : 0;
	n += csc_tmem_alloc(buf, 1) ? 1 : 0;
	n += csc_tmem_alloc(buf, 1) ? 1 : 0;
	csc_tmem_free(buf, buf+2);
	csc_tmem_free(buf, buf+6);
	cclog((n == 3) && TMEM_TEST_USED(buf[3]), "Create a memory island in the middle\n");

	csc_tmem_free(buf, buf+4);
	n = csc_tmem_attrib(buf, buf+2, &msize);
	cclog((n == 0) && TMEM_SIZE(buf[1]) == 5, "Freed: tri-merged the memory hole. [%d]\n", TMEM_SIZE(buf[1]));

	/* testing split unit */
	csc_tmem_alloc(buf, 1);
	p = csc_tmem_alloc(buf, 5);
	n = csc_tmem_attrib(buf, p, &msize);
	cclog((n == 1) && (msize == sizeof(int)*3), "Do not split if the rest memory too small. [%ld]\n", msize);
	return 0;
}

static int tmem_unittest_memory_pattern(int *buf, int *rc)
{
	int	u = 0, f = 0;

	int used(int *mb)
	{
		u = (u << 4) | TMEM_SIZE(*mb); return 0;
	}

	int loose(int *mb)
	{
		f = (f << 4) | TMEM_SIZE(*mb); return 0;
	}

	csc_tmem_scan(buf, used, loose);
	if (rc) {
		*rc = u;
	}
	return f;
}

static void *tmem_unittest_memory_model(int *buf)
{
	int	*p[4], u, f;

	if (csc_tmem_init(buf, sizeof(int)*26) == NULL) {
		return NULL;
	}

	/* memory target:  2 words
	 * memory pattern: 1 + 4 + 2 + more */
	p[0] = csc_tmem_alloc(buf, sizeof(int));
	csc_tmem_alloc(buf, sizeof(int));
	p[1] = csc_tmem_alloc(buf, sizeof(int)*4);
	csc_tmem_alloc(buf, sizeof(int));
	p[2] = csc_tmem_alloc(buf, sizeof(int)*2);
	csc_tmem_alloc(buf, sizeof(int));
	csc_tmem_free(buf, p[0]);
	csc_tmem_free(buf, p[1]);
	csc_tmem_free(buf, p[2]);

	f = tmem_unittest_memory_pattern(buf, &u);
	cclog(u == 0x111 && f == 0x1428, "Create heap with 4 holes [%x %x]\n", u, f);
	return buf;
}

static int tmem_unittest_misc_memory(int *buf)
{
	int	n, k, *p;
	size_t	msize;

	msize = sizeof(int)*20;
	p = csc_tmem_init(buf, msize);
	cclog(p == buf, "Create heap with %d bytes\n", msize);
	if (p == NULL) return 0;

	n = csc_tmem_free(NULL, NULL);
	cclog(n == CSC_MERR_INIT, "Free NULL heap: %d\n", n);
	n = csc_tmem_free(buf, NULL);
	cclog(n == CSC_MERR_RANGE, "Free NULL memory: %d\n", n);

	/* test the memory initial clean function */
	tmem_config |= CSC_MEM_CLEAN;
	buf[2] = -1;
	p = csc_tmem_alloc(buf, 1);
	cclog(buf[2] == 0, "Memory is initialized to %x\n", *p);
	
	/* double free test */
	n = csc_tmem_free(buf, p);
	k = csc_tmem_free(buf, p);
	cclog(n == 0 && k == CSC_MERR_RANGE, "Memory is double freed. [%d]\n", k);

	/* test the memory initial non-clean function */
	tmem_config &= ~CSC_MEM_CLEAN;
	buf[2] = -1;
	p = csc_tmem_alloc(buf, sizeof(int));
	cclog(*p == -1, "Memory is not initialized. [%x]\n", *p);

	tmem_unittest_memory_model(buf);
	tmem_config &= ~CSC_MEM_FITMASK;
	tmem_config |= CSC_MEM_FIRST_FIT;
	p = csc_tmem_alloc(buf, sizeof(int)*2);
	n = tmem_unittest_memory_pattern(buf, &k);
	cclog(k == 0x1211 && n == 0x1128, "Allocated 2 words by First Fit method [%x %x]\n", k, n);

	csc_tmem_free(buf, p);
	tmem_config &= ~CSC_MEM_FITMASK;
	tmem_config |= CSC_MEM_BEST_FIT;
	p = csc_tmem_alloc(buf, sizeof(int)*2);
	n = tmem_unittest_memory_pattern(buf, &k);
	cclog(k == 0x1121 && n == 0x148, "Allocated 2 words by Best Fit method [%x %x]\n", k, n);

	csc_tmem_free(buf, p);
	tmem_config &= ~CSC_MEM_FITMASK;
	tmem_config |= CSC_MEM_WORST_FIT;
	p = csc_tmem_alloc(buf, sizeof(int)*2);
	n = tmem_unittest_memory_pattern(buf, &k);
	cclog(k == 0x1112 && n == 0x1425, "Allocated 2 words by Worst Fit method [%x %x]\n", k, n);
	return 0;
}

int csc_tmem_unittest(void)
{
	int	i, buf[256];
	int	plist[] = { -1, 0, 1, 0xf0f0f0f0, 0x55555555, 0x0f0f0f0f, 0x66666666 };

	for (i = 0; i < (int)(sizeof(plist)/sizeof(int)); i++) {
		cclog(tmem_parity(plist[i]) == tmem_parity(tmem_parity(plist[i])),
				"ODD Parity 0x%08x: 0x%08x 0x%08x\n", plist[i], 
				tmem_parity(plist[i]),
				tmem_parity(tmem_parity(plist[i])));
		cclog(tmem_parity16((short) plist[i]) == tmem_parity16(tmem_parity16((short)plist[i])),
				"ODD Parity16   0x%04x: 0x%04x 0x%04x\n", 
				(unsigned short) plist[i], 
				(unsigned short) tmem_parity16((short) plist[i]),
				(unsigned short) tmem_parity16(tmem_parity16((short)plist[i])));
	}

	cclog(-1, "Testing memory function supports empty allocation\n");
	tmem_config |= CSC_MEM_ZERO;
	tmem_unittest_empty_memory(buf);
	
	cclog(-1, "Testing memory function doesn't support empty allocation\n");
	tmem_config = CSC_MEM_DEFAULT;
	tmem_unittest_nonempty_memory(buf);

	cclog(-1, "Testing other memory functions\n");
	tmem_unittest_misc_memory(buf);
	return 0;
}
#endif	/* CFG_UNIT_TEST */

