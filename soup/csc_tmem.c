
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
/* gcc -Wall -DQUICK_TEST_MAIN -o tmem csc_tmem.c */

#include <stdio.h>
#include <limits.h>
#include <string.h>

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
#define UCHAR		unsigned char
#define CWORD		unsigned
#define CWSIZE		((int)sizeof(CWORD))

#define TMEM_MASK	(UINT_MAX >> 2)
#define TMEM_SIZE(n)	((int)(n) & TMEM_MASK)
#define TMEM_NEXT(n)	((int*)(n) + TMEM_SIZE(*(int*)(n)) + 1)
#define TMEM_CRASH(n)	(*((int*)(n)) != tmem_parity(*((int*)(n))))


#if	(UINT_MAX == 4294967295U)
#define TMEM_SET_USED(n)	((n) | 0x40000000U)
#define	TMEM_CLR_USED(n)	((n) & ~0x40000000U)
#define	TMEM_TEST_USED(n)	((n) & 0x40000000U)
#else
#define	TMEM_SET_USED(n)	((n) | 0x4000U)
#define	TMEM_CLR_USED(n)	((n) & ~0x4000U)
#define	TMEM_TEST_USED(n)	((n) & 0x4000U)
#endif

static int tmem_parity(int cw);
static int tmem_store_cword(int *mb, int size, int used);


/*!\brief Initialize the memory heap to be allocable.

   \param[in]  heap the memory heap for allocation.
   \param[in]  len the size of the memory heap.

   \return    The free space of the memory heap in unit of int 
              or -1 if the memory heap is too large or too small.

   \remark The given memory pool must be started at 'int' boundry.
   The minimum allocation unit is 'int'. Therefore the maximum managable 
   memory is 4GB in 32/64-bit system, or 32KB in 8/16-bit system.
*/
int csc_tmem_init(void *heap, size_t len)
{
	/* change size unit to per-int; the remains will be cut off  */
	len /= sizeof(int);	

	/* save one unit for heap managing  */
	len--;
	
	/* make sure the size is not out of range */
	if ((len < 1) || (len > (UINT_MAX >> 2))) {
		return -1;
	}

	/* create the heap management */
	tmem_store_cword(heap, (int)len, 1);
	
	/* create the first memory block */
	((int*)heap)++;
	len--;
	tmem_store_cword(heap, (int)len, 0);
	return (int)len;
}

void *csc_tmem_scan(void *heap, int (*used)(int*), int (*fresh)(int*))
{
	int	*mb;

	if (TMEM_CRASH(heap)) {
		return heap;	/* memory heap not available */
	}
	for (mb = ((int*)heap)+1; mb < TMEM_NEXT(heap); mb = TMEM_NEXT(mb)) {
		if (TMEM_CRASH(mb)) {
			return (void*)mb;	/* chain broken */
		}
		if (TMEM_TEST_USED(*mb)) {
			if (used && used(mb)) {
				break;
			}
		} else {
			if (fresh && fresh(mb)) {
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

   \remark The strategy of allocation is first fit.
*/
void *csc_tmem_alloc(void *heap, size_t n)
{
	int	 *found, *next;
	int	unum = (int)((n + sizeof(int) - 1) / sizeof(int));
	
	int fresh(int *mb)
	{
		if (TMEM_SIZE(*mb) >= unum) {
			if (found == NULL) {
				found = mb;
			}
#if	CSC_MEM_FITNESS == CSC_MEM_FIRST_FIT
			return 1;
#endif
#if	CSC_MEM_FITNESS == CSC_MEM_BEST_FIT
			if (TMEM_SIZE(*found) > TMEM_SIZE(*mb)) {
				found = mb;
			}
#endif
#if	CSC_MEM_FITNESS == CSC_MEM_WORST_FIT
			if (TMEM_SIZE(*found) < TMEM_SIZE(*mb)) {
				found = mb;
			}
#endif
		}
		return 0;
	}

	if (TMEM_CRASH(heap)) {
		return NULL;	/* memory heap not available */
	}
	if (n > TMEM_SIZE(*((int*)heap)) * sizeof(int)) {
		return NULL;	/* request out of size */
	}

	found = next = NULL;
	if (csc_tmem_scan(heap, NULL, fresh)) {
		return NULL;	/* chain broken */
	}
	if (found == NULL) {
		return NULL;	/* out of memory */
	}

	if (TMEM_SIZE(*found) < unum + 2) {	
		/* not worth to split this block */
		tmem_store_cword(found, *found, 1);
	} else {
		/* split this memory block */
		next = found + unum + 1;
		tmem_store_cword(next, TMEM_SIZE(*found) - unum - 1, 0);

		tmem_store_cword(found, unum, 1);
	}
	return (void*)(found+1);
}

/*!\brief free the allocated memory block.

   \param[in]  heap the memory heap for allocation.
   \param[in]  n the memory block.

   \return    0 if freed successfully 
              or -1 if the memory block not found.

   \remark csc_tmem_free() supports merging memory holes.
*/
int csc_tmem_free(void *heap, void *mem)
{
	int	*last, *found, cw;

	int used(int *mb)
	{
		if ((void*)(mb+1) == mem) {
			found = mb;
			/* try to down-merge the next memory block */
			mb = tmem_next(mb);
			if (mb >= tmem_next(heap)) {
				return 1;	/* end of memory chain */
			}
			if (TMEM_CRASH(*mb)) {
				return 1;	/* broken memory chain */
			}
			if (TMEM_TEST_USED(*mb)) {	/* free itself */
				tmem_store_cword(found, *found, 0);
			} else {	/* To merge the next free block */
				cw = TMEM_SIZE(*found) + TMEM_SIZE(*mb) + 1;
				tmem_store_cword(found, cw, 0);
			}
			return 1;
		}
		return 0;
	}
	int fresh(int *mb)
	{
		last = mb;
		return 0;
	}

	if (TMEM_CRASH(heap)) {
		return -1;	/* memory heap not available */
	}

	last = found = NULL;
	if (csc_tmem_scan(heap, used, fresh)) {
		return -2;	/* memory chain broken */
	}

	if (found == NULL) {
		/* BE WARE: To free a free memory returns -3 "not found" */
		return -3;	/* memory not found */
	}

	/* try to up-merge the previous memory block */
	if (TMEM_NEXT(last) == found) {
		cw = TMEM_SIZE(*last) + TMEM_SIZE(*found) + 1;
		tmem_store_cword(last, cw, 0);
	}
	return 0;
}

/* applying odd parity so 15 (16-bit) or 31 (32-bit) 1-bits makes MSB[1]=0,
 * which can easily sorting out -1 as an illegal word. */
static int tmem_parity(int cw)
{
	unsigned  tmp = (unsigned)cw;
	int	i, n;

	for (i = n = 0; i < 8*sizeof(int) - 1; i++, tmp >>= 1) {
		n += tmp & 1;
	}
	n++;	/* make odd bit even */
	
#if	(UINT_MAX == 4294967295U)
	cw &= ~0x80000000U;
	cw |= (n << 31);
#else
	cw &= ~0x8000U;
	cw |= (n << 15);
#endif
	return cw;
}

static int tmem_store_cword(int *mb, int size, int used)
{
	if (used) {
		size = TMEM_SET_USED(size);
	}
	*mb = tmem_parity(size);
	return *mb;
}


#ifdef	QUICK_TEST_MAIN
static char *linedump(void *mem, int msize)
{	
	unsigned char	*tmp = mem;
	static	char	buf[256];
	char	*vp = buf;

	if (msize * 3 > sizeof(buf)) {
		msize = sizeof(buf) / 3;
	}
	while (msize--) {
		sprintf(vp, "%02X", *tmp++);
		vp += 2;
		*vp++ = ' ';
	}
	*vp = 0;
	return buf;
}

static void *tmem_pick(void *heap, int n)
{
	UCHAR 	*mb;

	for (mb = tmem_begin(heap); !tmem_end(heap, mb); 
			mb = tmem_next(mb)) {
		if (n == 0) {
			return mb + CWSIZE;
		}
		n--;
	}
	return NULL;
}

static int tmem_dump(void *heap)
{
	CWORD	cw;
	UCHAR	*mb;
	int 	i, avail;

	if ((cw = tmem_load_cword(heap)) == (CWORD) -1) {
		printf("Memory Segment not available at [%p].\n", heap);
		return 0;
	}
	printf("Memory Segment at [%p][%x]: %d bytes\n", 
			heap, cw, TMEM_SIZE(cw));

	i = avail = 0;
	for (mb = tmem_begin(heap); !tmem_end(heap, mb); 
			mb = tmem_next(mb)) {
		cw = tmem_load_cword(mb);
		printf("[%3d][%5d][%08x]: %4d [%s]\n", i, 
				(int)(mb - (UCHAR*)heap), cw,
				TMEM_SIZE(cw), linedump(mb, 8));
		i++;
		if (TMEM_TEST_USED(cw) == 0) {
			avail += TMEM_SIZE(cw);
		}
	}
	printf("Total blocks: %d;  %d bytes available.\n", i, avail);
	return i;
}


int main(void)
{
	char	buf[256];
	char	*p;

	printf("ODD Parity 0x%08x: 0x%08x\n", -1, tmem_parity(-1));
	printf("ODD Parity 0x%08x: 0x%08x\n", 0, tmem_parity(0));
	printf("ODD Parity 0x%08x: 0x%08x\n", 
			tmem_parity(-1), tmem_parity(tmem_parity(-1)));

	memset(buf, 0, sizeof(buf));
	csc_tmem_init(buf, sizeof(buf));
	tmem_dump(buf);

	while ((p = csc_tmem_alloc(buf, 25)) != NULL) {
		strcpy(p, "hello");
	}
	tmem_dump(buf);

	printf("Freeing first and last memory block.\n");
	csc_tmem_free(buf, p);
	p = tmem_pick(buf, 0);
	csc_tmem_free(buf, p);
	p = tmem_pick(buf, 7);
	csc_tmem_free(buf, p);
	tmem_dump(buf);

	printf("Create a memory fregment.\n");
	p = tmem_pick(buf, 2);
	csc_tmem_free(buf, p);
	p = tmem_pick(buf, 4);
	csc_tmem_free(buf, p);
	tmem_dump(buf);

	printf("Merge the memory hole.\n");
	p = tmem_pick(buf, 3);
	csc_tmem_free(buf, p);
	tmem_dump(buf);
	return 0;
}
#endif

