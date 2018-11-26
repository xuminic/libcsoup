
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

#define TMEM_MAX	((int)(UINT_MAX >> 2))
#define TMEM_MASK	TMEM_MAX
#define TMEM_SIZE(n)	((int)(n) & TMEM_MASK)


#if	(UINT_MAX == 4294967295U)
#define TMEM_SET_USED(n)	((n) | 0x40000000U)
#define	TMEM_CLR_USED(n)	((n) & ~0x40000000U)
#define	TMEM_TEST_USED(n)	((n) & 0x40000000U)
#else
#define	TMEM_SET_USED(n)	((n) | 0x4000U)
#define	TMEM_CLR_USED(n)	((n) & ~0x4000U)
#define	TMEM_TEST_USED(n)	((n) & 0x4000U)
#endif

static CWORD tmem_parity(CWORD cw);
static UCHAR *tmem_begin(UCHAR *segment);
static int tmem_end(UCHAR *segment, UCHAR *mb);
static UCHAR *tmem_next(UCHAR *mb);
static CWORD tmem_load_cword(UCHAR *mb);
static void tmem_store_cword(UCHAR *mb, int size, int used);


/*!\brief Initialize the memory segment to be allocable.

   \param[in]  segment the memory segment for allocation.
   \param[in]  len the size of the memory segment.

   \return    The free space of the memory segment. 
              or -1 if the memory segment is too large or too small.

   \remark The maximum managable memory segment is the maximum integer 
   divided by 4, which means 1GB in 32-bit system or 16k in 8-bit system.
*/
int csc_tmem_init(void *segment, int len)
{
	len -= CWSIZE;
	if ((len < CWSIZE) || (len > TMEM_MAX)) {
		return -1;	/* size out of range */
	}

	/* create the managing block */
	tmem_store_cword(segment, len, 1);
	
	/* create the first memory block */
	segment = (UCHAR *)segment + CWSIZE;
	len -= CWSIZE;
	tmem_store_cword(segment, len, 0);
	return len;
}

/*!\brief allocate a piece of dynamic memory block inside the specified 
   memory segment.

   \param[in]  segment the memory segment for allocation.
   \param[in]  n the size of the expecting allocated memory block.

   \return    point to the allocated memory block in the memory segment. 
              or NULL if not enough space for allocating.

   \remark The strategy of allocation is first fit.
*/
void *csc_tmem_alloc(void *segment, int n)
{
	CWORD	cw;
	UCHAR	*mb;

	for (mb = tmem_begin(segment); !tmem_end(segment, mb); 
			mb = tmem_next(mb)) {
		if ((cw = tmem_load_cword(mb)) == (CWORD) -1) {
			break;	/* chain broken or ended */
		}
		if (TMEM_TEST_USED(cw)) {
			continue;	/* allocated block */
		}
		if (TMEM_SIZE(cw) < n) {
			continue;	/* too small to allocate */
		}

		if (TMEM_SIZE(cw) < n + CWSIZE + CWSIZE) {	
			/* can not or not worth to split */
			tmem_store_cword(mb, (int) cw, 1);
		} else {
			/* split the current memory block */
			tmem_store_cword(mb, n, 1);

			segment = mb + n + CWSIZE;
			tmem_store_cword(segment, TMEM_SIZE(cw)-n-CWSIZE, 0);
		}
		return mb + CWSIZE;
	}
	return NULL;
}

/*!\brief free the allocated memory block.

   \param[in]  segment the memory segment for allocation.
   \param[in]  n the memory block.

   \return    0 if freed successfully 
              or -1 if the memory block not found.

   \remark csc_tmem_free() supports merging memory holes.
*/
int csc_tmem_free(void *segment, void *mem)
{
	CWORD	cw, cic; 
	UCHAR	*mb, *mic = NULL;

	for (mb = tmem_begin(segment); !tmem_end(segment, mb); 
			mb = tmem_next(mb)) {
		if (mb + CWSIZE == mem) {
			break;	/* found it */
		}
		mic = mb;
	}
	if (tmem_end(segment, mb)) {
		return -1;	/* not found or broken */
	}

	cw = tmem_load_cword(mb);

	/* trying up-merge the previous memory block */
	if (mic) {
		cic = tmem_load_cword(mic);
		if (!TMEM_TEST_USED(cic)) {
			cw = TMEM_SIZE(cw) + TMEM_SIZE(cic) + CWSIZE;
			mb = mic;
		}
	}

	/* trying to down-merge the next memory block */
	mic = mb + TMEM_SIZE(cw) + CWSIZE;
	if (!tmem_end(segment, mic)) {
		cic = tmem_load_cword(mic);
		if (!TMEM_TEST_USED(cic)) {
			cw = TMEM_SIZE(cw) + TMEM_SIZE(cic) + CWSIZE;
		}
	}

	/* seal the freed memory block */
	tmem_store_cword(mb, (int) cw, 0);
	return 0;
}

static UCHAR *tmem_begin(UCHAR *segment)
{
	if (segment == NULL) {
		return NULL;
	}
	if (tmem_load_cword(segment) == (CWORD) -1) {
		return NULL;	/* memory segment not available */
	}
	return segment + CWSIZE;
}

static int tmem_end(UCHAR *segment, UCHAR *mb)
{
	CWORD	cw;

	if ((mb == NULL) || (segment == NULL)) {
		return 1;
	}

	if ((cw = tmem_load_cword(segment)) == (CWORD) -1) {
		return -1;	/* control word broken */
	}
	segment += TMEM_SIZE(cw) + CWSIZE;	/* mark the end gate */

	/* if it's not in the end of the memory segment,
	 * make sure the memory block is validated and in range */
	if ((cw = tmem_load_cword(mb)) == (CWORD) -1) {
		return -1;	/* control word broken */
	}
	if (mb + TMEM_SIZE(cw) + CWSIZE > segment) {
		return 1;	/* out of the memory segment */
	}
	return 0;	/* not at the end */
}

static UCHAR *tmem_next(UCHAR *mb)
{
	CWORD	cw;

	if ((cw = tmem_load_cword(mb)) == (CWORD) -1) {
		return NULL;	/* control word broken */
	}

	/* just return the next location of the memory block.
	 * there's no need to verify its validation here */
	mb += TMEM_SIZE(cw) + CWSIZE;
	return mb;
}

/* applying odd parity so 15 (16-bit) or 31 (32-bit) 1-bits makes MSB[1]=0,
 * which can easily sorting out -1 as an illegal word. */
static CWORD tmem_parity(CWORD cw)
{
	CWORD	tmp = cw;
	int	i, n;

	for (i = n = 0; i < CWSIZE*8 - 1; i++, tmp >>= 1) {
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

static CWORD tmem_load_cword(UCHAR *mb)
{
	CWORD	cw = 0;

#if	(UINT_MAX == 4294967295U)
	cw = (cw << 8) | *mb++;
	cw = (cw << 8) | *mb++;
#endif
	cw = (cw << 8) | *mb++;
	cw = (cw << 8) | *mb++;

	if (cw == tmem_parity(cw)) {
		return cw;
	}
	return -1;
}

static void tmem_store_cword(UCHAR *mb, int size, int used)
{
	CWORD	n;

	if (used) {
		n = TMEM_SET_USED(size);
	} else {
		n = TMEM_CLR_USED(size);
	}
	n = tmem_parity(n);

	mb += CWSIZE - 1;
#if	(UINT_MAX == 4294967295U)
	*mb-- = (UCHAR)n; n >>= 8;
	*mb-- = (UCHAR)n; n >>= 8;
#endif
	*mb-- = (UCHAR)n; n >>= 8;
	*mb-- = (UCHAR)n; n >>= 8;
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

static void *tmem_pick(void *segment, int n)
{
	UCHAR 	*mb;

	for (mb = tmem_begin(segment); !tmem_end(segment, mb); 
			mb = tmem_next(mb)) {
		if (n == 0) {
			return mb + CWSIZE;
		}
		n--;
	}
	return NULL;
}

static int tmem_dump(void *segment)
{
	CWORD	cw;
	UCHAR	*mb;
	int 	i, avail;

	if ((cw = tmem_load_cword(segment)) == (CWORD) -1) {
		printf("Memory Segment not available at [%p].\n", segment);
		return 0;
	}
	printf("Memory Segment at [%p][%x]: %d bytes\n", 
			segment, cw, TMEM_SIZE(cw));

	i = avail = 0;
	for (mb = tmem_begin(segment); !tmem_end(segment, mb); 
			mb = tmem_next(mb)) {
		cw = tmem_load_cword(mb);
		printf("[%3d][%5d][%08x]: %4d [%s]\n", i, 
				(int)(mb - (UCHAR*)segment), cw,
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

