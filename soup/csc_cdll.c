
/*!\file       csc_cdll.c
   \brief      The management function of circular doubly linked list.

   This file supplies a group of functions to process the circular doubly 
   linked list.

   \author     "Andy Xuming" <xuming@users.sourceforge.net>
   \date       2013-2014
   \copyright  GNU Public License.
*/
/* Copyright (C) 1998-2014  Xuming <xuming@users.sourceforge.net>
   
   This program is free software; you can redistribute it and/or 
   modify it under the terms of the GNU General Public License as 
   published by the Free Software Foundation; either version 2, or 
   (at your option) any later version.
	   
   This program is distributed in the hope that it will be useful, 
   but WITHOUT ANY WARRANTY; without even the implied warranty of 
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License, the file COPYING in this directory, for
   more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "libcsoup.h"


/*!\brief Insert a node after the reference node

   \param[in]  refn The reference node where to insert after   
   \param[in]  node 
   \return     void
*/
void csc_cdl_insert_after(CSCLNK *refn, CSCLNK *node)
{
	refn->next->prev = node;
	node->next = refn->next;
	refn->next = node;
	node->prev = refn;
}

CSCLNK *csc_cdl_insert_head(CSCLNK *anchor, CSCLNK *node)
{
	if (anchor == NULL) {
		node->prev = node->next = node;
	} else {
		csc_cdl_insert_after(anchor->prev, node);
	}
	return node;	/* return the new anchor */
}

CSCLNK *csc_cdl_insert_tail(CSCLNK *anchor, CSCLNK *node)
{
	if (anchor == NULL) {
		anchor = node->prev = node->next = node;
	} else {
		csc_cdl_insert_after(anchor->prev, node);
	}
	return anchor;
}

CSCLNK *csc_cdl_remove(CSCLNK *anchor, CSCLNK *node)
{
	node->prev->next = node->next;
	node->next->prev = node->prev;
	if (anchor == node) {
		anchor = node->next;
	}
	if (anchor == node) {	/* single node list */
		anchor = NULL;
	}
	return anchor;
}

CSCLNK *csc_cdl_next(CSCLNK *anchor, CSCLNK *node)
{
	if (node->next == anchor) {
		return NULL;
	}
	return node->next;
}

CSCLNK *csc_cdl_search(CSCLNK *anchor, int(*compare)(void *, void *), void *refload)
{
	CSCLNK	*node;

	for (node = anchor; node != NULL; node = csc_cdl_next(anchor, node)) {
		if (!compare((void*)node->payload, refload)) {
			return node;
		}
	}
	return NULL;
}

CSCLNK *csc_cdl_goto(CSCLNK *anchor, int idx)
{
	CSCLNK	*node;
	int	i = 0;

	for (node = anchor; node != NULL; node = csc_cdl_next(anchor, node)) {
		if (idx == i) {
			return node;
		}
		i++;
	}
	return NULL;
}

CSCLNK *csc_cdl_alloc_head(CSCLNK **anchor, int size)
{
	CSCLNK	*node;

	if ((node = smm_alloc(sizeof(CSCLNK)+size)) == NULL) {
		return NULL;
	}
	*anchor = csc_cdl_insert_head(*anchor, node);
	return node;
}

CSCLNK *csc_cdl_alloc_tail(CSCLNK **anchor, int size)
{
	CSCLNK	*node;

	if ((node = smm_alloc(sizeof(CSCLNK)+size)) == NULL) {
		return NULL;
	}
	*anchor = csc_cdl_insert_tail(*anchor, node);
	return node;
}

int csc_cdl_free(CSCLNK **anchor, CSCLNK *node)
{
	*anchor = csc_cdl_remove(*anchor, node);
	smm_free(node);
	return 0;
}

int csc_cdl_destroy(CSCLNK **anchor)
{
	CSCLNK	*cur, *node;

	node = *anchor; 
	while (node != NULL) {
		cur = node;
		node = csc_cdl_next(*anchor, node);
		smm_free(cur);
	}
	*anchor = NULL;
	return 0;
}

#if 0
int main()
{
	CSCLNK	*node, *anchor = NULL;
	char	*cont[] = { "Hello", "World", "Peace", "Love", "Bullshit", NULL };

	node = csc_cdl_alloc_head(&anchor, 16);
	strcpy((char*)node->payload, cont[0]);

	node = csc_cdl_alloc_head(&anchor, 16);
	strcpy((char*)node->payload, cont[1]);

	node = csc_cdl_alloc_tail(&anchor, 16);                
	strcpy((char*)node->payload, cont[2]);

	for (node = anchor; node != NULL; node = csc_cdl_next(anchor, node)) {
		printf("%s\n", (char*)node->payload);
	}
	return 0;
}
#endif

