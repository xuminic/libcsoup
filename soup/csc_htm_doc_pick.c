
/*!\file       csc_htm_doc_pick.c
   \brief      find the body of a string without heading and 
               tailing white spaces

   \author     "Andy Xuming" <xuming@users.sourceforge.net>
   \date       2013-2023
*/
/* Copyright (C) 1998-2023  "Andy Xuming" <xuming@users.sourceforge.net>

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

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "libcsoup.h"

/*!\brief pick out the document field in an HTML page.
 
   The function is used to locate the document field and copy it to 
   the given buffer.

   \param[in]  s     The HTML page in form of string
   \param[out] sp    The start point of the located HTML tag
   \param[in]  from  The begin mark for the searching
   \param[in]  to    The end mark for the searching
   \param[in]  buf   The buffer to store the located document
   \param[in]  blen  The length of the buffer

   For example if 's' is "<td class=gdt1>File Size:</td>x...",
      csc_htm_doc_pick(s, &sp, "<td", "</td>", buf, sizeof(buf));
   returns a pointer to "x..." for the next search, stores "File Size:" 
   into 'buf', and points 'sp' to "<td class".

      csc_htm_doc_pick(s, &sp, "<td", "</td>", NULL, 0);
   returns a pointer to "x..." for the next search and points 'sp' to "<td class"
   so you need to manually handle this tag.

      csc_htm_doc_pick(s, &sp, "<td", "</td>", NULL, -1);
   returns a pointer to "File Size:", points 'sp' to "<td class" and 
   inserts an '\0' after "File Size:". Since the '\0' breaks the source string
   there will be no next search.
  
   \return If search failed it returns NULL. Otherwise,
           if 'buf' is NULL and 'blen' is -1, it points to the document.
	   if 'blen' is not -1, it points to the end of the located tag.
   \remark This function may change the source string.
*/
char *csc_htm_doc_pick(char *s, char **sp, char *from, char *to, char *buf, int blen)
{
	if ((s = strstr(s, from)) == NULL) {
		return NULL;
	}

	if (sp) {	/* save and return the start point */
		*sp = s;
	}

	/* move to the end of the tag */
	if ((s = strchr(s + strlen(from), '>')) == NULL) {
		return NULL;
	}

	/* mark the starting point */
	from = csc_trim_head(++s, " ");		/* from = ++s; */

	if ((s = strstr(s, to)) == NULL) {	/* s moves to the end point */
		return NULL;
	}
	
	if (buf) {
		csc_memcpy(buf, blen, from, s);
		csc_trim_tail(buf, " ");
	} else if (blen < 0) {	/* broken mode will break the original string */
		*s = 0;
		csc_trim_tail(from, " ");
		return from;	/* broken mode will return the content string */
	}
	return s + strlen(to);
}

