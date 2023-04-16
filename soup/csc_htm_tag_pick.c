
/*!\file       csc_htm_tag_pick.c
   \brief      pick out the attribute of a tag

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

/*!\brief pick out the attribute field of a tag.
 
   \param[in]  s     The HTML page in form of string
   \param[in]  from  The begin mark for the searching
   \param[in]  to    The end mark for the searching
   \param[in]  buf   The buffer to store the located document
   \param[in]  blen  The length of the buffer

   if 's' is
     <meta name="juicyads-site-verification" content="0f3e47704e352bf534e98d4d45411fda"/> 
   then
     csc_htm_tag_pick(s, "name=\"", "\"", buf, blen);
   will return 'juicyads-site-verification' by 'buf'.
     csc_htm_tag_pick(s, "name=\"", "\"", NULL, 0);
   will return a pointer to 'juicyads-site-verification" content="0f...' to the end.
     csc_htm_tag_pick(s, "name=\"", "\"", NULL, -1);
   will return 'juicyads-site-verification' but break the original string by inserting '\0'.
 
   \return The pointer to the located content if succeed, otherwise NULL.
   \remark This function may change the source string.
*/
char *csc_htm_tag_pick(char *s, char *from, char *to, char *buf, int blen)
{
	char	*endp;

	if ((endp = strchr(s + strlen(from), '>')) == NULL) {	/* set the picking boundry */
		return NULL;
	}
	if ((s = strstr(s, from)) == NULL) {
		return NULL;
	}
	if (s > endp) {
		return NULL;	/* hit the boundry */
	}
	from = s + strlen(from);	/* 'from' move to the copy starting point */

	if ((s = strstr(from, to)) == NULL) {
		return NULL;
	}
	if (s > endp) {
		return NULL;	/* hit the boundry */
	}

	if (buf) {
		csc_memcpy(buf, blen, from, s);
	} else if (blen < 0) {	/* broken mode will break the original string */
		*s = 0;		/* break the string */
	}
	return from;	/* return the copy starting point */
}

