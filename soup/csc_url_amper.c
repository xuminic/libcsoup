
/*!\file       csc_url_amper.c
   \brief      substitute the HTML entity by ASC characters like ampersand

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
#include <stdlib.h>

#include "libcsoup.h"

/*!\brief substitute the HTML entity by ASC characters like ampersand
 
   This function is used to replace the HTML entity "&amp;" by the printable
   character "&", because the 'wget' doesn't accept the HTML entities.

   For example, if the input string is
     http://50.7.233.114/ehg/image.php?f=5154150da59ceb92e8ce9fd13ef7bab7615cd
     b58-503119-892-1237-png&amp;t=370249-94283429070c8dadfba302cdbdd75f3dfb
     dedc12&amp;n=039.png
   then change to
     http://50.7.233.114/ehg/image.php?f=5154150da59ceb92e8ce9fd13ef7bab7615cd
     b58-503119-892-1237-png;t=370249-94283429070c8dadfba302cdbdd75f3dfb
     dedc12;n=039.png 

   https://stackoverflow.com/questions/9084237/what-is-amp-used-for
   https://www.freeformatter.com/html-entities.html

   \param[in]   url     The source string
   \param[out]  buffer  The destination buffer
   \param[in]   blen    The lenght of the buffer

   \return The pointer to the destination buffer
   \remark There are many HTML entities but 'wget' gets most impact by "&amp;"
*/
char *csc_url_amper(char *url, char *buffer, int blen)
{
	char	*p;

	if ((buffer == NULL) || (blen == 0)) {
		return NULL;
	}
	blen--;		/* save a space for asc-0 */
	for (p = buffer; blen && *url; ) {
		if (!strncmp(url, "&amp;", 5)) {
			*p++ = '&';
			blen--;
			url += 5;
		} else if (!strncmp(url, "&nbsp;", 6)) {
			*p++ = 255;
			blen--;
			url += 6;
		} else {
			*p++ = *url++;
			blen--;
		}
	}
	*p++ = 0;
	return buffer;
}

/*!\brief substitute the HTML entity by ASC characters like ampersand
 
   This function is the same to csc_url_amper() except it writes the result
   back to the source string.
   Normally the HTML entities are shorter than its counterpart ASCII so
   ideally it won't blow the buffer.

   \param[in]   url     The source string

   \return The pointer to 'url'
   \remark Make sure the 'url' is not a const string.
*/
char *csc_url_amper_wb(char *url)
{
	return csc_url_amper(url, url, strlen(url)+1);
}

/*!\brief substitute the HTML entity by ASC characters like ampersand
 
   This function is the same to csc_url_amper() except it allocates
   a memory to store the result string.
   Normally the HTML entities are shorter than its counterpart ASCII so
   ideally it won't blow the buffer.

   \param[in]  url     The source string
   \param[in]  extra   The extra bytes in the allocation if in needs

   \return The pointer to the allocated string.
   \remark The caller must free the string after use.
*/
char *csc_url_amper_alloc(char *url, int extra)
{
	char	*buf;
	int	blen;

	/* normally the HTML entities are shorter than its counterpart ASCII */
	blen = strlen(url) + 1;
	if ((buf = malloc(blen)) == NULL) {
		return NULL;
	}
	return csc_url_amper(url, buf, blen);
}

