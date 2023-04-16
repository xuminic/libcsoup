
/*!\file       csc_strrpch.c
   \brief      substitute a character in a string 

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

/*!\brief substitute a character in a string.
 
   This function is used to replace the 'old' char in the string 's' 
   with 'new' char.


   \param[in]  s     The source string
   \param[in]  num   How many character being substituted
                     = 0: replace all occurance in the string
                     > 0: replace the specified 'num' occurance in the string
                     < 0: replace the specified 'num' occurance in the string from tail 
   \param[in]  oldc  The character being substituted
   \param[in]  newc  The character to be

   \return The number of finally being replaced characters.
   \remark This function change the source string.
*/
int csc_strrpch(char *s, int num, int oldc, int newc)
{
	if (num == 0) {		/* unlimited search and replace */
		while (*s) {
			if (*s == oldc) {
				*s = newc;
				num++;
			}
			s++;
		}
	} else if (num > 0) {	/* limited search and replace from left */
		while (num && *s) {
			if (*s == oldc) {
				*s = newc;
				num--;
			}
			s++;
		}
	} else {		/* limited search and replace from right */
		char	*p = s + strlen(s) - 1;
		while (num && (p >= s)) {
			if (*p == oldc) {
				*p = newc;
				num++;
			}
			p--;
		}
	}
	return num;
}

