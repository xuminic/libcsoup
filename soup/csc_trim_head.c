/*!\file       csc_trim_head.c
   \brief      skip the unwanted characters from the head of a string.

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

/*!\brief skip the unwanted characters from the head of a string.
 
   The csc_trim_head() is used to trim the head of a string by skipping the
   unwanted characters according to the specified character set. 
   Most of characters are one to one match, except a whitespace. A whitespace
   in the character set can match any whitespace.

   For example, if the character set is "/: ", it would match '/', ':' and any
   whitespaces like ' ', '\t', '\n', etc

   s[] = "https:\t//libzip.org/g/1958342/016a3b968d////  \n"
   csc_trim_head(s, "hpst:/ ") trims to "libzip.org/g/1958342/016a3b968d////  \n"
   and return its length.
   
   \param[in]  s    The source string
   \param[in]  cset The character set

   \return The string after trimming.
   \remark This function doesn't changes the source string but shift the start pointer
*/

char *csc_trim_head(char *s, char *cset)
{
	for ( ; *s && csc_isdelim(cset, *s); s++);
	return s;
}


