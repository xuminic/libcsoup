
/*!\file       csc_memcpy.c
   \brief      copy a piece of memory then appending '\0'

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

/*!\brief copy a piece of memory then appending '\0'
 
   This function is used to copy contents between 'from' and 'to', 
   not include 'to', to 'dest' ended with appended '\0'

   \param[in]  dest  The buffer to store the memory
   \param[in]  dlen  The length of the buffer
   \param[in]  from  The start address of the memory copy
   \param[in]  to    The end address of the memory copy (not included)

   \return The number in bytes of the copied memory (not include the ending '\0')
*/
int csc_memcpy(char *dest, int dlen, char *from, char *to)
{
	int	n = 0;

	for (n = 0; (--dlen > 0) && (from < to); n++) *dest++ = *from++;
	*dest++ = 0;
	return n;
}

