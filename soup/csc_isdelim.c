
/*!\file       csc_isdelim.c
   \brief      check if a char is in the delimiter list, all whitespace are treated equal

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

/*!\brief check if a char is in the delimiter list
 
   The csc_isdelim() is uesed to check if a char byte is a delimiter.
   The delimiter can be more than one, so if any of them matches, the function matches.
   The special part of the function is it sees all whitespace equal.
   If a whitespace is in the delimiter list, then any whitespace matches.

   For example, if the delimiter list is "\t\\/", then ' ', '\n', '/', '\\' all matches.

   \param[in]  delim  The string of the delimiter list
   \param[in]  ch     The char for matching

   \return 1 if matches the delimiter, 0 if not
*/
int csc_isdelim(char *delim, int ch)
{
	while (*delim) {
		if (*delim == (char) ch) {
			return 1;
		} else if (SMM_ISSPACE(*delim) && SMM_ISSPACE(ch)) {
			return 1;
		}
		delim++;
	}
	return 0;
}


