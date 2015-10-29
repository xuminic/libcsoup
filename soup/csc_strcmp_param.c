
/*!\file       csc_strcmp_param.c
   \brief      Compare two parameter strings. 
               Empty or blank string is equal to NULL string.

   \author     "Andy Xuming" <xuming@users.sourceforge.net>
   \date       2013-2014
*/
/* Copyright (C) 1998-2014  "Andy Xuming" <xuming@users.sourceforge.net>

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

#include <stdio.h>
#include <string.h>

/*!\brief Compare two parameter strings while empty or blank string is equal 
   to a NULL string pointer.

   The function compares the two parameter strings 's1' and 's2'.  It returns 
   an integer less than, equal to, or greater than zero if 's1' is found, 
   respectively, to be less than, to match, or be greater than 's2'.

   The difference between csc_strcmp_param() and strcmp() is 's1' and 's2'
   can be NULL and equal to empty string ("") or blank string ("\t\f\v\n\r ")

   \param[in]  s1  string 1, can be NULL.
   \param[in]  s2  string 2, can be NULL.

   \return     an integer less than, equal to, or greater than zero if 's1' is
   found, respectively, to be less than, to match, or be greater than 's2'.
*/
int csc_strcmp_param(const char *s1, const char *s2)
{
	//printf("csc_strcmp_param: {%s}{%s}\n", dest, sour);
	if (dest && sour) {
		dest = csc_strbody(dest, NULL);
		sour = csc_strbody(sour, NULL);
		return strcmp(dest, sour);
	} else if (!dest && !sour) {
		return 0;
	} else if (dest) {
		dest = csc_strbody(dest, NULL);
		return *dest;
	} else {
		sour = csc_strbody(sour, NULL);
		return *sour;
	}
	return 0;
}

