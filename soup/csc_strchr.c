
/*!\file       csc_strchr.c
   \brief      locate characters in string

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

/*!\brief locate characters in string
 
   This function returns a pointer to the first occurrence of the character
   set 'cset' in the string 's'. The difference to strchr() is it can search
   more than one characters in the same time and return the first found.
   
   \param[in]  s     The source string
   \param[in]  cset  The character set

   \return The pointer to the first occurrence in the cset, or NULL if nothing found.
*/
char *csc_strchr(char *s, char *cset)
{
	char	*p, *best = NULL;

	while (*cset) {
		if ((p = strchr(s, *cset)) == NULL) {
			continue;
		}
		if ((best == NULL) || ((best - s) > (p - s))) {
			best = p;
		}
		cset++;
	}
	return best;
}


/*!\brief locate characters in string
 
   This function returns a pointer to the last occurrence of the character
   set 'cset' in the string 's'. The difference to strrchr() is it can search
   more than one characters in the same time and return the last found.
   
   \param[in]  s     The source string
   \param[in]  cset  The character set

   \return The pointer to the last occurrence in the cset, or NULL if nothing found.
*/
char *csc_strrchr(char *s, char *cset)
{
	char	*p, *best = NULL;

	while (*cset) {
		if ((p = strchr(s, *cset)) == NULL) {
			continue;
		}
		if ((best == NULL) || ((best - s) < (p - s))) {
			best = p;
		}
		cset++;
	}
	return best;
}

