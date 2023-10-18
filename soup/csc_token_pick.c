/*!\file       csc_token_pick.c
   \brief      pick a token from a string

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
#include <stdlib.h>
#include <string.h>

#include "libcsoup.h"

/*!\brief pick a token from a string
 
   The csc_token_pick_ro() is used to pick out a token from a string.
   If there are more than one tokens, it picks by index.  For example, 

   csc_token_pick_ro("https://libzip.org/g/1958342/016a3b968d/", '/', 0,...) points to "https:"
   csc_token_pick_ro("https://libzip.org/g/1958342/016a3b968d/", '/', 1, ...) points to ""
   csc_token_pick_ro("https://libzip.org/g/1958342/016a3b968d/", '/', 2, ...) points to "libzip.org"
   csc_token_pick_ro("https://libzip.org/g/1958342/016a3b968d/", '/', 3, ...) points to "g"
   csc_token_pick_ro("https://libzip.org/g/1958342/016a3b968d/", '/', 4, ...) points to "1958342"

   \param[in]   s    The source string
   \param[in]   sep  The delimiter to seperate the tokens
   \param[in]   idx  The index to the tokens
   \param[out]  len  The effective lenght of the string

   \return The pointer to the token, or NULL if index out of token.
   \remark This function does not change the source string.
*/
char *csc_token_pick_ro(char *s, int sep, int idx, int *len)
{
	int	i;

	for (i = 0; i < idx; i++) {
		if ((s = strchr(s, sep)) == NULL) {
			return NULL;
		}
		s++;
	}
	for (i = 0; s[i] && (s[i] != sep); i++);
	if (len) {
		*len = i;
	}
	return s;
}


/*!\brief pick a token from a string
 
   The csc_token_pick() is similar to csc_token_pick_ro() except it will
   chop off everything after the token.

   \param[in]   s    The source string
   \param[in]   sep  The delimiter to seperate the tokens
   \param[in]   idx  The index to the tokens

   \return The pointer to the token, or NULL if index out of token.
   \remark This function changes the source string.
*/
char *csc_token_pick(char *s, int sep, int idx)
{
	int	len;

	if ((s = csc_token_pick_ro(s, sep, idx, &len)) != NULL) {
		s[len] = 0;
	}
	return s;
}

/*!\brief pick a token from a string
 
   The csc_token_pick_alloc() is similar to csc_token_pick_ro() except it will
   allocate a piece of memory to store the token.

   \param[in]  s      The source string
   \param[in]  sep    The delimiter to seperate the tokens
   \param[in]  idx    The index to the tokens
   \param[in]  extra  The extra bytes in the allocation if in needs

   \return The memory storing the token.
   \remark This function doesn't change the source string.
*/
char *csc_token_pick_alloc(char *s, int sep, int idx, int extra)
{
	char	*p;
	int	len;

	if ((s = csc_token_pick_ro(s, sep, idx, &len)) == NULL) {
		return NULL;
	}
	if ((p = malloc(len+extra+1)) != NULL) {
		memcpy(p, s, len);
		p[len] = 0;
	}
        return p;
}

/*!\brief pick a token from a string
 
   The csc_token_pick_copy() is similar to csc_token_pick_ro() except it will
   copy the token to the specified buffer.

   \param[in]  s      The source string
   \param[in]  sep    The delimiter to seperate the tokens
   \param[in]  idx    The index to the tokens
   \param[in]  buf    Caller supplied buffer for copying the token
   \param[in]  blen   The length of the 'buf'

   \return The pointer to the token in the source string 's'.
   \remark This function doesn't change the source string.
*/
char *csc_token_pick_copy(char *s, int sep, int idx, char *buf, int blen)
{
	int	len;

	if ((s = csc_token_pick_ro(s, sep, idx, &len)) != NULL) {
		csc_strlmove(buf, blen, s, len);
	}
	return s;
}

