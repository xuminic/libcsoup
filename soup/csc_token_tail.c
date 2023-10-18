
/*!\file       csc_token_tail.c
   \brief      find the tailing token in a string

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

/*!\brief find the tailing token in a string
 
   The csc_token_tail_ro() is used to find the last token in a string.
   It returns a pointer to the token and its length in 'len'.

   For example, when 'sep' is '/':
   return "1958342-5" from "https://libzip.org/s/7ea07158bd/1958342-5"
   return "016a3b968d/" from "https://libzip.org/g/1958342/016a3b968d/" 

   \param[in]   s    The source string
   \param[in]   sep  The delimiter to seperate the tokens
   \param[out]  len  The lenght of the return token

   \return The pointer to the token.
   \remark This function does not change the source string.
   \remark If removing the tailing '/', some servers may fail to response
*/
char *csc_token_tail_ro(char *s, int sep, int *len)
{
	char	cset[4] = "  ";
	int	i, rc;

	cset[0] = (char) sep;	/* one for 'sep' one for whitespaces */
	csc_trim_tail_ro(s, cset, &rc);	/* remove the trailing seperator and white spaces */
	for (i = rc - 1; (i >= 0) && (s[i] != sep); i--);
	if (len) {
		*len = rc - i - 1;
	}
	return s + i + 1;
}

/*!\brief find the tailing token in a string
 
   The csc_token_tail() is similar to csc_token_tail_ro() except it will
   remove the tailing seperate delimiter and whitespaces.

   For example, when 'sep' is '/':
   return "1958342-5" from "https://libzip.org/s/7ea07158bd/1958342-5"
   return "016a3b968d" from "https://libzip.org/g/1958342/016a3b968d/" 

   \param[in]   s    The source string
   \param[in]   sep  The delimiter to seperate the tokens

   \return The pointer to the token.
   \remark This function changses the source string.
   \remark Warning: if removing the tailing '/', some servers may fail to response
*/
char *csc_token_tail(char *s, int sep)
{
	int	len;

	s = csc_token_tail_ro(s, sep, &len);
	s[len] = 0;
	return s;
}

/*!\brief find the tailing token in a string
 
   The csc_token_tail_alloc() is similar to csc_token_tail_ro() except it will
   allocate a piece of memory to store the token.

   \param[in]  s     The source string
   \param[in]  sep   The delimiter to seperate the tokens
   \param[in]  extra The extra bytes in the allocation if in needs

   \return The memory storing the token.
   \remark This function doesn't changes the source string.
   \remark The memory should be freed by the caller.
   \remark The memory size is the length of the trimmed string + the extra bytes + 1

*/
char *csc_token_tail_alloc(char *s, int sep, int extra)
{
	char	*p;
	int	len;

	s = csc_token_tail_ro(s, sep, &len);
	if ((p = malloc(len+extra+1)) != NULL) {
		memcpy(p, s, len);
		p[len] = 0;
	}
	return p;
}

/*!\brief find the tailing token in a string
 
   The csc_token_tail_copy() is similar to csc_token_tail_ro() except it will
   copy the token to the specified buffer.

   \param[in]  s     The source string
   \param[in]  sep   The delimiter to seperate the tokens
   \param[in]  buf   Caller supplied buffer for copying the trimmer string
   \param[in]  blen  The length of the 'buf'

   \return The pointer to the token in the source string 's'.
   \remark This function doesn't changes the source string.
*/
char *csc_token_tail_copy(char *s, int sep, char *buf, int blen)
{
	int	len;

	s = csc_token_tail_ro(s, sep, &len);
	csc_strlmove(buf, blen, s, len);
	return s;
}

