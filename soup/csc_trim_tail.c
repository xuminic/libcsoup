/*!\file       csc_trim_tail.c
   \brief      remove the unwanted char set from the tail of a string.

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

/*!\brief remove the unwanted characters from the tail of a string.
 
   The csc_trim_tail_ro() is used to trim the tail of a string by seeking out 
   the unwanted characters according to the specified character set. 
   Most of characters are one to one match, except a whitespace. A whitespace
   in the character set can match any whitespace.

   For example, if the character set is "/: ", it would match '/', ':' and any
   whitespaces like ' ', '\t', '\n', etc

   s[] = "https://libzip.org/g/1958342/016a3b968d////  \n"
   csc_trim_tail_ro(s, "/ ") trims to "https://libzip.org/g/1958342/016a3b968d////  \n"
   and stores the length of "https://libzip.org/g/1958342/016a3b968d" to 'len'.
   
   \param[in]  s    The source string
   \param[in]  cset The character set
   \param[out] len  The length of the trimmed string

   \return The length of the string after trimming.
   \remark This function doesn't changes the source string.
*/
char *csc_trim_tail_ro(char *s, char *cset, int *len)
{
	int	i = strlen(s);

	//for (i--; (i >= 0) && csc_isdelim(cset, s[i]); s[i--] = 0;
	for (i--; (i >= 0) && csc_isdelim(cset, s[i]); i--);
	if (len) {
		*len = i + 1;
	}
	return s;
}

/*!\brief remove the unwanted characters from the tail of a string.
 
   The csc_trim_tail() is similar to csc_trim_tail_ro() except it will
   remove the unwanted characters according to the specified character set. 
   Most of characters are one to one match, except a whitespace. A whitespace
   in the character set can match any whitespace.

   For example, if the character set is "/: ", it would match '/', ':' and any
   whitespaces like ' ', '\t', '\n', etc

   s[] = "https://libzip.org/g/1958342/016a3b968d////  \n"
   csc_trim_tail(s, "/ ") trims to "https://libzip.org/g/1958342/016a3b968d"
   
   \param[in]  s    The source string
   \param[in]  cset The character set

   \return The string after trimming.
   \remark This function changes the source string.
*/
char *csc_trim_tail(char *s, char *cset)
{
	int	len;

	csc_trim_tail_ro(s, cset, &len);
	s[len] = 0;
	return s;
}

/*!\brief remove the unwanted characters from the tail of a string.
 
   The csc_trim_tail_alloc() is similar to csc_trim_tail_ro() except it will 
   allocate a piece of memory to store the trimmed string.

   \param[in]  s     The source string
   \param[in]  cset  The character set
   \param[in]  extra The extra bytes in the allocation if in needs

   \return The memory storing the string after trimming.
   \remark This function doesn't changes the source string.
   \remark The memory should be freed by the caller.
   \remark The memory size is the length of the trimmed string + the extra bytes + 1
*/
char *csc_trim_tail_alloc(char *s, char *cset, int extra)
{
	int	len;

	csc_trim_tail_ro(s, cset, &len);
	if ((cset = malloc(len+extra+1)) != NULL) {
		memcpy(cset, s, len);
		cset[len] = 0;
	}
	return cset;
}

/*!\brief remove the unwanted characters from the tail of a string.
 
   The csc_trim_tail_copy() is similar to csc_trim_tail_ro() except it will
   copy the trimmed string to the specified buffer.

   \param[in]  s     The source string
   \param[in]  cset  The character set
   \param[in]  buf   Caller supplied buffer for copying the trimmer string
   \param[in]  blen  The length of the 'buf'

   \return The pointer to the trimmed string in the source string 's'.
   \remark This function doesn't changes the source string.
*/
char *csc_trim_tail_copy(char *s, char *cset, char *buf, int blen)
{
	int	len;

	csc_trim_tail_ro(s, cset, &len);
	csc_strlmove(buf, blen, s, len);
	return s;
}


