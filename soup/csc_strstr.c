
/*!\file       csc_strstr.c
   \brief      locate a substring 

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
#include <stdarg.h>

#include "libcsoup.h"


/*!\brief locate a substring from tail
   
   This function is like strstr() except it searches substrings from tail.

   \param[in]   haystack  The source string
   \param[in]   tailp     Specify the tail point for the search. 
                          If NULL then searching from the end of the source string.
   \param[in]   needle    The sub-string

   \return The pointer to the found sub-string, or NULL if not found.
*/
char *csc_strrstr(char *haystack, char *tailp, char *needle)
{
	if (tailp == NULL) {
		tailp = haystack + strlen(haystack) - strlen(needle);
	} else {
		tailp -= strlen(needle);
	}

	while (tailp >= haystack) {
		if (!strncmp(tailp, needle, strlen(needle))) {
			return tailp;
		}
		tailp--;
	}
	return NULL;
}

/*!\brief locate a substring
 
   This function finds a group of sub-strings which specified by 'slist'.
   The terminating null bytes ('\0') in the sub-strings are not compared. 
   For example, 
   
   for a given string "Each invocation of va_start() must be matched",
   The 'slist' of ["in", "va", NULL] for csc_strstr() returns "invocation of va".
   The 'slist' of ["on o", "va", "()", NULL] or csc_strstr() returns "on of va_start()".
   
   Note that the function returns the shortest sub-string, so for the 'slist' of
   ["a", "t", "()", NULL] it returns "art()" rather than "ach invocation of va_start()".

   \param[in]   s      The source string
   \param[out]  endp   The pointer to the end of the located substring (*endp not included)
   \param[in]   slist  The sub-string list for searching; end by NULL.

   \return The pointer to the found sub-string and the end pointer returns by 'endp'.
           or NULL if no such sub-string found.
   \remark This string list 'slist' must be ended by NULL.
   \remark It searches the shortest sub-string
*/
char *csc_strstr(char *s, char **endp, char *slist[])
{
	char	*p, *p_mark, *p_end;
	int	i, n;

	for (n = 0; slist[n]; n++);	/* move to the end of the sub-string list */
	while ((p_end = strstr(s, slist[n-1])) != NULL) {	/* locate the last sub-string */
		/* locate other sub-strings in backward order */
		p_mark = p_end;
		for (i = n - 2; i >= 0; i--) {
			if ((p = csc_strrstr(s, p_mark, slist[i])) == NULL) {
				break;	/* one of the sub_strings not found */
			}
			if (p >= p_mark) {
				break;	/* the sub-string is not in range */
			}
			/* successfully found the sub-string then move forward the end pointer */
			p_mark = p;
		}
		if (i < 0) {	/* successfully found the sub-string list */
			if (endp) {
				/* locating the end point of the last sub-string */
				*endp = p_end + strlen(slist[n-1]);
			}
			return p_mark;
		}

		/* move to the last sub-string for the next search */
		s = p_end + strlen(slist[n-1]);
	}
	return NULL;
}

/*!\brief locate a substring
 
   This function is like csc_strstr() except the sub-strings are given
   as function arguments. The function arguments end by NULL.

   \param[in]   s      The source string
   \param[out]  endp   The pointer to the end of the string (*endp not included)

   \return The pointer to the found sub-string and the end pointer returns by 'endp'.
           or NULL if no such sub-string found.
   \remark This sub-string list must be ended by NULL.
   \remark Maximum 127 sub-strings allowed
*/
char *csc_strstr_list(char *s, char **endp, ...)
{
	va_list	ap;
	char	*sublist[128], *rc = NULL;
	int	n;

	va_start(ap, endp);
	for (n = 0; (n < 128) && ((sublist[n] = va_arg(ap, char *)) != NULL); n++);
	if (n) {
		rc = csc_strstr(s, endp, sublist);
	}
	va_end(ap);
	return rc;
}



#if 0
char *csc_strstr(char *s, char **endp, char *first, char *last, ...)
{
	va_list	ap;
	char	*begin, *end, *next, *cp;

	while ((begin = strstr(s, first)) != NULL) {
		next = begin + strlen(first);
		if ((end = strstr(next, last)) == NULL) {
			break;
		}
		end += strlen(last);
		//strx_puts(begin, end);

		va_start(ap, last);
		while ((cp = va_arg(ap, char *)) != NULL) {
			if ((next = strstr(next, cp)) == NULL) {
				break;
			}
			if (next > end) {	/* out of boundry */
				break;
			}
			next += strlen(cp);
		}
		va_end(ap);

		if (cp == NULL) {	/* matched */
			if (endp) {
				*endp = end;
			}
			//strx_puts(begin, end);
			return begin;
		}
		s = end;
	}
	return NULL;
}
#endif

/*
void strx_puts(char *from, char *to)
{
        while (from != to) {
                putchar(*from++);
        }
        putchar('\n');
}
*/

