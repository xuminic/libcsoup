
/*!\file       csc_strlcmp.c
   \brief      Compare two strings with different lengths.
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
#include <stdarg.h>

#include "libcsoup.h"

/*!\brief Compare two strings with different lengths.

   The function compares the two parameter strings 's1' and 's2'.  It returns 
   an integer less than, equal to, or greater than zero if 's1' is found, 
   respectively, to be less than, to match, or be greater than 's2'.

   The difference between csc_strlcmp() and strncmp() is length parameter is not required.

   \param[in]  s1  string 1
   \param[in]  s2  string 2

   \return     an integer less than, equal to, or greater than zero if 's1' is
   found, respectively, to be less than, to match, or be greater than 's2'.
   \remark  NULL string is acceptable, but differ to space ' '
*/
int csc_strlcmp(const char *s1, const char *s2)
{
	size_t	n1, n2;

	if (!s1 && !s2) {
		return 0;	/* NULL is equal to NULL */
	}
	if (!s1 || !s2) {
		return s1 ? *s1 : *s2;
        }

	n1 = strlen(s1);
	n2 = strlen(s2);
	return strncmp(s1, s2, n1 > n2 ? n2 : n1);
}

/*!\brief Compare one string to a sub-string.

   The function similar to csc_strlcmp(), except the comparing length
   defined by the second string 's2'.

   \param[in]  s1  string 1
   \param[in]  s2  string 2

   \return  same to strncmp()
   \remark  NULL string is acceptable, but differ to space ' '
*/
int csc_strlcmp_sub(const char *s1, const char *s2)
{
	if (!s1 && !s2) {
		return 0;	/* NULL is equal to NULL */
	}
	if (!s1 || !s2) {
		return s1 ? *s1 : *s2;
        }
	return strncmp(s1, s2, strlen(s2));
}

/*!\brief Compare one string to a group of sub-string.

   The function similar to csc_strlcmp(), except it compares with a group of
   sub-strings. The comparing length defines by the sub-strings.

   \param[in]  dest  The string to compare with
   \param[in]  src   First sub-string

   \return  same to strncmp()
   \remark  The sub-string list must be ended by NULL.
   \example csc_strlcmp_list(s, "http://", "https://", NULL)
*/
int csc_strlcmp_list(char *dest, char *src, ...)
{
	va_list	ap;
	char	*s;
	int	rc = -1;

	if (!dest) {
		return !src ? 0 : 1;
	}

	va_start(ap, src);
	s = src;
	while (s) {
		if ((rc = strncmp(dest, s, strlen(s))) == 0) {
			break;	/* return succeed */
		}
		s = va_arg(ap, char *);
	}
	va_end(ap);
	return rc;
}



/*!\brief Compare two parameter strings while empty or blank string is equal 
   to a NULL string pointer.

   The function compares the two parameter strings 's1' and 's2'.  It returns 
   an integer less than, equal to, or greater than zero if 's1' is found, 
   respectively, to be less than, to match, or be greater than 's2'.

   The difference between csc_strlcmp_body() and strcmp() is 's1' and 's2'
   can be NULL and equal to empty string ("") or blank string ("\t\f\v\n\r ")

   \param[in]  s1  string 1, can be NULL.
   \param[in]  s2  string 2, can be NULL.

   \return  same to strncmp()
   \remark  In this function NULL and '\0' are equal.
*/
int csc_strlcmp_body(const char *s1, const char *s2)
{
	int	len1, len2;

	len1 = len2 = 0;
	if (s1) {
		s1 = csc_strbody((char*)s1, &len1);
	}
	if (s2) {
		s2 = csc_strbody((char*)s2, &len2);
	}
	if (s1 && s2) {
		return strncmp(s1, s2, len1 < len2 ? len2 : len1);
	} else if (!s1 && !s2) {
		return 0;
	} else if (s1) {
		return *s1;
	}
	return *s2;
}

