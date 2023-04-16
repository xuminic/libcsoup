
/*!\file        csc_strrcmp.c 
   \brief       Compare two strings from the right end
   \author      "Andy Xuming" <xuming@users.sourceforge.net>
   \date        2013-2023
*/
/*  Copyright (C) 2013-2023  "Andy Xuming" <xuming@users.sourceforge.net>

    This file is part of CSOUP, Chicken Soup library

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
#include <stdarg.h>
#include <string.h>


/*!\brief Compare two strings from the right end.
   
   This function is similar to strcmp() except it comparing strings 
   from the tail.

   \param[in]  s1  string 1
   \param[in]  s2  string 2

   \return  same to strcmp()
   \remark  NULL string is acceptable, but differ to space ' '
*/
int csc_strrcmp(const char *s1, const char *s2)
{
	int	n1, n2;


	if (!s1 && !s2) {
		return 0;	/* NULL is equal to NULL */
	}
	if (!s1 || !s2) {
		return s1 ? *s1 : *s2;
	}

	/* matching the length from tail */
	n1 = strlen(s1);
	n2 = strlen(s2);
	if (n1 < n2) {
		s2 += n2 - n1;
	} else {
		s1 += n1 - n2;
	}

	return strcmp(s1, s2);
}

/*!\brief Compare two strings from the right end.
   
   This function is similar to csc_strrcmp() except it ignores case. 

   \param[in]  s1  string 1
   \param[in]  s2  string 2

   \return  same to strcmp()
   \remark  NULL string is acceptable, but differ to space ' '
*/
int csc_strrcmp_nc(const char *s1, const char *s2)
{
	int	n1, n2;


	if (!s1 && !s2) {
		return 0;	/* NULL is equal to NULL */
	}
	if (!s1 || !s2) {
		return s1 ? *s1 : *s2;
	}

	/* matching the length from tail */
	n1 = strlen(s1);
	n2 = strlen(s2);
	if (n1 < n2) {
		s2 += n2 - n1;
	} else {
		s1 += n1 - n2;
	}

	return strcasecmp(s1, s2);
}

/*!\brief Compare one string to a group of sub-string from the right end.

   The function similar to csc_strrcmp(), except it compares with a group of
   sub-strings. 

   \param[in]  dest  The string to compare with
   \param[in]  src   First sub-string

   \return  same to strcmp()
   \remark  The sub-string list must be ended by NULL.
*/
int csc_strrcmp_list(char *dest, char *src, ...)
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
		if ((rc = csc_strrcmp(dest, s)) == 0) {
			break;		/* found it */
		}
		s = va_arg(ap, char *);
	}
	va_end(ap);
	return rc;
}


/*!\brief Compare one string to a group of sub-string from the right end, ignore case.

   The function similar to csc_strrcmp_nc(), except it compares with a group of
   sub-strings. 

   \param[in]  dest  The string to compare with
   \param[in]  src   First sub-string

   \return  same to strcmp()
   \remark  The sub-string list must be ended by NULL.
*/
int csc_strrcmp_list_nc(char *dest, char *src, ...)
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
		if ((rc = csc_strrcmp_nc(dest, s)) == 0) {
			break;		/* found it */
		}
		s = va_arg(ap, char *);
	}
	va_end(ap);
	return rc;
}


/*!\brief Compare one string to a group of sub-string from the right end, ignore case.

   The function similar to csc_strrcmp_nc(), except it compares with a group of
   sub-strings. 

   \param[in]  dest  The string to compare with
   \param[in]  src   First sub-string

   \return  same to strcmp()
   \remark  The sub-string list must be ended by NULL.
*/
int csc_strrcmp_arry(char *dest, char **src)
{
	int	i;

	if (!src || !*src) {
		return -1;
	}

	for (i = 0; src[i]; i++) {
		if (!csc_strrcmp_nc(dest, src[i])) {
			return 0;
		}
	}
	return 1;
}


/*!\brief Compare a list of strings.

   The csc_strcmp_list() is used to compare a target string to a list of 
   strings. If one of the string is identical to the target string, The 
   csc_strcmp_list() would return 0 for matching.

   \param[in]  dest The target string.
   \param[in]  src  The first string in the string list. The last member in
               the string list must be NULL.

   \retval     0 if one of the strings are match. 
               non-zero if none of the strings are match.
   \remark     for example: csc_strcmp_list(myext, ".c", ".h", ".cc", NULL);
*/
int csc_strcmp_list(char *dest, char *src, ...)
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
		if ((rc = strcmp(dest, s)) == 0) {
			break;		/* found it */
		}
		s = va_arg(ap, char *);
	}
	va_end(ap);
	return rc;
}

/*!\brief Compare a list of strings, ignore case.

   The function is similar to csc_strcmp_list() except ignoring case.

   \param[in]  dest The target string.
   \param[in]  src  The first string in the string list. The last member in
               the string list must be NULL.

   \retval     0 if one of the strings are match. 
               non-zero if none of the strings are match.
   \remark     for example: csc_strcmp_list(myext, ".c", ".h", ".cc", NULL);
*/
int csc_strcmp_list_nc(char *dest, char *src, ...)
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
		if ((rc = strcasecmp(dest, s)) == 0) {
			break;		/* found it */
		}
		s = va_arg(ap, char *);
	}
	va_end(ap);
	return rc;
}


