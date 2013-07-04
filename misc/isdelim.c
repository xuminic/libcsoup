
/* Copyright (C) 1998-2013  Xuming <xuming@users.sourceforge.net>
   
   This program is free software; you can redistribute it and/or 
   modify it under the terms of the GNU General Public License as 
   published by the Free Software Foundation; either version 2, or 
   (at your option) any later version.
	   
   This program is distributed in the hope that it will be useful, 
   but WITHOUT ANY WARRANTY; without even the implied warranty of 
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License, the file COPYING in this directory, for
   more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include <ctype.h>
#include <stdio.h>
#include <string.h>

/* isspace() macro has a problem in Cygwin when compiling it with -mno-cygwin.
 * I assume it is caused by minGW because it works fine with cygwin head files.
 * The problem is it treats some Chinese characters as space characters.
 * A sample is: 0xC5 0xF3 0xD3 0xD1 */
#define IsSpace(c)	((((c) >= 9) && ((c) <= 0xd)) || ((c) == 0x20))

int isdelim(char *delim, int ch)
{
	while (*delim) {
		if (*delim == (char) ch) {
			return 1;
		} else if ((*delim == ' ') && IsSpace(ch)) {
			return 1;
		}
		delim++;
	}
	return 0;
}


