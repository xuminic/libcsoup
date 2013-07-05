/*  libcsoup.h - main head file for the CSOUP library

    Copyright (C) 2013  "Andy Xuming" <xuming@users.sourceforge.net>

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

#ifndef	_LIBCSOUP_H_
#define _LIBCSOUP_H_

#define LIBCSOUP_VERSION	"1.0.0"

#include "cliopt.h"
#include "slog.h"
#include "smm.h"

size_t strlcopy(char *dst, const char *src, size_t siz);
char *strcpy_alloc(const char *src);
int fixtoken(char *sour, char **idx, int ids, char *delim);
int ziptoken(char *sour, char **idx, int ids, char *delim);
int isdelim(char *delim, int ch);
int mkargv(char *sour, char **idx, int ids);

/* see csoup_cmp_file_extname.c */
int csoup_cmp_file_extname(char *fname, char *ext);
int csoup_cmp_file_extlist(char *fname, char **ext);
int csoup_cmp_file_extargs(char *fname, char *ext, ...);

/* see csoup_strcmp_list.c */
int csoup_strcmp_list(char *dest, char *src, ...);

/* see memdump.c */
int memdump(void *mem, int range, int column, int mode);

/* see crc*.c */
unsigned short crc16_byte(unsigned short crc, unsigned char data);
unsigned short crc16(unsigned short crc, unsigned char *buf, size_t len);
unsigned crc32_byte(unsigned crc, unsigned char data);
unsigned crc32(unsigned crc, unsigned char *buf, size_t len);
unsigned char crc8_byte(unsigned char crc, unsigned char data);
unsigned char crc8(unsigned char crc, unsigned char *buf, size_t len);
unsigned short crc_ccitt_byte(unsigned short crc, unsigned char c);
unsigned short crc_ccitt(unsigned short crc, unsigned char *buf, size_t len);


#endif	/* _LIBCSOUP_H_ */

