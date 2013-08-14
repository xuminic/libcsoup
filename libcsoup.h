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

#define LIBCSOUP_VERSION	"0.1.0"

#include "slog.h"
#include "smm.h"

#define CLIOPT_PARAM_NONE	0
#define CLIOPT_PARAM_NUMBER	1
#define CLIOPT_PARAM_STRING	2
#define CLIOPT_PARAM_CHAR	3

#define CLI_SHORT		1
#define CLI_LONG		2
#define CLI_BOTH		3
#define CLI_COMMENT		4
#define CLI_EXTLINE		8
#define CLI_EOL			16

#define CLI_LF_GATE		20

struct	cliopt	{
	int	opt_char;
	char	*opt_long;
	int	param;
	char	*comment;
};

#include <getopt.h>
struct	clirun	{
	int	optind;
	char	*optarg;
	int	argc;
	char	**argv;
	struct	option	oplst[1];
};

/* see csc_cli_option.c */
int csc_cli_type(struct cliopt *optbl);
int csc_cli_table_size(struct cliopt *optbl);
int csc_cli_print(struct cliopt *optbl);

/* see csc_cli_alloc_list.c */
char *csc_cli_alloc_list(struct cliopt *optbl);

/* see csc_cli_alloc_table.c */
void *csc_cli_alloc_table(struct cliopt *optbl);

/* see csc_cli_getopt_alloc.c */
void *csc_cli_getopt_alloc(struct cliopt *optbl);

/* see csc_cli_getopt.c */
void *csc_cli_setopt(void *clibuf, int argc, char **argv);
int csc_cli_getopt(void *clibuf, struct cliopt *optbl);




/* Extended File Name Filter setting
 *  * Input string could be "avi,wmv,mkv" or "+avi:wmv:-mkv"
 *   * Stored format will be "*.avi", "*.wmv", "*.mkv"
 *    */
typedef struct  {
	char	*filter[1];
} CSEFF;

void *csc_extname_filter_open(char *s);
int csc_extname_filter_close(void *efft);
int csc_extname_filter_match(void *efft, char *fname);

size_t csc_strlcpy(char *dst, const char *src, size_t siz);
char *csc_strcpy_alloc(const char *src, int extra);
int csc_fixtoken(char *sour, char **idx, int ids, char *delim);
int csc_ziptoken(char *sour, char **idx, int ids, char *delim);
int csc_isdelim(char *delim, int ch);
int csc_mkargv(char *sour, char **idx, int ids);

/* see csc_cmp_file_extname.c */
int csc_cmp_file_extname(char *fname, char *ext);
int csc_cmp_file_extlist(char *fname, char **ext);
int csc_cmp_file_extargs(char *fname, char *ext, ...);

/* see csoup_strcmp_list.c */
int csc_strcmp_list(char *dest, char *src, ...);

char *csc_path_basename(char *path, char *buffer, int blen);
char *csc_path_path(char *path, char *buffer, int blen);


/* see memdump.c */
int csc_memdump(void *mem, int range, int column, int mode);

/* see csc_crc*.c */
unsigned short csc_crc16_byte(unsigned short crc, char data);
unsigned short csc_crc16(unsigned short crc, void *buf, size_t len);
unsigned long csc_crc32_byte(unsigned long crc, char data);
unsigned long csc_crc32(unsigned long crc, void  *buf, size_t len);
unsigned char csc_crc8_byte(unsigned char crc, char data);
unsigned char csc_crc8(unsigned char crc, void *buf, size_t len);
unsigned short csc_crc_ccitt_byte(unsigned short crc, char data);
unsigned short csc_crc_ccitt(unsigned short crc, void *buf, size_t len);

/* see iso639.c */
char *csc_iso639_lang_to_iso(char *lang);
char *csc_iso639_lang_to_short(char *lang);
char *csc_iso639_iso_to_lang(char *iso);


#endif	/* _LIBCSOUP_H_ */

