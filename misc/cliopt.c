
/*  cliopt.c - command line option help

    Copyright (C) 2011-2013  "Andy Xuming" <xuming@users.sourceforge.net>

    This file is part of EZTHUMB, a utility to generate thumbnails

    EZTHUMB is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    EZTHUMB is distributed in the hope that it will be useful,
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

#include "cliopt.h"


static int cli_type(struct cliopt *optbl)
{
	int	rc = 0;

	if (optbl->opt_long && *optbl->opt_long) {
		if (isalnum(optbl->opt_char)) {
			rc = CLI_BOTH;		/* 'o', "option", 0, NULL */
		} else {
			rc = CLI_LONG;		/* 1, "option", 0, NULL */
		}
	} else if (isalnum(optbl->opt_char)) {
		rc = CLI_SHORT;			/* 'o', NULL, 0, NULL */
	} else if (optbl->comment == NULL) {
		rc = CLI_EOL;			/* 0, NULL, 0, NULL */
	} else if (optbl->param == -1) {
		rc = CLI_EXTLINE;		/* 0, NULL, -1, "Half line" */
	} else {
		rc = CLI_COMMENT;		/* 0, NULL, 0, "Full line" */
	}
	return rc;
}

static int cli_table_size(struct cliopt *optbl)
{
	int	i, rc;

	for (i = 0; (rc = cli_type(optbl)) != CLI_EOL; optbl++) {
		if (rc & CLI_BOTH) {
			i++;
		}
	}
	return i;
}

char *cli_alloc_list(struct cliopt *optbl)
{
	char	*list, *p;
	int	rc;

	if ((list = calloc(cli_table_size(optbl) + 1, 2)) == NULL) {
		return NULL;
	}

	for (p = list; (rc = cli_type(optbl)) != CLI_EOL; optbl++) {
		if (rc & CLI_SHORT) {
			*p++ = optbl->opt_char;
			if (optbl->param > 0) {
				*p++ = ':';
			}
		}
	}
	return list;
}

void *cli_alloc_table(struct cliopt *optbl)
{
	struct	option	*table, *p;
	int	rc;

	table = calloc(cli_table_size(optbl) + 1, sizeof(struct option));
	if (table == NULL) {
		return NULL;
	}

	for (p = table; (rc = cli_type(optbl)) != CLI_EOL; optbl++) {
		if (rc & CLI_LONG) {
			p->name    = optbl->opt_long;
			p->has_arg = optbl->param > 0 ? 1 : 0;
			p->val     = optbl->opt_char;
			p++;
		}
	}
	return (void*) table;
}

int  cli_print(struct cliopt *optbl)
{
	char	tmp[128];
	int	rc;

	for ( ; (rc = cli_type(optbl)) != CLI_EOL; optbl++) {
		switch (rc) {
		case CLI_COMMENT:
			puts(optbl->comment);
			continue;
		case CLI_EXTLINE:
			tmp[0] = 0;
			break;
		case CLI_SHORT:
			sprintf(tmp, "  -%c", optbl->opt_char);
			break;
		case CLI_LONG:
			sprintf(tmp, "     --%s", optbl->opt_long);
			break;
		case CLI_BOTH:
			sprintf(tmp, "  -%c,--%s", 
				optbl->opt_char, optbl->opt_long);
			break;
		}
                  
		if (optbl->param == 1) {
			strcat(tmp, " N");
		} else if (optbl->param > 1) {
			strcat(tmp, " C");
		}

		if (optbl->comment == NULL) {
			printf("%s\n", tmp);
		} else if (*optbl->comment == '*') {
			continue;	/* hidden option */
		} else if ((rc = strlen(tmp)) < CLI_LF_GATE) {
			memset(tmp + rc, ' ', CLI_LF_GATE - rc);
			tmp[CLI_LF_GATE] = 0;
			printf("%s  %s\n", tmp, optbl->comment);
		} else {
			printf("%s\n", tmp);
			memset(tmp, ' ', CLI_LF_GATE);
			tmp[CLI_LF_GATE] = 0;
			printf("%s  %s\n", tmp, optbl->comment);
		}
	}
	return 0;
}


void *cli_setopt(struct clirun *rtbuf, int argc, char **argv)
{
	if (!rtbuf && !(rtbuf = malloc(sizeof(struct clirun)))) {
		return NULL;
	}

	rtbuf->optind = 0;
	rtbuf->optarg = NULL;
	rtbuf->argc   = argc;
	rtbuf->argv   = argv;
	return rtbuf;
}

int cli_getopt(struct clirun *rtbuf, struct cliopt *optbl)
{
	int	i, rc;

	if (!rtbuf || !optbl) {
		return -1;	/* not available */
	}
	if ((rtbuf->optind == 0) && (rtbuf->argv[0][0] != '-')) {
		rtbuf->optind++;
	}
	if (rtbuf->optind >= rtbuf->argc) {
		return -2;	/* end of scan */
	}
	if (rtbuf->argv[rtbuf->optind][0] != '-') {
		return -2;	/* end of scan */
	}

	for (i = 0; (rc = cli_type(optbl + i)) != CLI_EOL; i++) {
		if (rc == CLI_SHORT) {
			if (rtbuf->argv[rtbuf->optind][1] == 
					optbl[i].opt_char) {
				break;
			}
		} else if (rc == CLI_LONG) {
			if (rtbuf->argv[rtbuf->optind][1] == '-') {
				if (!strcmp(&rtbuf->argv[rtbuf->optind][2], 
							optbl[i].opt_long)) {
					break;
				}
			}
		} else if (rc == CLI_BOTH) {
			if (rtbuf->argv[rtbuf->optind][1] == '-') {
				if (!strcmp(&rtbuf->argv[rtbuf->optind][2],
							optbl[i].opt_long)) {
					break;
				}
			} else {
				if (rtbuf->argv[rtbuf->optind][1] == 
						optbl[i].opt_char) {
					break;
				}
			}
		}
	}
	if (rc == CLI_EOL) {
		return -2;	/* end of scan */
	}

	rtbuf->optind++;
	if (optbl[i].param > 0) {	/* require an option */
		if (rtbuf->optind >= rtbuf->argc) {
			return -3;	/* broken parameters */
		}
		rtbuf->optarg = rtbuf->argv[rtbuf->optind];
		rtbuf->optind++;
	}
	return optbl[i].opt_char;
}


