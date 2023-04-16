/*  memdump.c - test harness of memdump()

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libcsoup.h"
#include "libcsoup_debug.h"

int strings_strbody(void)
{
	struct	dicts	{
		char	*dest;
		char	*sour;
	} testcase[] = {
		{ "abc",  "       abc" },
		{ NULL, "  \t\t   " },
		{ " abc ", "   abc   " },
		{ NULL, NULL }
	};
	char	*p;
	int	i, rc;

	cslog("csc_strlcmp_body() testing:\n");		/* csc_strcmp_param() */
	for (i = 0; i < (int)(sizeof(testcase)/sizeof(struct dicts)); i++) {
		cslog("Comparing {%s} and {%s} ... ", testcase[i].dest, testcase[i].sour); 
		rc = csc_strlcmp_body(testcase[i].dest, testcase[i].sour);
		cslog("%d\n", rc);
	}
	cslog("\ncsc_strbody() testing:\n");
	for (i = 0; i < (int)(sizeof(testcase)/sizeof(struct dicts)); i++) {
		if (testcase[i].dest) {
			p = csc_strbody(testcase[i].dest, &rc);
			cslog("Picking from {%s} ... %s (%d)\n", testcase[i].dest, p, rc);
		}
		if (testcase[i].sour) {
			p = csc_strbody(testcase[i].sour, &rc);
			cslog("Picking from {%s} ... %s (%d)\n", testcase[i].sour, p, rc);
		}
	}				

	return 0;
}

static int strings_strbival(void)
{
	char	*testcase[] = {
		"1024x768x24",
		"  1024  768  24  ",
		"0x100x0x200+0xff",
		"0123",
		NULL
	};
	int	i, v1, v2;

	cslog("\ncsc_strbival_int() testing: xX+*\n");
	for (i = 0; testcase[i]; i++) {
		v1 = csc_strbival_int(testcase[i], "xX+*", &v2);
		cslog("[%s]:  %d %d\n", testcase[i], v1, v2);
	}
	cslog("csc_strbival_int() testing:\n");
	for (i = 0; testcase[i]; i++) {
		v1 = csc_strbival_int(testcase[i], NULL, &v2);
		cslog("[%s]:  %d %d\n", testcase[i], v1, v2);
	}

	return 0;
}

static int strings_strinsert(void)
{
#define	STRINSERTSMPL	"Alpha AXP of DEC"
	char	buf[24];
	int	rc;

	cslog("\nFrom [Alpha AXP of DEC] to [Alpha RISC of DEC]: ");
	strcpy(buf, STRINSERTSMPL);
	csc_strinsert(buf, sizeof(buf), &buf[6], 3, "RISC");
	cslog("%s\n", buf);

	cslog("From [Alpha AXP of DEC] to [RISCAlpha AXP of DEC]: ");
	strcpy(buf, STRINSERTSMPL);
	csc_strinsert(buf, sizeof(buf), NULL, 0, "RISC");
	cslog("%s\n", buf);

	cslog("From [Alpha AXP of DEC] to [Alpha AXP of DECCISC]: ");
	strcpy(buf, STRINSERTSMPL);
	csc_strinsert(buf, sizeof(buf), buf+sizeof(buf), 0, "CISC");
	cslog("%s\n", buf);

	cslog("From [Alpha AXP of DEC] to [Alpha RISCCISAXP of DEC]: ");
	strcpy(buf, STRINSERTSMPL);
	csc_strinsert(buf, sizeof(buf), &buf[6], 0, "RISCCIS");
	cslog("%s\n", buf);

	cslog("From [Alpha AXP of DEC] to buffer overflow: ");
	strcpy(buf, STRINSERTSMPL);
	rc = csc_strinsert(buf, sizeof(buf), &buf[6], 0, "RISCCISC");
	cslog("%s [%d]\n", buf, rc);

	cslog("From [Alpha AXP of DEC] to [Alpha AXP _AXP of DEC]: ");
	strcpy(buf, STRINSERTSMPL);
	csc_strinsert(buf, sizeof(buf), buf+10, -4, "_");
	cslog("%s\n", buf);

	cslog("From [Alpha AXP of DEC] to out of boundry: ");
	strcpy(buf, STRINSERTSMPL);
	rc = csc_strinsert(buf, sizeof(buf), &buf[3], -4, "_");
	cslog("%s [%d]\n", buf, rc);

	cslog("From [Alpha AXP of DEC] to [Alpha is gone]: ");
	strcpy(buf, STRINSERTSMPL);
	csc_strinsert(buf, sizeof(buf), buf+6, 100, "is gone");
	cslog("%s\n", buf);

	cslog("From [Alpha AXP of DEC] to [Alpha of DEC]: ");
	strcpy(buf, STRINSERTSMPL);
	csc_strinsert(buf, sizeof(buf), buf+6, 4, NULL);
	cslog("%s\n", buf);

	return 0;
}


static void strx_puts(char *from, char *to)
{
	while (from != to) {
		putchar(*from++);
	}
        putchar('\n');
}

static int strings_url_web(void)
{
	char	key[512], tmp[128], *from, *to;
	int	i;

	/* csc_trim_head() */
	strcpy(key, "h\n\tttps://libzip.org/g/195/3b968d$#////  ");
	printf("csc_trim_head(): %s\n", csc_trim_head(key, "hps:t/ "));	/* url_skip_head_ctlsp() */

	/* csc_trim_tail_ro() */
	strcpy(key, "https://libzip.org/g/195/3b968d$#////  ");
	to = csc_trim_tail_ro(key, "$#/ ", &i);
	printf("csc_trim_tail_ro(): %s [%d]\n", to, i);
	to = csc_trim_tail_alloc(key, "$#/ ", 0);
	printf("csc_trim_tail_alloc(): %s\n", to);
	free(to);
	to = csc_trim_tail_copy(key, "$#/ ", tmp, sizeof(tmp));
	printf("csc_trim_tail_copy(): %s\n", to);
	to = csc_trim_tail(key, "$#/ ");		/* url_trim_tail() */
	printf("csc_trim_tail(): %s\n", to);

	strcpy(key, "https://libzip.org/g/195/3b968d$#////  ");
	to = csc_trim_body_ro(key, "$#/ ht", &i);
	printf("csc_trim_body_ro(): %s [%d]\n", to, i);
	to = csc_trim_body(key, "$#/ ht");
	printf("csc_trim_body(): %s\n", to);

	strcpy(key, "https://libzip.org/g/195/3b968d$#////  ");
	to = csc_token_tail_ro(key, '/', &i);
	printf("csc_token_tail_ro(): %s [%d]\n", to, i);
	to = csc_token_tail_alloc(key, '/', 0);		/* url_get_tail() */
	printf("csc_token_tail_alloc(): %s\n", to);
	free(to);

	for (i = 0; i < 10; i++) {
		to = csc_token_pick_alloc(key, '/', i, 0);	/* url_get_path() */
		if (to) {
			printf("csc_token_pick_alloc(%d): %s\n", i, to);
			free(to);
		}
	}

	/* csc_url_amper() */
	to = csc_url_amper_alloc("http://50.7.233.114/ehg/png&amp;t=370249&amp;n=039.png", 32);
	printf("csc_url_amper_alloc(): %s\n", to);	/* url_reform() */
	strcpy(to, "http://50.7.233.114/ehg/png&amp;t=370249&amp;n=039.png");
	printf("csc_url_amper_wb(): %s\n", csc_url_amper_wb(to));
	free(to);

	/* csc_strrpch() */	/* strx_strrpch() */
	strcpy(key, "replace the 'old' char in the string 's' with 'new'");
	csc_strrpch(key, 0, '\'', '\"');
	printf("csc_strrpch: %s\n", key);
	strcpy(key, "replace the 'old' char in the string 's' with 'new'");
	csc_strrpch(key, 2, '\'', '\"');
	printf("csc_strrpch: %s\n", key);
	strcpy(key, "replace the 'old' char in the string 's' with 'new'");
	csc_strrpch(key, -2, '\'', '\"');
	printf("csc_strrpch: %s\n", key);

	/* csc_strstr() */	/* strx_strstr() */
	from = csc_strstr_list("Each invocation of va_start() must be matched", 
			&to, "a", "t", "()", NULL);
	if (from) {
		strx_puts(from, to);
	}
	from = csc_strstr_list("Each invocation of va_start() must be matched", 
			&to, "a", "c", "mu", "()", NULL);
	if (from) {
		strx_puts(from, to);
	}
	
	printf("csc_strrcmp_nc(): %d\n", csc_strrcmp_nc("filename.c", "E.c"));
	printf("csc_strrcmp(): %d\n", csc_strrcmp_list("filename.c", ".java", "e.", ".", "c", NULL));

#if 0
	htm_common_pick("<meta name=\"juicyads\" content=\"0f3e4770\"/>", "\"", "\"", key, sizeof(key));
	printf("htm_common_pick: %s\n", key);
	htm_common_pick("<meta name=\"juicyads\" content=\"0f3e4770\"/>", "content=\"", "\"/>", key, sizeof(key));
	printf("htm_common_pick: %s\n", key);
#endif
	return 0;
}


int strings_main(void *rtime, int argc, char **argv)
{
	/* stop the compiler complaining */
	(void) rtime; (void) argc; (void) argv;

	strings_strbody();
	strings_strbival();
	strings_strinsert();
	strings_url_web();
	return 0;
}


struct	clicmd	strings_cmd = {
	"strings", strings_main, NULL, "Testing the string process functions"
};

extern  struct  clicmd  strings_cmd;

