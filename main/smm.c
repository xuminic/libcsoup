
/*  smm_main.c - main entry to test the SMM library

    Copyright (C) 2013  "Andy Xuming" <xuming@users.sourceforge.net>

    This file is part of LIBSMM, System Masquerade Module library

    LIBSMM is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    LIBSMM is distributed in the hope that it will be useful,
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

#define VERSION	"0.1"


static int do_signal_break(int sig)
{
	printf("Signal %d received\n", sig);
	return sig;
}

static int do_smm_chdir(char *path)
{
	char	*cwd;
	int	rc;

	rc = smm_chdir(path);
	
	cwd = smm_cwd_alloc();
	printf("Enter: %s\n", cwd);
	free(cwd);

	printf("Press any key to continue ... ");
	getchar();
	printf("(%d)\n", rc);
	return 0;
}

static int do_push_dir(char *path)
{
	char	*cwd, *cid;
	int	rc;

	cwd = smm_cwd_alloc();
	printf("Current: %s\n", cwd);
	free(cwd);

	cid = smm_cwd_push();
	
	rc = smm_chdir(path);
	cwd = smm_cwd_alloc();
	printf("Enter: %s\n", cwd);
	free(cwd);

	smm_cwd_pop(cid);
	
	cwd = smm_cwd_alloc();
	printf("Return: %s\n", cwd);
	free(cwd);

	printf("Press any key to continue ... ");
	getchar();
	printf("(%d)\n", rc);
	return 0;
}

static int do_stat_file(char *path)
{
	int	rc;

	rc = smm_fstat(path);
	switch (rc) {
	case SMM_FSTAT_REGULAR:
		printf("%s: regular\n", path);
		break;
	case SMM_FSTAT_DIR:
		printf("%s: directory\n", path);
		break;
	case SMM_FSTAT_LINK:
		printf("%s: link\n", path);
		break;
	case SMM_FSTAT_DEVICE:
		printf("%s: device\n", path);
		break;
	}
	printf("(%d)\n", rc);
	return 0;
}


static int pathtrek_cb(void *option, char *path, int type, void *info)
{
	struct	smmdir	*sdir = info;

	switch (type) {
	case SMM_MSG_PATH_ENTER:
		printf("Enter %s\n", path);
		break;
	case SMM_MSG_PATH_LEAVE:
		printf("Leave %s (%d:%d)\n", path, 
				sdir->stat_dirs, sdir->stat_files);
		break;
	case SMM_MSG_PATH_STAT:
		printf("Finish (%d:%d)\n", sdir->stat_dirs, sdir->stat_files);
		break;
	case SMM_MSG_PATH_EXEC:
		printf("Processing %s\n", path);
		break;
	}
	return 0;
}

static int do_path_trek(char *path, int flags)
{
	int	rc;

	rc = smm_pathtrek(path, flags, pathtrek_cb, NULL);
	printf("(%d)\n", rc);
	return 0;
}


static  char    *usage = "\
OPTIONS:\n\
  -c DIR    change current working directory\n\
  -p DIR    push/pop current working directory\n\
  -r DIR    process directory recurrsively\n\
     --dir-fifo\n\
     --dir-first\n\
     --dir-last\n\
  -s FILE   state of the file \n\
";

static	struct	cliopt	clist[] = {
	{   0, NULL,      0, "OPTIONS:" },
	{ 'c', NULL,      2, "change current working directory" },
	{ 'p', NULL,      2, "push/pop current working directory" },
	{ 's', NULL,      2, "state of the file" },
	{ 'r', NULL,      2, "process directory recurrsively" },
	{   1, "help",    0, "*Display the help message" },
	{   2, "version", 0, "*Display the version message" },
	{   3, "dir-fifo", 0, NULL },
	{   4, "dir-first", 0, NULL },
	{   5, "dir-last",  0, NULL },
	{ 0, NULL, 0, NULL }
};


static  char    *version = "smm " VERSION
", Test program for the System Masquerade Module library.\n\
Copyright (C) 2011 \"Andy Xuming\" <xuming@users.sourceforge.net>\n\
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n\
This is free software: you are free to change and redistribute it.\n\
There is NO WARRANTY, to the extent permitted by law.\n";

int smm_main(int argc, char **argv)
{
	struct	option	*argtbl;
	char	*arglist;
	int	c, d_flags;

	smm_init(0);
	smm_signal_break(do_signal_break);

	arglist = cli_alloc_list(clist);
	argtbl  = cli_alloc_table(clist);
	d_flags = SMM_PATH_DIR_FIFO;
	while ((c = getopt_long(argc, argv, arglist, argtbl, NULL)) > 0) {
		switch (c) {
		case 1:
			puts(usage);
			goto quick_quit;
		case 2:
			puts(version);
			goto quick_quit;
		case 3:
			d_flags &= ~SMM_PATH_DIR_MASK;
			d_flags |= SMM_PATH_DIR_FIFO;
			break;
		case 4:
			d_flags &= ~SMM_PATH_DIR_MASK;
			d_flags |= SMM_PATH_DIR_FIRST;
			break;
		case 5:
			d_flags &= ~SMM_PATH_DIR_MASK;
			d_flags |= SMM_PATH_DIR_LAST;
			break;
		case 'c':
			do_smm_chdir(optarg);
			break;
		case 'p':
			do_push_dir(optarg);
			break;
		case 's':
			do_stat_file(optarg);
			break;
		case 'r':
			do_path_trek(*++argv, d_flags);
			break;
		default:
			printf("Unknown option. [%c]\n", c);
			goto quick_quit;
		}
	}
quick_quit:
	free(argtbl);
	free(arglist);
	return 0;
}

