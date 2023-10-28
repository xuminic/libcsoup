/*!\file       csc_cli_qopt.c
   \brief      command line option utility

   These functions are not getopt free and thread safe.

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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libcsoup.h"
#include "csc_cli_private.h"

struct	clirt	{
	int	optind;
	int	optopt;
	char	*optlast;
	char	*optarg;
	int	argc;
	char	**argv;
};


/*!\brief  Create a structure for parsing command line arguments.

   \param[in]  argc   The number of arguments.
   \param[in]  argv   The string list of arguments.

   \return  A pointer to the data structure for parsing command line
            if succeed, or NULL if failed.
*/
void *csc_cli_qopt_open(int argc, char **argv)
{
	struct	clirt	*rtbuf;

	if ((rtbuf = smm_alloc(sizeof(struct clirt))) != NULL) {
		rtbuf->argc   = argc;
		rtbuf->argv   = argv;
	}
	return rtbuf;
}

/*!\brief Close and release the allocated data structure..

   \param[in]  ropt The previous allocated data structure for parsing 
                    command line arguments.
   \return   0 if succeed, otherwise it was failed.
*/
int csc_cli_qopt_close(void *ropt)
{
	smm_free(ropt);
	return 0;
}

/*!\brief Retrieve the index of the next element to be processed in argv.

   \param[in]  ropt The previous allocated data structure for parsing 
                    command line arguments.
   \return The index of the next element to be processed in argv.        
   \remark Similar to the 'optind' in getopt() function.
*/
int csc_cli_qopt_optind(void *ropt)
{
	return ((struct clirt *)ropt)->optind;
}


/*!\brief Retrieve the last option character.

   \param[in]  ropt The previous allocated data structure for parsing 
                    command line arguments.

   \return The last option character.
   \remark If an option argument was detected missing, it returns ':'.
*/
int csc_cli_qopt_optopt(void *ropt)
{
	return ((struct clirt *)ropt)->optopt;
}

/*!\brief Retrieve the last option string.

   \param[in]  ropt The previous allocated data structure for parsing 
                    command line arguments.

   \return The last option string.
*/
char *csc_cli_qopt_optlast(void *ropt)
{
	return ((struct clirt *)ropt)->optlast;
}

/*!\brief Retrieve the required argument.

   \param[in]  ropt The previous allocated data structure for parsing 
                    command line arguments.

   \return The pointer to the required argument.
   \remark Similar to the 'optarg' in getopt() function.
*/
char *csc_cli_qopt_optarg(void *ropt)
{
	return ((struct clirt *)ropt)->optarg;
}


/*!\brief Parse command-line options without getopt() involved.

   \param[in]  ropt   The previous allocated data structure for parsing 
                      command line arguments.
   \param[in]  optbl  The pointer to the option table in 'struct cliopt'

   \return  If an option was successfully found, then csc_cli_qopt() returns 
            the option character. If all command-line options have been parsed,
	    then getopt() returns something < 0.  If getopt() encounters an 
	    option character that was not in optstring, then '?' is returned 
	    and the option character can be returned by csc_cli_qopt_optopt().
	    If getopt() encounters an option with a missing argument, then '?' 
	    is returned and ':' will be returned by csc_cli_qopt_optopt().
*/
int csc_cli_qopt(void *ropt, struct cliopt *optbl)
{
	struct	clirt	*rtbuf = ropt;
	char	*opt;
	int	rc;

	if (!rtbuf || !optbl) {
		return -1;	/* not available */
	}

	opt = *rtbuf->argv;

	/** Skip the first parameter if it's not an option.
	 *  The point is you can start to ananlysis the command line by
	 *  "command -f1 -f2 ..." or by "-f1 -f2 ..."
	 */
	if ((rtbuf->optind == 0) && (*opt != '-') && (*opt != '+')) {
		rtbuf->optind++;
		rtbuf->argv++;
		opt = *rtbuf->argv;
	}

	if (rtbuf->optind >= rtbuf->argc) {
		rtbuf->optopt = 0;
		rtbuf->optarg = NULL;
		return -2;	/* end of scan by length */
	}
	if (!strcmp(opt, "--")) {
		rtbuf->optopt = '-';
		rtbuf->optarg = opt;
		return -3;	/* end of scan by break */
	}
	if ((*opt != '-') && (*opt != '+')) {
		rtbuf->optopt = *opt;
		rtbuf->optarg = opt;
		return -4;	/* end of scan by no more options */
	}

	for ( ; (rc = csc_cli_type(optbl)) != CLI_EOL; optbl++) {
		if (rc == CLI_SHORT) {
			if (opt[1] == optbl->opt_char) {
				break;
			}
		} else if (rc == CLI_LONG) {
			if ((opt[0] == '-') && (opt[1] == '-') && !strcmp(opt+2, optbl->opt_long)) {
				break;
			}
		} else if (rc == CLI_BOTH) {
			if (opt[1] == optbl->opt_char) {
				break;
			} else if ((opt[0] == '-') && (opt[1] == '-') && !strcmp(opt+2, optbl->opt_long)) {
				break;
			}
		}
	}
	
	/* preload optopt and optlast in case error option or next argument missing */
	rtbuf->optopt = opt[1];		
	rtbuf->optlast = *rtbuf->argv;

	if (rc == CLI_EOL) {
		/* getopt(3): By default, getopt() prints an error message on standard error, 
		 * places the erroneous option character in optopt, and returns '?' as the 
		 * function result. */
		if (*opt == '+') {
			rtbuf->optarg = opt;
			return -5;	/* end of scan by dead break */
		} else {
			rtbuf->optind++;
			rtbuf->argv++;
			rtbuf->optarg = NULL;
			return '?';	/* unknown option */
		}
	}

	rtbuf->optind++;
	rtbuf->argv++;
	rtbuf->optarg = NULL;
	if ((CSC_CLI_PARAM(optbl) == 1) || (CSC_CLI_PARAM(optbl) == 3)) { 
		/* one argument required */
		opt = *rtbuf->argv;

		/* getopt(3): If the first character (following any optional '+' or '-' 
		 * described above) of optstring is a colon (':'), then getopt() likewise 
		 * does not print an error message. In addition, it returns ':' instead  
		 * of '?' to indicate a missing option argument.  This allows the caller 
		 * to distinguish the two different types of errors. */
		if (rtbuf->optind >= rtbuf->argc) {
			rtbuf->optopt = ':';
			return ':';	/* end of scan by lost argument */
		}
		if ((*opt == '-') || (*opt == '+')) {
			rtbuf->optopt = ':';
			return ':';	/* miss an argument */
		}
		rtbuf->optarg = *rtbuf->argv++;
		rtbuf->optind++;
		rtbuf->optopt = 0;	/* not error occurred */
	} else if ((CSC_CLI_PARAM(optbl) == 2) || (CSC_CLI_PARAM(optbl) == 4)) {
		/* one optional argument required */
		if (opt[1] != '-') {	/* short form */
			if (opt[2]) {
				rtbuf->optarg = &opt[2];
			}
		} else {	/* long form */
			opt += strlen(optbl->opt_long) + 2;
			if (*opt == '=') {
				rtbuf->optarg = ++opt;
			}
		}
		rtbuf->optopt = 0;	/* not error occurred */
	}
	return optbl->opt_char;
}


