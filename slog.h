/* README:
Debug level is 0-7 using Bit2 to Bit0 in the control word
  0: unmaskable output (for show-off printf like information)
  1: unmaskable error message (when error occur)
  2: warning output (something might be functionably problem, like server 
     returned not-so-good results. the program itself should be still intact)
  3: information, buffered output (information maybe useful for the user)
  4: debug (debug information for the developer)
  5: program progress (the workflow between modules)
  6: module workflow (the detail progress inside a function module)
  7: function workflow (very trivial information shows how the program 
     running detailly inside a function)
Bit3 is used to indicate flush or non-flush mode.

Module indicator uses Bit31 to Bit4 in the control word (reserved)


slog_init(int default);
slog_set_level(int control_word);
slog_get_level();

slog_bind_stdio();
slog_bind_stderr();
slog_bind_file();
slog_bind_socket();
slog_bind_window();

slog(int control_word, char *fmt, ...);

*/

/*  slog.h

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

#ifndef	_SLOG_H_
#define _SLOG_H_

#define	SLOG_BUFFER		1024	/* maximum log buffer */

#define SLOG_LVL_SHOWOFF	0
#define SLOG_LVL_ERROR		1
#define SLOG_LVL_WARNING	2
#define SLOG_LVL_INFO		3
#define SLOG_LVL_DEBUG		4
#define SLOG_LVL_PROGRAM	5
#define SLOG_LVL_MODULE		6
#define SLOG_LVL_FUNC		7
#define SLOG_LVL_MASK		7
#define SLOG_FLUSH		8

#define SLOG_LEVEL(x)	((x) & SLOG_LVL_MASK)
#define SLOG_MODULE(x)	((x) & ~SLOG_LVL_MASK)

/* short name of slog debug level */
#define SLSHOW		SLOG_LVL_SHOWOFF
#define SLERR		SLOG_LVL_ERROR
#define SLWARN		SLOG_LVL_WARNING
#define SLINFO		SLOG_LVL_INFO
#define SLDBG		SLOG_LVL_DEBUG
#define SLPROG		SLOG_LVL_PROGRAM
#define SLMOD		SLOG_LVL_MODULE
#define SLFUNC		SLOG_LVL_FUNC

/* device bit mask */
#define SLOG_TO_STDOUT		1
#define SLOG_TO_STDERR		2
#define SLOG_TO_FILE		4
#define SLOG_TO_SOCKET		8
#define SLOG_TO_WINDOW		16


typedef int (*F_STD)(int, char*, int);


typedef	struct		{
	unsigned	cword;		/* control word: modules and level */
	unsigned	device;		/* mask of output devices */

	/* log file as output device */
	char		*filename;
	FILE		*logd;

	/* standard i/o as output device */
	F_STD		stdoutput;
	F_STD		stderrput;
} SMMDBG;


void slog_def_open(int cword);
void slog_def_close(void);
int slog_def_stdout(int flush, char *buf, int len);
int slog_def_stderr(int flush, char *buf, int len);
void *slog_open(int cword);
int slog_close(void *control);
SMMDBG *slog_control(void *control);
int slog_validate(SMMDBG *dbgc, int cw);
unsigned slog_control_word_read(void *control);
unsigned slog_control_word_write(void *control, unsigned cword);
int slog_level_read(void *control);
int slog_level_write(void *control, int dbg_lvl);
int slog_bind_stdout(void *control, F_STD func);
int slog_unbind_stdout(void *control);
int slog_bind_stderr(void *control, F_STD func);
int slog_unbind_stderr(void *control);
int slog_bind_file(void *control, char *fname, int append);
int slog_unbind_file(void *control);
int slog_output(SMMDBG *dbgc, int cw, char *buf, int len);
int slogc(void *control, int cw, char *fmt, ...);
int slogs(void *control, int cw, char *buf, int len);

int slog(int cw, char *fmt, ...);
int slos(int cw, char *buf);

int slogz(char *fmt, ...);
int slosz(char *buf);

#endif	/* _SLOG_H_ */

