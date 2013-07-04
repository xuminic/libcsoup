/* README:
Debug level is 0-7 using Bit2 to Bit0 in the control word
  0: unmaskable, no buffer output (for show-off printf like information)
  1: unmaskable error, buffered output (when error occur)
  2: warning, buffered output (something might be functionably problem, 
     like server returned not-so-good results. the program itself should 
     be still intact)
  3: information, buffered output (information maybe useful for the user)
  4: debug (debug information for the developer)
  5: program progress (the workflow between modules)
  6: module workflow (the detail progress inside a function module)
  7: function workflow (very trivial information shows how the program 
     running detailly inside a function)

Module indicator uses Bit31 to Bit3 in the control word 
(29 bits supports 29 modules at most)


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
#define SLOG_LVL_BLOCK		6
#define SLOG_LVL_FUNC		7


#define SLOG_TO_STDOUT		1
#define SLOG_TO_STDERR		2
#define SLOG_TO_FILE		4
#define SLOG_TO_SOCKET		8
#define SLOG_TO_WINDOW		16

typedef	struct		{
	unsigned	control;	/* module mask and level */
	unsigned	device;

	char	*filename;
	int	logd;

} SMMDBG;

#define SLOG_LEVEL(x)	((x) & 7)
#define SLOG_MODULE(x)	((x) & ~7)


void slog_init(int cword);
void slog_destroy(void);
unsigned slog_control_word_read(void);
unsigned slog_control_word_write(unsigned cword);
int slog_level_read(void);
int slog_level_write(int dbg_lvl);
int slog_bind_stdout(void);
int slog_unbind_stdout(void);
int slog_bind_stderr(void);
int slog_unbind_stderr(void);
int slog_bind_file(char *fname, int append);
int slog_unbind_file(void);
int slog(int cw, char *fmt, ...);


#endif	/* _SLOG_H_ */

