/*  memdump.c

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
#include <string.h>

#define MEMDUMP_MODE_WID_MASK	0xff
#define MEMDUMP_MODE_NO_GLYPH	0x100

#define MEMDUMP_COL_MAX	32	/* no display more than this column a line */

int memdump(void *mem, int range, int column, int mode)
{
	char	lbuf[MEMDUMP_COL_MAX * 17];
	char	abuf[MEMDUMP_COL_MAX + 4], tmp[32];
	int	i, step, ccnt, cidx, direct;

	direct = 0;
	if (range < 0) {
		direct = -1;
		range  = - range;
	}
	if (column > MEMDUMP_COL_MAX) {
		column = MEMDUMP_COL_MAX;
	}

	ccnt = cidx = 0;
	sprintf(lbuf, "%p: ", mem);
	while (range > 0) {
		switch (mode & MEMDUMP_MODE_WID_MASK) {
		case 16:
			step = 2;
			sprintf(tmp, "%04x ", *((unsigned short *)mem));
			break;
		case 32:
			step = 4;
			sprintf(tmp, "%08x ", *((unsigned *)mem));
			break;
		case 64:
			step = 8;
			sprintf(tmp, "%016llx ", *((unsigned long long *)mem));
			break;
		default:
			step = 1;
			sprintf(tmp, "%02x ", *((unsigned char *)mem));
			break;
		}
		strcat(lbuf, tmp);
		memcpy(&abuf[cidx], mem, step);

		cidx  += step;
		range -= step;
		if (direct < 0) {
			mem = (void*)((unsigned long)mem - step);
		} else {
			mem = (void*)((unsigned long)mem + step);
		}

		ccnt++;
		if (ccnt == column) {
			for (i = 0; i < cidx; i++) {
				if ((abuf[i] < ' ') || (abuf[i] > 0x7e)) {
					abuf[i] = '.';
				}
			}
			abuf[i] = 0;

			if (mode & MEMDUMP_MODE_NO_GLYPH) {
				printf("%s\n", lbuf);
			} else {
				printf("%s %s\n", lbuf, abuf);
			}

			ccnt = cidx = 0;
			sprintf(lbuf, "%p: ", mem);
		}
	}
	return 0;
}
