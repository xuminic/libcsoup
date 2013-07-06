/*  crc.c - test harness of CRC functions

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
#include <unistd.h>

#include "libcsoup.h"

static	char	testbuf[2048];

int crc_main(int argc, char **argv)
{
	unsigned	c32;
	unsigned short	c16, cci;
	unsigned char	c8;
	int		i;

	for (i = 0; i < sizeof(testbuf); i++) {
		testbuf[i] = i + 1;
	}
	c32 = crc32(0, testbuf, sizeof(testbuf));
	c16 = crc16(0, testbuf, sizeof(testbuf));
	cci = crc_ccitt(0, testbuf, sizeof(testbuf));
	c8  = crc8(0, testbuf, sizeof(testbuf));
	slog(SLINFO, "RUN1: CRC32=%X  CRC16=%X  CRC-CCITT=%X  CRC8=%X\n", 
			c32, c16, cci, c8);

	c32 = crc32(c32, testbuf, sizeof(testbuf));
	c16 = crc16(c16, testbuf, sizeof(testbuf));
	cci = crc_ccitt(cci, testbuf, sizeof(testbuf));
	c8  = crc8(c8, testbuf, sizeof(testbuf));
	slog(SLINFO, "RUN2: CRC32=%X  CRC16=%X  CRC-CCITT=%X  CRC8=%X\n", 
			c32, c16, cci, c8);

	c32 = crc32(0, testbuf, sizeof(testbuf));
	c16 = crc16(0, testbuf, sizeof(testbuf));
	cci = crc_ccitt(0, testbuf, sizeof(testbuf));
	c8  = crc8(0, testbuf, sizeof(testbuf));
	slog(SLINFO, "RUN3: CRC32=%X  CRC16=%X  CRC-CCITT=%X  CRC8=%X\n", 
			c32, c16, cci, c8);

	testbuf[128]++;
	c32 = crc32(0, testbuf, sizeof(testbuf));
	c16 = crc16(0, testbuf, sizeof(testbuf));
	cci = crc_ccitt(0, testbuf, sizeof(testbuf));
	c8  = crc8(0, testbuf, sizeof(testbuf));
	slog(SLINFO, "RUN4: CRC32=%X  CRC16=%X  CRC-CCITT=%X  CRC8=%X\n", 
			c32, c16, cci, c8);
	return 0;
}

