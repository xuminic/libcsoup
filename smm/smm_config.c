
/*  smm_config.c - configure parameters management 

    Copyright (C) 2011  "Andy Xuming" <xuming@users.sourceforge.net>

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

#include <stdio.h>
#include <stdlib.h>

#include "libcsoup.h"

#ifdef	CFG_WIN32_API
void *smm_config_open(int sysroot, char *path, char *fname)
{
}

int smm_config_flush(void *cfg)
{
}

int smm_config_close(void *cfg)
{
}

int smm_config_delete(void *cfg)
{
}

char *smm_config_read(void *cfg, char *mkey, char *skey)
{
}

int smm_config_write(void *cfg, char *mkey, char *skey, char *value)
{
}

int smm_config_read_long(void *cfg, char *mkey, char *skey, long *val)
{
}

int smm_config_write_long(void *cfg, char *mkey, char *skey, long val)
{
}

#endif

#ifdef	CFG_UNIX_API

void *smm_config_open(int sysroot, char *path, char *fname)
{
}

int smm_config_flush(void *cfg)
{
}

int smm_config_close(void *cfg)
{
}

int smm_config_delete(void *cfg)
{
}

char *smm_config_read(void *cfg, char *mkey, char *skey)
{
}

int smm_config_write(void *cfg, char *mkey, char *skey, char *value)
{
}

int smm_config_read_long(void *cfg, char *mkey, char *skey, long *val)
{
}

int smm_config_write_long(void *cfg, char *mkey, char *skey, long val)
{
}

#endif

