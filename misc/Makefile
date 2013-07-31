
include ../Make.conf

CFLAGS	+= -I..

#SRCS	:= $(shell echo *.c)
SRCS	:= cli_alloc_getopt.c	\
	  cli_alloc_list.c	\
	  cli_alloc_table.c	\
	  cli_getopt.c		\
	  cliopt.c		\
	  crc16.c		\
	  crc16c.c		\
	  crc32.c		\
	  crc8.c		\
	  csoup_cmp_file_extname.c \
	  csoup_strcmp_list.c	\
	  fixtoken.c		\
	  isdelim.c		\
	  iso639.c		\
	  memdump.c		\
	  mkargs.c		\
	  strcpy_alloc.c	\
	  strlcopy.c		\
	  ziptoken.c

OBJS	:= $(SRCS:.c=.o)

.PHONY: all clean
	
all: $(OBJS)

clean:
	$(RM) $(OBJS)



