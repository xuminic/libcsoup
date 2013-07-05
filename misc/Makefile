
include ../Make.conf

CFLAGS	+= -I..

#SRCS	:= $(shell echo *.c)
SRCS	:= cli_alloc_getopt.c	\
	  cli_alloc_list.c	\
	  cli_alloc_table.c	\
	  cli_getopt.c		\
	  cliopt.c		\
	  csoup_cmp_file_extname.c \
	  csoup_strcmp_list.c	\
	  fixtoken.c		\
	  isdelim.c		\
	  memdump.c		\
	  mkargs.c		\
	  strlcopy.c		\
	  ziptoken.c

OBJS	:= $(SRCS:.c=.o)

.PHONY: all clean
	
all: $(OBJS)

clean:
	$(RM) $(OBJS)



