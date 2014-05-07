
CFLAGS	+= -I..

#SRCS	:= $(shell echo *.c)
SRCS	:= csc_cli_alloc_list.c	\
	   csc_cli_alloc_table.c \
	   csc_cli_getopt_alloc.c \
	   csc_cli_getopt.c	\
	   csc_cli_option.c	\
	   csc_mkargs.c

OBJS	:= $(SRCS:.c=.o)

.PHONY: all clean
	
all: $(OBJS)

clean:
	$(RM) $(OBJS)



