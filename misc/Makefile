
include ../Make.conf

CFLAGS	+= -I..

OBJS	= cliopt.o  fixtoken.o  isdelim.o  mkargs.o  strlcopy.o  ziptoken.o \
	  csoup_cmp_file_extname.o  csoup_strcmp_list.o memdump.o

.PHONY: all clean
	
all: $(OBJS)

clean:
	$(RM) $(OBJS)



