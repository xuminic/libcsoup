
CFLAGS	+= -I..

#SRCS   := $(shell echo *.c)
SRCS	:= slog_core.c slog_csoup.c slog_socket.c

OBJS	:= $(SRCS:.c=.o)

.PHONY: all clean
	
all: $(OBJS)

clean:
	$(RM) $(OBJS)



