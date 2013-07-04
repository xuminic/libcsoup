
include ../Make.conf

CFLAGS	+= -I..

SRCS	= main.c fixtoken.c smm.c memdump.c slog.c

TARGET	= csoup


.PHONY: all clean $(TARGET)
all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -L.. -o $@ $(SRCS) -lcsoup

clean:
	$(RM) $(TARGET)



