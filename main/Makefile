
include ../Make.conf

CFLAGS	+= -I..

SRCS	= main.c fixtoken.c smm.c memdump.c slog.c crc.c fontpath.c

TARGET	= csoup


.PHONY: all clean $(TARGET)
all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -L.. -o $@ $(SRCS) -lcsoup

universal_crc: universal_crc.c
	$(CC) $(CFLAGS) -o $@ $<

crc: universal_crc
	universal_crc -a tab -b 32 -p 0x04c11db7 -i 0xffffffff -x 0xffffffff -r > crc32.c
	universal_crc -a tab -b 16 -p 0x1021 > crc16.c
	universal_crc -a tab -b 8 -p 0x7 > crc8.c

clean:
	$(RM) $(TARGET)
	$(RM) universal_crc crc*.c



