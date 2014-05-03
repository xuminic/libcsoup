
export	CC	= gcc
export	AR	= ar
export	CP	= cp
export	RM	= rm -f

PREFIX	= /usr/local
BINDIR	= /usr/local/bin
MANDIR	= /usr/local/man/man1

# Options: CFG_WIN32_API, CFG_UNIX_API
SYSAPI	= 
DEBUG	= -g -DDEBUG
DEFINES = 

export	CFLAGS	= -Wall -Wextra -O3 $(DEBUG) $(DEFINES) $(SYSAPI) 

ifndef	RELCS
RELCS	= libcsoup-$(shell version.sh)
endif

TARGET	= libcsoup.a

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<


.PHONY: all clean misc slog smm main doc
	
all: main

main: $(TARGET)
	make -C main all

$(TARGET) : misc slog smm
	$(RM) $(TARGET)
	$(AR) crus $(TARGET) misc/*.o slog/*.o smm/*.o

misc:
	make -C misc all

slog:
	make -C slog all

smm:
	make -C smm all

doc:
	doxygen doc/Doxyfile

clean:
	make -C misc clean
	make -C slog clean
	make -C smm clean
	make -C main clean
	$(RM) $(TARGET)

release:
	if [ -d $(RELCS) ]; then $(RM) -r $(RELCS); fi
	-mkdir $(RELCS)
	$(CP) *.h Make* $(RELCS)
	$(CP) -a misc slog smm main $(RELCS)
	make -C $(RELCS) clean
	make -C $(RELCS)/main clean


