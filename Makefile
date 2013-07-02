
include Make.conf

TARGET	= libcsoup.a

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<


.PHONY: all clean misc slog smm
	
all: $(TARGET)

$(TARGET) : misc slog smm
	$(RM) $(TARGET)
	$(AR) crus $(TARGET) misc/*.o slog/*.o smm/*.o

misc:
	make -C misc all

slog:
	make -C slog all

smm:
	make -C smm all

clean:
	make -C misc clean
	make -C slog clean
	make -C smm clean
	$(RM) $(TARGET)



