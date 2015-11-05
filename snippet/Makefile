


CFLAGS	= -I./external/iup/include `pkg-config gtk+-2.0 --cflags` -L./external/iup/lib/Linux310_64
LIBS	= `pkg-config gtk+-2.0 --libs` -lX11 -liup -lpthread

SRC	= iup_thread_sync_idler2.c	\
	  iup_thread_sync_idler.c	\
	  iup_thread_sync_timer.c	\
	  pthread_myq_cancellation.c	\
	  pthread_queue_simple.c

TARGET	= $(basename $(SRC))

%: %.c
	gcc $(CFLAGS) -o $@ $< $(LIBS)

all: $(TARGET)

clean:
	rm $(TARGET)
