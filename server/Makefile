SOURCE = ./aesdsocket.c
OUTPUT = ./aesdsocket

CROSS_COMPILE =
CC?=$(CROSS_COMPILE)gcc
CFLAGS?= -g -Wall -Werror
LDFLAGS?= -pthread -lrt

all: aesdsocket

aesdsocket: $(SOURCE)
	$(CC) $(CFLAGS) $^ -o $@ $(INCLUDES) $(LDFLAGS)

clean:
	rm -f $(OUTPUT)
	rm -f *.o
