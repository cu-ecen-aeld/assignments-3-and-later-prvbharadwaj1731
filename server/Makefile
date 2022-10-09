#This Makefile is used to compile "aesdsocket.c".
#If "make CROSS_COMPILE=aarch64-none-linux-gnu-" is used, the program will be cross-compiled for the arm64-bit architecture

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
