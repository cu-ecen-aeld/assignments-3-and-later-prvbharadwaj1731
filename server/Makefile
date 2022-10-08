INCLUDES = ./aesdsocket.c
OUTPUT = ./aesdsocket

CROSS_COMPILE=
CC=$(CROSS_COMPILE)gcc

all: $(INCLUDES)
	$(CC) -Wall -Werror -g $(INCLUDES) -o $(OUTPUT) -lrt -lpthread
	
clean:
	rm -f $(OUTPUT)
	rm -f *.o
