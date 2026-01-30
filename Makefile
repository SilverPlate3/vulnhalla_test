CC=gcc
CFLAGS=-Wall

all: vulnerable

vulnerable: vulnerable.c
	$(CC) $(CFLAGS) -o vulnerable vulnerable.c

clean:
	rm -f vulnerable *.o
