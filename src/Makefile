CC = gcc-13
CFLAGS = -O3 -std=c17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wdouble-promotion -Wformat=2 -Wstrict-prototypes -Werror -D_FILE_OFFSET_BITS=64
LDLIBS = -lcrypto -ldl

.PHONY: all clean
all: a180215
a180215: a180215.c Makefile
	$(CC) $(CFLAGS) a180215.c -o $@ $(LDFLAGS) $(LDLIBS)
clean:
	rm -f a180215
