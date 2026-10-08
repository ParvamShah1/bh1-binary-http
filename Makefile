CC     ?= cc
CFLAGS ?= -std=gnu11 -O2 -Wall -Wextra -Wpedantic

COMMON = src/bh1.c src/bh1.h

all: bserve bcurl

bserve: src/bserve.c $(COMMON)
	$(CC) $(CFLAGS) -pthread -o $@ src/bserve.c src/bh1.c

bcurl: src/bcurl.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ src/bcurl.c src/bh1.c

test: all
	python3 tests/conformance.py

clean:
	rm -f bserve bcurl

.PHONY: all test clean
