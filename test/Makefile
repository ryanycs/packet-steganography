CC = gcc
CFLAGS = -Wall -lpcap

SDIR = ../src
IDIR = ../include
DEPS = $(IDIR)/protocol.h $(IDIR)/utils.h

all: test-read

test-read: test-read.c $(SDIR)/read.c $(DEPS)
	$(CC) -o $@ $^ -I$(IDIR)

.PHONY: clean

clean:
	rm -f test-read