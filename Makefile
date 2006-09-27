CC = gcc
CPPFLAGS = -DDEBUG
CFLAGS = -Wall -W -g
LDFLAGS =

SOEXT = so


BINS = libsse3.$(SOEXT) test-sse3

all: $(BINS)

libsse3.$(SOEXT): libsse3.o
	$(CC) $(LDFLAGS) -o libsse3.$(SOEXT) -shared libsse3.o

test-sse3: test-sse3.o

.PHONY: all clean distclean install
clean:
	rm -f *.o $(BINS)

distclean: clean

install: all
