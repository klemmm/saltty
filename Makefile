CFLAGS=-fPIC -Wall -fno-stack-protector
CC=gcc
LDLIBS=-lpthread

all: saltty

saltty: saltty.o conf.o

saltty.o: saltty.c saltty.h conf.h

conf.o: conf.c saltty.h conf.h

clean:
	rm -f core* saltty *.o *~
