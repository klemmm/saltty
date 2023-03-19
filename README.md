# saltty

## What is it?

This is a tool to demonstrate the possibility of obtaining (and keeping)
unauthorized access to a (real or pseudo) tty device when the admin runs any
command as another (evil/compromised) user. This access to the tty device
can then be used to log passwords, for example.

This is meant as a demonstration tool only, please use responsibly (on your
own machine, or with permission from admin).

##  Typical usage scenario

Let's call _admin_ the user account of the admin (i.e. the unprivileged
account of the person that can use su/sudo to become root). 

Let's call _evil_ the evil/compromised user account (this account does not
have any privileges). 

### STEP 1. The _evil_ user compiles and run the "saltty" daemon.

#### As _evil_
```
evil@machine:~/saltty$ make
gcc -fPIC -Wall -fno-stack-protector   -c -o saltty.o saltty.c
gcc -fPIC -Wall -fno-stack-protector   -c -o conf.o conf.c
gcc   saltty.o conf.o  -lpthread -o saltty
evil@machine:~/saltty$ ./saltty
Hidden as: bash
evil@machine:~/saltty$
```

The daemon is now waiting in the background. The following lines are added
in the daemon's log file (by default: /tmp/log.txt): 

```
Started as PID 9351, waiting for injectable process...
Monitoring...
```

### STEP 2. The admin becomes root and run some command as _evil_

#### As _admin_
```
admin@machine:~$ su 
Password: 
root@machine:/home/admin# su -c "somecommand" evil
root@machine:/home/admin# exit
```

At this step, the daemon recovers access to the admin's tty by hijacking the
"somecommand" process. The following lines are logged by the daemon:
```
Activity detected! Waking up.
Victim process found: 10277 (on tty: /dev/pts/5)
Injecting tty-stealer...
Injected code finished execution, restoring original process context...
Received stolen tty file descriptor from victim process!
Waiting for sniffable process...
Monitoring...
```

This also works with "sudo -u evil [-s] somecommand", or with any way to run 
any command as _evil_ without closing stdin/stdout/stderr. An interactive
shell (or even any shell) is NOT required, and "somecommand" does NOT need
to have the admin's tty as a controlling terminal (an open file descriptor
to it is sufficient).

### STEP 3. The admin run (on the same tty) any command asking for a password

#### As _admin_
```
admin@machine:~$ su
Password:
su: Authentication failure.
admin@machine:~$ 
```

The daemon detects an "interesting" command and log the passwords along with
relevant informations:
```
Activity detected! Waking up.
Sniffable process found: /bin/su
[Mon Oct  3 08:38:50 2016] BIN=/bin/su CMDLINE="su" PASSWORD="blahblah"
```


## Configuration

In most cases, this tool will require adaptation to your specific use case.
Various settings are available in files conf.h and conf.c.

### 1. General settings

The file conf.h has the following defines: 

__PID_MAX__: the maximum process ID in the target system.

__HIDDEN_NAME__: the fake name the daemon will hide itself as.
TMPDIR: any temporary directory, must be writeable/executable by _evil_ and
readable by _admin_.

__LOG_FILE__: the location of the daemon's log file. Must be in a directory
writeable by _evil_.

__INJECT_LIST__: a NULL-terminated list of commands that will trigger an attempt
to hijack a process to recover the admin's tty (in STEP 2). Full path to
binary is required.

__SNIFF_LIST__: a NULL-terminated list of commands that will trigger an attempt
to read a password from the admin's tty (in STEP 3). Full path to binary is
required.

__HANDLER_LIST__: a NULL-terminated list of handlers (see next section). Each
handler manages a program from __SNIFF_LIST__. These two lists must have the
same size, as the first program is __SNIFF_LIST__ is managed by the first
handler in __HANDLER_LIST__, and so on.

__MONITOR_MAX__: this value must be greater than (or equal to) the number of
elements in __INJECT_LIST__, __HANDLER_LIST__ and__ SNIFF_LIST__.

__READER_THREADS__: in the handlers (see next section), the number of calls to
the function __read_tty()__ may not exceed __READER_THREADS__ value.

### 2. Handlers

Each time a program in __SNIFF_LIST__ is ran from the admin's tty, the
corresponding handler function (from __HANDLER_LIST__) is executed.

The handler's role (besides logging the password) is to display adequate
prompts (such as "Password: ") and generally take care of any stuff specific
to su, or sudo, or ssh, and so on.

Sample handlers exists for su and sudo, but you will need to customize them,
and add more for your specific needs.

Each handler is a function taking a pointer to a __state_t__ structure. This
structure contains useful information about the program ran by the admin,
and enables us to access the admin's tty.

The following useful fields exists in state_t: 

__int fd__: this is the file descriptor to the admin's tty. Can be used for
writing or ioctl/tc[s|g]etattr. __DO NOT READ FROM IT__. A special __read_tty()__
function is provided for that, it is required that you use it.

__int tty__: a number representing the tty device (major*256 + minor).

__char *name__: string representing the program that triggered the password
recovery attempt.

__FILE *file__: a "high-level" stream to the admin's tty. __DO NOT READ FROM IT__.

The following helper functions can be used: 

__ssize_t read_tty(state_t*, void*, size_t)__: read data from admin's tty,
usable exactly like the read system call, except that you pass the state_t
pointer instead of the file descriptor. May be used up to __READER_THREADS__
time per handler invokation. Subsequent calls will always read 0 bytes.

__echo_on(state_t*)__ / __echo_off(state_t*)__: enable/disable admin's tty echo.

__log_password(state_t*)__: will read a password from the admin's tty and log
it. Counts as an usage of __read_tty()__ towards the __READER_THREADS__ limit.

Each handler can intercept up to __READER_THREADS__ lines typed by the admin.
After the handler returns, further input won't be intercepted.

## ioctl(TIOCSTI) attack

A known, and somewhat related (but different) attack is the so-called TIOCSTI attack. In this attack, when _root_ does a __su evil__, the user __evil__ has the possibility of grabbing the file descriptor to the tty, and later _push back_ ("simulate") various malicious inputs on the admin's session. This attack works only if some process running as UID __evil__ can have the admin's tty as a __controlling tty__ (merely having a file descriptor referring to the tty is not sufficient, as the __ioctl__ will fail with __EPERM__).

It has been hypothesized that to avoid this attack, __root__ should refrain from opening an interactive session as another user. Unfortunately, this is not sufficient. It is true that __su -c "command" user__ correctly calls __setsid()__ in the majority of Linux distros, denying the attacker a controlling tty (preventing the TIOCSTI attack, but not the password interception!). However, other job launch mechanisms, such as __start-stop-daemon__ (which is AFAIK the primary mechanism to launch services in non-systemd debian-based distros) do not, unless invoked with the __-b__ (background option). 

With the __-b__ option, __start-stop_daemon__ performs the _daemonization_ itself, then runs the service (in that case, there is no problem). Without __-b__, __start-stop-daemon__ assumes that the actual service is responsible for for proper/secure _daemonization_. Unfortunately, this assumption is dangerous: even if the actual service performs the _daemonization_ securely, and closes the tty / calls __setsid()__ at once, there exists a window of opportunity where the process can be injected with __ptrace__. This race condition is trivially exploited by using __inotify__ on the target service binary. More generally, any service launch mechanism that drops privileges before closing the tty is at risk.  

The TIOCSTI attack can be tested with this tool. In __conf.h__, if __ATTEMPT_TIOCSTI__ is defined, then the tool will automatically attempt a TIOCSTI attack whenever a victim process with a controlling tty can be injected. Otherwise, it will fall back to the password-interception method. The define __PUSH_PAYLOAD__ defines the malicious command pushed back into the admin's session, and __PUSH_IDLE_TIME__ defines the inactivity delay (in seconds) on the tty after which the program will perform the push-back. There is a pathetic attempt to hide the attack with some ANSI sequences, but it could probably be a lot better. An example of "evil" script attempting to hide from history is provided in __evil.sh__.

Various informations related to this attack can be found on: http://www.halfdog.net/Security/2012/TtyPushbackPrivilegeEscalation/

Example session:

```
evil@machine:~$ cat /tmp/evil
cp /bin/sh /tmp/blah && chmod 4755 /tmp/blah
evil@machine:~$ ./saltty
Hidden as: bash
Started as PID 5020, waiting for injectable process...
```


```
root@machine:~# start-stop-daemon --chuid evil --exec /usr/bin/myservice --start #some services are launched like this by /etc/init.d/XXX scripts in some non-systemd distros
root@machine:~# ls -l /tmp/blah
-rwsr-xr-x 1 root root 125400 oct.   4 20:30 /tmp/blah
```


```
evil@machine:~$ cat /tmp/log.txt
Monitoring...
Activity detected! Waking up.
Victim process found: 5021 (on tty: /dev/pts/4)
Victim process has a controlling terminal! Attempting ioctl(TIOCSTI) attack.
Forcing the victim process to do our bidding...
Injected code finished execution, restoring original process context...
```

#### 

## Mitigation strategies

- ptrace() should be restricted (/proc/sys/kernel/yama/ptrace_scope) on
  production systems

- When running a command as another user, the terminal (fds 0, 1, and 2)
  should be closed before doing setuid()


## Mini-FAQ

Q. How the daemon gets the tty file descriptor?

A. When the admin runs some process as the _evil_ user, the daemon injects code into this process with ptrace(). This code sends the tty file descriptor to the daemon by unix sockets. 

---

Q. Why the ptrace injection fails?

A. Ensure that /proc/sys/kernel/yama/ptrace_scope contains 0.

---

Q. Which OS/platforms are supported?

A. Only Linux/x64. Please also note that it has been only tested with GCC.

---

Q. How the daemon knows when a program (su, sudo, etc.) is ran?

A. By using inotify(7) on the program binaries.

---

Q. Why the number of tty-interceptions (READER_THREADS) is limited?

A. Because the only way (AFAIK) to get data from tty is to call read()
before the legitimate password-asking program (su, sudo...). Therefore,
READER_THREADS threads are created to do this, before calling the handler.

---

Q. How reliable is this tool? 

A. There is plenty of potential issues (thread-safety problems, race
conditions, etc.), but in practice it seems that it almost never causes
problems. These potential issues exists because the daemon can't spend too
much time checking, otherwise we may call read() too late on the admin tty
(i.e. *after* the legitimate password-asking program).



