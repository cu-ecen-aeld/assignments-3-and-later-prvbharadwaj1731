#! /bin/sh

#References: 
# 1) https://man7.org/linux/man-pages/man8/start-stop-daemon.8.html
# 2) https://gist.github.com/RichardBronosky/b037de3e8763887b034298057200bd02


case "$1" in
	start)
		echo "Starting aesdsocket on port 9000"
		start-stop-daemon -S -n aesdsocket -a /usr/bin/aesdsocket -- -d
		;;
	stop)
		echo "Stopping aesdsocket on port 9000"
		start-stop-daemon -K -n aesdsocket
		;;
	*)
		echo "How to use: $0 {start|stop}"
	exit 1
esac
exit 0
