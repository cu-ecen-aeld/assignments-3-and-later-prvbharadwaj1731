#! /bin/sh 
#References: 
# 1) https://man7.org/linux/man-pages/man8/start-stop-daemon.8.html 
# 2) https://gist.github.com/RichardBronosky/b037de3e8763887b034298057200bd02
usage() {
	echo "Command: $0 <start/stop>"
	echo "Functionality: starts/stops the aesdsocket daemon."
}

#Check that one arguments has been provided
if [ ! $# -eq 1 ]
then
	usage
	exit 1
fi

if [ $1 = "start" ]
then
    echo "Starting aesdsocket"
    start-stop-daemon -S -n aesdsocket -a /usr/bin/aesdsocket -- -d
elif [ $1 = "stop" ]
then
    echo "Stopping aesdsocket"
    start-stop-daemon -K -n aesdsocket
fi
