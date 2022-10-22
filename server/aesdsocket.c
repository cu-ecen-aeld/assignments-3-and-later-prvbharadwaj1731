/**
* @file aesdsocket.c
* @brief Creates a server on port 9000
*
* Sets up a server on port 9000 and accepts any connection.
* The contents obtained are appended in /var/tmp/aesdsocketdata
* Once the client ends the connection, the full content of the file is returned to it
* Logs acceptance and closure of connections
* Accepts new clients redirecting them to threads,
* until SIGINT or SIGTERM signals are received.
*/

//Includes
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "queue.h"
#include <pthread.h>
#include <time.h>
#include <semaphore.h>

//Defines
#define     USE_AESD_CHAR_DEVICE
#define     SERVER_QUEUE    (10)

#ifdef USE_AESD_CHAR_DEVICE
#define     LOG_PATH        ("/dev/aesdchar")
#else
#define     LOG_PATH        ("/var/tmp/aesdsocketdata")
#endif
#define     RECV_BUFF_LEN   (1024)

struct thread_t
{
    pthread_t thread_id;
    int socket_client;
    int socket_server;
    pthread_mutex_t *mutex;
    int finished;
    int *file_size;
    struct sockaddr_storage client_addr;

    //Linked list node instance
    SLIST_ENTRY(thread_t) node;
};

//Globals
int graceful_exit = 0;
int file_fd = 0;
int file_size = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
#ifndef USE_AESD_CHAR_DEVICE
sem_t sem_timestamp;
#endif

/**
* usage
* @brief Prints the usage of the program.
*
* @param  char* command called
* @return void
*/
void usage(char *command)
{
    //Print the usage
    printf("Command: %s <flag>\n", command);
    printf("Functionality: Creates a server, <flag> must be set to \"-d\" if the caller wants to run it as a daemon.\n");

    exit(1);
}

/**
* sighandler
* @brief Handles the SIGINT and SIGTERM signals.
*
* @param  int signal that triggered this function
* @return void
*/
void signalhandler(int sig)
{
    if(sig == SIGINT || sig == SIGTERM)
    {
       syslog(LOG_INFO, "Caught signal, exiting");
    
       graceful_exit = 1;

       //Enable semaphore to speed up exit
#ifndef USE_AESD_CHAR_DEVICE
       sem_post(&sem_timestamp);
#endif
    }
}

#ifndef USE_AESD_CHAR_DEVICE
/**
* timestamp_handler
* @brief Handles the time alarm.
*
* @param  int signal that triggered this function
* @return void
*/
void sigalrm_handler(int sig)
{
    if(sig == SIGALRM)
    {
        //Enable semaphore
        sem_post(&sem_timestamp);
    }
}

/**
* timestamp_handler
* @brief Handles the timestamping of the server log file.
*
* @param  void * void
* @return void
*/
void *timestamp_handler(void *unused)
{
    while(!graceful_exit)
    {
        //Wait for the semaphore to be set by the SIGALRM handler
        sem_wait(&sem_timestamp);

        syslog(LOG_INFO, "10 seconds passed, printing timestamp");
        int ret = pthread_mutex_lock(&mutex);
        if(ret != 0)
        {
            syslog(LOG_ERR, "Could not lock mutex: %s", strerror(ret));
            exit(1);  
        }

        //Get the timestamp
        char timestr[200];
        time_t t;
        struct tm *t2;

        t = time(NULL);
        t2 = localtime(&t);
        if (t2 == NULL) 
        {
            syslog(LOG_ERR, "Could not get local time");
            goto mutex_release; 
        }
        strcpy(timestr, "timestamp:");
        strftime(&timestr[10], sizeof(timestr) - 10, "%a, %d %b %Y %T %z", t2);
        char *buff = malloc(sizeof(char) * strlen(timestr) + 2);
        if(!buff)
        {
            syslog(LOG_ERR, "Could not allocate memory for the timestamp: %s", strerror(errno));
            goto mutex_release; 
        }
        sprintf(buff, "%s%s", timestr, "\n");

        //Write it appending to the file
        if(lseek(file_fd, 0, SEEK_END) == -1)
        {
            syslog(LOG_ERR, "Could not get to the beginning of the file: %s", strerror(errno));
            goto exit_all; 
        }
        
        int written_bytes;
        int len_to_write = strlen(buff);
        char *ptr_to_write = buff;
        while(len_to_write != 0)
        {
            written_bytes = write(file_fd, ptr_to_write, len_to_write);
            if(written_bytes == -1)
            {
                //If the error is caused by an interruption of the system call try again
                if(errno == EINTR)
                    continue;

                //Else, error occurred, print it to syslog and finish program
                syslog(LOG_ERR, "Could not write to the file: %s", strerror(errno));
                goto exit_all; 
            }
            len_to_write -= written_bytes;
            ptr_to_write += written_bytes; 
        }

        file_size += strlen(buff);

    exit_all:
        free(buff);
    mutex_release:
        //Release mutex
        ret = pthread_mutex_unlock(&mutex);
        if(ret != 0)
        {
            syslog(LOG_ERR, "Could not unlock mutex: %s", strerror(ret));
            exit(1); 
        }
    }

    return NULL;
}
#endif

/**
* print_accepted_conn
* @brief Prints the IP address used by the client socket
*
* @param  sockaddr_storage contains client information
* @return void
*/
void print_accepted_conn(struct sockaddr_storage client_addr)
{
    //Get information from the client
    //Credits: https://stackoverflow.com/questions/1276294/getting-ipv4-address-from-a-sockaddr-structure
    if(client_addr.ss_family == AF_INET)
    {
        char addr[INET6_ADDRSTRLEN];
        struct sockaddr_in *addr_in = (struct sockaddr_in *)&client_addr;
        inet_ntop(AF_INET, &(addr_in->sin_addr), addr, INET_ADDRSTRLEN);
        syslog(LOG_INFO, "Accepted connection from %s", addr);
    }
    else if(client_addr.ss_family == AF_INET6)
    {
        char addr[INET6_ADDRSTRLEN];
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&client_addr;
        inet_ntop(AF_INET6, &(addr_in6->sin6_addr), addr, INET6_ADDRSTRLEN);
        syslog(LOG_INFO, "Accepted connection from %s", addr);
    }
}

/**
* print_closed_conn
* @brief Prints the IP address used by the client socket
*
* @param  sockaddr_storage contains client information
* @return void
*/
void print_closed_conn(struct sockaddr_storage client_addr)
{
    if(client_addr.ss_family == AF_INET)
    {
        char addr[INET6_ADDRSTRLEN];
        struct sockaddr_in *addr_in = (struct sockaddr_in *)&client_addr;
        inet_ntop(AF_INET, &(addr_in->sin_addr), addr, INET_ADDRSTRLEN);
        syslog(LOG_INFO, "Closed connection from %s", addr);
    }
    else if(client_addr.ss_family == AF_INET6)
    {
        char addr[INET6_ADDRSTRLEN];
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&client_addr;
        inet_ntop(AF_INET6, &(addr_in6->sin6_addr), addr, INET6_ADDRSTRLEN);
        syslog(LOG_INFO, "Closed connection from %s", addr);
    }
}

/**
* serve_client
* @brief Serves a client from a socket connection
* 
* The server functionality is described in more detail at
* the file header.
*
* @return void
*/
void *serve_client(void *thread_info)
{
    struct thread_t *thread_info_parsed = (struct thread_t *) thread_info;

    print_accepted_conn(thread_info_parsed->client_addr);

    //Wait for data
    int recv_ret;
    int index = 0;
    //Keep track of how many RECV_BUFF_LEN chunks "recv_data" has
    int chunks = 1;
    
    //Start with a size, potentially increasing it if an entire packet cannot fit into it
    char *recv_data = malloc(sizeof(char)*RECV_BUFF_LEN*chunks);
    if(!recv_data)
    {
        syslog(LOG_ERR, "Could not malloc: %s", strerror(errno));
        goto exit_nofree; 
    }

    do
    {
        recv_ret = recv(thread_info_parsed->socket_client, &recv_data[index], RECV_BUFF_LEN, 0);
        if(recv_ret == -1)
        {
            syslog(LOG_ERR, "An error occurred reading from the socket: %s", strerror(errno));
            goto exit_all;  
        }
        index += recv_ret;

        if(index != 0)
        {
            //Check if the last value received is "\n"
            if(recv_data[index - 1] == '\n')
            {
                //When a newline is received, the entire message can be processed. 
                //Lock the use of the file descriptor
                int ret = pthread_mutex_lock(thread_info_parsed->mutex);
                if(ret != 0)
                {
                    syslog(LOG_ERR, "Could not lock mutex: %s", strerror(ret));
                    goto exit_all;  
                }

                //Put the contents into the chosen file
                //Write the string to the file
                //Send all the contents read from the chosen file back to the client

#ifndef USE_AESD_CHAR_DEVICE
                if(lseek(file_fd, 0, SEEK_END) == -1)
                {
                    syslog(LOG_ERR, "Could not get to the end of the file: %s", strerror(errno));
                    ret = pthread_mutex_unlock(thread_info_parsed->mutex);
                    if(ret != 0)
                    {
                        syslog(LOG_ERR, "Could not unlock mutex: %s", strerror(ret));
                    }
                    goto exit_all;  
                }
#else
                file_fd = open(LOG_PATH, O_CREAT | O_RDWR | O_TRUNC, 0666);
                if(file_fd == -1)
                {
                    syslog(LOG_ERR, "Could not create the log file: %s", strerror(errno));
                    goto exit_all;  
                }
#endif
                int written_bytes;
                int len_to_write = index;
                char *ptr_to_write = recv_data;
                while(len_to_write != 0)
                {
                    written_bytes = write(file_fd, ptr_to_write, len_to_write);
                    if(written_bytes == -1)
                    {
                        //If the error is caused by an interruption of the system call try again
                        if(errno == EINTR)
                        {
                            //Free the mutex
                            ret = pthread_mutex_unlock(thread_info_parsed->mutex);
                            if(ret != 0)
                            {
                                syslog(LOG_ERR, "Could not unlock mutex: %s", strerror(ret));
                            }
                            continue;
                        }
                           

                        //Else, error occurred, print it to syslog and finish program
                        syslog(LOG_ERR, "Could not write to the file: %s", strerror(errno));
                        ret = pthread_mutex_unlock(thread_info_parsed->mutex);
                        if(ret != 0)
                        {
                            syslog(LOG_ERR, "Could not unlock mutex: %s", strerror(ret));
                        }
                        goto exit_all; 
                    }
                    len_to_write -= written_bytes;
                    ptr_to_write += written_bytes; 
                }

                *thread_info_parsed->file_size = *thread_info_parsed->file_size + index;
#ifndef USE_AESD_CHAR_DEVICE
                //Send all the contents read from /var/tmp/aesdsocketdata back to the client
                if(lseek(file_fd, 0, SEEK_SET) == -1)
                {
                    syslog(LOG_ERR, "Could not get to the beginning of the file: %s", strerror(errno));
                    ret = pthread_mutex_unlock(thread_info_parsed->mutex);
                    if(ret != 0)
                    {
                        syslog(LOG_ERR, "Could not unlock mutex: %s", strerror(ret));
                    }
                    goto exit_all; 
                }
#endif
                //Perform reads to send the file contents to the socket client
                int to_be_sent = *thread_info_parsed->file_size;
                char buff_read[RECV_BUFF_LEN];
    
                while(to_be_sent)
                {
                    syslog(LOG_INFO, "To be sent is: %d", to_be_sent);
                    int send_bytes = 0;
                    int read_bytes = read(file_fd, buff_read, RECV_BUFF_LEN);
                    if(read_bytes != 0)
                        send_bytes = read_bytes;

                    if(read_bytes == -1)
                    {
                        //If the error is caused by an interruption of the system call try again
                        if(errno == EINTR)
                        {
                            //Free the mutex
                            ret = pthread_mutex_unlock(thread_info_parsed->mutex);
                            if(ret != 0)
                            {
                                syslog(LOG_ERR, "Could not unlock mutex: %s", strerror(ret));
                            }

                            continue;
                        }

                        //Else, error occurred, print it to syslog and finish program
                        syslog(LOG_ERR, "Could not read from the file: %s", strerror(errno));
                        ret = pthread_mutex_unlock(thread_info_parsed->mutex);
                        if(ret != 0)
                        {
                            syslog(LOG_ERR, "Could not unlock mutex: %s", strerror(ret));
                        }
                        goto exit_all; 
                    }

                    //Less bytes remaining
                    to_be_sent -= read_bytes;
                    
                    //Send the contents back to the client
                    int sent_bytes = -1;
                    int send_off = 0;
                    while(sent_bytes != 0)
                    {
                        sent_bytes = send(thread_info_parsed->socket_client, &buff_read[send_off], send_bytes, 0);
                        if(sent_bytes == -1)
                        {
                            //If the error is caused by an interruption of the system call try again
                            if(errno == EINTR)
                            {
                                //Free the mutex
                                ret = pthread_mutex_unlock(thread_info_parsed->mutex);
                                if(ret != 0)
                                {
                                    syslog(LOG_ERR, "Could not unlock mutex: %s", strerror(ret));
                                }
                                continue;
                            }

                            //Else, error occurred, print it to syslog and finish program
                            syslog(LOG_ERR, "Could not read from the file: %s", strerror(errno));
                            ret = pthread_mutex_unlock(thread_info_parsed->mutex);
                            if(ret != 0)
                            {
                                syslog(LOG_ERR, "Could not unlock mutex: %s", strerror(ret));
                            }
                            goto exit_all; 
                        }
                        send_bytes -= sent_bytes;
                        send_off += sent_bytes;
                    }
                    
                }
#ifdef USE_AESD_CHAR_DEVICE
                //Close the file used to log all the data received
                if(close(file_fd) == -1)
                {
                    //Else, error occurred, print it to syslog and finish program
                    syslog(LOG_ERR, "Could not close log file: %s", strerror(errno));
                    exit(1);
                }
#endif
                //Reset index to use the malloc'ed buffer from the beginning
                index = 0;

                //The lock can be freed
                ret = pthread_mutex_unlock(thread_info_parsed->mutex);
                if(ret != 0)
                {
                    syslog(LOG_ERR, "Could not unlock mutex: %s", strerror(ret));
                    goto exit_all; 
                }
            }
            //Realloc the array if it got full without an '\n'
            else if(index == (RECV_BUFF_LEN*chunks))
            {
                chunks++;
                recv_data = realloc(recv_data, sizeof(char)*RECV_BUFF_LEN*chunks);
                if(!recv_data)
                {
                    syslog(LOG_ERR, "Could not realloc: %s", strerror(errno));
                    goto exit_all; 
                }
            }
        }

    } while(recv_ret != 0 && !graceful_exit);

exit_all:
    //Free the used buffer
    free(recv_data);
exit_nofree:
    //Close the client socket if the client did not close it first
    if(recv_ret != 0)
    {
        if(close(thread_info_parsed->socket_client) == -1)
        {
            //Else, error occurred, print it to syslog and finish program
            syslog(LOG_ERR, "Could not close socket: %s", strerror(errno));
            exit(1);
        }
    }
    //Inform the main thread that this thread is finished
    thread_info_parsed->finished = 1;

    print_closed_conn(thread_info_parsed->client_addr);

    return NULL;
}

/**
* socketserver
* @brief Creates a server listening to port 9000
* 
* The server functionality is described in more detail at
* the file header.
*
* @return void
*/
void socketserver(int sck)
{
    //Start listening to addr+port
    if(listen(sck, SERVER_QUEUE) == -1)
    {
        syslog(LOG_ERR, "An error occurred listening the socket: %s", strerror(errno));
        return;        
    }

    syslog(LOG_INFO, "The server is listening to port 9000");

#ifndef USE_AESD_CHAR_DEVICE
    file_fd = open(LOG_PATH, O_CREAT | O_RDWR | O_TRUNC, 0666);
    if(file_fd == -1)
    {
        syslog(LOG_ERR, "Could not create the log file: %s", strerror(errno));
        goto exit_sck;  
    }
    //Create an interval timer to timestamp the file
    struct itimerspec interval_time;
	struct itimerspec last_interval_time;

	//Set up to signal SIGALRM if timer expires
    timer_t timer = 0;
	int ret = timer_create(CLOCK_REALTIME, NULL, &timer);
	if(ret == -1)
    {
        syslog(LOG_ERR, "Could not create timer: %s", strerror(errno));
        goto exit_all; 
    }
		
	struct sigaction action;
    action.sa_handler = sigalrm_handler;
    action.sa_flags = 0;
    sigset_t empty;
    if(sigemptyset(&empty) == -1)
    {
        syslog(LOG_ERR, "Could not set up empty signal set: %s.", strerror(errno));
        goto exit_filesck; 
    }
    action.sa_mask = empty;
    if(sigaction(SIGALRM, &action, NULL) == -1)
    {
        syslog(LOG_ERR, "Could not set up handle for SIGINT: %s.", strerror(errno));
        goto exit_filesck;
    }

	//Arm the interval timer
	interval_time.it_interval.tv_sec = 10;
	interval_time.it_interval.tv_nsec = 0;
	interval_time.it_value.tv_sec = 10;
	interval_time.it_value.tv_nsec = 0;

	ret = timer_settime(timer, 0, &interval_time, &last_interval_time);
	if(ret)
    {
        syslog(LOG_ERR, "Could not create timer: %s", strerror(errno));
        goto exit_filesck; 
    }

    //Initialize Semaphore associated with timestamping
    if(sem_init(&sem_timestamp, 0, 0) == -1)
    {
        syslog(LOG_ERR, "Could not create semaphore: %s", strerror(errno));
        goto exit_filescktm; 
    }

    //Initialize the timestamp handling thread, preventing the use of reentrant functions inside an alarm handler
    pthread_t timestamp_thread;
    ret = pthread_create(&timestamp_thread, NULL, timestamp_handler, NULL);
    if(ret!= 0)
    {            
        syslog(LOG_ERR, "Could not create new thread: %s", strerror(ret));

        //Implementation defined: wait for next request, not terminate server
        goto exit_all; 
    }
#endif
    //Set up the linked list of threads
    SLIST_HEAD(head_s, thread_t) head;
    //Initialize it
    SLIST_INIT(&head);

    //Start a loop of receiving contents  
    while(!graceful_exit)
    {
        struct sockaddr_storage client_addr;
        socklen_t addr_size = sizeof client_addr;

        //Accept a connection
        int connection_fd = accept(sck, (struct sockaddr *) &client_addr, &addr_size);
        if(connection_fd == -1)
        {
            if(errno == EINTR)
            {
                //The signal has set "graceful_exit" and the next while iteration will not happen
                continue;
            }
            else
            {
                syslog(LOG_ERR, "An error occurred accepting a new connection to the socket: %s", strerror(errno));
                //Implementation defined: wait for next request, not terminate server
                continue;
            }
        }

        //Add new service information to a new element of the thread linked list
        struct thread_t *new = malloc(sizeof(struct thread_t));
        new->socket_client = connection_fd;
        new->finished = 0;
        new->socket_server = sck;
        new->file_size = &file_size;
        new->mutex = &mutex;
        memcpy((void *) &new->client_addr, (const void *) &client_addr, sizeof(struct sockaddr_storage));
        
        //Create the thread that will serve the client
        int ret = pthread_create(&new->thread_id, NULL, serve_client, (void *) new);
        if(ret!= 0)
        {            
            syslog(LOG_ERR, "Could not create new thread: %s", strerror(ret));

            //Implementation defined: wait for next request, not terminate server
            continue; 
        }

        //Add the thread information to the linked list
        SLIST_INSERT_HEAD(&head, new, node);

        //Perform cleaning of the current list on every new connection
        struct thread_t *element = NULL;
        struct thread_t *tmp = NULL;
        SLIST_FOREACH_SAFE(element, &head, node, tmp)
        {
            if(element->finished)
            {
                SLIST_REMOVE(&head, element, thread_t, node);
                //Join the thread
                int ret = pthread_join(element->thread_id, NULL);
                if(ret != 0)
                {
                    syslog(LOG_ERR, "Could not join thread: %s", strerror(ret));
                    continue;  
                }
                //Free the memory used by the structure
                free(element);
            }
        }
    }

    //Make sure all threads finish and are joined
    while(!SLIST_EMPTY(&head))
    {
        struct thread_t *element = NULL;
        struct thread_t *tmp = NULL;
        SLIST_FOREACH_SAFE(element, &head, node, tmp)
        {
            if(element->finished)
            {
                SLIST_REMOVE(&head, element, thread_t, node);
                //Join the thread
                int ret = pthread_join(element->thread_id, NULL);
                if(ret != 0)
                {
                    syslog(LOG_ERR, "Could not join thread: %s", strerror(ret));
                    continue;  
                }
                //Free the memory used by the structure
                free(element);
            }
        }
    }
#ifndef USE_AESD_CHAR_DEVICE
    ret = pthread_join(timestamp_thread, NULL);
    if(ret != 0)
    {
        syslog(LOG_ERR, "Could not join thread: %s", strerror(ret));
    }

exit_all:
    if(sem_destroy(&sem_timestamp) == -1)
    {
        syslog(LOG_ERR, "Could not destroy semaphore: %s", strerror(errno));
    }
exit_filescktm:
    ret = timer_delete(timer);
    if(ret == -1)
    {
        syslog(LOG_ERR, "Could not create timer: %s", strerror(errno));
        goto exit_filesck; 
    }
exit_filesck:
    //Close the file used to log all the data received
    if(close(file_fd) == -1)
    {
        //Else, error occurred, print it to syslog and finish program
        syslog(LOG_ERR, "Could not close log file: %s", strerror(errno));
        exit(1);
    }
    //Delete the file
    if(remove(LOG_PATH) == -1)
    {
        //Else, error occurred, print it to syslog and finish program
        syslog(LOG_ERR, "Could not remove log file: %s", strerror(errno));
        exit(1);
    }
exit_sck:
#endif
    //After stopping to accept requests, the socket can be closed
    if(close(sck) == -1)
    {
        //Else, error occurred, print it to syslog and finish program
        syslog(LOG_ERR, "Could not close socket: %s", strerror(errno));
        //Even though error, try to close following files
    }

    return;
}

/**
* main
* @brief Follows the steps described in the file header.
* 
* @param int	number of command arguments
* @param char**	array of arguments; argv[1] is <filename>, and argv[2] is <string>
* @return 0
*/
int main(int c, char **argv)
{

    //Open the log to write to the default "/var/log/syslog" and set the LOG_USER facility
    openlog(NULL, 0, LOG_USER);

    //Set up the signals handler
    struct sigaction action;
    action.sa_handler = signalhandler;
    action.sa_flags = 0;
    sigset_t empty;
    if(sigemptyset(&empty) == -1)
    {
        syslog(LOG_ERR, "Could not set up empty signal set: %s.", strerror(errno));
        exit(1); 
    }
    action.sa_mask = empty;
    if(sigaction(SIGINT, &action, NULL) == -1)
    {
        syslog(LOG_ERR, "Could not set up handle for SIGINT: %s.", strerror(errno));
        exit(1);
    }
    if(sigaction(SIGTERM, &action, NULL) == -1)
    {
        syslog(LOG_ERR, "Could not set up handle for SIGTERM: %s.", strerror(errno));
        exit(1);
    }

    //Socket bind before a potential fork()
    //Build struct with the address related to the socket
    struct addrinfo hints;
    //Needs to be freed after using
    struct addrinfo *res;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;
    if(getaddrinfo(NULL, "9000", &hints, &res) != 0)
    {
        syslog(LOG_ERR, "An error occurred setting up the socket.");
        exit(1);
    }

    //Create the socket file descriptor
    int sck = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if(sck == -1)
    {
        syslog(LOG_ERR, "An error occurred setting up the socket: %s", strerror(errno));
        exit(1);
    }
    //Bind the socket to the addr+port specified in "getaddrinfo"
    if(bind(sck, res->ai_addr, res->ai_addrlen) == -1)
    {
        syslog(LOG_ERR, "An error occurred binding the socket: %s", strerror(errno));
        exit(1);        
    }

    //Free the addr linked list now that we have already used it
    freeaddrinfo(res);

    //Check if -d has been provided
    if(c == 1)
    {
        syslog(LOG_INFO, "Server running in no-daemon mode.");
        //Handle server
        socketserver(sck);

        exit(0);
    }
    else if(c == 1 + 1)
    {
        //The argument must be -d
        if(strcmp(argv[1], "-d") != 0)
        {
            syslog(LOG_ERR, "Invalid number of arguments");
            usage(argv[0]);
            exit(1);
        }

        //Start server as a daemon
        syslog(LOG_INFO, "Server running in daemon mode.");
        int fork_ret = fork();
        if(fork_ret == -1)
        {
            syslog(LOG_ERR, "Unable to perform fork that creates daemon: %s.", strerror(errno));
            exit(1);
        }
        else if(fork_ret == 0)
        {
            //Child process
            //Create new session and process group to prevent Terminal signals mixing with the Daemon
            if(setsid() == -1)
            {
                syslog(LOG_ERR, "Unable to create a new session and process group: %s", strerror(errno));
                exit(1);
            }
            //Set the working directory to the root directory
            if(chdir("/") == -1)
            {
                syslog(LOG_ERR, "Unable to change working directory: %s", strerror(errno));
                exit(1);
            }

            //stdin, stdout and stderr could be redirected but I will not do it 
            //to align to the demonstration from Coursera, where killing the daemon outputs in stdout.

            //Handle server
            socketserver(sck);
            
            exit(0);
        }
        //Exit the parent process to actually make the child process be a daemon
        exit(0);
    }
    else
    {
        syslog(LOG_ERR, "Invalid number of arguments");
        usage(argv[0]);
        exit(1);
    }
    

    return 0;
}
