/*Assignment 6 aesdsocket implementation*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <syslog.h>
#include "queue.h"
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <semaphore.h>

#define     QUEUE_LENGTH    (10)
#define     BUFFER_SIZE   (1024)
#define     USE_AESD_CHAR_DEVICE

#ifdef USE_AESD_CHAR_DEVICE
#define LOGFILE_PATH ("/dev/aesdchar")
#else
#define     LOGFILE_PATH  ("/var/tmp/aesdsocketdata")
#endif




struct thread_t
{
    pthread_t thread_id;
    int client_socket_t;
    int server_socket_t;
    int logfile_fd;
    pthread_mutex_t *mutex;
    bool complete;
    int *file_size;
    struct sockaddr_storage client_address;

    //singly linked list node 
    SLIST_ENTRY(thread_t) node;
};

//Global variables
bool graceful_exit_handle = false;
int file_fd = 0;
int file_size = 0;

//Mutex initialization
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

#ifdef USE_AESD_CHAR_DEVICE
sem_t timestamp_semaphore;
#endif


//Signal handler for SIGINT and SIGTERM
void signal_handler(int sig)
{
    if(sig == SIGINT || sig == SIGTERM)
    {
       syslog(LOG_INFO, "Caught SIGINT or SIGTERM. Exiting...");    
       graceful_exit_handle = true;
       
#ifdef USE_AESD_CHAR_DEVICE
	sem_post(&sem_timestamp);
#endif
 
    }
}


#ifdef USE_AESD_CHAR_DEVICE

//Handles printing timestamp every 10 seconds
void timestamp_handler(int sig_id)
{
    if(sig_id == SIGALRM)
    {
    	sem_wait(&sem_timestamp);
        //printing timestamp after 10 seconds, when SIGALRM is raised
        int unlock_ret = pthread_mutex_lock(&mutex);
        if(unlock_ret != 0){
            syslog(LOG_ERR, "Error occured during mutex lock = %s. Exiting...", strerror(errno));
            exit(-1);  
        }

        //Get the timestamp
        char timestamp[256];
        time_t curr_time;
        struct tm *t2;

        curr_time = time(NULL);
        t2 = localtime(&curr_time);
        if (t2 == NULL){
            syslog(LOG_ERR, "Error occured during localtime(). Exiting...");
            goto mutex_release; 
        }
        strcpy(timestamp, "timestamp:");
        strftime(&timestamp[10], sizeof(timestamp) - 10, "%a, %d %b %Y %T %z", t2);
        char *timestamp_buffer = malloc(sizeof(char) * strlen(timestamp) + 2);
        if(!timestamp_buffer){
            syslog(LOG_ERR, "Error occured during malloc() for timestamp = %s. Exiting...", strerror(errno));
            goto mutex_release; 
        }
        sprintf(timestamp_buffer, "%s%s", timestamp, "\n");

        if(lseek(file_fd, 0, SEEK_END) == -1){
            syslog(LOG_ERR, "Error occured during lseek() to EOF = %s. Exiting...", strerror(errno));
            goto exit_label1; 
        }
        
        int written_bytes;
        int len_to_write = strlen(timestamp_buffer);
        char *ptr_to_write = timestamp_buffer;
        while(len_to_write != 0){
            written_bytes = write(file_fd, ptr_to_write, len_to_write);
            if(written_bytes == -1){
                if(errno == EINTR)
                    continue;

                syslog(LOG_ERR, "Error occured during write() = %s. Exiting...", strerror(errno));
                goto exit_label1; 
            }
            len_to_write -= written_bytes;
            ptr_to_write += written_bytes; 
        }

        file_size += strlen(timestamp_buffer);

exit_label1:
        free(timestamp_buffer);
mutex_release:
        unlock_ret = pthread_mutex_unlock(&mutex);
        if(unlock_ret != 0){
            syslog(LOG_ERR, "Error occured during mutex lock release = %s. Exiting...", strerror(errno));
            exit(-1); 
        }
    }
}

#endif

//Print IP address of client whose connection is accepted
void accept_connection(struct sockaddr_storage client_address)
{
    if(client_address.ss_family == AF_INET){
        char addr[INET6_ADDRSTRLEN];
        struct sockaddr_in *addr_in = (struct sockaddr_in *)&client_address;
        inet_ntop(AF_INET, &(addr_in->sin_addr), addr, INET_ADDRSTRLEN);
        syslog(LOG_INFO, "Accepted connection from %s", addr);
    }
    else if(client_address.ss_family == AF_INET6){
        char addr[INET6_ADDRSTRLEN];
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&client_address;
        inet_ntop(AF_INET6, &(addr_in6->sin6_addr), addr, INET6_ADDRSTRLEN);
        syslog(LOG_INFO, "Accepted connection from %s", addr);
    }
}

//Print IP address of client whose connection is closed
void closed_connection(struct sockaddr_storage client_address)
{
    if(client_address.ss_family == AF_INET){
        char addr[INET6_ADDRSTRLEN];
        struct sockaddr_in *addr_in = (struct sockaddr_in *)&client_address;
        inet_ntop(AF_INET, &(addr_in->sin_addr), addr, INET_ADDRSTRLEN);
        syslog(LOG_INFO, "Closed connection from %s", addr);
    }
    else if(client_address.ss_family == AF_INET6){
        char addr[INET6_ADDRSTRLEN];
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&client_address;
        inet_ntop(AF_INET6, &(addr_in6->sin6_addr), addr, INET6_ADDRSTRLEN);
        syslog(LOG_INFO, "Closed connection from %s", addr);
    }
}

//Handle a client that we accepeted from a socket connection
void *socket_handle1(void *thread_info)
{
    struct thread_t *thread_data = (struct thread_t *) thread_info;

    //Print IP
    accept_connection(thread_data->client_address);

    int recv_ret;
    int index = 0;
    //Keep track of number of BUFFER_SIZE receive_blocks "recv_data" has
    int receive_blocks = 1;
    
    char *recv_data = malloc(sizeof(char)*BUFFER_SIZE*receive_blocks);
    if(!recv_data){
        syslog(LOG_ERR, "Error occured during malloc() in recv = %s. Exiting...", strerror(errno));
        goto exit_label2; 
    }

    //Receive data from client and store in file continuously till EOP is received
    do{
        recv_ret = recv(thread_data->client_socket_t, &recv_data[index], BUFFER_SIZE, 0);
        if(recv_ret == -1){
            syslog(LOG_ERR, "Error occured during recv() while reading from socket = %s. Exiting...", strerror(errno));
            goto exit_label3;  
        }
        index += recv_ret;

        if(index != 0){
            //Check if EOP "\n" is received
            if(recv_data[index - 1] == '\n'){
                //Lock mutex for writing into file
                int lock_ret = pthread_mutex_lock(thread_data->mutex);
                if(lock_ret != 0){
                    syslog(LOG_ERR, "Error occured during mutex lock = %s. Exiting...", strerror(errno));
                    goto exit_label3;  
                }

                //Write to logfile         
                if(lseek(thread_data->logfile_fd, 0, SEEK_END) == -1){
                    syslog(LOG_ERR, "Error occured during lseek() to EOF = %s. Exiting...", strerror(errno));
                    int unlock_ret = pthread_mutex_unlock(thread_data->mutex);
                    if(unlock_ret != 0){
                        syslog(LOG_ERR, "Error occured during mutex lock release = %s. Exiting...", strerror(errno));
                    }
                    goto exit_label3;  
                }

                int written_bytes;
                int len_to_write = index;
                char *ptr_to_write = recv_data;
                while(len_to_write != 0){
                    written_bytes = write(thread_data->logfile_fd, ptr_to_write, len_to_write);
                    if(written_bytes == -1){
                        if(errno == EINTR){ //User gave Ctrl+C
                            int unlock_ret = pthread_mutex_unlock(thread_data->mutex);
                            if(unlock_ret != 0){
                                syslog(LOG_ERR, "Error occured during mutex lock release in write() = %s. Exiting...", strerror(errno));
                            }
                            continue;
                        }

                        syslog(LOG_ERR, "Error occured during write() = %s. Exiting...", strerror(errno));
                        int unlock_ret = pthread_mutex_unlock(thread_data->mutex);
                        if(unlock_ret != 0){
                            syslog(LOG_ERR, "Error occured during mutex lock release in write() = %s. Exiting...", strerror(errno));
                        }
                        goto exit_label3; 
                    }
                    len_to_write -= written_bytes;
                    ptr_to_write += written_bytes; 
                }

                *thread_data->file_size = *thread_data->file_size + index;

                //Send all the contents from logfile to client
                if(lseek(thread_data->logfile_fd, 0, SEEK_SET) == -1){
                    syslog(LOG_ERR, "Error occured during lseek() to start of file = %s. Exiting...", strerror(errno));
                    int unlock_ret = pthread_mutex_unlock(thread_data->mutex);
                    if(unlock_ret != 0){
                        syslog(LOG_ERR, "Error occured during mutex lock release in lseek() to start of file = %s. Exiting...", strerror(errno));
                    }
                    goto exit_label3; 
                }
                
                //Send data back to client 
                int to_be_sent = *thread_data->file_size;
                char buff_read[BUFFER_SIZE];
    
                while(to_be_sent){
                    int send_bytes = 0;
                    int read_bytes = read(thread_data->logfile_fd, buff_read, BUFFER_SIZE);
                    if(read_bytes != 0)
                        send_bytes = read_bytes;

                    if(read_bytes == -1){
                        if(errno == EINTR){
                            int unlock_ret = pthread_mutex_unlock(thread_data->mutex);
                            if(unlock_ret != 0){
                                syslog(LOG_ERR, "Error occured during mutex lock release in read() = %s. Exiting...", strerror(errno));
                            }
                            continue;
                        }

                        syslog(LOG_ERR, "Error occured during read() = %s. Exiting...", strerror(errno));
                        int unlock_ret = pthread_mutex_unlock(thread_data->mutex);
                        if(unlock_ret != 0){
                            syslog(LOG_ERR, "Error occured during mutex lock release after read() = %s. Exiting...", strerror(errno));
                        }
                        goto exit_label3; 
                    }
                    to_be_sent -= read_bytes;
                    
                    int sent_bytes = -1;
                    int send_off = 0;
                    while(sent_bytes != 0){
                        sent_bytes = send(thread_data->client_socket_t, &buff_read[send_off], send_bytes, 0);
                        if(sent_bytes == -1){
                            if(errno == EINTR){
                                int unlock_ret = pthread_mutex_unlock(thread_data->mutex);
                                if(unlock_ret != 0){
                                    syslog(LOG_ERR, "Error occured during mutex lock release in send() = %s. Exiting...", strerror(errno));
                                }
                                continue;
                            }

                            syslog(LOG_ERR, "Error occured during send() = %s. Exiting...", strerror(errno));
                            int unlock_ret = pthread_mutex_unlock(thread_data->mutex);
                            if(unlock_ret != 0){
                                syslog(LOG_ERR, "Error occured during mutex lock release after send() = %s. Exiting...", strerror(errno));
                            }
                            goto exit_label3; 
                        }
                        send_bytes -= sent_bytes;
                        send_off += sent_bytes;
                    }                    
                }

                //Reset index 
                index = 0;
                //Free mutex
                int unlock_ret = pthread_mutex_unlock(thread_data->mutex);
                if(unlock_ret != 0){
                    syslog(LOG_ERR, "Error occured during mutex lock release = %s. Exiting...", strerror(errno));
                    goto exit_label3; 
                }
            }
            else if(index == (BUFFER_SIZE*receive_blocks)){
                receive_blocks++;
                recv_data = realloc(recv_data, sizeof(char)*BUFFER_SIZE*receive_blocks);
                if(!recv_data){
                    syslog(LOG_ERR, "Error occured during realloc() = %s. Exiting...", strerror(errno));
                    goto exit_label3; 
                }
            }
        }

    } while(recv_ret != 0 && !graceful_exit_handle); //Handle received data until we recieve Ctrl+C from user or EOP

exit_label3:
    free(recv_data);
exit_label2:
    if(recv_ret != 0){
        if(close(thread_data->client_socket_t) == -1){
            syslog(LOG_ERR, "Error occured during socket close = %s. Exiting...", strerror(errno));
            exit(-1);
        }
    }
    thread_data->complete = true;
    closed_connection(thread_data->client_address);
    return NULL;
}


/*Listen on socket, set itimer to 10 seconds for printing timestamp, and create linked list to store 
socket data from different threads
*/
void manage_socket(int socket_t)
{
    if(listen(socket_t, QUEUE_LENGTH) == -1){
        syslog(LOG_ERR, "Error occured during socket listen = %s. Exiting...", strerror(errno));
        return;        
    }

    syslog(LOG_INFO, "Listening on port 9000");

    file_fd = open(LOGFILE_PATH, O_CREAT | O_RDWR | O_TRUNC, 0666);
    if(file_fd == -1){
        syslog(LOG_ERR, "Error occured during logfile create = %s. Exiting...", strerror(errno));
        goto exit_socket_t;  
    }

#ifdef USE_AESD_CHAR_DEVICE
    //Create an interval timer for timestamp generation
    struct itimerspec interval_10sec;
	struct itimerspec previous_interval_time;

    timer_t timer = 0;
	int timer_ret = timer_create(CLOCK_REALTIME, NULL, &timer);
	if(timer_ret == -1){
        syslog(LOG_ERR, "Error occured during timer create() = %s. Exiting...", strerror(errno));
        goto exit_label4; 
    }
		
	struct sigaction action;
    action.sa_handler = timestamp_handler;
    action.sa_flags = 0;
    sigset_t empty;
    if(sigemptyset(&empty) == -1){
        syslog(LOG_ERR, "Error occured during setting empty signal = %s. Exiting...", strerror(errno));
        goto exit_filesocket_t; 
    }
    action.sa_mask = empty;

    //Set handler for SIGALRM
    if(sigaction(SIGALRM, &action, NULL) == -1){
        syslog(LOG_ERR, "Error occured during setting handler to SIGALRM = %s. Exiting...", strerror(errno));
        goto exit_filesocket_t;
    }

	//Arm timer
	interval_10sec.it_interval.tv_sec = 10;
	interval_10sec.it_interval.tv_nsec = 0;
	interval_10sec.it_value.tv_sec = 10;
	interval_10sec.it_value.tv_nsec = 0;

	int settime_ret = timer_settime(timer, 0, &interval_10sec, &previous_interval_time);
	if(settime_ret){
        syslog(LOG_ERR, "Error occured in timer_settime() = %s. Exiting...", strerror(errno));
        goto exit_filesocket_t; 
    }
#endif

    //singly linked list setup
    SLIST_HEAD(head_s, thread_t) head;
    SLIST_INIT(&head);

    while(!graceful_exit_handle){
        struct sockaddr_storage client_address;
        socklen_t addr_size = sizeof client_address;

        //conn accept
        int conn_fd = accept(socket_t, (struct sockaddr *) &client_address, &addr_size);
        if(conn_fd == -1){
            if(errno == EINTR){
                continue;
            }
            else{
                syslog(LOG_ERR, "Error occured during accept() = %s. Exiting...", strerror(errno));
                continue;
            }
        }

        struct thread_t *new_thread = malloc(sizeof(struct thread_t));
        new_thread->client_socket_t = conn_fd;
        new_thread->complete = 0;
        new_thread->server_socket_t = socket_t;
        new_thread->logfile_fd = file_fd;
        new_thread->file_size = &file_size;
        new_thread->mutex = &mutex;
        memcpy((void *)&new_thread->client_address, (const void *)&client_address, sizeof(struct sockaddr_storage));
        
        int thread_create_ret = pthread_create(&new_thread->thread_id, NULL, socket_handle1, (void *) new_thread);
        if(thread_create_ret!= 0){            
            syslog(LOG_ERR, "Error occured creating new thread = %s. Exiting...", strerror(errno));
            continue; 
        }
        //Add the thread data to singly linked list
        SLIST_INSERT_HEAD(&head, new_thread, node);
    }

    while(!SLIST_EMPTY(&head)){
        struct thread_t *elem = NULL;
        struct thread_t *tmp = NULL;
        SLIST_FOREACH_SAFE(elem, &head, node, tmp)
        {
            if(elem->complete){
                SLIST_REMOVE(&head, elem, thread_t, node);
                //join thread
                int thread_join_ret = pthread_join(elem->thread_id, NULL);
                if(thread_join_ret != 0){
                    syslog(LOG_ERR, "Error occured during thread join = %s. Exiting...", strerror(errno));
                    continue;  
                }
                free(elem);
            }
        }
    }

exit_label4:
    if(timer_delete(timer) == -1){
        syslog(LOG_ERR, "Error occured during deleting timer = %s. Exiting...", strerror(errno));
        goto exit_filesocket_t; 
    }

exit_filesocket_t:
    if(close(file_fd) == -1){
        syslog(LOG_ERR, "Error occured during file close = %s. Exiting...", strerror(errno));
        exit(-1);
    }
    if(remove(LOGFILE_PATH) == -1){
        syslog(LOG_ERR, "Error occured deleting logfile = %s. Exiting...", strerror(errno));
        exit(-1);
    }
exit_socket_t:
    if(close(socket_t) == -1){
        syslog(LOG_ERR, "Error occured during socket close = %s. Exiting...", strerror(errno));
    }

    return;
}



//Main routine, receives user input for daemon mode or normal mode
int main(int argc, char **argv)
{

    //Initialze system logging facility under LOG_USER
    openlog(NULL, 0, LOG_USER);

    //Set up the signals handler
    struct sigaction action;
    action.sa_handler = signal_handler;
    action.sa_flags = 0;
    sigset_t empty;
    if(sigemptyset(&empty) == -1){
        syslog(LOG_ERR, "Error occured setting empty signal %s.", strerror(errno));
        exit(-1); 
    }
    action.sa_mask = empty;

    //Set handler for SIGINT
    if(sigaction(SIGINT, &action, NULL) == -1){
        syslog(LOG_ERR, "Error occured setting up handler for SIGINT = %s. Exiting...", strerror(errno));
        exit(-1);
    }

    //Set handler for SIGTERM
    if(sigaction(SIGTERM, &action, NULL) == -1){
        syslog(LOG_ERR, "Error occured setting up handler for SIGTERM = %s. Exiting...", strerror(errno));
        exit(-1);
    }

    //bind socket to port and address
    struct addrinfo hints;
    struct addrinfo *res;

    //clear hints structure before passing to getaddrinfo
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;
    if(getaddrinfo(NULL, "9000", &hints, &res) != 0){
        syslog(LOG_ERR, "Error occured during socket setup. Exiting...");
        exit(-1);
    }

    //socket create
    int socket_t = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if(socket_t == -1){
        syslog(LOG_ERR, "Error occured during socket create = %s. Exiting...", strerror(errno));
        exit(-1);
    }
    //bind socket
    if(bind(socket_t, res->ai_addr, res->ai_addrlen) == -1){
        syslog(LOG_ERR, "Error occured during socket bind = %s. Exiting...", strerror(errno));
        exit(-1);        
    }

    freeaddrinfo(res);

    //Daemon process creation
    if(argc == 1){
        syslog(LOG_INFO, "Server running in no-daemon mode.");
        manage_socket(socket_t);
        exit(0);
    }
    else if(argc == 2){
        //Check if argument provided is -d
        if(strcmp(argv[1], "-d") != 0){
            syslog(LOG_ERR, "Incorrect argument. Exiting...");
            syslog(LOG_ERR, "Call application in aesdsocket -d for daemon mode.");
            exit(-1);
        }

        //Start server as a daemon
        syslog(LOG_INFO, "Server running as daemon.");

        //Daemon creation
        int fork_ret = fork();
        if(fork_ret == -1){
            syslog(LOG_ERR, "Error occured during fork() = %s. Exiting...", strerror(errno));
            exit(-1);
        }
        else if(fork_ret == 0){
            //In child
            if(setsid() == -1){
                syslog(LOG_ERR, "Error occured during setsid() = %s. Exiting...", strerror(errno));
                exit(-1);
            }
            //Set the working directory to root
            if(chdir("/") == -1){
                syslog(LOG_ERR, "Error occured during chdir to root = %s. Exiting...", strerror(errno));
                exit(-1);
            }

            //redirect stdout
            dup(0);

            //Call socket manager
            manage_socket(socket_t);            
            exit(0);
        }
        //exit parent to complete daemon creation
        exit(0);
    }
    else
    {
        syslog(LOG_ERR, "Incorrect arguments. Exiting...");
        syslog(LOG_ERR, "Call application as aesdsocket for NORMAL mode, and aesdsocket -d for DAEMON mode");
        exit(-1);
    } 

    return 0;
}


