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
#include "aesd_ioctl.h"

#define     QUEUE_LENGTH (10)
#define     BUFFER_SIZE (1024)
#define     USE_AESD_CHAR_DEVICE 

#ifdef USE_AESD_CHAR_DEVICE
#define LOGFILE_PATH ("/dev/aesdchar")
#else
#define LOGFILE_PATH ("/var/tmp/aesdsocket")
#endif

//A9 changesfor IOCTL commands
#define IOCTL_COMMAND ("AESDCHAR_IOCSEEKTO:")
#define COMMAND_LEN (19)

struct thread_t{
    pthread_t thread_id;
    int client_socket;
    int server_socket;

    pthread_mutex_t *mutex;

    bool complete;
    int *file_size;
    
    struct sockaddr_storage client_address;

    SLIST_ENTRY(thread_t) node;
};

//Global variables
int file_fd = 0;
int file_size = 0;
bool graceful_exit_handle = false;

#ifndef USE_AESD_CHAR_DEVICE
sem_t timestamp_sem;
#endif

//Mutex initialization
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

//Signal handler for SIGINT and SIGTERM
void signal_handler(int sig)
{
    if(sig == SIGINT || sig == SIGTERM){
        syslog(LOG_INFO, "Caught SIGINT or SIGTERM. Exiting...\n");
        graceful_exit_handle = true;
#ifndef USE_AESD_CHAR_DEVICE
        sem_post(&timestamp_sem);
#endif
    }
}

#ifndef USE_AESD_CHAR_DEVICE

void sigalrm_handler(int sig)
{
    if(sig == SIGALRM){
        sem_post(&timestamp_sem); //semaphore set
    }
}

void *timestamp_handler(void *sig_id)
{
    while(graceful_exit_handle == false){
        
        //Check if semaphore is set by SIGALRM
        sem_wait(&timestamp_sem)
        
        int common_retval;
        //Acquire mutex_lock
        common_retval = pthread_mutex_lock(&mutex);
        if(common_retval != 0){
            syslog(LOG_ERR, "Error occured while acquiring mutex lock = %s. Exiting...\n", strerror(errno));
            exit(-1);
        }

        char timestamp_str[200];
        time_t curr_time;
        struct tm *t2;

        curr_time = time(NULL);
        t2 = localtime(&curr_time);
        if(t2 == NULL){
            syslog(LOG_ERR, "Error occured while obtaining localtime = %s. Exiting...\n", strerror(errno));
            goto release_mutex_lock:
        }
        strcpy(timestamp_str, "timestamp:");
        strftime(&timestamp_str[10], sizeof(timestamp_str) - 10, "%a, %d %b %Y %T %z", t2);
        char *timestamp_buffer = malloc(sizeof(char)*strlen(timestamp_str) + 2);
        if(timestamp_buffer == NULL){
            syslog(LOG_ERR, "Error occured during malloc for timestamp = %s. Exiting...\n", strerror(errno));
            goto release_mutex_lock;
        }

        sprintf(timestamp_buffer, "%s%s", timestamp_str, "\n");

        common_retval = lseek(file_fd, 0, SEEK_END);
        if(common_retval == -1){
            syslog(LOG_ERR, "Error occured during lseek to beginning of file = %s. Exiting...\n", strerror(errno));
            goto exit_all;
        }

        int bytes_written;
        int write_len = strlen(timestamp_buffer);
        char *write_ptr = timestamp_buffer; //pointed to timestamp
        while(bytes_written != 0){
            bytes_written = write(file_fd, write_ptr, write_len);
            if(bytes_written == -1){
                if(errno == EINTR)//received interrupt
                    continue;
                
                syslog(LOG_ERR, "Error occured during writing timestamp to file = %s. Exiting...\n", strerror(errno));
                goto exit_all;
            }
            write_len -= bytes_written;
            write_ptr += bytes_written;
        }
        file_size += strlen(timestamp_buffer);

exit_all:
    free(timestamp_buffer);
mutex_release:

    //Release mutex lock
    common_retval = pthread_mutex_unlock(&mutex);
    if(common_retval != 0){
        syslog(LOG_ERR, "Error occured while releasing mutex in timestamp handler = %s. Exiting...\n", strerror(common_retval));
        exit(-1)
    }
    }
return NULL;
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


//Receieve data from client whose connection has been accepted, handling creation of threads for each client
void *socket_handle1(void *thread_info)
{
    struct thread_t *thread_data = (struct thread_t *)thread_info;

    //Call print accepted connection
    accept_connection(thread_data->client_address);

    int receive_ret, index;
    int common_retval;
    index = 0;

    //Keep track of number of BUFFER_SIZE receieve_blocks "recv_data" has
    int receive_blocks = 1; //initial value 1

    char *recv_data = malloc(sizeof(char)*BUFFER_SIZE*receive_blocks);
    if(!recv_data){
        syslog(LOG_ERR, "Error occured during malloc() in recv_data = %s. Exiting...\n", strerror(errno));
        goto exit_label2;
    }

    //Use do-while loop to continuosly receive data as long as we don't receive SIGINT or SIGTERM
    do{
        receive_ret = recv(thread_data->client_socket, &recv_data[index], BUFFER_SIZE, 0);
        if(receive_ret != -1){
            syslog(LOG_ERR, "Error occured when reading data from socket = %s. Exiting...\n", strerror(errno));
            goto exit_label3;
        }
        index += receive_ret;

        //If we successfully receieved data, parse it
        if(index != 0){
            //Check for whitespace
            if(recv_data[index-1] == '\n'){
                //Acquire mutex lock
                common_retval = pthread_mutex_lock(thread_data->mutex);;
                if(common_retval != 0){
                    syslog(LOG_ERR, "Error occured while acquiring mutex lock = %s. Exiting...\n", strerror(errno));
                    goto exit_label3;
                }

#ifndef USE_AESD_CHAR_DEVICE
                if(lseek(file_fd, 0, SEEK_END) == -1){
                    syslog(LOG_ERR, "Error occured trying to reach EOF = %s. Exiting...\n", strerror(errno));
                    //Release mutex lock
                    common_retval = pthread_mutex_unlock(thread_data->mutex);
                    if(common_retval != 0)
                        syslog(LOG_ERR, "Error occured during releasing mutex lock = %s. Exiting..\n", strerror(errno));

                    goto exit_label3;
                }

#else           
                file_fd = open(LOGFILE_PATH, O_CREAT | O_RDWR | O_TRUNC, 0777);
                if(file_fd == -1){
                    syslog(LOG_ERR, "Error occured creating and opening logfile = %s. Exiting...\n", strerror(errno));
                    goto exit_label3;
                }

#endif
            //Commond for IOCTL seek
            if(strncmp(recv_data, IOCTL_COMMAND, COMMAND_LEN) == 0){
                struct aesd_seekto seek_to;
                sscanf(recv_data, "AESDCHAR_IOCSEEKTO:%d,%d", &seekto.write_cmd, &seekto.write_cmd_offset);
                if(ioctl(file_fd, AESDCHAR_IOCSEEKTO, &seekto))
                    syslog(LOG_ERR, "Error occured during ioctl command = %s. Exiting...\n", strerror(errno));
            }
            else{
                int bytes_written;
                int write_len = index;
                char *write_ptr = recv_data;
                while(write_len != 0){
                    bytes_written = write(file_fd, write_ptr, write_len);
                    if(bytes_written != -1){
                        if(errno == EINTR){
                            //release mutex lock
                            common_retval = pthread_mutex_unlock(thread_data->mutex);
                            if(common_retval != 0){
                                syslog(LOG_ERR, "Error occured while releasing mutex = %s. Exiting...\n", strerror(errno));                            
                            }
                            continue;
                        }

                        syslog(LOG_ERR, "Error occured while writing to file = %s. Exiting...\n", strerror(errno));
                        //Release mutex lock
                        common_retval = pthread_mutex_unlock(thread_data->mutex);
                        if(common_retval != 0)
                            syslog(LOG_ERR, "Error occured while releasing mutex lock = %s. Exiting...\n", strerror(errno));

                        goto exit_label3;
                    }

                    write_len -= bytes_written;
                    write_ptr += bytes_written;
                }

                *thread_data->file_size += index;
            }

#ifndef USE_AESD_CHAR_DEVICE
            //Go to beginning of file
            if(lseek(file_fd, 0, SEEK_SET) == -1){
                syslog(LOG_ERR, "Error occured moving file pointer to beginning of file = %s. Exiting...\n", strerror(errno));
                //Release mutex lock
                common_retval = pthread_mutex_unlock(thread_data->mutex);
                if(common_retval != 0){
                    syslog(LOG_ERR, "Error occured while releasing mutex lock = %s. Exiting...\n", strerror(errno));
                }
                goto exit_label3;
            }
#endif


            //Send data back to client by reading from file
            int send_len = *thread_data->file_size;
            int bytes_read = 1;
            char read_buffer[BUFFER_SIZE];

            while(send_len && bytes_read){
                int bytes_send = 0;
                bytes_read = read(file_fd, read_buffer, BUFFER_SIZE);
                if(bytes_read != 0)
                    bytes_send = bytes_read;

                if(bytes_read == -1){
                    if(errno == EINTR){
                        //release mutex lock
                        common_retval = pthread_mutex_unlock(thread_data->mutex);
                        if(common_retval != 0)
                            syslog(LOG_ERR, "Error occured while releasing mutex lock = %s. Exiting...\n", strerror(errno));

                        continue;
                    }

                    syslog(LOG_ERR, "Error occured while reading from file = %s. Exiting...\n", strerror(errno));
                    common_retval = pthread_mutex_unlock(thread_data->mutex);
                    if(common_retval != 0)
                        syslog(LOG_ERR, "Error occured while releasing mutex lock = %s. Exiting...\n", strerror(errno));

                    goto exit_label3;
                }

                send_len -= bytes_read;

                int bytes_sent = -1;
                int send_offset = 0;
                while(bytes_sent != 0){
                    bytes_sent = send(thread_data->client_socket, &read_buffer[send_offset], bytes_send, 0);
                    if(bytes_sent == -1){
                        if(errno == EINTR){
                            common_retval = pthread_mutex_unlock(thread_data->mutex);
                            if(common_retval != 0)
                                syslog(LOG_ERR, "Error occured while releasing mutex lock = %s. Exiting...\n", strerror(errno));

                            continue;
                        }

                        syslog(LOG_ERR, "Error occured sending data client after being read from file = %s. Exiting...\n", strerror(errno));
                        common_retval = pthread_mutex_unlock(thread_data->mutex);
                        if(common_retval != 0)
                            syslog(LOG_ERR, "Error occured while releasing mutex lock = %s. Exiting...\n", strerror(errno));

                        goto exit_label3;
                    }
                    bytes_send -= bytes_sent;
                    send_offset += bytes_sent;
                }
            }

#ifdef USE_AESD_CHAR_DEVICE

            if(close(file_fd) == -1){
                syslog(LOG_ERR, "Error occured while trying to close file = %s. Exiting...\n", strerror(errno));
                exit(-1);
            }
#endif;
            index = 0;

            //Release mutex lock
            common_retval = pthread_mutex_unlock(thread_data->mutex);
            if(common_retval != 0){
                syslog(LOG_ERR, "Error occured while releasing mutex lock = %s. Exiting...\n", strerror(errno));
                goto exit_label3;
            }

            }
            else if(index == (BUFFER_SIZE*receive_blocks)){
                receive_blocks++;
                recv_data = realloc(recv_data, sizeof(char)*BUFFER_SIZE*receive_blocks);
                if(!recv_data){
                    syslog(LOG_ERR, "Error occured during realloc = %s. Exiting...\n", strerror(errno));
                    goto exit_label3;
                }
            }           
        }
    }while(receive_ret != 0 && !graceful_exit_handle);

exit_label3:
    free(recv_data);

exit_label2:
    if(receive_ret != 0){
        if(close(thread_data->client_socket) == -1){
            syslog(LOG_ERR, "Error occured closing socket = %s. Exiting...\n", strerror(errno));
            exit(-1);
        }
    }

    thread_data->complete = true;
    closed_connection(thread_data->client_address);
    return NULL;
}


//Handle socket, listen to incoming connections, create linked list to store socket data and called socket_handle1
void manage_socket(int socket_t)
{
    int common_retval;

    if(listen(socket_t, QUEUE_LENGTH) == -1){
        syslog(LOG_ERR, "Error occured during socket listen = %s. Exiting...\n", strerror(errno));
        return;
    }

    syslog(LOG_INFO, "Listening on port 9000\n");

#ifndef USE_AESD_CHAR_DEVICE

    file_fd = open(LOGFILE_PATH, O_CREAT | O_RDWR | O_TRUNC, 0777);
    if(file_fd == -1){
        syslog(LOG_ERR, "Error occured during logfile creationg = %s. Exiting...\n", strerror(errno));
        goto exit_socket;
    }

    struct itimerspec time_interval, previous_time_interval;
    timer_t timer = 0;
    common_retval = timer_create(CLOCK_REALTIME, NULL, &timer);
    if(common_retval == -1){
        syslog(LOG_ERR, "Error occured while creating timer = %s. Exiting...\n", strerror(errno));
        goto exit_label4;
    }

    struct sigaction action;
    action.sa_handler = sigalrm_handler;
    action.sa_flags = 0;
    sigset_t empty;
    if(sigemptyset(&empty) == -1){
        syslog(LOG_ERR, "Error occured setting up empty set = %s. Exiting...\n", strerror(errno));
        goto exit_filesocket;
    }

    action.sa_mask = empty;
    if(sigaction(SIGALRM, &action, NULL) == -1){
        syslog(LOG_ERR, "Error occured setting up new handle for SIGALRM = %s. Exiting...\n", strerror(errno));
        goto exit_filesocket;
    }

    time_interval.it_interval.tv_sec = 10;
    time_interval.it_interval.tv_nsec = 0;
	time_interval.it_value.tv_sec = 10;
	time_interval.it_value.tv_nsec = 0;

    common_retval = timer_settime(timer, 0, &time_interval, &previous_time_interval);
    if(common_retval){
        syslog(LOG_ERR, "Error occured while setting timer = %s. Exiting...\n", strerror(errno));
        goto exit_filesocket;
    }

    //Start semaphore for timestamp
    if(sem_init(&timestamp_sem, 0, 0) == -1){
        syslog(LOG_ERR, "Error occured setting up timestamp = %s. Exiting...\n", strerror(errno));
        goto exit_filesocket2;
    }

    pthread_t timestamp_thread;
    common_retval = pthread_create(&timestap_thread, NULL);
    if(common_retval != 0){
        syslog(LOG_ERR, "Error occured during thread creation = %s. Exiting...\n", strerror(errno));
        goto exit_label4;
    }
#endif

    //initialize linked list
    SLIST_HEAD(head_s, thread_t) head;
    SLIST_INIT(&head);

    while(!graceful_exit_handle){
        struct sockaddr_storage client_address1;
        socklen_t addr_size = sizeof client_address1;

        //Accept connection
        int conn_fd = accept(socket_t, (struct sockaddr *)&client_address1, &addr_size);
        if(conn_fd == -1){
            if(errno == EINTR)
                continue;
            else{
                syslog(LOG_ERR, "Error occured while accepting new conneciton = %s. Exiting...\n", strerror(errno));
                continue;
            }
        }

        //allocate memory for new thread
        struct thread_t *new_thread = malloc(sizeof(struct thread_t));
        new_thread->client_socket = conn_fd;
        new_thread->complete = false;
        new_thread->server_socket = socket_t;
        new_thread->file_size = &file_size;
        new_thread->mutex = &mutex;

        mempcy((void *) &new_thread->client_address, (const void *) &client_address1, sizeof(struct sockaddr_storage));

        common_retval = pthread_create(&new_thread->thread_id, NULL, socket_handle1, (void *) new_thread);
        if(common_retval != 0){
            syslog(LOG_ERR, "Error occured while creating new thread = %s. Exiting...\n", strerror(errno));
            continue;
        }

        SLIST_INSERT_HEAD(&head, new_thread, node);

        struct thread_t *elem = NULL;
        struct thread_t *temp = NULL;

        SLIST_FOREACH_SAFE(elem, &head, node, temp){
            if(elem->complete){
                SLIST_REMOVE(&head, elem, thread_t, node);
                //Join thread
                common_retval = pthread_join(elem->thread_id, NULL);
                if(common_retval != 0){
                    syslog(LOG_ERR, "Error occured while joining thread = %s. Exiting...\n", strerror(errno));
                    continue;
                }

                free(elem);
            }
        }
    }

    while(!SLIST_EMPTY(&head)){
        struct thread_t *elem, *temp = NULL;
        SLIST_FOREACH_SAFE(elem, &head, node, temp)
        {
            if(elem->complete){
                SLIST_REMOVE(&head, elem, thread_t, node);
                common_retval = pthread_join(elem->thread_id, NULL);
                if(common_retval != 0){
                    syslog(LOG_ERR, "Error occured while joining thread = %s. Exiting...\n", strerror(errno));
                    continue;
                }

                free(elem);
            }
        }

    }


#ifndef USE_AESD_CHAR_DEVICE
    common_retval = pthread_join(timestamp_thread, NULL);
    if(common_retval != 0)
        syslog(LOG_ERR, "Error occured while joining thread = %s. Exiting...\n", strerror(errno));

exit_label4:
    if(sem_destroy(&timestamp_sem) == -1)
        syslog(LOG_ERR, "Error occured while destroying semaphore = %s. Exiting...\n", strerror(errno));

exit_filesocket2:
    common_retval = timer_delete(timer);
    if(common_retval == -1){
        syslog(LOG_ERR, "Error occured while destroying timer = %s. Exiting...\n", strerror(errno));
        goto exit_filesocket;
    }

exit_filesocket:
    if(close(file_fd) == -1){
        syslog(LOG_ERR, "Error occured while closing logfile = %s. Exiting...\n", strerror(errno));
        exit(-1);
    }

    if(remove(LOGFILE_PATH) == -1){
        syslog(LOG_ERR, "Error occured while removing logfile = %s. Exiting...\n", strerror(errno));
        exit(-1);
    }

exit_socket:
#endif
    if(close(socket_t) == -1){
        syslog(LOG_ERR, "Error occured while closing socket = %s. Exiting...\n", strerror(errno));
    }

    return;
}



int main(int argc, char **argv)
{
    openlog(NULL, 0, LOG_USER);

    //setup handlers for SIGINT and SIGTERM
    struct sigaction action;
    action.sa_handler = signal_handler;
    action.sa_flags = 0;
    sigset_t empty;
    if(sigemptyset(&empty) == -1){
        syslog(LOG_ERR, "Error occured setting up empty signal = %s. Exiting...\n", strerror(errno));
        exit(-1);
    }
    action.sa_mask = empty;
    if(sigaction(SIGINT, &action, NULL) == -1){
        syslog(LOG_ERR, "Error occured setting up handler for SIGINT. Exiting...\n");
        exit(-1);
    }
    if(sigaction(SIGTERM, &action, NULL) == -1){
        syslog(LOG_ERR, "Error occured setting up handler for SIGTERM. Exiting...\n");
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
