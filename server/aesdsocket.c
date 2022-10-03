/**
* @file aesdsocket.c
* @brief Creates a server on port 9000
*
* Sets up a server on port 9000 and accepts any connection.
* The contents obtained are appended in /var/tmp/aesdsocketdata
* Once the client ends the connection, the full content of the file is returned to it
* Logs acceptance and closure of connections
* Accepts new clients until SIGINT or SIGTERM signals are received
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

//Defines
#define     SERVER_QUEUE    (10)
#define     LOG_PATH        ("/var/tmp/aesdsocketdata")
#define     RECV_BUFF_LEN   (1024)

//Globals
int graceful_exit = 0;

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
    }
}

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
* exit_wrapper
* @brief Closes socket and used files before exiting
* 
* @param int    socket fd
* @param int    log fd+
* @return void
*/
void exit_wrapper(int sck, int file_fd)
{
    //After stopping to accept requests, the socket can be closed
    if(close(sck) == -1)
    {
        //Else, error occurred, print it to syslog and finish program
        syslog(LOG_ERR, "Could not close socket: %s", strerror(errno));
        exit(1);
    }
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
        exit(1);        
    }

    syslog(LOG_INFO, "The server is listening to port 9000");

    //Create the file that will log the messages received
    int file_fd = open(LOG_PATH, O_CREAT | O_RDWR | O_TRUNC, 0666);
    if(file_fd == -1)
    {
        syslog(LOG_ERR, "Could not create the log file: %s", strerror(errno));
        exit(1);  
    }

    //Start a loop of receiving contents
    int file_size = 0;
    char *recv_data = NULL;

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
                break;
            }
            else
            {
                syslog(LOG_ERR, "An error occurred accepting a new connection to the socket: %s", strerror(errno));
                exit(1);
            }
        }

        print_accepted_conn(client_addr);

        //Wait for data
        int recv_ret;
        int index = 0;
        //Keep track of how many RECV_BUFF_LEN chunks "recv_data" has
        int chunks = 1;
        
        //Start with a size, potentially increasing it if an entire packet cannot fit into it
        recv_data = malloc(sizeof(char)*RECV_BUFF_LEN*chunks);
        if(!recv_data)
        {
            syslog(LOG_ERR, "Could not malloc: %s", strerror(errno));
            exit(1);  
        }

        do
        {
            recv_ret = recv(connection_fd, &recv_data[index], RECV_BUFF_LEN, 0);
            if(recv_ret == -1)
            {
                syslog(LOG_ERR, "An error occurred reading from the socket: %s", strerror(errno));
                exit(1);  
            }
            index += recv_ret;

            if(index != 0)
            {
                //Check if the last value received is "\n"
                if(recv_data[index - 1] == '\n')
                {
                    //Put the contents into /var/tmp/aesdsocketdata
                    //Write the string to the file
                    //Send all the contents read from /var/tmp/aesdsocketdata back to the client
                    if(lseek(file_fd, 0, SEEK_END) == -1)
                    {
                        syslog(LOG_ERR, "Could not get to the end of the file: %s", strerror(errno));
                        exit(1);  
                    }

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
                                continue;

                            //Else, error occurred, print it to syslog and finish program
                            syslog(LOG_ERR, "Could not write to the file: %s", strerror(errno));
                            exit(1);
                        }
                        len_to_write -= written_bytes;
                        ptr_to_write += written_bytes; 
                    }

                    file_size += index;

                    //Send all the contents read from /var/tmp/aesdsocketdata back to the client
                    if(lseek(file_fd, 0, SEEK_SET) == -1)
                    {
                        syslog(LOG_ERR, "Could not get to the beginning of the file: %s", strerror(errno));
                        exit(1);  
                    }
                    
                    //Perform reads to send the file contents to the socket client
                    int to_be_sent = file_size;
                    char buff_read[RECV_BUFF_LEN];
                    while(to_be_sent)
                    {
                        int send_bytes = 0;
                        int read_bytes = read(file_fd, buff_read, RECV_BUFF_LEN);
                        if(read_bytes != 0)
                            send_bytes = read_bytes;

                        if(read_bytes == -1)
                        {
                            //If the error is caused by an interruption of the system call try again
                            if(errno == EINTR)
                                continue;

                            //Else, error occurred, print it to syslog and finish program
                            syslog(LOG_ERR, "Could not read from the file: %s", strerror(errno));
                            exit(1);
                        }

                        //Less bytes remaining
                        to_be_sent -= read_bytes;
                        
                        //Send the contents back to the client
                        int sent_bytes = -1;
                        int send_off = 0;
                        syslog(LOG_INFO, "Send bytes: %d", send_bytes);
                        while(sent_bytes != 0)
                        {
                            sent_bytes = send(connection_fd, &buff_read[send_off], send_bytes, 0);
                            if(sent_bytes == -1)
                            {
                                //If the error is caused by an interruption of the system call try again
                                if(errno == EINTR)
                                    continue;

                                //Else, error occurred, print it to syslog and finish program
                                syslog(LOG_ERR, "Could not read from the file: %s", strerror(errno));
                                exit(1);
                            }
                            send_bytes -= sent_bytes;
                            send_off += sent_bytes;
                        }
                        
                    }

                    //Reset index to use the malloc'ed buffer from the beginning
                    index = 0;
                }
                //Realloc the array if it got full without an '\n'
                else if(index == (RECV_BUFF_LEN*chunks))
                {
                    chunks++;
                    recv_data = realloc(recv_data, sizeof(char)*RECV_BUFF_LEN*chunks);
                    if(!recv_data)
                    {
                        syslog(LOG_ERR, "Could not realloc: %s", strerror(errno));
                        exit(1);  
                    }
                }
            }

        } while(recv_ret != 0 && !graceful_exit);

        //Free the used buffer
        free(recv_data);
        print_closed_conn(client_addr);
    }

    exit_wrapper(sck, file_fd);
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
