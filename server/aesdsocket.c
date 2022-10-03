/*
 * Author: Pranav Bharadwaj
 * Date: 09/30/2022
 * Formatted for space using codebeautify.org
 * References:
 
 1) Getting IPv4 address: https://stackoverflow.com/questions/1276294/getting-ipv4-address-from-a-sockaddr-structure
 2) https://beej.us/guide/bgnet/html/#audience
 3) https://www.tutorialspoint.com/c_standard_library/c_function_strerror.htm 
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>

#define LOGFILE_PATH	("/var/tmp/aesdsocketdata")
#define BUFFER_SIZE	(1024) //chosen as buffer size, can be reduced to 512 as well

//Global to handle signal exit
bool graceful_exit_handler = false;

//signal handler for SIGINT and SIGTERM
void signal_handler(int sig) {
  if (sig == SIGINT || sig == SIGTERM) {
    syslog(LOG_INFO, "Caught signal. Exiting...");
    graceful_exit_handler = true;
    exit(0);
  }
}

void managesocket(int socket_t) {
  int listen_ret = listen(socket_t, 10);
  if (listen_ret == -1) { //keep socket size 10 to listen for 10 incoming connections in queue
    syslog(LOG_ERR, "Error occured while listening to socket = %s. Exiting...", strerror(errno));
    exit(-1);
  }

  syslog(LOG_INFO, "Listening on port 9000");

  //Create the file that will log the messages received
  int log_fd = open(LOGFILE_PATH, O_CREAT | O_RDWR | O_TRUNC, 0766);
  if (log_fd == -1) {
    syslog(LOG_ERR, "Error creating logfile =  %s. Exiting...", strerror(errno));
    exit(-1);
  }

  int file_size = 0;
  char *recv_data = NULL;
  
  while (graceful_exit_handler == false) {

    struct sockaddr_storage client_addr;
    socklen_t addr_size = sizeof client_addr;

    int conn_fd = accept(socket_t, (struct sockaddr * ) & client_addr, & addr_size);
    if (conn_fd == -1) {
      if (errno == EINTR)
        continue;
      else {
        syslog(LOG_ERR, "Error occured during accepting new connection = %s. Exiting...", strerror(errno));
        exit(-1);
      }
    }
    //Get IPv4 address of client
    if (client_addr.ss_family == AF_INET) {
      char addr[INET6_ADDRSTRLEN];
      struct sockaddr_in * addr_in = (struct sockaddr_in * ) & client_addr;
      inet_ntop(AF_INET, & (addr_in -> sin_addr), addr, INET_ADDRSTRLEN);
      syslog(LOG_INFO, "Accepted connection from %s", addr);
      printf("Accepted connection from %s\n", addr);
    } else if (client_addr.ss_family == AF_INET6) {
      char addr[INET6_ADDRSTRLEN];
      struct sockaddr_in6 * addr_in6 = (struct sockaddr_in6 * ) & client_addr;
      inet_ntop(AF_INET6, & (addr_in6 -> sin6_addr), addr, INET6_ADDRSTRLEN);
      syslog(LOG_INFO, "Accepted connection from %s", addr);
      printf("Accepted connection from %s\n", addr);
    }

    //Wait for data
    int recv_ret;
    //Start with a size, potentially incresing it if an entire packet cannot fit into it
    recv_data = malloc(sizeof(char) * BUFFER_SIZE);
    if(!recv_data){
    	syslog(LOG_ERR, "Error occured during malloc = %s. Exiting...", strerror(errno));
    	exit(-1);
    }
    int recv_idx = 0;
    //How many 'BUFFER_SIZE' receive_blocks "recv_data" we have received from client till now
    int receive_blocks = 1;
    do {
      recv_ret = recv(conn_fd, & recv_data[recv_idx], BUFFER_SIZE, 0);
      if (recv_ret == -1) {
        syslog(LOG_ERR, "Error occured while reading from socket = %s. Exiting...", strerror(errno));
        exit(-1);
      }
//      printf("Received data = %s\n", &recv_data[recv_idx]);
      recv_idx += recv_ret;

      if (recv_idx != 0) {
        if (recv_data[recv_idx - 1] == '\n') {

          if (lseek(log_fd, 0, SEEK_END) == -1) {
            syslog(LOG_ERR, "Error occured while lseek() to EOF = %s. Exiting...", strerror(errno));
            exit(-1);
          }

          int write_byte_ret;
          int write_len = recv_idx;
          char * write_ptr = recv_data;
          while (write_len != 0) {
            write_byte_ret = write(log_fd, write_ptr, write_len);
            
            if (write_byte_ret == -1) {
              if (errno == EINTR)
                continue;
              else {
                syslog(LOG_ERR, "Error occured while writing to file = %s. Exiting...", strerror(errno));
                exit(-1);
              }
            }
            write_len -= write_byte_ret;
            write_ptr += write_byte_ret;
          }

          file_size += recv_idx;

          if (lseek(log_fd, 0, SEEK_SET) == -1) {
            syslog(LOG_ERR, "Error occured while lseek() to BOF = %s. Exiting...", strerror(errno));
            exit(-1);
          }

          char * log_read = malloc(sizeof(char) * file_size);
          char * log_read_offset = log_read;
          int bytes_to_read = file_size;
          int bytes_read_count;
          while (bytes_to_read != 0) {
            bytes_read_count = read(log_fd, log_read_offset, bytes_to_read);
            if (bytes_read_count == -1) {
              if (errno == EINTR)
                continue;
              else {
                syslog(LOG_ERR, "Error occured during reading from logfile = %s. Exiting...", strerror(errno));
                exit(-1);
              }

            }
            bytes_to_read -= bytes_read_count;
            log_read_offset += bytes_read_count;
          }
          //Send the contents back to the client
          send(conn_fd, log_read, file_size, 0);
          //Free the used bufferr
          free(log_read);

          //Reset recv_idx to loop again
          recv_idx = 0;
        }
        //Realloc the array if it got full without an '\n'
        else if (recv_idx == (BUFFER_SIZE * receive_blocks)) {
          receive_blocks++;
          recv_data = realloc(recv_data, sizeof(char) * BUFFER_SIZE * receive_blocks);
        }
      }

    } while (recv_ret != 0 && !graceful_exit_handler);

    //Free the malloced space
    free(recv_data);

    if (client_addr.ss_family == AF_INET) {
      char addr[INET6_ADDRSTRLEN];
      struct sockaddr_in * addr_in = (struct sockaddr_in * ) & client_addr;
      inet_ntop(AF_INET, & (addr_in -> sin_addr), addr, INET_ADDRSTRLEN);
      syslog(LOG_INFO, "Closed connection from %s", addr);
    } else if (client_addr.ss_family == AF_INET6) {
      char addr[INET6_ADDRSTRLEN];
      struct sockaddr_in6 * addr_in6 = (struct sockaddr_in6 * ) & client_addr;
      inet_ntop(AF_INET6, & (addr_in6 -> sin6_addr), addr, INET6_ADDRSTRLEN);
      syslog(LOG_INFO, "Closed connection from %s", addr);
    }
  }

  //Close socket now, after sending all data to client
  if (close(socket_t) == -1) {
    syslog(LOG_ERR, "Error occured during closing socket = %s. Exiting...", strerror(errno));
    exit(-1);
  }
  if (close(log_fd) == -1) {
    syslog(LOG_ERR, "Error occured during closing log file = %s. Exiting...", strerror(errno));
    exit(-1);
  }
  //Delete the file
  if (remove(LOGFILE_PATH) == -1) {
    syslog(LOG_ERR, "Error occured during deleting log file = %s. Exiting...", strerror(errno));
    exit(-1);
  }
}

int main(int argc, char ** argv) {

  //Open the log to write to the default "/var/log/syslog" and set the LOG_USER facility
  openlog(NULL, 0, LOG_USER);

  //Set up the signals handler
  struct sigaction signal_action;
  signal_action.sa_handler = signal_handler;
  signal_action.sa_flags = 0;
  sigset_t empty;
  if (sigemptyset( & empty) == -1) {
    syslog(LOG_ERR, "Error occured during setting empty set = %s. Exiting...", strerror(errno));
    exit(-1);
  }
  signal_action.sa_mask = empty;

  //Set handler for the signals SIGINT and SIGTERM

  if (sigaction(SIGTERM, & signal_action, NULL) == -1) {
    syslog(LOG_ERR, "Error occured during setting handler for SIGTERM = %s. Exiting...", strerror(errno));
    exit(-1);
  }
  if (sigaction(SIGINT, & signal_action, NULL) == -1) {
    syslog(LOG_ERR, "Error occured during setting handler for SIGINT = %s. Exiting...", strerror(errno));
    exit(-1);
  }

  //Create socket struct
  struct addrinfo hints;
  struct addrinfo * result;
  memset( & hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_flags = AI_PASSIVE; //chose any protocol as system sees fit
  hints.ai_socktype = SOCK_STREAM; //chose TCP
  if (getaddrinfo(NULL, "9000", & hints, & result) != 0) {
    syslog(LOG_ERR, "Error occured during socket setup = %s. Exiting...", strerror(errno));
    exit(-1);
  }

  int socket_t = socket(result -> ai_family, result -> ai_socktype, result -> ai_protocol);
  if (socket_t == -1) {
    syslog(LOG_ERR, "Error occured during starting socket = %s. Exiting...", strerror(errno));
    exit(-1);
  }
 
// Handling port reuse
  int yes = 1;
  if(setsockopt(socket_t, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1)
  {
    syslog(LOG_ERR, "Error occured during setsockopt = %s. Exiting...", strerror(errno));
    exit(-1);
  }


  //bind socket
  if (bind(socket_t, result -> ai_addr, result -> ai_addrlen) == -1) {
    syslog(LOG_ERR, "Error occured during socket binding = %s. Exiting...", strerror(errno));
    exit(-1);
  }

  //CALL FREE on result as we have used malloc
  freeaddrinfo(result);

  //Check for daemon mode argument
  //Check input arguments 
  if (argc == 1) {
    syslog(LOG_INFO, "No argument provided. Running in non-daemon mode.");
    managesocket(socket_t);
  } else if (argc == 2) {

    //check input argument
    if (strcmp(argv[1], "-d") != 0) {
      syslog(LOG_ERR, "Error occured while reading input argument. Exiting...");
      syslog(LOG_ERR, "start program in daemon mode by using this form: ./aesdsocket -d");
      exit(-1);
    }
    //start as daemon
    syslog(LOG_INFO, "Running as daemon");

    //Daemon creation process

    int fork_ret = fork();
    if (fork_ret == -1) {
      syslog(LOG_ERR, "Error occured during fork() = %s. Exiting...", strerror(errno));
      exit(-1);
    } else if (fork_ret == 0) {
      //In child now            
      //remove terminal associated with child
      if (setsid() == -1) {
        syslog(LOG_ERR, "Error occured during setsid() = %s. Exiting...", strerror(errno));
        exit(-1);
      }
      //Set pwd to root
      if (chdir("/") == -1) {
        syslog(LOG_ERR, "Error occured during setting directory to root = %s. Exiting...", strerror(errno));
        exit(-1);
      }

      //redirect stdout
      dup(0);
      managesocket(socket_t);
      exit(0);
    }
    //Exit parent process to complete daemon creation
    exit(0);
  } else {
    syslog(LOG_ERR, "Error occured with invalid arguments");
    syslog(LOG_ERR, "to use in daemon mode, use ./aesdsocket -d");
    exit(-1);
  }

  return 0;
}











