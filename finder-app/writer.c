#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char *argv[])
{
	FILE *fd; //file descriptor
	
	openlog(NULL, 0, LOG_USER);
	
	//check for correct number of input arguments
	if(argc != 3){
		syslog(LOG_ERR, "Wrong number of arguments provided. Exiting...\n");
		perror("Wrong number of arguments provided. Exiting...\n");
//		exit(1);
		return(1);
	}
	
	if(argv[2] == ""){
		syslog(LOG_ERR, "Input string not specified. Exiting...\n");
		perror("Input string not specified. Exiting...\n");
//		exit(1);
		return(1);
	}
	
	//try opening file specified in argument
	fd= fopen(argv[1], "w+");
	if(fd == NULL){
		syslog(LOG_ERR, "Error opening file. Exiting...\n");
		perror("Error opening file. Exiting...\n");
//		exit(1);
		return(1);
	}	
	syslog(LOG_DEBUG, "Writing %s to %s\n", argv[2], argv[1]);
	
	fprintf(fd, "%s", argv[2]);
	
	closelog();
	fclose(fd);
	return 0;
}
