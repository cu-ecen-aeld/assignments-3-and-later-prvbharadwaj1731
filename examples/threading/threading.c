#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>

#define TIMESCALE_CONVERSION_FACTOR (1000000)
// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    //struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    
    struct thread_data* thread_func_args = (struct thread_data*) thread_param;
    
    //we shall use the function nanosleep(), as sleep() itself is implemented in Linux using nanosleep()
    //Reference can be found here: https://man7.org/linux/man-pages/man2/nanosleep.2.html
    //Reference for code structure: https://linuxhint.com/nanosleep-function-c/
    struct timespec ts_required = {0, (thread_func_args->wait_to_obtain_ms)*TIMESCALE_CONVERSION_FACTOR}; //multiplied by 10^6 to convert ms to ns
    struct timespec ts_remaining;
    
    int return_status = nanosleep(&ts_required, &ts_remaining);
    
    while(return_status == -1){
    	if(errno == EINTR){ //EINTR means the pause has been interrupted by signal. Reference at above link
    		//sleep for remaining time
    		ts_required.tv_sec = 0;
    		ts_remaining.tv_nsec = ts_required.tv_nsec;
    		return_status = nanosleep(&ts_required, &ts_remaining);
    	}else //Error has occured in nanosleep()
    	{
    		ERROR_LOG("Sleep error. Exiting...");
    		thread_func_args->thread_complete_success = false;
    		return (void *)thread_func_args;
    	}
    }
    
    
    //Acquire mutex lock
    pthread_mutex_lock(thread_func_args->mutex);
    
    //Wait after acquiring mutex lock
    ts_required.tv_sec = 0;
    ts_required.tv_nsec = thread_func_args->wait_to_release_ms*TIMESCALE_CONVERSION_FACTOR;
    
    return_status = nanosleep(&ts_required, &ts_remaining);
    while(return_status == -1){
    	if(errno == EINTR){
    		ts_required.tv_sec = 0;
    		ts_remaining.tv_nsec = ts_required.tv_nsec;
    		return_status = nanosleep(&ts_required, &ts_remaining);
    	}else{
    		ERROR_LOG("Sleep error. Exiting...");
    		thread_func_args->thread_complete_success = false;
    		return (void *)thread_func_args;
    	}
    }
    
    //Release mutex lock
    pthread_mutex_unlock(thread_func_args->mutex);
    thread_func_args->thread_complete_success = true;
    return (void*)thread_func_args;
    
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */
     
     //Dynamic allocation of memory for struct
     struct thread_data *thread_func_args = malloc(sizeof(struct thread_data));
     if(!thread_func_args){
     	ERROR_LOG("Could not allocate new thread memory. Exiting...");
     	return false;
     }
     
     thread_func_args->mutex = mutex;
     thread_func_args->wait_to_obtain_ms = wait_to_obtain_ms;
     thread_func_args->wait_to_release_ms = wait_to_release_ms;
     
     int return_status = pthread_create(thread, NULL, threadfunc, (void *)thread_func_args);
     if(return_status != 0){
     	ERROR_LOG("Thread could not be created. Exiting...");
     	thread = NULL;
     	return false;
     }     
     
    return true;
}

