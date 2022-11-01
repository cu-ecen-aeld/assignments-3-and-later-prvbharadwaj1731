/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h>
#else
#include "string.h"
#include <unistd.h>
#include <sys/syscall.h>
#endif

#include "aesd-circular-buffer.h"

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */

struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    bool elem_found = false;
    uint8_t index;
    struct aesd_buffer_entry *entry_ret = NULL;

    //Check input for validity
    if(!entry_offset_byte_rtn || !buffer)
        return NULL;

    index = buffer->out_offs;
    int i = 0; //iterator for element entry
    //Check buffer to be full or not
    if(buffer->full)
        i = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; //set this to max length
    else{
        //check for wraparound logic
        if(buffer->in_offs > buffer->out_offs)
            i = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - buffer->in_offs + buffer->out_offs + 1;
        else if(buffer->in_offs < buffer->out_offs) //standard case
            i = buffer->out_offs - buffer->in_offs;
        else
            return NULL;
    }


    //Now with length set and an element available, enqueue it
    while(!elem_found && i){
        //Check element size
        if(buffer->entry[index].size >= char_offset + 1){
            entry_ret = &buffer->entry[index];
            *entry_offset_byte_rtn = char_offset;
            elem_found = true;
        }
        else
            char_offset -= buffer->entry[index].size;

        i--; //Now length reduced by 1
        index++;
        //wraparound logic for index if it exceeds AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED
        index = index % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    return entry_ret;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
const char *aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    const char *add_entry_ret = NULL;
    if(!buffer || !add_entry)
        return add_entry_ret;

    //Check if buffer is full
    if(buffer->full){
        add_entry_ret = buffer->entry[buffer->out_offs].buffptr;
        buffer->full_size -= buffer->entry[buffer->out_offs].size;
        buffer->out_offs++; //move out pointer by 1

        //Check for wraparound for pointer        
        buffer->out_offs = buffer->out_offs % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    //Actually add the new element to the buffer
    buffer->entry[buffer->in_offs].size = add_entry->size;
    buffer->entry[buffer->in_offs].buffptr = add_entry->buffptr;
    buffer->full_size += add_entry->size;
    buffer->in_offs++;

    //Another check for wraparound of pointer
    buffer->in_offs = buffer->in_offs % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

    //Check if buffer is full
    if(buffer->in_offs == buffer->out_offs) //Full condition
        buffer->full = true;

    return add_entry_ret;
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}


#ifdef __KERNEL__

//loff_t is a 64-bit signed data type used to support large file offset seeks
loff_t aesd_circular_buffer_getoffset(struct aesd_circular_buffer *buffer, unsigned int buff_number, unsigned int buff_offset)
{
    int buffer_offset = 0;
    int i;

    if(buff_number > AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - 1){        
        return -1;
    }
    //Check if offset requested is greater than size supported
    if(buff_offset > buffer->entry[buff_number].size - 1){
        return -1;
    }

    for(i=0; i<buff_number; i++)
    {
        if(buffer->entry[i].size == 0) //no buffer loaded, size 0
            return -1;
        
        buffer_offset += buffer->entry[i].size;
    }

    return buffer_offset + buff_offset;    
}

#endif
