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
#include <linux/string.h>
#else
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
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
   //Validate input pointers
    if(!entry_offset_byte_rtn || !buffer)
        return NULL;

    bool elem_found = false;
    int buffer_index = buffer->out_offs; //holds read out pointer offset
    struct aesd_buffer_entry *ret = NULL;

    //check if buffer is full
    int len = 0; //holds length
    if(buffer->full)
        len = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

    else{
        if(buffer->in_offs > buffer->out_offs) //check if read_ptr > write_ptr
            len = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - (buffer->in_offs + buffer->out_offs + 1);
        else if(buffer->in_offs < buffer->out_offs)
            len = buffer->out_offs - buffer->in_offs;
        else //this means buffer is empty
            return NULL; 
    }

    while(len && (elem_found == false)){
        if(buffer->entry[buffer_index].size >= char_offset + 1){
            ret = &buffer->entry[buffer_index];
            *entry_offset_byte_rtn = char_offset;
            elem_found = true;
        }
        else{
            char_offset -= buffer->entry[buffer_index].size;
        }

        len--;
        buffer_index++;
        buffer_index = buffer_index % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; //ensures offsets wrap around once reaching end of buffer
    }

    return ret;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
const char *aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry) //made a change to function return type
{
    const char *func_return = NULL;

    //check pointer validity before proceeding
    if(!add_entry || !buffer)
        return func_return;
    else if(buffer->full){
        func_return = buffer->entry[buffer->out_offs].buffptr;
        buffer->out_offs++;
        //modulus for wrap around logic
        buffer->out_offs = buffer->out_offs % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }
    
    //actually add the element into the buffer
    buffer->entry[buffer->in_offs].size = add_entry->size;
    buffer->entry[buffer->in_offs].buffptr = add_entry->buffptr;
    buffer->in_offs++; //added one element, increment
    
    //forgot to add wrap around logic for in_offs
    buffer->in_offs = buffer->in_offs % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

    //full check after inserting element
    if(buffer->in_offs == buffer->out_offs)
        buffer->full = true;

    return func_return;
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}

