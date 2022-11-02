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
    bool found = false;
    uint8_t index;
    struct aesd_buffer_entry *ret = NULL;
    int i = 0;

    //Frist check pointers are valid
    if(!buffer || !entry_offset_byte_rtn)
        return NULL;

    index = buffer->out_offs;


    //If the list is full, AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED is the max length
    if(buffer->full)
        i = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    //If not full, count how many steps does the out_off need to take to meet with in_off
    else
    {
        if(buffer->in_offs < buffer->out_offs)
            i = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - buffer->out_offs + buffer->in_offs + 1;
        else if(buffer->out_offs < buffer->in_offs)
            i = buffer->in_offs - buffer->out_offs;
        else
        {
             return NULL; //List is empty
        }
           
    }

    while(i && !found)
    {
        //Check if the current element's size meets the offset requested
        if(buffer->entry[index].size >= char_offset + 1)
        {
            //We found the element to be returned
            ret = &buffer->entry[index];
            //The offset within the element is "char_offset"
            *entry_offset_byte_rtn = char_offset;
            found = true;
        }
        //If doesn't fit, subtract the size of the buffer checked
        else
            char_offset -= buffer->entry[index].size;

        i--;
        index++;
        index %= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
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
const char *aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    const char *ret = NULL;
    //Check inputs
    if(!buffer || !add_entry)
        return ret;

    //Increment read pointer, if the list is full
    else if(buffer->full)
    {
        ret = buffer->entry[buffer->out_offs].buffptr;
        buffer->full_size -= buffer->entry[buffer->out_offs].size;
        buffer->out_offs++;
        buffer->out_offs %= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        
    }

    //This three lines are always performed
    buffer->entry[buffer->in_offs].size = add_entry->size;
    buffer->entry[buffer->in_offs].buffptr = add_entry->buffptr;
    buffer->full_size += add_entry->size;
    buffer->in_offs++;
    //Make sure that offsets are within bounds
    buffer->in_offs %= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

    //Check if the list has become full
    if(buffer->in_offs == buffer->out_offs)
        buffer->full = true;

    return ret;
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}

#ifdef __KERNEL__
/**
* Returns the absolute offset from a buffer number + offset combination
*/
loff_t aesd_circular_buffer_getoffset(struct aesd_circular_buffer *buffer, unsigned int buff_number, unsigned int buff_offset)
{
    int i;
    int offset = 0;

    if(buff_number > AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - 1)
        return -1;

    if(buff_offset > buffer->entry[buff_number].size - 1)
        return -1;

    for(i=0; i<buff_number; i++)
    {
        if(buffer->entry[i].size == 0)
        {
            //Not enough buffers loaded into the circular buffer
            return -1;
        }
        offset += buffer->entry[i].size;
    }
    return (offset + buff_offset);
}
#endif

