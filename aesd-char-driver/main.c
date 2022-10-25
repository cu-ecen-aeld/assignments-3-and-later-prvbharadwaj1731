/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
#include <linux/syscalls.h>
#include <asm/uaccess.h>

int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Pranav Bharadwaj"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    /**
     * TODO: handle open
     */
    //Increment device use count by a process
    try_module_get(THIS_MODULE);
     
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    //Decrement device use count by a process
    module_put(THIS_MODULE); 
    
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */
    size_t entry_pos = 0;
    struct aesd_buffer_entry *entry_ptr = NULL;
    
    //acquire mutex lock
    mutex_lock(&aesd_device.lock);

    //get position in buffer for input element
    entry_ptr = aesd_circular_buffer_find_entry_offset_for_fpos(&aesd_device.buffer, *f_pos, &entry_pos);
    if(entry_ptr == NULL){
        PDEBUG("Error while accessing circular buffer to read. Exiting...\n");
        //release mutex lock
        mutex_unlock(&aesd_device.lock);
        //refresh all pointers and return values
        *f_pos = 0;
        retval = 0;
        return retval;
    }

    //check how many spaces left and only copy as much as that
    //To do this, we need to copy data from kernelspace to userspace. This is accomplished using the copy_to_user()
    if(entry_pos + count >= entry_ptr->size){
        int copy_ret = copy_to_user(buf, &entry_ptr->buffptr[entry_pos], entry_ptr->size - entry_pos);
        if(copy_ret != 0){
            PDEBUG("Error occured while copying data from kernelspace to userspace. Exiting...\n");
            //release mutex_lock;
            mutex_unlock(&aesd_device.lock);
            retval = -EINVAL;
            return retval;
        }

        //set position of file pointer
        *f_pos += entry_ptr->size;
        retval = entry_ptr->size - entry_pos;
    }else{
        int copy_ret = copy_to_user(buf, &entry_ptr->buffptr[entry_pos], count);
        if(copy_ret != 0){
            PDEBUG("Error occured while copying data from kernelspace to userspace. Exiting...\n");
            //release mutex lock
            mutex_unlock(&aesd_device.lock);
            retval = -EINVAL;
            return retval;
        }

        //set position of file pointer
        *f_pos += count;
        retval  = count;
    }

    //release mutex lock
    mutex_unlock(&aesd_device.lock);
     
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */
    const char *free_ptr = NULL;

    //check validity of input data
    if(!filp || !buf){
        PDEBUG ("Error occured with input data to aesd_write. Exiting...\n");
    }
    if(!count){
        PDEBUG("Error occured during write, attempting to write 0 bytes. Exiting...\n");
        retval = 0;
        return retval;
    }

    //acquire mutex lock
    mutex_lock(&aesd_device.lock);

    //Partial write check
    if(aesd_device.size_partial){

        //reallocate memory for the partial write
        aesd_device.data_partial = krealloc(aesd_device.data_partial, sizeof(char)*(aesd_device.size_partial + count), GFP_KERNEL);
        if(aesd_device.data_partial == NULL){
            PDEBUG("Error occured while reallocating memory. Exiting...\n");
            //release mutex_lock
            mutex_unlock(&aesd_device.lock);
            retval = -EINVAL;
            return retval;
        }
    }

    //allocate space for normal write
    else{
        aesd_device.data_partial = kmalloc(sizeof(char)*count, GFP_KERNEL);
        if(aesd_device.data_partial == NULL){
            PDEBUG("Error occured while allocating memory. Exiting...\n");
            //release mutex lock
            mutex_unlock(&aesd_device.lock);
            retval = -EINVAL;
            return retval;
        }
    }

    //To check if input has \n in between data
    while(count != 0){
        //manually copy byte by byte to userspace
        get_user(aesd_device.data_partial[aesd_device.size_partial], &buf[retval]);
        retval++;
        aesd_device.size_partial++;
        count--;

        //check if the byte copied == \n
        if(aesd_device.data_partial[aesd_device.size_partial - 1] == '\n'){
            //create new entry into buffer for remaining data
            struct aesd_buffer_entry new_entry;

            //allocate space for remaining data
            new_entry.buffptr = kmalloc(sizeof(char)*aesd_device.size_partial, GFP_KERNEL);
            if(new_entry.buffptr == NULL){
                PDEBUG("Error occured while allocating memory for writing data after whitespace was encountered. Exiting...");
                //release mutex lock
                mutex_unlock(&aesd_device.lock);
                retval = -ENOMEM;
                return retval;
            }
            new_entry.size = aesd_device.size_partial;

            //copy contents into this new entry in buffer and call aesd_circular_buffer_add_entry
            memcpy((void *)new_entry.buffptr, aesd_device.data_partial, aesd_device.size_partial);
            free_ptr = aesd_circular_buffer_add_entry(&aesd_device.buffer, &new_entry);
            if(free_ptr == NULL){
                //Call free if entry cannot be added and reset free_ptr
                kfree(free_ptr);
                free_ptr = NULL;
            }
            //free partial data stored in aesd_device and reset size_partial
            kfree(aesd_device.data_partial);
            aesd_device.size_partial = 0;

            if(count != 0){
                aesd_device.data_partial = kmalloc(sizeof(char)*count, GFP_KERNEL);
                if(aesd_device.data_partial == NULL){
                    PDEBUG("Error occured while allocating memory for remaining data after whitespace. Exiting...");
                    //release mutex lock
                    mutex_unlock(&aesd_device.lock);
                    retval = -ENOMEM;
                    return retval;
                }
            }
        

        }
    }

    //Release mutex lock
    mutex_unlock(&aesd_device.lock);

    return retval;
}
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */

    //Initialize mutex
    mutex_init(&aesd_device.lock);

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */
    //destroy mutex
    mutex_destroy(&aesd_device.lock);

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);

