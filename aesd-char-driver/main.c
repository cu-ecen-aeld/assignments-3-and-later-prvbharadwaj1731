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

//linux includes

#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include <asm/uaccess.h>
#include "aesdchar.h"
#include "aesd_ioctl.h"

int aesd_major = 0; // use dynamic major
int aesd_minor = 0;

MODULE_AUTHOR("Pranav Bharadwaj")
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    //Handle open
    PDEBUG("open");
    //increments number of devices by 1
    try_module_get(THIS_MODULE);

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    //decrements number of open devices by 1
    module_put(THIS_MODULE);

    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
    ssize_t return_val = 0;
    size_t entry_offset = 0;
    struct aesd_buffer_entry *entry = NULL;
    PDEBUG("read %zu bytes with offset %lld\n", count, *f_pos);

    //acquire mutex lock, use lock_interruptible this time
    if(mutex_lock_interruptible(&aesd_device.lock)){
        return_val = -EINTR; //Interrupt received
        return return_val;
    }

    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&aesd_device.buffer, *f_pos, &entry_offset);
    if(entry == NULL){
        PDEBUG("Error during aesdchar access. Exiting...\n");
        mutex_unlock(&aesd_device.lock);
        *f_pos = 0;
        return_val = 0;
        return return_val;
    }

    if(entry_offset + count >= entry->size){
        if(copy_to_user(buf, &entry->buffptr[entry_offset], entry->size - entry_offset) != 0){
            PDEBUG("Error while copying memory from kernel space to user space. Exiting...\n");
            mutex_unlock(&aesd_device.lock);
            return_val = -EINVAL;
            return return_val;
        }

        *f_pos += (entry->size - entry_offset);
        return_val = entry->size - entry_offset;
    }
    else{
        if(copy_to_user(buf, &entry->buffptr[entry_offset], count) != 0){
            PDEBUG("Error while copying memory from kernel space to user space. Exiting...\n");
            mutex_unlock(&aesd_device.lock);
            return_val = -EINVAL;
            return return_val;
        }

        *f_pos += count;
        return_val = count;
    }

    mutex_unlock(&aesd_device.lock);
    return return_val;
}


ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
    ssize_t return_val = 0;
    const char *ptr_to_free = NULL;
    PDEBUG("writing %zu bytes with offset of %lld\n",count, *f_pos);
    
    //Check input validity
    if(!filp || !buf){
        return_val = -EINVAL;
        return return_val;
    }

    //Also check if we are trying to write with count of 0
    if(count == 0){
        PDEBUG("Error while writing into buffer, size = 0. Exiting...\n");
        return_val = 0;
        return return_val;
    }

    //Acquire mutex lock
    mutex_lock_interruptible(&aesd_device.lock);

    //Check for partial writes
    if(aesd_device.size_partial){
        aesd_device.data_partial = krealloc(aesd_device.data_partial, sizeof(char)*(aesd_device.size_partial + count), GFP_KERNEL);
        if(!aesd_device.data_partial){
            PDEBUG("Error occured during krealloc. Exiting...\n");
            //release mutex lock
            mutex_unlock(&aesd_device.lock);
            return_val = -ENOMEM; //not enough memory for krealloc
            return return_val;
        }
    }

    while(count){
        
        //Take input from user space into kernel space
        get_user(aesd_device.data_partial[aesd_device.size_partial], &buf[return_val]);
        return_val++;
        aesd_device.size_partial++;
        count--;

        //Check for \n (whitespace)
        if(aesd_device.data_partial[aesd_device.size_partial - 1] == '\n'){
            //Go next entry in buffer
            struct aesd_buffer_entry new_entry;
            new_entry.buffptr = kmalloc(sizeof(char) * aesd_device.size_partial, GFP_KERNEL);
            if(!new_entry.buffptr){
                PDEBUG("Error occured during malloc for new entry after receiving whitespace. Exiting...\n");

                //Release mutex lock
                mutex_unlock(&aesd_device.lock);
                return_val = -ENOMEM;
                return return_val;
            }
            new_entry.size = aesd_device.size_partial;
            //Now that a new entry is allocated, copy remaining contents into it
            memcpy((void *)new_entry.buffptr, aesd_device.data_partial, aesd_device.size_partial);

            ptr_to_free = aesd_circular_buffer_add_entry(&aesd_device.buffer, &new_entry);
            if(ptr_to_free){
                kfree(ptr_to_free);
                ptr_to_free = NULL;
            }

            //Free everything
            kfree(aesd_device.data_partial);
            aesd_device.size_partial = 0;

            //Check if any more data left
            if(count){
                aesd_device.data_partial = kmalloc(sizeof(char)*count, GFP_KERNEL);
                if(!aesd_device.data_partial == NULL){
                    PDEBUG("Error occured during kmalloc for remaining count. Exiting...\n");
                    return_val = -ENOMEM;
                    return return_val;
                }
            }
        }
    }

    *f_pos += return_val;

    //Release mutex lock
    mutex_unlock(&aesd_device.lock);
    return return_val;
}

loff_t aesd_llseek(struct file *filp, loff_t offset, int mode)
{
    loff_t return_val;
    if(!filp){
        PDEBUG("Error occured with file pointer. Not Valid. Exiting...\n");
        return_val = -EINVAL;
        return return_val;
    }

    //Acquire mutex lock
    if(mutex_lock_interruptible(&aesd_device.lock)){
        return_val = -EINVAL;
        return return_val;
    }

    //use fixed_size_llseek()
    return_val = fixed_size_llseek(filp, offset, mode, aesd_device.buffer.full_size);
    if(return_val == -EINVAL)
        PDEBUG("Error occured during fixed_size_llseek(). Offset provided might be invalid. Exiting...\n");
    
    mutex_unlock(&aesd_device.lock);
    return return_val;
}

static long aesd_adjust_file_offset(struct file *filp, unsigned int cmd, unsigned int cmd_offset)
{
    loff_t offset;
    long return_val;

    //Acquire mutex lock
    if(mutex_lock_interruptible(&aesd_device.lock)){
        return_val = -EINVAL;
        return return_val;
    }

    offset = aesd_circular_buffer_getoffset(&aesd_device.buffer, cmd, cmd_offset);
    if(offset == -1)
        return_val = -EINVAL;
    else{
        filp->f_pos = offset;
        return_val = 0;
    }

    //Release mutex lock
    mutex_unlock(&aesd_device.lock);
    return return_val;
}


long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    long return_val = 0;
    struct aesd_seekto seekto; //new structure for data sent from userspace to kernel space

    if(_IOC_TYPE(cmd) != AESD_IOC_MAGIC)
        return -EINVAL;
    
    if(_IOC_NR(cmd) > AESDCHAR_IOC_MAXNR)
        return -EINVAL;
    
    if(cmd == AESDCHAR_IOCSEEKTO){
        //perform data transfer from userspace to kernelspace
        if(copy_to_user(&seekto, (const void *)arg, sizeof(struct aesd_seekto)) != 0)
            return_val = -EFAULT;
        else
            return_val = aesd_adjust_file_offset(filp, seekto.write_cmd, seekto.write_cmd_offset);
    }
    else
        return_val = -ENOTTY;

    return return_val;
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

