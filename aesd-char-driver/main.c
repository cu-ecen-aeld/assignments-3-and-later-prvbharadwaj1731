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
#include <linux/syscalls.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include <asm/uaccess.h>
#include "aesdchar.h"
#include "aesd_ioctl.h"

int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Pranav Bharadwaj");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    //Handle open
    PDEBUG("open\n");
    try_module_get(THIS_MODULE);

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    //Handle release
    PDEBUG("release\n");
    module_put(THIS_MODULE);

    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    size_t  entry_offset = 0;
    struct aesd_buffer_entry *entry = NULL;
    PDEBUG("read %zu bytes with offset %lld\n",count,*f_pos);
    
    //"count" is the number of bytes to be returned
    //"f_pos" is the offset from where to start the read

    //Set mutex
    if(mutex_lock_interruptible(&aesd_device.lock))
    {
        retval = -EINTR;
        return retval;
    }

    //Get the entry corresponding to the request
    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&aesd_device.buffer, *f_pos, &entry_offset);
    //Check for the results
    if(!entry)
    {
        PDEBUG("Access to aesdchar is returning without contents read\n");
        mutex_unlock(&aesd_device.lock);
        *f_pos = 0;
        retval = 0;
        return retval;
    }
    //Copy from entry offset, "count" or size
    if(entry_offset + count >= entry->size)
    {
        //Copy only until the size
        if(copy_to_user(buf, &entry->buffptr[entry_offset],  entry->size - entry_offset) != 0)
        {
            PDEBUG("Could not copy memory to the user\n");
            mutex_unlock(&aesd_device.lock);
            retval = -EINVAL;
            return retval;
        }
        *f_pos = *f_pos + entry->size - entry_offset;
        retval = entry->size - entry_offset;
    }
    else
    {
        //Copy until the count
        //Copy only until the size
        if(copy_to_user(buf, &entry->buffptr[entry_offset],  count) != 0)
        {
            PDEBUG("Could not copy memory to the user\n");
            mutex_unlock(&aesd_device.lock);
            retval = -EINVAL;
            return retval;
        }
        *f_pos = *f_pos + count;
        retval = count;
    }

    //Release mutex
    mutex_unlock(&aesd_device.lock);

    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    const char *to_be_freed = NULL;
    PDEBUG("write %zu bytes with offset %lld\n",count,*f_pos);
    

    //Check filp and buf validity
    if(!filp || !buf)
    {
        PDEBUG("Could not reallocate a temporary command\n");
        retval = -EINVAL;
        return retval;
    }

    //Check that the count is not 0
    if(!count)
    {
        PDEBUG("Attempt to write 0 bytes\n");
        retval = 0;
        return retval;
    }

    //Set mutex
    if(mutex_lock_interruptible(&aesd_device.lock))
    {
        retval = -EINTR;
        return retval;
    }

    //Check if there is a partial write active
    if(aesd_device.partial_size)
    {
        aesd_device.partial_content = krealloc(aesd_device.partial_content, 
                                              sizeof(char)*(aesd_device.partial_size + count), GFP_KERNEL); 
        if(!aesd_device.partial_content)
        {
            PDEBUG("Could not reallocate a temporary command\n");
            mutex_unlock(&aesd_device.lock);
            retval = -ENOMEM;
            return retval;
        }
    }
    //If not, allocate temporary space
    else
    {
        aesd_device.partial_content = kmalloc(sizeof(char)*count, GFP_KERNEL);
        if(!aesd_device.partial_content)
        {
            PDEBUG("Could not allocate a temporary command\n");
            mutex_unlock(&aesd_device.lock);
            retval = -ENOMEM;
            return retval;
        }
    }
    
    //Check every value in the entry and commit if '\n' is found
    while(count)
    {
        get_user(aesd_device.partial_content[aesd_device.partial_size], &buf[retval]);
        retval++;
        aesd_device.partial_size++;
        count--;

        //Check if the copied byte is as '\n'
        if(aesd_device.partial_content[aesd_device.partial_size - 1] == '\n')
        {
            //Create the new entry
            struct aesd_buffer_entry entry;
            entry.buffptr = kmalloc(sizeof(char)*aesd_device.partial_size, GFP_KERNEL);
            if(!entry.buffptr)
            {
                PDEBUG("Not enough memory available\n");
                mutex_unlock(&aesd_device.lock);
                retval = -ENOMEM;
                return retval;
            }
            entry.size = aesd_device.partial_size;

            //Copy the contents inside the entry
            memcpy((void *)entry.buffptr, aesd_device.partial_content, aesd_device.partial_size);

            //Add the entry to the buffer
            to_be_freed = aesd_circular_buffer_add_entry(&aesd_device.buffer, &entry);
            //Check if a buffer needs to be freed
            if(to_be_freed)
            {
                kfree(to_be_freed);
                to_be_freed = NULL;
            }

            //Free the partial contents
            kfree(aesd_device.partial_content);
            aesd_device.partial_size = 0;
            //Malloc again the remaining count
            if(count)
            {
                aesd_device.partial_content = kmalloc(sizeof(char)*count, GFP_KERNEL);
                if(!aesd_device.partial_content)
                {
                    PDEBUG("Could not allocate a temporary command\n");
                    mutex_unlock(&aesd_device.lock);
                    retval = -ENOMEM;
                    return retval;
                }
            }
        }
    }

    //Release mutex
    mutex_unlock(&aesd_device.lock);

    return retval;
}

loff_t aesd_llseek(struct file *filp, loff_t offset, int mode)
{
    loff_t retval;

    //Check filp and buf validity
    if(!filp)
    {
        PDEBUG("llseek requested without a valid filp\n");
        retval = -EINVAL;
        return retval;
    }
    
    if(mutex_lock_interruptible(&aesd_device.lock))
    {
        retval = -EINTR;
        return retval;
    }

    retval = fixed_size_llseek(filp, offset, mode, aesd_device.buffer.full_size);

    PDEBUG("lseek return value: %lld; offset: %lld;",retval,offset);
    if(retval == -EINVAL)
    {
        PDEBUG("llseek requested with an invalid offset\n");
    }

    mutex_unlock(&aesd_device.lock);
    
    return retval;
}

static long aesd_adjust_file_offset(struct file *filp,unsigned int write_cmd, unsigned int write_cmd_offset)
{
    loff_t offset;
    long retval;

    if(mutex_lock_interruptible(&aesd_device.lock))
    {
        retval = -EINTR;
        return retval;
    }

    offset = aesd_circular_buffer_getoffset(&aesd_device.buffer, write_cmd, write_cmd_offset);
    PDEBUG("Adjusting offset to %lld. Requested buffer number: %d; Requested offset: %d",offset, write_cmd, write_cmd_offset);

    if(offset == -1)
        retval = -EINVAL;
    else
    {
        filp->f_pos = offset;
        retval = 0;
    }
    mutex_unlock(&aesd_device.lock);

    return retval;
}


long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    long retval = 0;
    struct aesd_seekto seekto;

    if(_IOC_TYPE(cmd) != AESD_IOC_MAGIC) 
        return -EINVAL;

    if(_IOC_NR(cmd) > AESDCHAR_IOC_MAXNR) 
        return -EINVAL;

    switch(cmd)
    {
    case AESDCHAR_IOCSEEKTO:
        if(copy_from_user(&seekto,(const void __user *)arg,sizeof(struct aesd_seekto))!=0)
        {
            retval = -EFAULT;
        } 
        else
        {
            retval = aesd_adjust_file_offset(filp,seekto.write_cmd, seekto.write_cmd_offset);
        }
        break;
    default:
        retval = -ENOTTY;
        break;
    }

    return retval;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
    .llseek =   aesd_llseek,
    .unlocked_ioctl = aesd_ioctl,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev\n", err);
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

    //After memsetting the struct, the mutex needs to be initialized
    mutex_init(&aesd_device.lock);
    //The partial writes pointer will be used within the write operations

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

    //Destroy the mutex
    mutex_destroy(&aesd_device.lock);

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
