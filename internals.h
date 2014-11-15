#ifndef INTERNALS_H_
#define INTERNALS_H_

struct proc_dir_entry {
    unsigned int low_ino;
    umode_t mode;
    nlink_t nlink;
    kuid_t uid;
    kgid_t gid;
    loff_t size;
    const struct inode_operations *proc_iops;
    const struct file_operations *proc_fops;
    struct proc_dir_entry *next, *parent, *subdir;
    void *data;
    atomic_t count;         /* use count */
    atomic_t in_use;        /* number of callers into module in progress; */
    /* negative -> it's going away RSN */
    struct completion *pde_unload_completion;
    struct list_head pde_openers;   /* who did ->open, but not ->release */
    spinlock_t pde_unload_lock; /* proc_fops checks and pde_users bumps */
    u8 namelen;
    char name[];
};

#endif
