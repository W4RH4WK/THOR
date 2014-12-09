#ifndef PROCFILE_H
#define PROCFILE_H

/* entry for /proc/thor */
extern struct proc_dir_entry *procfile;

/* create procfile */
int procfile_init(void);

/* remove procfile */
void procfile_cleanup(void);

#endif
