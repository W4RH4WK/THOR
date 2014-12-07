#ifndef PROCFILE_H
#define PROCFILE_H

#include "module.h"

#define THOR_PROCFILE THOR_MODULENAME

/* entry for /proc/thor */
extern struct proc_dir_entry *procfile;

/* create procfile */
int procfile_init(void);

/* remove procfile */
void procfile_cleanup(void);

#endif
