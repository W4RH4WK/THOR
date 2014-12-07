#ifndef LSMODHIDER_H
#define LSMODHIDER_H

/* initialize lsmod hider module */
int lsmodhider_init(void);

/* cleanup lsmod hider module */
void lsmodhider_cleanup(void);

/* add module to hiding list */
void add_to_module_list(const char *name, unsigned int len);

/* remove module from hiding list */
void remove_from_module_list(const char *name, unsigned int len);

/* clear hiding list */
void clear_module_list(void);

#endif

