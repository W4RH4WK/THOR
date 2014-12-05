#ifndef SOCKETHIDER_H
#define SOCKETHIDER_H

/* initialize socket hider module */
int sockethider_init(void);

/* cleanup socket hider module */
void sockethider_cleanup(void);

/* add (tcp4) port to hiding list */
void add_to_tcp4_list(int port);

/* remove (tcp4) port from hiding list */
void remove_from_tcp4_list(int port);

/* clear hiding list */
void clear_tcp4_list(void);

#endif
