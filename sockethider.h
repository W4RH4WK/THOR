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

/* clear (tcp4) hiding list */
void clear_tcp4_list(void);

/* add (tcp6) port to hiding list */
void add_to_tcp6_list(int port);

/* remove (tcp6) port from hiding list */
void remove_from_tcp6_list(int port);

/* clear (tcp6) hiding list */
void clear_tcp6_list(void);

/* add (udp4) port to hiding list */
void add_to_udp4_list(int port);

/* remove (udp4) port from hiding list */
void remove_from_udp4_list(int port);

/* clear (udp4) hiding list */
void clear_udp4_list(void);

/* add (udp6) port to hiding list */
void add_to_udp6_list(int port);

/* remove (udp6) port from hiding list */
void remove_from_udp6_list(int port);

/* clear (udp6) hiding list */
void clear_udp6_list(void);

#endif
