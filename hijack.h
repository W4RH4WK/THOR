#ifndef HIJACK_H
#define HIJACK_H

int hijack_init(void);
void hijack_cleanup(void);

void hijack(void *function, void *new_function);
void unhijack(void *function);

#endif

