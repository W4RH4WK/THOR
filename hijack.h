#ifndef HIJACK_H
#define HIJACK_H

/* initialize the hijack_list */
int hijack_init(void);

/* cleanup, release hijack_list and all the hijack information it stores */
void hijack_cleanup(void);

/* 
 * hijack a given function (make it jump to new_function)
 * stores information about the hijack in hijack_list which
 * must be cleared with hijack_cleanup upon exit (ex. rmmod)
 */
void hijack(void *function, void *new_function);

/* unhijackes a given function if it has been hijacked previously */
void unhijack(void *function);

#endif

