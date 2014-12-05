#ifndef HELPER_H
#define HELPER_H

#define MIN(a,b) \
   ({ typeof (a) _a = (a); \
      typeof (b) _b = (b); \
     _a < _b ? _a : _b; })

/* set page protection read write */
void set_addr_rw(void *addr);

/* set page protection read only */
void set_addr_ro(void *addr);

#endif
