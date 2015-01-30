#ifndef HELPER_H
#define HELPER_H

#define MIN(a,b) \
   ({ typeof (a) _a = (a); \
      typeof (b) _b = (b); \
     _a < _b ? _a : _b; })

#endif

void write_no_prot(void *addr, void *data, int len);

int strendcmp(const char *str, const char *suffix);

