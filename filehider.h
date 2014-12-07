#ifndef FILEHIDER_H
#define FILEHIDER_H

/* initialize file hider module */
int filehider_init(void);

/* cleanup file hider module */
void filehider_cleanup(void);

/* add file to hiding list */
void add_to_file_list(const char *name, unsigned int len);

/* remove file from hiding list */
void remove_from_file_list(const char *name, unsigned int len);

/* clear hiding list */
void clear_file_list(void);

#endif
