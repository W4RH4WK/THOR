#include "helper.h"
#include "logging.h"

#include <linux/slab.h>

struct _hijack_list {
    void *function;
    char *first_instructions;
    unsigned int first_instructions_size;
    struct list_head list;
};

/* hijack list */
static struct _hijack_list hijack_list;

/* hijack a given function (make it jump to new_function) */
/* stores information about the hijack in hijack_list which
 * must be cleared with hijack_cleanup upon exit (ex. rmmod) */
void hijack(void *function, void *new_function)
{
    struct _hijack_list *tmp;
    int32_t jmp;

    bool found = false;

    list_for_each_entry(tmp, &(hijack_list.list), list) {
        if(tmp->function == function) {
            found = true;
            break;
        }
    }

    if(!found)
    {
        tmp = (struct _hijack_list*)kmalloc(sizeof(struct _hijack_list), GFP_KERNEL);
        tmp->function = function;
#if defined(CONFIG_X86)
        /* store the first instructions as we overwrite them */
        tmp->first_instructions_size = 5;
        tmp->first_instructions = (char*)kmalloc(tmp->first_instructions_size, GFP_KERNEL);
        memcpy(tmp->first_instructions, function, tmp->first_instructions_size);
#else
# error architecture not yet supported
#endif
        list_add(&(tmp->list), &(hijack_list.list));
    }

#if defined(CONFIG_X86)
    /* calculate the distance to our new function */
    jmp = (int32_t)(new_function - function);

    set_addr_rw(function);

    /* x86 rjmp */
    ((char*)function)[0] = 0xE9;

    /* store jump address as little endian */
    ((char*)function)[1] = (jmp & 0xFF);
    ((char*)function)[2] = (jmp & 0xFF00) >> 8;
    ((char*)function)[3] = (jmp & 0xFF0000) >> 16;
    ((char*)function)[4] = jmp >> 24;

    set_addr_ro(function);
#else
# error architecture not yet supported
#endif
}

/* unhijackes a given function if it has been hijacked previously */
void unhijack(void *function)
{
    struct _hijack_list *tmp;
    bool found = false;

    list_for_each_entry(tmp, &(hijack_list.list), list) {
        if(tmp->function == function) {
            found = true;
            break;
        }
    }

    if(!found) {
        LOG_WARN("unhijack: function %p not found, cannot unhijack", function);
        return;
    }

    set_addr_rw(function);
#if defined(CONFIG_X86)
    memcpy(function, tmp->first_instructions, tmp->first_instructions_size);
#else
# error architecture not yet supported
#endif
    set_addr_ro(function);
}

/* initialize the hijack_list */
int hijack_init(void)
{
    INIT_LIST_HEAD(&hijack_list.list);

    return 0;
}

/* cleanup, release hijack_list and all the hijack information it
 * stores */
void hijack_cleanup(void)
{
    struct _hijack_list *tmp;
    struct list_head *pos, *q;

    list_for_each_safe(pos, q, &(hijack_list.list)) {
        tmp = list_entry(pos, struct _hijack_list, list);
        unhijack(tmp->function);
        list_del(pos);
        kfree(tmp->first_instructions);
        kfree(tmp);
    }
}

