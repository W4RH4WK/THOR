#include "hijack.h"

#include "helper.h"
#include "logging.h"

#include <linux/slab.h>

/* node for hijack list */
struct _hijack_list {
    void *function;
    char *first_instructions;
    unsigned int first_instructions_size;
    struct list_head list;
};

/* hijack list */
static struct _hijack_list hijack_list;

int hijack_init(void)
{
    INIT_LIST_HEAD(&hijack_list.list);

    return 0;
}

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

void hijack(void *function, void *new_function)
{
    struct _hijack_list *tmp;
#if defined(CONFIG_X86)
    int32_t jmp;
    char the_jump[5];
#endif

    bool found = false;

    list_for_each_entry(tmp, &(hijack_list.list), list) {
        if(tmp->function == function) {
            found = true;
            break;
        }
    }

    if (!found) {
        tmp = (struct _hijack_list*) kmalloc(sizeof(struct _hijack_list), GFP_KERNEL);
        tmp->function = function;
#if defined(CONFIG_X86)
        /* store the first instructions as we overwrite them */
        tmp->first_instructions_size = 5;
        tmp->first_instructions = (char*) kmalloc(tmp->first_instructions_size, GFP_KERNEL);
        memcpy(tmp->first_instructions, function, tmp->first_instructions_size);
#else
# error architecture not supported yet
#endif
        list_add(&(tmp->list), &(hijack_list.list));
    }

#if defined(CONFIG_X86)
    /* calculate the distance to our new function */
    jmp = (int32_t) (new_function - function);

    the_jump[0] = 0xE9;
    the_jump[1] = (jmp & 0xFF);
    the_jump[2] = (jmp & 0xFF00) >> 8;
    the_jump[3] = (jmp & 0xFF0000) >> 16;
    the_jump[4] = jmp >> 24;

    write_no_prot(function, &the_jump, tmp->first_instructions_size);
#else
# error architecture not supported yet
#endif
}

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

    if (!found) {
        LOG_WARN("unhijack: function %p not found, cannot unhijack", function);
        return;
    }

#if defined(CONFIG_X86)
    write_no_prot(function, tmp->first_instructions, tmp->first_instructions_size);
#else
# error architecture not supported yet
#endif
}
