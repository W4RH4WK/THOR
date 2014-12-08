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

void hijack(void *orig_function, void *new_function)
{
    struct _hijack_list *tmp;
    void *function = orig_function;
#if defined(CONFIG_X86)
    int32_t jmp;
    char the_jump[5];
#elif defined(CONFIG_ARM)
    uint32_t the_jump[4]; /* 2 for ARM, 4 for ARM THUMB */
    bool is_thumb = false;
#endif

    bool found = false;

#if defined(CONFIG_ARM)
    if ((uint32_t) function & 0x00000001) {
        /* subtract 1 from the THUMB address to get the actual memory address */
        function = (void*) ((char*)function - 1);
        is_thumb = true;
    }
#endif

    list_for_each_entry(tmp, &(hijack_list.list), list) {
        if(tmp->function == function) {
            found = true;
            break;
        }
    }

    if (!found) {
        tmp = (struct _hijack_list*) kmalloc(sizeof(struct _hijack_list), GFP_KERNEL);
        tmp->function = orig_function;
        /* store the first instructions as we overwrite them */
#if defined(CONFIG_X86)
        tmp->first_instructions_size = 5;
#elif defined(CONFIG_ARM)
        if(is_thumb) {
            tmp->first_instructions_size = 16;
        }
        else {
            tmp->first_instructions_size = 8;
        }
#else
# error architecture not supported yet
#endif
        tmp->first_instructions = (char*) kmalloc(tmp->first_instructions_size, GFP_KERNEL);
        memcpy(tmp->first_instructions, function, tmp->first_instructions_size);

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
#elif defined(CONFIG_ARM)
    if (is_thumb) {
        /* ARM THUMB */
        uint16_t *tj = (uint16_t*) the_jump;

        tj[0] = 0xB401; /* push {r0} */
        tj[1] = 0xF8DF; /* ldr r0, [pc, #8] */
        tj[2] = 0x0008; /* continuation of last instruction */
        tj[3] = 0x4684; /* mov ip, r0 */
        tj[4] = 0xBC01; /* pop {r0} */
        tj[5] = 0x4760; /* bx ip */

        tj[6] = ((uint32_t)new_function & 0x0000FFFF);
        tj[7] = ((uint32_t)new_function >> 16);
    }
    else {
        /* ARM */
        the_jump[0] = (uint32_t) 0xE51FF004; // ldr pc, [pc, -#4]
        the_jump[1] = (uint32_t) new_function;
    }
#else
# error architecture not supported yet
#endif

    write_no_prot(function, &the_jump, tmp->first_instructions_size);
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

#if defined(CONFIG_ARM)
    if ((uint32_t) function & 0x00000001) {
        /* subtract 1 from the THUMB address to get the actual memory address */
        function = (void*) ((char*)function - 1);       
    }
#endif

    write_no_prot(function, tmp->first_instructions, tmp->first_instructions_size);
}

