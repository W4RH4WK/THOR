#include "helper.h"

#include <linux/fs.h>

#if defined(CONFIG_ARM)
# include <asm/cacheflush.h>
# if defined(CONFIG_STRICT_MEMORY_RWX)
#  include <asm/mmu_writeable.h>
# endif
#endif

#if defined(CONFIG_X86)
void set_addr_rw(void *addr)
{
    unsigned int level;
    pte_t *pte = lookup_address((unsigned long) addr, &level);
    if (pte->pte &~ _PAGE_RW)
        pte->pte |= _PAGE_RW;
}

void set_addr_ro(void *addr)
{
    unsigned int level;
    pte_t *pte = lookup_address((unsigned long) addr, &level);
    pte->pte = pte->pte &~_PAGE_RW;
}
#else
void cacheflush ( void *begin, unsigned long size )
{
    flush_icache_range((unsigned long)begin, (unsigned long)begin + size);
}
#endif

void write_no_prot(void *addr, void *data, int len)
{
#if defined(CONFIG_X86)
    // TODO: set_addr_rw/ro on actual len
    set_addr_rw(addr);
    memcpy(addr, data, len);
    // TODO: don't set ro if page was rw before?
    set_addr_ro(addr);
#elif defined(CONFIG_ARM)
# if defined(CONFIG_STRICT_MEMORY_RWX)
    unsigned long *target_arm = (unsigned long*)addr;
    unsigned long *code_arm = (unsigned long*)data;
    unsigned int i;
    for(i=0;i<len;i++)
    {
        mem_text_write_kernel_word(target_arm + i, *(code_arm + i));
    }
# else
    memcpy(addr, data, len);
    cacheflush(addr, len);
# endif
#else
# error architecture not supported yet
#endif
}

