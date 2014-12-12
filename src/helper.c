#include "helper.h"

#include <linux/fs.h>

#if defined(CONFIG_ARM)
# include <asm/cacheflush.h>
#endif

#if defined(CONFIG_ARM) && defined(CONFIG_STRICT_MEMORY_RWX)
#include <linux/sched.h>
#include <asm/tlbflush.h>
#include <asm/smp_plat.h>

#undef dsb
#define dsb(option) __asm__ __volatile__ ("dsb " #option : : : "memory")
#define possible_tlb_flags      (v4_possible_flags | \
                                 v4wbi_possible_flags | \
                                 fr_possible_flags | \
                                 v4wb_possible_flags | \
                                 fa_possible_flags | \
                                 v6wbi_possible_flags | \
                                 v7wbi_possible_flags)
#define always_tlb_flags        (v4_always_flags & \
                                 v4wbi_always_flags & \
                                 fr_always_flags & \
                                 v4wb_always_flags & \
                                 fa_always_flags & \
                                 v6wbi_always_flags & \
                                 v7wbi_always_flags)

#define tlb_flag(f)     ((always_tlb_flags & (f)) || (__tlb_flag & possible_tlb_flags & (f)))

#define tlb_op(f, regs, arg)    __tlb_op(f, "p15, 0, %0, " regs, arg)

static struct {
    pmd_t *pmd_to_flush;
    pmd_t *pmd;
    unsigned long addr;
    pmd_t saved_pmd;
    bool made_writeable;
} mem_unprotect;

struct tlb_args {
        struct vm_area_struct *ta_vma;
        unsigned long ta_start;
        unsigned long ta_end;
};

static inline void __local_flush_tlb_kernel_page(unsigned long kaddr)
{
    const int zero = 0;
    const unsigned int __tlb_flag = __cpu_tlb_flags;

    tlb_op(TLB_V4_U_PAGE, "c8, c7, 1", kaddr);
    tlb_op(TLB_V4_D_PAGE, "c8, c6, 1", kaddr);
    tlb_op(TLB_V4_I_PAGE, "c8, c5, 1", kaddr);
    if (!tlb_flag(TLB_V4_I_PAGE) && tlb_flag(TLB_V4_I_FULL))
            asm("mcr p15, 0, %0, c8, c5, 0" : : "r" (zero) : "cc");

    tlb_op(TLB_V6_U_PAGE, "c8, c7, 1", kaddr);
    tlb_op(TLB_V6_D_PAGE, "c8, c6, 1", kaddr);
    tlb_op(TLB_V6_I_PAGE, "c8, c5, 1", kaddr);
}

static inline void __flush_tlb_kernel_page(unsigned long kaddr)
{
    const unsigned int __tlb_flag = __cpu_tlb_flags;

    kaddr &= PAGE_MASK;

    if (tlb_flag(TLB_WB))
        dsb(ishst);

    __local_flush_tlb_kernel_page(kaddr);
    tlb_op(TLB_V7_UIS_PAGE, "c8, c3, 1", kaddr);

    if (tlb_flag(TLB_BARRIER)) {
        dsb(ish);
        isb();
    }
}

static inline void ipi_flush_tlb_kernel_page(void *arg)
{
    struct tlb_args *ta = (struct tlb_args *)arg;

    local_flush_tlb_kernel_page(ta->ta_start);
}

void flush_tlb_kernel_page(unsigned long kaddr)
{
    if (tlb_ops_need_broadcast()) {
        struct tlb_args ta;
        ta.ta_start = kaddr;
        on_each_cpu(ipi_flush_tlb_kernel_page, &ta, 1);
    } else {
        __flush_tlb_kernel_page(kaddr);
    }

    /* XXX */
    /*broadcast_tlb_a15_erratum();*/
}

void mem_text_address_writeable(unsigned long addr)
{
    struct task_struct *tsk = current;
    struct mm_struct *mm = tsk->active_mm;
    pgd_t *pgd = pgd_offset(mm, addr);
    pud_t *pud = pud_offset(pgd, addr);

    mem_unprotect.made_writeable = 0;

    /*
     * removed because we actually want to write to non text sections
     * if ((addr < (unsigned long)RX_AREA_START) ||
     *     (addr >= (unsigned long)RX_AREA_END))
     *     return;
     */

    mem_unprotect.pmd = pmd_offset(pud, addr);
    mem_unprotect.pmd_to_flush = mem_unprotect.pmd;
    mem_unprotect.addr = addr & PAGE_MASK;

    if (addr & SECTION_SIZE)
            mem_unprotect.pmd++;

    mem_unprotect.saved_pmd = *mem_unprotect.pmd;
    if ((mem_unprotect.saved_pmd & PMD_TYPE_MASK) != PMD_TYPE_SECT)
        return;

    *mem_unprotect.pmd &= ~PMD_SECT_APX;

    flush_pmd_entry(mem_unprotect.pmd_to_flush);
    flush_tlb_kernel_page(mem_unprotect.addr);
    mem_unprotect.made_writeable = 1;
}

void mem_text_address_restore(void)
{
    if (mem_unprotect.made_writeable) {
        *mem_unprotect.pmd = mem_unprotect.saved_pmd;
        flush_pmd_entry(mem_unprotect.pmd_to_flush);
        flush_tlb_kernel_page(mem_unprotect.addr);
    }
}

static DEFINE_SPINLOCK(mem_text_writeable_lock);

void mem_text_writeable_spinlock(unsigned long *flags)
{
	spin_lock_irqsave(&mem_text_writeable_lock, *flags);
}

void mem_text_writeable_spinunlock(unsigned long *flags)
{
	spin_unlock_irqrestore(&mem_text_writeable_lock, *flags);
}

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
    /* TODO: set_addr_rw/ro on actual len */
    set_addr_rw(addr);
    memcpy(addr, data, len);
    /* TODO: don't set ro if page was rw before? */
    set_addr_ro(addr);
#elif defined(CONFIG_ARM)
# if defined(CONFIG_STRICT_MEMORY_RWX)
    unsigned long flags;
    mem_text_writeable_spinlock(&flags);
    /* TODO: mem_text_address_writeable on actual len */
    mem_text_address_writeable((unsigned long)addr);
    memcpy(addr, data, len);
    cacheflush(addr, len);
    mem_text_address_restore();
    mem_text_writeable_spinunlock(&flags);
# else
    memcpy(addr, data, len);
    cacheflush(addr, len);
# endif
#else
# error architecture not supported yet
#endif
}
