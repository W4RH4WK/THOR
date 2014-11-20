# THOR

The Horrific Omnipotent Rootkit - or something like that, targeted at kernel
3.14 (archlinux LTS at the time of writing).

## Requirements

Apart from the linux kernel headers, the linux source code is required in order
to build this rootkit since unexported code is used.

Just make sure `/usr/src/linux` points to the linux source directory of the
target kernel. Or you could simply change the `Makefile`.

## How to Use

TODO

## Acknowledgement

- [Arkadiusz "ivyl" Hiler](https://github.com/ivyl/rootkit)
- [Morgan "mrrrgn" Phillips](https://github.com/mrrrgn/simple-rootkit)
- [uzyszkodnik](https://github.com/uzyszkodnik/rootkit)
