# LegoOS

![Status](https://img.shields.io/badge/Version-Experimental-green.svg)
![License](https://img.shields.io/aur/license/yaourt.svg?style=popout)
![ISA](https://img.shields.io/badge/ISA-x86--64-orange.svg)
![Platform](https://img.shields.io/badge/Platform-Linux-red.svg)

LegoOS is a disseminated, distributed operating system designed and built for resoucre disaggregation. LegoOS is one of the implementation of the Splitkernel. The OSDI'18 paper has more interesting design details.

[[Paper]](https://engineering.purdue.edu/~yiying/LegoOS-OSDI18.pdf) [[Slides]]()

## Codebase Organization
Several terms in this repository are used differently from the paper description. And in all the documentations here, we will use the code term.

| Paper Term | Code Term|
|:------------|:----------|
| Resource _Monitor_    | Resource _Manager_  |
| Global Resource _Manager_    | Global Resource _Monitor_  |
| ExCache    | pcache   |

Let's first get familiar with the codebase. If you have played with Linux kernel, welcome home. LegoOS has a similar directory organization: 1) `arch/` is for low-level ISA-specific hooks, 2) `drivers/` has `acpi`, `infiniband`, `pci`, and `tty` drivers, 3) `init/`, `kernel/`, `lib/`, and `mm/` are shared essential core kernel utilities. 4) `linux-modules/` are Linux kernel modules for storage manager and global resource monitors. We reused most of Linux code to ease our own porting of infiniband drivers.

This code repository also many __major__ subsystems (e.g., managers, monitors, networking) and the following table describes where you can find the corresponding code:

| Major Subsystems | Directory |
|:---------|:-----------|
|Processor Manager| managers/processor/|
|Memory Manager |managers/memory/|
|Storage Manager |linux-modules/storage/|
|Managers' Network Stack|net/|
|Global Process Monitor |linux-modules/monitor/gpm/|
|Global Memory Monitor |linux-modules/monitor/gmm/|
|Monitors' Network Stack|linux-modules/fit/|

As for the processor manager, it has the following subsystems:

| Processor Manager Internal | Purpose |Directory|
|:---------------------------|:--------|:---------|
|pcache|Virtual Cache Management|managers/processor/pcache/|
|strace|Syscall Tracer|managers/processor/strace/|
|fs|Filesystem State Layer|managers/processor/fs/|
|mmap|Cached Distributed Memory Information|managers/processor/mmap/|
|replication|Memory Replication|managers/processor/replication.c|
|fork|Process Creation Notification|managers/processor/fork.c|
|exec|Execute Notification|managers/processor/exec.c|
|misc|misc|all others|

As for the memory manager, it has the following subsystems:

| Memory Manager Internal| Purpose | Directory|
|:-----------------------|:--------|:---------|
|pcache|Handle pcache Events|managers/memory/handle_pcache/|
|loader|Program Loader|managers/memory/loader/|
|pgcache|Page Cache|managers/memory/pgcache/|
|replication|Handle Memory Replication|managers/memory/replica/|
|vm|Distributed Virtual Memory Management|managers/memory/vm/|
|fs|Filesystem Operations|managers/memory/m2s_read_write.c|
|misc|misc| all others|

Storage manager and global resource monitors are not LegoOS's main focus at this stage, each of them has one simple task just as their name suggested.

## Platform Requirement
asd

## Config and Build

Build in current source tree:
- `$ make defconfig`
        This will generate a default `.config` file in your current directory.
        You can change the configurations by modifying the `.config` file.
- `$ make`
        This will build our vmImage: `arch/x86/boot/bzImage`

## Testing
### 1. With QEMU
- `$ ./scripts/run.sh`
        This will run the standalone kernel image in QEMU.
        Those `printk()` messages will go into `test-output/ttyS1`.

### 2. With physical machine
- `$ make install`
        This will install our kernel into `/boot` as if it is normal linux.
	So it can be recognized by GRUB. Normally, it is `/boot/vmlinuz-0.0.1`
        Here, `printk()` messages will also be sent from the serial port.
        Serial is directly connected between two physical machines, so messages
        can only be caught by corresponding machine. All the connection info
        are listed in google sheet: `Wuklab-Machines`. E.g., 04 and 05, 06 and 07.
