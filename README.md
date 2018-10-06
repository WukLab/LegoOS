# LegoOS

![Status](https://img.shields.io/badge/Version-Experimental-green.svg)
![License](https://img.shields.io/aur/license/yaourt.svg?style=popout)
![ISA](https://img.shields.io/badge/ISA-x86--64-yellow.svg)

[//]: “%![Platform](https://img.shields.io/badge/Platform-Linux-red.svg)%”

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

This code repository has many __major__ subsystems (e.g., managers, monitors, networking) and the following table describes where you can find the corresponding code:

| Major Subsystems | Directory |
|:---------|:-----------|
|Processor Manager| `managers/processor/`|
|Memory Manager |`managers/memory/`|
|Storage Manager |`linux-modules/storage/`|
|Managers' Network Stack|`net/`|
|Global Process Monitor |`linux-modules/monitor/gpm/`|
|Global Memory Monitor |`linux-modules/monitor/gmm/`|
|Monitors' Network Stack|`linux-modules/fit/`|

As for the __Processor Manager__, it has the following subsystems:

| Processor Manager Internal | Purpose |Directory|
|:---------------------------|:--------|:---------|
|pcache|Virtual Cache Management|`managers/processor/pcache/`|
|strace|Syscall Tracer|`managers/processor/strace/`|
|fs|Filesystem State Layer|`managers/processor/fs/`|
|mmap|Cached Distributed Memory Information|`managers/processor/mmap/`|
|replication|Memory Replication|`managers/processor/replication.c`|
|fork|Process Creation Notification|`managers/processor/fork.c`|
|exec|Execute Notification|`managers/processor/exec.`c|
|misc|misc|all others|

As for the __Memory Manager__, it has the following subsystems:

| Memory Manager Internal| Purpose | Directory|
|:-----------------------|:--------|:---------|
|pcache|Handle pcache Events|`managers/memory/handle_pcache/`|
|loader|Program Loader|`managers/memory/loader/`|
|pgcache|Page Cache|`managers/memory/pgcache/`|
|replication|Handle Memory Replication|`managers/memory/replica/`|
|vm|Distributed Virtual Memory Management|`managers/memory/vm/`|
|fs|Filesystem Operations|`managers/memory/m2s_read_write.c`|
|misc|misc| all others|

Storage manager and global resource monitors are not LegoOS's main focus at this stage, each of them has one simple task just as their name suggested.

## Platform Requirement
LegoOS has been tested __only__ in the following hardware setting:

|Hardware| Vendor and Model|
|:--|:--|
|Server| Dell PowerEdge R730|
|CPU| [Intel Xeon E5-2620 v3](https://ark.intel.com/products/83352/Intel-Xeon-Processor-E5-2620-v3-15M-Cache-2-40-GHz-)|
|InfiniBand NIC|[Mellanox MCX354A-TCBT ConnectX-3 VPI](https://store.mellanox.com/products/mellanox-mcx354a-tcbt-connectx-3-vpi-adapter-card-dual-port-qsfp-fdr10-ib-40gb-s-and-10gbe-pcie3-0-x8-8gt-s-rohs-r6.html?sku=MCX354A-TCBT&gclid=Cj0KCQjwl9zdBRDgARIsAL5Nyn0_Fiuw4-8TGIOE7lNr07YZmKz-CxXvBz1lV8FsTJ3rZwCeeSetF2saAnfmEALw_wcB)|

And the following toolchains:

|Software|Version|
|:--|:--|
|CentOS|7.2|
|GCC|4.8.5 20150623 (Red Hat 4.8.5-16)|
|GNU assembler|2.23.52.0.1 (x86_64-redhat-linux)|
|GNU ld|2.23.52.0.1-55.el7 20130226|
|GNU libc|2.17|
|GRUB2|2.02|

Of all the above hardware and software requirments, __the CPU and the NIC are the hard requirement__. Currently, LegoOS can only run on `Intel x86` CPUs. As for the NIC card, LegoOS has ported an `mlx4_ib` driver, which _probably_ can run on other Mellanox cards, but we have not tested other than the one we used. As long as you have the CPU and the NIC, we think you can run LegoOS on top your platform. You need __at least two machines__, connected by either InfiniBand switch or direct connection.

We understand that one key for an OS to be successful is let people be able to try it out. We are deeply sorry that we can not provide further technical support if you are using a different platform.

## Config and Compile

For process and memory manager, LegoOS uses the standard `Kconfig` way. For storage and global resource managers, which are built as Linux kernel modules, LegoOS uses a header file to manually typeset all configurations. We will describe the details below.

Each manager or monitor should be configured and complied at its own machine's directory. To be able to run LegoOS, you need at least two physical machines.

### Processor and Memory Manager
The default setting of LegoOS won't require any knowledge of Kconfig, all you need to do is changing the generated `.config` file. If you want to hack those Kconfig files, we recommend you to read the [documentation](https://www.kernel.org/doc/Documentation/kbuild/kconfig-language.txt) from Linux kernel and some other online resources.

1. `make defconfig`: After this doing, a `.config` file will be created locally.

2. Configure Process Manager: Open `.config`, find and delete the following line:
	```
	# CONFIG_COMP_PROCESSOR is not set
	```

3. Configure Memory Manager: Open `.config`, find and delete the following line:
	```
	# CONFIG_COMP_MEMORY is not set
	```

4. Step 2) and Step 3) are exclusive, you only need to configure one type of manager. After you finished one of them, type `make`. If you did step 2), you will see the following lines promoted, type `Y` and `Enter`. You can just type `Enter` till the end. Default settings works well.
	```
	[LegoOS git:(master)] $ make
	scripts/kconfig/conf  --silentoldconfig Kconfig
	*
	* Restart config...
	*
	*
	* Lego Processor Component Configurations
	*
	Configure Lego as processor component (COMP_PROCESSOR) [N/y/?] (NEW) y
	  Enable Process Checkpoint (CHECKPOINT) [N/y/?] (NEW)
	```

After doing above steps, the LegoOS kernel will be ready at `arch/x86/boot/bzImage`.

### Linux Modules
Storage manager, global resource monitors, and their network stack are linux kernel modules. They can only run on `Linux-3.11.1`. Because their network stack is only supported at this kernel version.

Once you have switched `Linux-3.11.1`, just go to `linux-modules/` and type `make`, which will compile all the following modules (and their config files):

| Module | Config File|
|:--|:--|
|Storage Manager|`linux-modules/storage/CONFIG_LEGO_STORAGE.h`|
|Global Resource Monitors|`linux-modules/monitor/include/monitor_config.h`|
|FIT| `linux-modules/fit/fit_config.h`|

## Run

### One Process Manager and One Memory Manager (_1P-1M_)

### One Processor Manager, one Memory Manager, and one Storage Manager (_1P-1M-1S_)

### Multiple


### 2. With physical machine
- `$ make install`
        This will install our kernel into `/boot` as if it is normal linux.
	So it can be recognized by GRUB. Normally, it is `/boot/vmlinuz-0.0.1`
        Here, `printk()` messages will also be sent from the serial port.
        Serial is directly connected between two physical machines, so messages
        can only be caught by corresponding machine. All the connection info
        are listed in google sheet: `Wuklab-Machines`. E.g., 04 and 05, 06 and 07.
