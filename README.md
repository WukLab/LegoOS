```
 _                      ___  ____
| |    ___  __ _  ___  / _ \/ ___|
| |   / _ \/ _` |/ _ \| | | \___ \
| |__|  __/ (_| | (_) | |_| |___) |
|_____\___|\__, |\___/ \___/|____/
           |___/
```

![Status](https://img.shields.io/badge/Version-Experimental-blue.svg)
![License](https://img.shields.io/badge/license-GPLv2-brightgreen.svg)
![ISA](https://img.shields.io/badge/ISA-x86--64-yellow.svg)

[//]: “%![Platform](https://img.shields.io/badge/Platform-Linux-red.svg)%”

LegoOS is a disseminated, distributed operating system built for hardware resource disaggregation. LegoOS is a research operating system being built from scratch and released by researchers from Purdue University. LegoOS splits traditional operating system functionalities into loosely-coupled monitors, and run those monitors directly on hardware device. You can find more details from our OSDI'18 paper.

[[Paper]](https://www.usenix.org/conference/osdi18/presentation/shan)
[[Keynote]](https://github.com/WukLab/LegoOS/tree/master/Documentation/LegoOS-OSDI-Slides.key)
[[Tech Notes]](http://lastweek.io)
[[Google Trace Plot]](https://github.com/WukLab/LegoOS/tree/master/Documentation/google-trace.md)

Table of Contents
=================

   * [LegoOS](#legoos)
      * [Developers](#developers)
      * [Codebase Organization](#codebase-organization)
      * [Platform Requirement](#platform-requirement)
      * [Configure and Compile](#configure-and-compile)
         * [Configure Processor or Memory Manager](#configure-processor-or-memory-manager)
            * [Configure Processor ExCache Size](#configure-processor-excache-size)
         * [Configure Linux Modules](#configure-linux-modules)
         * [Configure Network](#configure-network)
            * [FIT](#fit)
            * [QPN](#qpn)
            * [LID](#lid)
            * [Node ID and Number of Machines](#node-id-and-number-of-machines)
         * [Configure Output](#configure-output)
            * [Setup printk()](#setup-printk)
            * [Setup Serial Connection](#setup-serial-connection)
      * [Install and Run](#install-and-run)
         * [1P-1M](#1p-1m)
            * [Sample .config](#sample-config)
         * [1P-1M-1S](#1p-1m-1s)
            * [Configurations](#configurations)
            * [Boot](#boot)
            * [Sample .config](#sample-config-1)
         * [Multiple Managers](#multiple-managers)
         * [Virtual Machine](#virtual-machine)
            * [VM Setup](#vm-setup)
            * [InfiniBand](#infiniband)

## Developers

- [Profiling](https://github.com/WukLab/LegoOS/tree/master/Documentation/profile.md)
- [strace](https://github.com/WukLab/LegoOS/tree/master/Documentation/strace.md)
- [Counters and Watchdog](https://github.com/WukLab/LegoOS/tree/master/Documentation/counters.md)
- [Memory Manager Configurations](https://github.com/WukLab/LegoOS/tree/master/Documentation/mc-config.md)

## Codebase Organization
Several terms in this repository are used differently from the paper description. Some of them might be used interchangeably here.

| Paper Term | Code Term|
|:------------|:----------|
| Resource _Monitor_    | Resource _Manager_  |
| Global Resource _Manager_    | Global Resource _Monitor_  |
| ExCache    | pcache   |
|p-local|zerofill|

Now let's first get familiar with the codebase. If you have played with Linux kernel, welcome home. We reused most of Linux code to ease our own porting of InfiniBand drivers. The consequence is now LegoOS supports almost all _essential_ Linux kernel functionalities. Overall, LegoOS has a similar directory organization:
- `arch/` is for low-level ISA-specific hooks
- `drivers/` has `acpi`, `infiniband`, `pci`, and `tty` drivers
- `init/`, `kernel/`, `lib/`, and `mm/` are shared essential core kernel utilities
- `linux-modules/` are Linux kernel modules for storage manager and global resource monitors

This code repository has many __major__ subsystems (e.g., managers, monitors, networking). The following table describes where you can find the corresponding code:

| Major Subsystems | Directory |
|:---------|:-----------|
|Processor Manager| `managers/processor/`|
|Memory Manager |`managers/memory/`|
|Storage Manager |`linux-modules/storage/`|
|Managers' Network Stack|`net/`|
|Global Process Monitor |`linux-modules/monitor/gpm/`|
|Global Memory Monitor |`linux-modules/monitor/gmm/`|
|Monitors' Network Stack|`linux-modules/fit/`|

As for the __Processor Manager__ (PM), it has the following subsystems:

| PM Internal | Purpose |Directory|
|:---------------------------|:--------|:---------|
|pcache|Virtual Cache Management|`managers/processor/pcache/`|
|strace|Syscall Tracer|`managers/processor/strace/`|
|fs|Filesystem State Layer|`managers/processor/fs/`|
|mmap|Virtual Memory State Layer |`managers/processor/mmap/`|
|replication|Memory Replication|`managers/processor/replication.c`|
|fork|Process Creation Notification|`managers/processor/fork.c`|
|exec|Execute Notification|`managers/processor/exec.`c|
|misc|misc|all others|

As for the __Memory Manager__ (MM), it has the following subsystems:

| MM Internal| Purpose | Directory|
|:-----------------------|:--------|:---------|
|pcache|Handle pcache Events|`managers/memory/handle_pcache/`|
|loader|Program Loader|`managers/memory/loader/`|
|pgcache|Page Cache|`managers/memory/pgcache/`|
|replication|Handle Memory Replication|`managers/memory/replica/`|
|vm|Virtual Memory|`managers/memory/vm/`|
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
|InfiniBand Switch|[Melanox IS5035](http://www.mellanox.com/related-docs/prod_ib_switch_systems/IS5035.pdf)|

And the following toolchains:

|Software|Version|
|:--|:--|
|CentOS|7.2|
|GCC|4.8.5 20150623 (Red Hat 4.8.5-16)|
|GNU assembler|2.23.52.0.1 (x86_64-redhat-linux)|
|GNU ld|2.23.52.0.1-55.el7 20130226|
|GNU libc|2.17|
|GRUB2|2.02|

Of all the above hardware and software requirments, __the CPU and the Infiniband NIC are the hard requirements__. Currently, LegoOS can only run on `Intel x86` CPUs. As for the Infiniband NIC card, LegoOS has ported an `mlx4_ib` driver, which _probably_ can run on other Mellanox cards, but we have not tested other than the one we used. As long as you have the CPU and the Infiniband NIC, we think you can run LegoOS on top your platform. You need __at least two machines__, connected by Infiniband switch (back-to-back connection is not supported now).

We understand that one key for an OS to be successful is let people be able to try it out. We are deeply sorry that we can not provide further technical support if you are using a different platform.

## Configure and Compile

__The README is still raw and scratchy, it might not be complete and it might also seems confusing. The whole tutorial can be improved only if there are people trying out LegoOS and give us feedback. If you have any issues, please don't hesitate to contact us (Github Issue is preferred). We really appreciate your input here.__

__CAVEAT:__ Configure, compile, and run a LegoOS kernel is similar to test a new Linux kernel. You need to have root access to the machine. The whole process may involve multiple machine power cycles. __Before you proceed, make sure you have some methods (e.g., `IPMI`) to monitor and reboot _remote_ physical machine.__ It is possible to just use virtual machines, but with a constrained setting (described below). If you running into any issues, please don’t hesitate to contact us!

For processor and memory manager, LegoOS uses the Linux `Kconfig` way. If are not familiar with it, or encounter any issues while configuring LegoOS, we recommend you refer to online Kconfig tutorials.

For storage and global resource managers, which are built as Linux kernel modules, LegoOS uses a header file to manually typeset all configurations. We will describe the details below.

Each manager or monitor should be configured and complied at its own machine's directory. To be able to run LegoOS, you need at least two physical machines.

### Configure Processor or Memory Manager
The default setting of LegoOS won't require any knowledge of Kconfig, all you need to do is changing the generated `.config` file. If you want to hack those Kconfig files, we recommend you read the [documentation](https://www.kernel.org/doc/Documentation/kbuild/kconfig-language.txt) from Linux kernel and some other online resources.

And note that this is just the __general__ configuration steps. If you want to configure for specific settings, such as running with only one processor and one memory manager, please refer to the following sections for more detailed steps.

1. `make defconfig`: After this doing, a `.config` file will be created locally.

2. Configure Processor Manager: Open `.config`, find and delete the following line:
	```
	# CONFIG_COMP_PROCESSOR is not set
	```

3. Configure Memory Manager: Open `.config`, find and delete the following line:
	```
	# CONFIG_COMP_MEMORY is not set
	```

4. Step 2) and Step 3) are exclusive, you only need to configure one type of manager. After you finished one of them, type `make`. If you did step 2), you will see the following lines promoted, type `Y` and `Enter`. You can type `Enter` for all Kconfig options. Except the ones such as setting up default home memory ID, which will be covered by Network section below. For now, just set the ID to a random number (e.g., 0). All default settings works well.
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

#### Configure Processor ExCache Size
There is one more knob for processor managers: __ExCache Size__. We reused the old way of reserving DRAM from Linux: the [`memmap=nn[KMG]$ss[KMG]`](https://www.kernel.org/doc/html/v4.14/admin-guide/kernel-parameters.html). Due to implementation issues, the semantic in LegoOS is not very straightforward. Basically, the actual ExCache size is __half__ the size you specified at `memmap`.

Assume you want to reserve contiguous DRAM start from physical address `4GB`:
- To have a 512MB ExCache, use `memmap=1G$4G`
- To have a 1GB ExCache, use `memmap=2G$4G`

For example, this is how it looks like in a `CentOS 7, /boot/grub2/grub.cfg`  file if `1GB` ExCache is configured:
```
menuentry 'CentOS Linux (4.0.0-lego+) 7 (Core)' ... {
	...
        linux16 /vmlinuz-4.0.0-lego+ memmap=2G\$4G
        initrd16 ...
	...
```
[Fat note: 1) Other bootloaders may have different semantics, and make sure you modified the right boot menuentry. 2) In grub2, make sure you are using `linux16/initrd16` instead of `linux/initrd`. The latter pair will load kernel into a physical address where LegoOS does not support.]

At LegoOS boot time, the ExCache configuration will be printed at the very beginning, and it has to be something like `memmap=X$X` without any `\` in the middle. Processor manager will complain if `memmap` goes wrong. An example output is [here](https://github.com/WukLab/LegoOS/blob/master/Documentation/configs/1P-1M-Processor-Output#L2).

### Configure Linux Modules
Storage manager, global resource monitors, and their network stack are linux kernel modules. They can only run on `Linux-3.11.1`. Because their network stack is only supported at this kernel version.

Once you have switched `Linux-3.11.1`, just go to `linux-modules/` and type `make`, which will compile all the following modules (and their config files):

| Module | Config File|
|:--|:--|
|Storage Manager|`linux-modules/storage/CONFIG_LEGO_STORAGE.h`|
|Global Resource Monitors|`linux-modules/monitor/include/monitor_config.h`|
|FIT| `linux-modules/fit/fit_config.h`|

### Configure Network
At current stage, setup InfiniBand connection is still a little bit complicated, and it involves hardcoded information. Unlike Ethernet, InfiniBand can not just connect to each other. It needs Ethernet to exchange some initial information first. The initial information includes: Local IDentifier (__LID__) and Queue Pair Number (__QPN__). Unfortunately, we currently do not have decent Ethernet drivers and socket code that could run everywhere. Thus, instead of using Ethernet to exchange LID and QPN, we __manually hardcode them into the source code__, and let InfiniBand layer use this hardcoded information directly. Do note that the hardcoded information is about __remote machines__, which the local machine is trying to connect to.

Also, make sure you have the InfiniBand NIC descibed in [Platform Requirement](#platform-requirement). They must be connected through a InfiniBand switch.

#### FIT
LegoOS uses a customized network stack named FIT, which is built based on [LITE](https://github.com/WukLab/lite). For more information of LITE, please refer to this [paper](https://dl.acm.org/citation.cfm?id=3132762). Here are some general concepts about FIT in LegoOS:
- FIT is a layer on top of kernel InfiniBand verbs
- FIT uses one polling thread to handle CQE, and this will not be the performance bottleneck
- FIT builds multiple QPs between each pair of machine
- Users of FIT share underlying QPs, multiplexed by FIT
- LegoOS mostly just uses the `ibapi_send_reply` API

#### QPN

This subsection tries to explain several Kconfig options related to QP. You don't need to tune any configurations of this subsection for a default run. If a default setting does not work, please create a Github issue with detailed error message (especially dmesg from linux kernel modules).

The number of QPs between each pair of machine is controlled by: `CONFIG_FIT_NR_QPS_PER_PAIR`. The default is 12, which is the number of CPU cores (one NUMA socket) we have in our platform.

The QPN information is controlled by: `CONFIG_FIT_FIRST_QPN`, default to 80. This is the QPN of the __first__ QP created by FIT layer.

For example, assume you use both above default settings, then FIT layer will have 12 QPs, and the first QP's QPN is 80. Since FIT is the only user who will create QPs, the 12 QPs will have __consecutive__ QPNs in the range of __[80, 91]__.

Now, the trick here is, we configure all LegoOS manager's FIT layer to use the same configuration, then each manager knows exactly what others' QPN information would be, which is __[`CONFIG_FIT_FIRST_QPN`, `CONFIG_FIT_FIRST_QPN` + `CONFIG_FIT_NR_QPS_PER_PAIR` - 1]__.

And this solves the hardcoded QPN issue.

#### LID
This subsection tries to explain how LID should be hardcoded. This process involes two steps: 1) get LID information from `iblinkinfo`, 2) build the LID table at `net/lego/fit_machine.c`.

InfiniBand LID can be obtained by running `iblinkinfo` at Linux. A snippet output from our platform would be:
```
...

CA: wuklab00 mlx4_0:
      0xe41d2d0300309251      8    1[  ] ==( 4X          10.0 Gbps Active/  LinkUp)==>      22    1[  ] "MF0;wuklab-ibsw:IS5035/U1" ( )
CA: wuklab01 mlx4_0:
      0xe41d2d0300309301     27    1[  ] ==( 4X          10.0 Gbps Active/  LinkUp)==>      22    2[  ] "MF0;wuklab-ibsw:IS5035/U1" ( )
CA: wuklab02 mlx4_0:
      0xe41d2d03003092d1     24    1[  ] ==( 4X          10.0 Gbps Active/  LinkUp)==>      22    3[  ] "MF0;wuklab-ibsw:IS5035/U1" ( )

...
```

From the above snippet, we learn a mapping between hostname and LID (hostname is not a must have, it is just like a domain name for IP address):
- `wuklab00` - `LID 8`
- `wuklab01` - `LID 27`
- `wuklab02` - `LID 24`

Now we have the LID information, let us hardcode them into a table at both `net/lego/fit_machine.c` and `linux-modules/fit/fit_machine.c`:
```
static struct fit_machine_info WUKLAB_CLUSTER[] = {
[0]     = {     .hostname =     "wuklab00",     .lid =  8,       },
[1]     = {     .hostname =     "wuklab01",     .lid =  27,      },
[2]     = {     .hostname =     "wuklab02",     .lid =  24,      },
...
```

Please make sure to fill the correct LID numbers. Any typos here will lead to an unsuccessful connection after early boot and it's hard to debug.

#### Node ID and Number of Machines
Now we've built the necessary information, it's time to think about the real connection. Currently, LegoOS does not support hotplug a hardware component at runtime (it is important and doable, but requires some extra pure engineering effort). Thus, you need to configure the node ID and number of connected machines at __compile time__.

They are described by these two configurations:
- `CONFIG_FIT_LOCAL_ID`
- `CONFIG_FIT_NR_NODES`

For one run, all LegoOS instance must have the same `CONFIG_FIT_NR_NODES`. And each LegoOS instance must have its unique `CONFIG_FIT_LOCAL_ID`. The detailed configuration will be described at `1P-1M` and `1P-1M-1S` sections.

After setting up above configurations, you also need to manually change the `lego_cluster_hostnames` array at `net/fit/fit_machine.c`. The array specifies the machines used in one run, and the array must be built based the ID sequence.

### Configure Output

#### Setup `printk()`
LegoOS output debug messages (`printk()`) to two sources: 1) `serial port`, 2) `VGA terminal`. Mostly only the output to serial port is useful, because this can be saved and later being examined. The output to VGA is useful when we run LegoOS with virtual machine (VM), so we are able to know what's going on (pretty old school, right?).

They are controlled by the following options in `Kconfig`:
```
#
# TTY Layer Configurations
#
# CONFIG_TTY_VT is not set
CONFIG_TTY_SERIAL=y
# CONFIG_TTY_SERIAL_TTYS0 is not set
CONFIG_TTY_SERIAL_TTYS1=y
# CONFIG_TTY_SERIAL_BAUD9600 is not set
CONFIG_TTY_SERIAL_BAUD115200=y
```

To enable VGA output, enable __`CONFIG_TTY_VT`__.

To enable serial output, enable __`CONFIG_TTY_SERIAL`__.
- Two ports are supported: `ttyS0` and `ttyS1`, they map to `CONFIG_TTY_SERIAL_TTYS0` and `CONFIG_TTY_SERIAL_TTYS1`, respectively. Only one of them should be enabled at one time.
- Two baud rate are supported: `9600` and `115200`, they map to `CONFIG_TTY_SERIAL_BAUD9600` and `CONFIG_TTY_SERIAL_BAUD115200`, respectively. Only one of them can be enabled at one time.
- For example, if the other end of serial cable is a Linux host that uses `/dev/ttyS1, 115200`, then the serial config at LegoOS side should use the combination of `CONFIG_TTY_SERIAL_TTYS1` and `CONFIG_TTY_SERIAL_BAUD115200`.

#### Setup Serial Connection

__Option 1: Virtual Machine__

If LegoOS is running within a virtual machine, you will be able to configure your hypervisor to save the serial output from LegoOS to a local host's file. In this setting, each port maps to one specific file, and baud rate does not matter. For `virsh + qemu` environment, you can add the following script to VM's description file. Please refer to other hypervisors' manual if you are not using `virsh + qemu`.

```
<serial type='file'>
  <source path='/root/LegoOS-ttyS0'/>
  <target port='0'/>
</serial>
<serial type='file'>
  <source path='/root/LegoOS-ttyS1'/>
  <target port='1'/>
</serial>

(Choose any pathname you see fit)
```

__Option 2: Physical Machine__

If LegoOS is running directly on a physical machine, you will need another machine to catch the serial output. These two servers can either be 1) directly connected by serial cable, or 2) connected through a __serial switch__.

In a direct serial connection setting, each LegoOS machine will need one peer physical machine to catch its output. This essentially increases the machine usage by 2x. Based on our own experience, __we highly recommend you setup a serial switch__.

## Install and Run

LegoOS's processor and memory manager _pretend_ as a Linux kernel by having all the necessary magic numbers at `bzimage` header. Thus, GRUB2 will treat LegoOS kernel as a normal Linux kernel. By doing so, LegoOS can leverage all existing boot options available.

Once you have successfully compiled the processor or memory manager, you can install the image simply by typing `make install`. After this, you will be able to find the LegoOS kernel image installed at `/boot` directory. For example:
```
[LegoOS git:(master)] $ ll /boot/vmlinuz-4.0.0-lego+
-rw-r--r--. 1 root root 1941056 Sep 27 17:41 /boot/vmlinuz-4.0.0-lego+
```

LegoOS pretends as a `Linux-4.0.0` to fool `glibc-2.17`, which somehow requires a pretty high version Linux kernel. To run LegoOS, you need to __reboot__ machine, and then boot into LegoOS kernel.

### 1P-1M
This section describes the case where we run LegoOS with only one processor manager and one memory manager, or __1P-1M__ setting. This is the simplest setting in LegoOS. This setting piggybacks a statically-linked user program binary into LegoOS image, thus we don't need another storage manager. The limitation is that only a simple user-program can be staticlly-linked and piggybacked (e.g., programs at `usr/`), because the difficulties of compiling a large program and kernel image size limitation.

This setting requires a special `Kconfig` option: `CONFIG_USE_RAMFS`, at both processor and memory. And this setting requires two physical machines (or virtual machines running on different physical host).


1. Network setting:
    - Set `CONFIG_FIT_LOCAL_ID` and `CONFIG_FIT_NR_NODES` properly at both processor and memory manager. For example, processor can use `CONFIG_FIT_LOCAL_ID=0, CONFIG_FIT_NR_NODES=2`, and memory can use `CONFIG_FIT_LOCAL_ID=1, CONFIG_FIT_NR_NODES=2`.
    - At processor manager, set the `CONFIG_DEFAULT_MEM_NODE` equals to the node ID of the memory manager. The `CONFIG_DEFAULT_STORAGE_NODE` will not have any effect. For example, use `CONFIG_DEFAULT_MEM_NODE=1`.
    - At memory manager, no need to setup default memory/storage node
2. At both processor and memory manager, open `.config`, find and enable `CONFIG_USE_RAMFS` option.
3. At memory manager, compile test user programs.
	```
	cd usr/
	make
	```
4. At memory manager, open `.config`, find `CONFIG_RAMFS_OBJECT_FILE`, and set it to the pathname to your test user program. __The user program has to be statically-complied.__ To start, you can set as follows:
	```
	CONFIG_USE_RAMFS=y
	CONFIG_RAMFS_OBJECT_FILE="usr/general.o"
	```

In 1P-1M setting, the above user program set at memory manager (`usr/general.o` here) will be executed automatically when processor and memory manager connected. Current LegoOS's ramfs option is limited to include only one user program.

#### Sample .config

We provid two `.config` samples for `1P-1M` setting. In these samples, we are using `usr/general.o` and `ttyS1 115200`. VGA terminal output is also enabled. You can find processor manager's output log [here](https://github.com/WukLab/LegoOS/tree/master/Documentation/configs/1P-1M-Processor-Output) (recorded while running LegoOS processor manager within VM).
- Processor
    - `make defconfig`
    - `cp Documentation/configs/1P-1M-Processor .config`
    - `make`
- Memory
    - `make defconfig`
    - `cp Documentation/configs/1P-1M-Memory .config`
    - `make`

### 1P-1M-1S
This section describes the case where we run LegoOS with one processor manager, one memory manager, and one storage manager, or __1P-1M-1S__ setting. This setting emulates the effect of breaking one monolithic server and connect the CPU, memory, and disk by network. This setting requires three physical machines, and there is no need for global resource managers (Note about VM: you will be able to run processor manager and memory manager within VM, but storage can not. Because VM setting produces unstable QPN).

#### Configurations
1. Network setting
    - Set node ID properly, for all processor, memory, and storage managers
    - At storage manager, modify `linux-modules/fit/fit_config.h`
    - At _both_ processor and memory manager
      - set `CONFIG_DEFAULT_MEM_NODE` equals to the node ID of the memory manager
      - set `CONFIG_DEFAULT_STORAGE_NODE` equals to the node ID of the storage manager

2. Make sure `CONFIG_USE_RAMFS` is __not__ configured at both processor and memory manager.
3. At processor manager, open `managers/processor/core.c` file, and find the function `procmgmt()`, type the name and arguments of the user program that you wish to run. The user program is at the storage node, you have to use the `absolute pathname` from the storage node. For example, to run TensorFlow:
   ```
   static int procmgmt(void *unused)
   {
            ...
         init_filename = "/usr/bin/python";
         argv_init[0] = init_filename;
         argv_init[1] = "/root/cifar10_main.py";
         ...

   ```

Our current way of running user program is very raw. Basically we manually specify the user program and arguments during compile time. This limits us to be able to test only one program during each run. LegoOS can not work with `/bin/bash`, but we have tried to use the basic `fork()+wait()` way to serialize testing.

#### Boot

After you have successfully configured and compiled the LegoOS images, you need to install the processor and memory managers and reboot these two machines. The following steps assume you have just finished compiling and tries to reboot:

1. Install processor manager into `/boot` of its own machine.
2. Install memory manager into `/boot` of its own machine.
3. Reboot only processor and memory machines into `vmlinux-4.0.0-lego`.
4. When both processor and memory machines hit `fit: Please wait for enough MAD...`, then at storage manager, do: __`insmod fit.ko`__. This may take around a minute.
5. At storage manager, after the above command return, do: __`insmod storage.ko`__.
6. You should be able to see many messages printed out after the above command return.

#### Sample .config

We provid two `.config` and `fit_config.h ` samples for the `1P-1M-1S` setting. To start, you can follow the below steps:
- Processor
    - `make defconfig`
    - `cp Documentation/configs/1P-1M-1S-Processor .config`
    - `make`
- Memory
    - `make defconfig`
    - `cp Documentation/configs/1P-1M-1S-Memory .config`
    - `make`
- Storage
    - `cp Documentation/configs-1P-1M-1S-fit_config.h linux-modules/fit/fit_config.h`
    - `cd linux-modules`
    - `make`

1P-1M-1S perfectly emulates the effect of disaggregating a single monolithic server. Unlike 1P-1M setting, this setting can run any user program, either dynamically-linked or statically-linked, as long as there is no missing syscall. But please be careful and patient while setting things up, any mistakes may lead to an unsuccessful run. Sorry for the inconvenience.

### Multiple Managers
To be able to run multiple managers, you will need at least five physical machines. Because now LegoOS will need global resource monitors (multiple monitors can co-exist). And due to our early implementation decisions, storage manager and global resource monitors can __not__ run on one physical server. For example, in a `1P-2M-1S` setting, you will need: one server for processor manager, two servers for memory managers, one for storage manager, and one for global resource monitors.

We will provide detailed tutorial on this soon.

### Virtual Machine
In general, you will be able run both processor and memory manager on VM without any issue. But we can not run storage manager within a VM. The reason is our network setting. We need to know peer's QP number (QPN) beforehand. While the QPN generated by a Linux which is running inside a VM, is not stable.

Overall, `1P-1M` can be tested with VM. With `1P-1M-1S` setting, the processor and memory manager can run inside VM, while storage manager has to run on physical machine.

#### VM Setup

It is recommended to have multiple CPU cores and several GB memory for each VM. The reason is LegoOS need at least two kernel threads which are pinned to cores to do network communication. For processor, if Victim Cache is configured, one more victim flush thread will be created.

For example, a simple basic configuration: 8 vCPUs, and 8GB memory.

#### InfiniBand

In order to run LegoOS on a VM, we need to export IB device from host to VM. And this VM must have exclusive access to this IB device. Please refer to Mellanox tutorials on this topic.
