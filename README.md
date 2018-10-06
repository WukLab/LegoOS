# LegoOS

![Status](https://img.shields.io/badge/Version-Experimental-green.svg)
![License](https://img.shields.io/aur/license/yaourt.svg?style=popout)
![ISA](https://img.shields.io/badge/ISA-x86--64-yellow.svg)

[//]: “%![Platform](https://img.shields.io/badge/Platform-Linux-red.svg)%”

LegoOS is a disseminated, distributed operating system built for hardware resource disaggregation. LegoOS is a research operating system being built from scratch and released by researchers from Purdue University. LegoOS splits traditional operating system functionalities into loosely-coupled monitors, and run those monitors directly on hardware device. You can find more details from our OSDI'18 paper.

[[Paper]](https://engineering.purdue.edu/~yiying/LegoOS-OSDI18.pdf) [[Slides]](https://www.usenix.org/conference/osdi18/presentation/shan)
[[Tech Notes]](http://lastweek.io)

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

## Configure and Compile
__CAVEAT:__ Configure, compile, and run a LegoOS kernel is similar to test a new Linux kernel. You need to have root access the machine. And the whole process may involve multiple machine power cycles. __Before you proceed, make sure you have some methods (e.g., `IPMI`) to monitor and reboot _remote_ physical machine.__ It is possible to just use virtual machines, but with a constrained setting (described below). If you running into any issues, please don’t hesitate to contact us!

For processor and memory manager, LegoOS uses the standard `Kconfig` way. For storage and global resource managers, which are built as Linux kernel modules, LegoOS uses a header file to manually typeset all configurations. We will describe the details below.

Each manager or monitor should be configured and complied at its own machine's directory. To be able to run LegoOS, you need at least two physical machines.

### Configure Processor and Memory Manager
The default setting of LegoOS won't require any knowledge of Kconfig, all you need to do is changing the generated `.config` file. If you want to hack those Kconfig files, we recommend you to read the [documentation](https://www.kernel.org/doc/Documentation/kbuild/kconfig-language.txt) from Linux kernel and some other online resources.

And note that this is just the __general__ configuration steps. If you want to configure for specific settings, such as running with only one processor and one memory manager, please refer to the following sections for more detailed steps.

1. `make defconfig`: After this doing, a `.config` file will be created locally.

2. Configure Process Manager: Open `.config`, find and delete the following line:
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

### Configure Linux Modules
Storage manager, global resource monitors, and their network stack are linux kernel modules. They can only run on `Linux-3.11.1`. Because their network stack is only supported at this kernel version.

Once you have switched `Linux-3.11.1`, just go to `linux-modules/` and type `make`, which will compile all the following modules (and their config files):

| Module | Config File|
|:--|:--|
|Storage Manager|`linux-modules/storage/CONFIG_LEGO_STORAGE.h`|
|Global Resource Monitors|`linux-modules/monitor/include/monitor_config.h`|
|FIT| `linux-modules/fit/fit_config.h`|

### Configure Network
Network setup is essential to have a successful connection. The detailed tutorial on this topic will available soon.

### Configure LegoOS's Output

#### Configure `printk()`
LegoOS output debug messages (`printk()`) to two sources: 1) serial port, 2) VGA terminal. Mostly only the output to serial port is useful, because this can be saved and later being examined. The output to VGA is useful when we run LegoOS with virtual machine (VM).

Both of them are controlled by the following options in Kconfig:
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

To enable VGA output, enable `CONFIG_TTY_VT`.

To enable serial output, enable `CONFIG_TTY_SERIAL`.
- Two ports are supported: `ttyS0` and `ttyS1`, they map to `CONFIG_TTY_SERIAL_TTYS0` and `CONFIG_TTY_SERIAL_TTYS1`, respectively. Only one of them can be enabled at one time.
- Two baud rate are supported: `9600` and `115200`, they map to `CONFIG_TTY_SERIAL_BAUD9600` and `CONFIG_TTY_SERIAL_BAUD115200`, respectively. Only one of them can be enabled at one time.

#### Setup Serial Connection

__Option 1: VM__

If LegoOS is running within a VM, you will be able to configure your hypervisor to save the serial output from LegoOS to a local host's file. For `virsh` environment, you can add the following script to VM's description file. Other hypervisors' setting is out the scope of this tutorial.
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

In a direct serial connection setting, each LegoOS machine will need one peer physical machine to catch its output. This essentially increases the machine usage by 2x. Based on our own experience, we recommend you to setup a serial switch. The setup of serial switch is out the scope of this tutorial.

## Install and Run

LegoOS's processor and memory manager _pretend_ as a Linux kernel by having all the necessary magic numbers at image header. Thus, GRUB2 will treat LegoOS kernel as a normal Linux kernel. By doing so, LegoOS can leverage all existing boot options available.

Once you have successfully compiled the processor or memory manager, you can install the image simply by typing `make install`. After this, you will be able to find the LegoOS kernel image installed at `/boot` directory. For example:
```
[LegoOS git:(master)] $ ll /boot/vmlinuz-4.0.0-lego+
-rw-r--r--. 1 root root 1941056 Sep 27 17:41 /boot/vmlinuz-4.0.0-lego+
```

LegoOS pretends as a `Linux-4.0.0` to fool `glibc-2.17`, which somehow requires a pretty high version Linux kernel. To run LegoOS, you need to __reboot__ machine, and then boot into LegoOS kernel.

### 1P-1M
This section describes the case where we run LegoOS with only one processor manager and one memory manager, or __1P-1M__ setting. This setting requires a special `Kconfig` option: `CONFIG_USE_RAMFS`, at both processor and memory. And this setting requires two physical machines.

1. Network setting:
    - Set node ID properly at both processor and memory manager
    - At processor manager, set the `CONFIG_DEFAULT_MEM_NODE` equals to the node ID of the memory manager. The `CONFIG_DEFAULT_STORAGE_NODE` will not have any effect.
    - At memory manager, both the above config options will not have any effect.
2. At both processor and memory manager, open `.config`, find and enable `CONFIG_USE_RAMFS` option.
3. At memory manager, open `.config`, find `CONFIG_RAMFS_OBJECT_FILE`, and set it to the pathname to your test user program. __The user program has to be statically-complied.__ To start, you can set as follows:
```
CONFIG_USE_RAMFS=y
CONFIG_RAMFS_OBJECT_FILE="usr/general.o"
```

In 1P-1M setting, the above user program set at memory manager (`usr/general.o` here) will be executed automatically when processor and memory manager connected. Current LegoOS's ramfs option is limited to include only one user program.

### 1P-1M-1S
This section describes the case where we run LegoOS with one processor manager, one memory manager, and one storage manager, or __1P-1M-1S__ setting. This setting emulates the effect of breaking one monolithic server and connect the CPU, memory, and disk by network. And this setting requires three physical machines.

1. Network setting:
    - Set node ID properly, at processor, memory, and storage manager
    - At _both_ processor and memory manager, set the `CONFIG_DEFAULT_MEM_NODE` equals to the node ID of the memory manager, set the `CONFIG_DEFAULT_STORAGE_NODE` equals to the node ID of the storage manager.
    - At memory manager,

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
}
```

1P-1M-1S perfectly emulates the effect of disaggregating a single monolithic server. Unlike 1P-1M setting, this setting can run any user program, either dynamically-linked or statically-linked, as long as there is no missing syscall. But please be careful and patient while setting things up, any mistakes may lead to an unsuccessful run. Sorry for the inconvenience.

### Multiple Managers
To be able to run multiple managers, you will need at least five physical machines. Because now LegoOS will need global resource monitors (multiple monitors can co-exist). And due to our early implementation decisions, storage manager and global resource monitors can __not__ run on one physical server. For example, in a `1P-2M-1S` setting, you will need: one server for processor manager, two servers for memory managers, one for storage manager, and one for global resource monitors.

We will provide detailed tutorial on this soon.

### Virtual Machine
In general, you will be able run both processor and memory manager on VM without any issue. But we can not run storage manager within a VM. The reason is our network setting. We need to know peer's QP number (QPN) beforehand. While the QPN generated by a Linux which is running inside a VM, is not stable.

Overall, 1P-1M can be tested with VM only. With 1P-1M-1S setting, the processor and memory manager can run inside VM, while storage manager has to run on physical machine.
