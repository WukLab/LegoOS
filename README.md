# LegoOS

![Status](https://img.shields.io/badge/Version-Experimental-green.svg)
![License](https://img.shields.io/aur/license/yaourt.svg?style=popout)

LegoOS is a disseminated, distributed operating system designed and built for resoucre disaggregation. LegoOS is one of the implementation of the Splitkernel. We can find more internal design of LegoOS from our OSDI'18 paper.

[[Paper](https://engineering.purdue.edu/~yiying/LegoOS-OSDI18.pdf)] [[Slides]()]

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
