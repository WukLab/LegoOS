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
