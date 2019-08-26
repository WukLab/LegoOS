# LegoOS-CloudLab Configurations

This is a manual about deploying LegoOS on CloudLab machines. For LegoOS, visit https://github.com/WukLab/LegoOS for more information.

### Creating Experiments

- We recommend using 3 interconnected bare metal machines with Ubuntu 14.04 and 3.11.1 Linux kernel. Higher Ubuntu version (e.g. 16.04) has the `gcc` version that is too advanced to compile the 3.11.1 kernel.
- The `r320` hardware in APT-Utah cluster supports  Infiniband, which LegoOS requires.  See http://docs.cloudlab.us/hardware.html for more information about `r320` .
- A disk image with 3.11.1 kernel and Ubuntu 14.04 could be accessed with `urn:publicid:IDN+apt.emulab.net+image+pennnetworks-PG0:Ubuntu14-3.11` on CloudLab.

### Software Environments

- To fetch information about the Infiniband links, use `sudo apt install infiniband-diags` to install the package which is able to do so.
- Run `sudo /etc/init.d/openibd force-restart` to run infiniband. If the command does not exist, try rebooting the machines.
- The official driver of NIC in LegoOS does not support `r320`. Some modification was done. Use `git clone https://github.com/fyc1007261/LegoOS` to fetch the customized version.
- Follow the instructions on https://github.com/Wuklab/LegoOS to setup the three monitors. For getting LID, `ibstat` command instead of `iblinkinfo` is recommended.

### Conducting Experiments

##### For processor and memory nodes

- After making any changes, such as changing the application to run or change some kernel code, `make` then `make install`.
- After `make install`, go to `/boot/grub/grub.cfg` (or `boot/grub2/grub.cfg` on CentOS) 
  - Modify `linux` and `initrd` to `linux16` and `initrd16`.
  - Configure the exCache size.
- Reboot.

##### For storage node

- After booting into Linux, use `ibstat` to ensure that Infiniband is working. If not, `sudo /etc/init.d/openibd force-restart`.

- When `ibstat` shows that the link is *up* instead of *polling*, then it is the time to enter processor and storage nodes.
- In `LegoOS/linux-modules`, type `sudo make fit_install`. After it returns, type `sudo make storage_install`.

### Some Tricks

-  It is recommended to boot into memory node 2 or 3 seconds earlier than processor node, which will make it less likely for the memory node to fail.

- LegoOS installer will modify the boot loader. The default `make install` will attach the image of LegoOS to "Ubuntu" when booting. To enter the real Ubuntu, you may select the `Linux 3.11.1`.