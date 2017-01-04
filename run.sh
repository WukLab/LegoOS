#
# Simple command to test the standalone kernel
#

qemu-system-x86_64 -s \
	-machine q35 \
	-cpu Nehalem \
	-kernel arch/x86/boot/bzImage \
	-m 16G \
	-monitor stdio \
	-serial file:output_ttyS0 \
	-serial file:output_ttyS1 \
	-smp cpus=24,cores=12,threads=2,sockets=2 \
	-numa node,cpus=0-11,mem=8G,nodeid=0 \
	-numa node,cpus=12-23,mem=8G,nodeid=1
