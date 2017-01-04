#
# Simple command to test the standalone kernel
#

set -e

#
# Create a new directory to store the serial output
# from printk().
#
OUTPUT_DIR="test-output"
if [ -e $OUTPUT_DIR ]; then
	if [ -f $OUTPUT_DIR ]; then
		echo "ERROR: $MOUNT_POINT is not a directly"
		exit 1
	fi
else
	mkdir -p $OUTPUT_DIR
fi

LEGO_KERNEL="arch/x86/boot/bzImage"
LINUX_KERNEL="/boot/vmlinuz-3.10.0-327.el7.x86_64"
KERNEL_PARAM="console=ttyS0 earlyprintk=serial,ttyS0,115200"

LEGO_SERIAL="-serial file:$OUTPUT_DIR/ttyS0 -serial file:$OUTPUT_DIR/ttyS1"
LINUX_SERIAL="-serial stdio"

KERNEL=$LEGO_KERNEL
SERIAL=$LEGO_SERIAL

# $ ./run linux
if [ "$1" == "linux" ]; then
	KERNEL=$LINUX_KERNEL
	SERIAL=$LINUX_SERIAL
fi

qemu-system-x86_64 -s \
	-kernel $KERNEL -append "$KERNEL_PARAM" \
	$SERIAL \
	-cpu Haswell \
	-m 16G \
	-nographic \
	-monitor stdio \
	-smp cpus=24,cores=12,threads=2,sockets=2 \
	-numa node,cpus=0-11,mem=8G,nodeid=0 \
	-numa node,cpus=12-23,mem=8G,nodeid=1
