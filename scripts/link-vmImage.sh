#
# Link objects selected by $(KBUILD_VMIMAGE_INIT) $(KBUILD_VMIMAGE_MAIN)
# Ordering when linking is important, and $(KBUILD_VMIMAGE_INIT) must be first.
#
# vmImage
#  ^
#  |
#  |
#  +-< $(KBUILD_VMIMAGE_INIT)
#  |   + init/version.o + more
#  |
#  +-< $(KBUILD_VMIMAGE_MAIN)
#  |   +--< drivers/built-in.o mm/built-in.o + more
#  |

set -e

info()
{
	if [ "${quiet}" != "silent_" ]; then
		printf "  %-7s %s\n" ${1} ${2}
	fi
}

vmImage_link()
{
	local lds="${objtree}/${KBUILD_LDS}"

	${LD} -T ${lds} -o ${1}		\
		${KBUILD_VMIMAGE_INIT}	\
		--start-group		\
		${KBUILD_VMIMAGE_MAIN}	\
		--end-group
}

# System.map is used by module-init tools and some debugging
# tools to retrieve the actual addresses of symbols in the kernel.
#
# The second row specify the type of the symbol:
#   A = Absolute
#   B = Uninitialised data (.bss)
#   C = Common symbol
#   D = Initialised data
#   G = Initialised data for small objects
#   I = Indirect reference to another symbol
#   N = Debugging symbol
#   R = Read only
#   S = Uninitialised data for small objects
#   T = Text code symbol
#   U = Undefined symbol
#   V = Weak symbol
#   W = Weak symbol
#   Corresponding small letters are local symbols
#
# For System.map filter away:
#   a - local absolute symbols
#   U - undefined global symbols
#   N - debugging symbols
#   w - local weak symbols
mksysmap()
{
	$NM -n $1 > $2
}

cleanup()
{
	rm -f System.map
	rm -f vmImage
	rm -f arch/${SRCARCH}/boot/System.map
	rm -f arch/${SRCARCH}/boot/vmImage
}

# Enable Debug Mode; Print commands.
if [ "${KBUILD_VERBOSE}" = "1" ]; then
	set -x;
fi

if [ "$1" == "${LD}" ]; then
	info LD vmImage
	vmImage_link vmImage

	info GEN .version
	if [ ! -r .version ]; then
		rm -f .version
		echo 1 > .version
	else
		mv .version .version.old
		expr 0$(cat .version.old) + 1 >.version
	fi

	info SYSMAP System.map
	mksysmap vmImage System.map

	#
	# Make a copy to boot directory
	#
	cp vmImage arch/${SRCARCH}/boot/
	cp System.map arch/${SRCARCH}/boot/
fi

if [ "$1" == "clean" ]; then
	info CLEAN vmImage
	cleanup
	exit 0
fi
