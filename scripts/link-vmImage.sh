# Link objects selected by $(KBUILD_VMIMAGE_INIT) $(KBUILD_VMIMAGE_MAIN)
# Ordering when linking is important, and $(KBUILD_VMIMAGE_INIT) must be first.
#
# vmImage
#  ^
#  |
#  |
#  +--< $(KBUILD_VMIMAGE_INIT)
#  |    +--< init/version.o + more
#  |
#  +--< $(KBUILD_VMIMAGE_MAIN)
#  |    +--< drivers/built-in.o mm/built-in.o + more
#  |
#  +--< $(kallsymso) (see description in KALLSYMS section)

# Error out on error
set -e

# Nice output in kbuild format
# Will be supressed by "make -s"
info()
{
	if [ "${quiet}" != "silent_" ]; then
		printf "  %-7s %s\n" ${1} ${2}
	fi
}

# Create ${2} .o file with all symbols from the ${1} object file
kallsyms()
{
	info KSYM ${2}
	local kallsymopt;

	if [ -n "${CONFIG_HAVE_UNDERSCORE_SYMBOL_PREFIX}" ]; then
		kallsymopt="${kallsymopt} --symbol-prefix=_"
	fi

	if [ -n "${CONFIG_KALLSYMS_ALL}" ]; then
		kallsymopt="${kallsymopt} --all-symbols"
	fi

	if [ -n "${CONFIG_KALLSYMS_ABSOLUTE_PERCPU}" ]; then
		kallsymopt="${kallsymopt} --absolute-percpu"
	fi

	if [ -n "${CONFIG_KALLSYMS_BASE_RELATIVE}" ]; then
		kallsymopt="${kallsymopt} --base-relative"
	fi

	local aflags="${KBUILD_AFLAGS} ${KBUILD_AFLAGS_KERNEL}               \
		      ${NOSTDINC_FLAGS} ${LEGO_INCLUDE} ${KBUILD_CPPFLAGS}"

	local afile="`basename ${2} .o`.S"

	${NM} -n ${1} | scripts/kallsyms ${kallsymopt} > ${afile}
	${CC} ${aflags} -c -o ${2} ${afile}
}

# Link of vmImage
# ${1} - optional extra .o files
# ${2} - output file
vmImage_link()
{
	local lds="${objtree}/${KBUILD_LDS}"
	local objects

	${LD} -T ${lds} -o ${2}		\
		${KBUILD_VMIMAGE_INIT}	\
		--start-group		\
		${KBUILD_VMIMAGE_MAIN}	\
		--end-group		\
		${1}
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
	$NM -n $1 | grep -v '\( [aNUw] \)\|\(__crc_\)\|\( \$[adt]\)\|\( .L\)' > $2
}

cleanup()
{
	rm -f .version
	rm -f .version.old
	rm -f .tmp_kallsyms*
	rm -f .tmp_vmImage*
	rm -f built-in.o
	rm -f System.map
	rm -f vmImage
	rm -f .vmImage.cmd
}

# Enable Debug Mode; Print commands.
if [ "${KBUILD_VERBOSE}" = "1" ]; then
	set -x;
fi

##
# Clean
#
if [ "$1" == "clean" ]; then
	info CLEAN vmImage
	cleanup
	exit 0
fi

# We need access to CONFIG_ symbols
case "${KCONFIG_CONFIG}" in
*/*)
	. "${KCONFIG_CONFIG}"
	;;
*)
	# Force using a file from the current directory
	. "./${KCONFIG_CONFIG}"
esac

##
# LD
#

info GEN .version
if [ ! -r .version ]; then
	rm -f .version
	echo 1 > .version
else
	mv .version .version.old
	expr 0$(cat .version.old) + 1 >.version
fi

# Final build of init/
# Weird, but for correct version number
${MAKE} -f "${srctree}/scripts/Makefile.build" obj=init

kallsymso=""
kallsyms_vmImage=""
if [ -n "${CONFIG_KALLSYMS}" ]; then

	# kallsyms support
	# Generate section listing all symbols and add it into vmImage
	# It's a three step process:
	# 1)  Link .tmp_vmImage1 so it has all symbols and sections,
	#     but __kallsyms is empty.
	#     Running kallsyms on that gives us .tmp_kallsyms1.o with
	#     the right size
	# 2)  Link .tmp_vmImage2 so it now has a __kallsyms section of
	#     the right size, but due to the added section, some
	#     addresses have shifted.
	#     From here, we generate a correct .tmp_kallsyms2.o
	# 2a) We may use an extra pass as this has been necessary to
	#     woraround some alignment related bugs.
	#     KALLSYMS_EXTRA_PASS=1 is used to trigger this.
	# 3)  The correct ${kallsymso} is linked into the final vmImage.
	#
	# a)  Verify that the System.map from vmImage matches the map from
	#     ${kallsymso}.

	kallsymso=.tmp_kallsyms2.o
	kallsyms_vmImage=.tmp_vmImage2

	# step 1
	vmImage_link "" .tmp_vmImage1
	kallsyms .tmp_vmImage1 .tmp_kallsyms1.o

	# step 2
	vmImage_link .tmp_kallsyms1.o .tmp_vmImage2
	kallsyms .tmp_vmImage2 .tmp_kallsyms2.o

	# step 2a
	if [ -n "${KALLSYMS_EXTRA_PASS}" ]; then
		kallsymso=.tmp_kallsyms3.o
		kallsyms_vmImage=.tmp_vmImage3

		vmImage_link .tmp_kallsyms2.o .tmp_vmImage3

		kallsyms .tmp_vmImage3 .tmp_kallsyms3.o
	fi
fi

info LD vmImage
vmImage_link "${kallsymso}" vmImage 

info SYSMAP System.map
mksysmap vmImage System.map
