The kernel's command-line parameters
====================================

The following is a consolidated list of the kernel parameters as
implemented by the __setup(), core_param() and module_param() macros
and sorted into English Dictionary order (defined as ignoring all
punctuation and sorting digits before letters in a case insensitive
manner), and with descriptions where known.

The kernel parses parameters from the kernel command line up to "--";
if it doesn't recognize a parameter and it doesn't contain a '.', the
parameter gets passed to init: parameters with '=' go into init's
environment, others are passed as command line arguments to init.
Everything after "--" is passed as an argument to init.

In addition, the following text indicates that the option::

	BUGS=	Relates to possible processor bugs on the said processor.
	KNL	Is a kernel start-up parameter.
	BOOT	Is a boot loader parameter.

Parameters denoted with BOOT are actually interpreted by the boot
loader, and have no meaning to the kernel directly.

Note that ALL kernel parameters listed below are CASE SENSITIVE, and that
a trailing = on the name of any parameter states that that parameter will
be entered as an environment variable, whereas its absence indicates that
it will appear as a kernel argument readable via /proc/cmdline by programs
running once the system is up.

The number of kernel parameters is not limited, but the length of the
complete command line (parameters including spaces etc.) is limited to
a fixed number of characters. This limit depends on the architecture
and is between 256 and 4096 characters. It is defined in the file
./include/asm/setup.h as COMMAND_LINE_SIZE.

Finally, the [KMG] suffix is commonly described after a number of kernel
parameter values. These 'K', 'M', and 'G' letters represent the _binary_
multipliers 'Kilo', 'Mega', and 'Giga', equalling 2^10, 2^20, and 2^30
bytes respectively. Such letter suffixes can also be entirely omitted:

.. include:: parameters.txt
   :literal:
