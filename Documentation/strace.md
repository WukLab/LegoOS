# Trace System Call

LegoOS includes a kernel version system call tracer. It is similar to strace, but in a much simplified form. The strace is only present in processor manager. It is controlled by the following Kconfig options (You need to enable `CONFIG_DEBUG_KERNEL` first):

```
#
# Processor Side Syscall Trace Options
#
CONFIG_STRACE=y
CONFIG_STRACE_PRINT_ON_ENTER=y
CONFIG_STRACE_PRINT_ON_LEAVE=y
CONFIG_STRACE_PRINT_ON_SPECIFIC=y
```

Explanations on Kconfig
- Once `CONFIG_STRACE` is enabled, the strace in kernel will be enabled to trace syscall. Here, trace means recording: a) number of syscall invocations, and b) syscall service time.
- Due to the huge amount of syscall activities, by default, the printing of each syscall is disabled. However, if you wish to print something on each syscall enter or exit, please enable `CONFIG_STRACE_PRINT_ON_ENTER` or `CONFIG_STRACE_PRINT_ON_LEAVE`, respectively.
- Further, sometimes you may only want to trace certain syscalls, say `mmap()`. Then you will find `CONFIG_STRACE_PRINT_ON_SPECIFIC` very useful. Once enabled, only certain active syscalls will be printed. These set of active system calls is controlled by `managers/processor/strace/core.c:strace_printable_nr[]`, which is an array indexed by syscall number. You need to change the array at compile time.

Note
- Source code files at: `managers/processor/strace/`.
- The strace will record all threads' activities of a process. Even if a thread exit, its record is kept and accumulated when strace does the final calculation.
- You can print strace info during runtime.

## Print

Call `exit_processor_strace()` to print this process's strace info. You can use `git grep exit_processor_strace` to find the current users of this function.

## Mechanisms

The detailed implementation mechanism is described in this [document](https://lastweek.github.io/lego/kernel/profile_strace/).