# Profiling

This document describes the profiling facilities included in the LegoOS kernel. The top-level Kconfig option `CONFIG_PROFILING`. Once you enable this Kconfig, you will be able to see its sub-Kconfigs. Each Kconfig option controls its own facility. Both processor and memory managers are able to use most of the profiling facilities.

```
#
# Lego Kernel Profiling
#
CONFIG_PROFILING=y
CONFIG_PROFILING_KERNEL_HEATMAP=y
CONFIG_PROFILING_POINTS=y
CONFIG_PROFILING_BOOT=y
CONFIG_PROFILING_BOOT_RPC=y
```

## Profile Points

Here comes my favorite feature of LegoOS. LegoOS profile points facility is added to trace specific functions, or even a small piece of code. It is added in the hope that it can help to find performance bottleneck. It is added in the hope that it can reduce the redundant coding chore.

Setting:
- Kconfig: `CONFIG_PROFILING_POINTS`
- Source Code: `kernel/profile/point.c` and `include/lego/profile_point.h`
- Sample Usage: [pcache zerofill](https://github.com/WukLab/LegoOS/blob/master/managers/processor/pcache/fault.c#L324)
- When: during runtime
- Impact: will impact all performance

For detailed usage, please refer to this [document](https://lastweek.github.io/lego/kernel/profile_points/).

## RPC

Remote Procedure Call (RPC) is the most used function in LegoOS. The whole kernel relies on RPC. Our RPC is provided by LITE (SOSP'17). In LegoOS, we constructed a simple RPC profiling benchmark to stress the underlying network stack, to get some baseline numbers. Since the RPC requester mostly is processor manager, current code can work only between processor and memory managers, and processor is the requester.

Settings
- Kconfig: `CONFIG_PROFILING_BOOT_RPC`
- Source Code: `managers/processor/rpc_profile.c`
- When: happen once during processor manager boot time
- Impact: will _not_ impact runtime performance

There are three variations in the profiling:
- Number of sending threads
- Send message length in bytes
- Reply message length in bytes

The function names in the source code file pretty much explains eveything. Please check the source code for more information. Currently the only caller is `manager_init()`.

<details><summary>Sample Output</summary>
<p>

```
[ 1052.876762] RPC Profile. [Peer node: 1. nr_threads: 1. nr_run/case: 100000. send: 32 reply 4]
[ 1053.503665]     CPU 8 Profile: s  32-r   4. Avg: 4201 ns.
[ 1053.603510] RPC Profile. [Peer node: 1. nr_threads: 2. nr_run/case: 100000. send: 32 reply 4]
[ 1054.505394]     CPU10 Profile: s  32-r   4. Avg: 5019 ns.
[ 1054.511219]     CPU12 Profile: s  32-r   4. Avg: 5019 ns.
[ 1054.603418] RPC Profile. [Peer node: 1. nr_threads: 4. nr_run/case: 100000. send: 32 reply 4]
[ 1056.398311]     CPU16 Profile: s  32-r   4. Avg: 9949 ns.
[ 1056.404134]     CPU14 Profile: s  32-r   4. Avg: 9950 ns.
[ 1056.410145]     CPU20 Profile: s  32-r   4. Avg: 9950 ns.
[ 1056.416156]     CPU18 Profile: s  32-r   4. Avg: 9950 ns.
[ 1056.422169] RPC Profile. [Peer node: 1. nr_threads: 1. nr_run/case: 100000. send: 32 reply 4096]
[ 1057.252033]     CPU22 Profile: s  32-r4096. Avg: 6288 ns.
[ 1057.257857] RPC Profile. [Peer node: 1. nr_threads: 2. nr_run/case: 100000. send: 32 reply 4096]
[ 1058.560195]     CPU 8 Profile: s  32-r4096. Avg: 8970 ns.
[ 1058.566019]     CPU 2 Profile: s  32-r4096. Avg: 8970 ns.
[ 1058.603049] RPC Profile. [Peer node: 1. nr_threads: 4. nr_run/case: 100000. send: 32 reply 4096]
[ 1061.190695]     CPU14 Profile: s  32-r4096. Avg: 17877 ns.
[ 1061.196614]     CPU16 Profile: s  32-r4096. Avg: 17878 ns.
[ 1061.202723]     CPU10 Profile: s  32-r4096. Avg: 17878 ns.
[ 1061.208831]     CPU12 Profile: s  32-r4096. Avg: 17877 ns.
[ 1061.214939] RPC Profile. [Peer node: 1. nr_threads: 1. nr_run/case: 100000. send: 4200 reply 4]
[ 1062.039174]     CPU18 Profile: s4200-r   4. Avg: 6163 ns.
[ 1062.044998] RPC Profile. [Peer node: 1. nr_threads: 2. nr_run/case: 100000. send: 4200 reply 4]
[ 1063.101353]     CPU22 Profile: s4200-r   4. Avg: 6486 ns.
[ 1063.107176]     CPU20 Profile: s4200-r   4. Avg: 6486 ns.
[ 1063.202625] RPC Profile. [Peer node: 1. nr_threads: 4. nr_run/case: 100000. send: 4200 reply 4]
[ 1065.248505]     CPU10 Profile: s4200-r   4. Avg: 12459 ns.
[ 1065.254417]     CPU 2 Profile: s4200-r   4. Avg: 12460 ns.
[ 1065.260525]     CPU12 Profile: s4200-r   4. Avg: 12460 ns.
[ 1065.266632]     CPU 8 Profile: s4200-r   4. Avg: 12460 ns.
[ 1065.272742] RPC Profile. [Peer node: 1. nr_threads: 1. nr_run/case: 100000. send: 4200 reply 4096]
[ 1066.305186]     CPU14 Profile: s4200-r4096. Avg: 8227 ns.
[ 1066.402329] RPC Profile. [Peer node: 1. nr_threads: 2. nr_run/case: 100000. send: 4200 reply 4096]
[ 1067.701967]     CPU18 Profile: s4200-r4096. Avg: 8996 ns.
[ 1067.707791]     CPU16 Profile: s4200-r4096. Avg: 8996 ns.
[ 1067.802200] RPC Profile. [Peer node: 1. nr_threads: 4. nr_run/case: 100000. send: 4200 reply 4096]
[ 1070.392868]     CPU 8 Profile: s4200-r4096. Avg: 17907 ns.
[ 1070.398789]     CPU20 Profile: s4200-r4096. Avg: 17907 ns.
[ 1070.404896]     CPU22 Profile: s4200-r4096. Avg: 17907 ns.
[ 1070.411005]     CPU 2 Profile: s4200-r4096. Avg: 17907 ns.
[ 1071.048445]     CPU 0 Profile: pcache_miss. Avg: 6313 ns.
[ 1071.664770]     CPU 0 Profile: pcache_flush. Avg: 6105 ns.
```
</p>
</details>

## TLB Shootdown

Setting:
- Kconfig: `CONFIG_PROFILING_BOOT`
- Source Code: `arch/x86/mm/tlb.c` and `kernel/profile/boot.c`
- When: happen once during manager boot time
- Impact: will _not_ impact runtime performance

There are two variations in the profiling:
- Number of remote cores
- Number of pages to flush on the remote core

Same as Linux, our flush ceiling is 33 pages. Once the pages to flush is more than 33, we flush the whole TLB.

<details><summary>Sample output</summary>
<p>

```
x86: Booted up 2 nodes, 24 CPUs
Profile (#0) TLB Shootdown at CPU0 ...
 FLUSH_ALL #nr_cpus
 ... nr_cpus:  23 latency:      7584 ns
 ... nr_cpus:  22 latency:      6165 ns
 ... nr_cpus:  21 latency:      6017 ns
 ... nr_cpus:  20 latency:      5939 ns
 ... nr_cpus:  19 latency:      5509 ns
 ... nr_cpus:  18 latency:      4980 ns
 ... nr_cpus:  17 latency:      4937 ns
 ... nr_cpus:  16 latency:      4619 ns
 ... nr_cpus:  15 latency:      4567 ns
 ... nr_cpus:  14 latency:      4438 ns
 ... nr_cpus:  13 latency:      4025 ns
 ... nr_cpus:  12 latency:      3570 ns
 ... nr_cpus:  11 latency:      3317 ns
 ... nr_cpus:  10 latency:      3496 ns
 ... nr_cpus:   9 latency:      3407 ns
 ... nr_cpus:   8 latency:      3214 ns
 ... nr_cpus:   7 latency:      3320 ns
 ... nr_cpus:   6 latency:      2617 ns
 ... nr_cpus:   5 latency:      2576 ns
 ... nr_cpus:   4 latency:      1868 ns
 ... nr_cpus:   3 latency:      1823 ns
 ... nr_cpus:   2 latency:      1560 ns
 ... nr_cpus:   1 latency:      1472 ns
 ... nr_cpus:   0 latency:        89 ns
 CPU0 -> CPU1 #ceiling=33 #nr_pages
 ... nr_pages:   1 latency:      1823 ns
 ... nr_pages:   2 latency:      1719 ns
 ... nr_pages:   3 latency:      1717 ns
 ... nr_pages:   4 latency:      1798 ns
 ... nr_pages:   5 latency:      1781 ns
 ... nr_pages:   6 latency:      1979 ns
 ... nr_pages:   7 latency:      2021 ns
 ... nr_pages:   8 latency:      2151 ns
 ... nr_pages:   9 latency:      2126 ns
 ... nr_pages:  10 latency:      2315 ns
 ... nr_pages:  11 latency:      2416 ns
 ... nr_pages:  12 latency:      2481 ns
 ... nr_pages:  13 latency:      2595 ns
 ... nr_pages:  14 latency:      2632 ns
 ... nr_pages:  15 latency:      2824 ns
 ... nr_pages:  16 latency:      2801 ns
 ... nr_pages:  17 latency:      2928 ns
 ... nr_pages:  18 latency:      2906 ns
 ... nr_pages:  19 latency:      3307 ns
 ... nr_pages:  20 latency:      3155 ns
 ... nr_pages:  21 latency:      3270 ns
 ... nr_pages:  22 latency:      3439 ns
 ... nr_pages:  23 latency:      3344 ns
 ... nr_pages:  24 latency:      3608 ns
 ... nr_pages:  25 latency:      3520 ns
 ... nr_pages:  26 latency:      3713 ns
 ... nr_pages:  27 latency:      3698 ns
 ... nr_pages:  28 latency:      4068 ns
 ... nr_pages:  29 latency:      3947 ns
 ... nr_pages:  30 latency:      4128 ns
 ... nr_pages:  31 latency:      4161 ns
 ... nr_pages:  32 latency:      4214 ns
 ... nr_pages:  33 latency:      4353 ns
 ... nr_pages:  34 latency:      4387 ns
 ... nr_pages:  35 latency:      4505 ns
 ... nr_pages:  36 latency:      4482 ns
 ... nr_pages:  37 latency:      4852 ns
 ... nr_pages:  38 latency:      4734 ns
 ... nr_pages:  39 latency:      4924 ns
 ... nr_pages:  40 latency:      4951 ns
 ... nr_pages:  41 latency:      4996 ns
Profile TLB Shootdown at CPU0 ... done
```
</p>
</details>
