# LegoOS Counter and Software Watchdog

This document describes various unified counters and software watchdog. The following sections will describe those counter printing functions:

- `dump_ib_stats()`
- `print_pcache_events()`
- `print_memory_manager_stats()`
- `print_thpool_stats()`


## Counters

LegoOS has many build-in counters. They are so yummy at debugging phase and it also helps a lot during actual testing. Combined with [profile points](https://github.com/WukLab/LegoOS/blob/master/Documentation/profile.md), these two provide a very systematic view of the system performance.

At both processor and memory manager, the counter facility is controlled by the top Kconfig option: `CONFIG_COUNTER`. Each manager has its own set of sub-Kconfig options, as listed below:

- Processor
```
CONFIG_COUNTER=y
CONFIG_COUNTER_FIT_IB=y
CONFIG_COUNTER_PCACHE=y
```

- Memory
```
#
# Lego Kernel Counters
#
CONFIG_COUNTER=y
CONFIG_COUNTER_FIT_IB=y
CONFIG_COUNTER_MEMORY_HANDLER=y
CONFIG_COUNTER_THPOOL=y
 ```

### FIT Network Counters
Both processor and memory has this type of counters. It is controlled by `CONFIG_COUNTER_FIT_IB`. If will affect every single RPC call. It will record the following stats:

- `nr_ib_send_reply`: number of send_reply invocations (RPC)
- `nr_ib_send`: number of send only invocations
- `nr_bytes_tx`: number of bytes transmited
- `nr_bytes_rx`: number of bytes received
- `nr_recvcq_cqes`: number of CQEs processed by each polling thread. This depend on `CONFIG_FIT_NR_RECVCQ_POLLING_THREADS`.

In order to print, call `dump_ib_stats()` at `net/lego/fit_ibapi.c`.

### Processor pcache Counters
pcache counters is controlled by `CONFIG_COUNTER_PCACHE`. pcache events are similar to linux vm events. It includes many critical activities. The implemention is separated into two major parts:

- `include/processor/pcache_stat.h`: counter type and helpers
- `managers/processor/pcache/stat.c`: human readable text description of each counter

In order to print, call `print_pcache_events()` at `managers/processor/pcache/stat.c`.

### Memory Handler Counters

This set of counters are in memory manager only. They are controlled by `CONFIG_COUNTER_MEMORY_HANDLER`. It count memory handler events such as `handle_mmap()`, `handle_fork()`. Similar to pcache couters, its implementation is separated into three major parts:

- `include/memory/stat.h`
- `managers/memory/stat.c`
- `managers/memory/core.c`

In order to print, call `print_memory_manager_stats()` at `managers/memory/stat.c`.

### Memory Thread Pool Counters

Memory manager has configurable worker threads to handle incoming messages. There is only one global network polling threads. Each worker thread has their own work queue.

This set of counters try to capture:
- number of works consumed by each worker
- average queuing delay of each work on the queue
- queuing delay distribution

It's main implementation is embedded in the `thpool_worker_func()`. Each inline function name pretty much explains itself.

In order to print, call `print_thpool_stats()` at `managers/memory/core.c`.

<details><summary>Sample Output</summary>
<p>

```
    worker[0]
        max_nr_queued=1 current_nr_queued=0 in_handler=NO
        nr_handled=1000004 nr_thpool_reqs=1000004
        total_queuing_ns: 196481292 avg_queuing_ns:196 max_queuing_ns: 787 min_queuing_ns: 124
         [  0,   5)    100.0%
         [  5,  10)    0.0%
         [ 10,  15)    0.0%
         [ 15,  20)    0.0%
         [ 20,  25)    0.0%
         [ 25,  30)    0.0%
         [ 30,  35)    0.0%
         [ 35,  40)    0.0%
         [ 40,  45)    0.0%
         [ 45,  50)    0.0%
         [ 50,  55)    0.0%
         [ 55,  60)    0.0%
         [ 60,  65)    0.0%
         [ 65,  70)    0.0%
         [ 70,  75)    0.0%
         [ 75,  80)    0.0%
         [ 80,  85)    0.0%
         [ 85,  90)    0.0%
         [ 90,  95)    0.0%
         [ 95, 100)    0.0%
         [100, 105)    0.0%
         [105, 110)    0.0%
         [110, 115)    0.0%
         [115, 120)    0.0%
         [120, 125)    0.0%
         [125, 130)    0.0%
         [130, 135)    0.0%
         [135, 140)    0.0%
         [140, 145)    0.0%
         [145, 150)    0.0%
         [150, 155)    0.0%
         [155, 160)    0.0%
         [160, 165)    0.0%
         [165, 170)    0.0%
         [170, 175)    0.0%
         [175, 180)    0.0%
         [180, 185)    0.0%
         [185, 190)    0.0%
         [190, 195)    0.0%
         [195, 200)    0.0%
```
</p>
</details>

## Software Watchdog

LegoOS includes a very simple software-based watchdog. The original purpose to build it is to debug memory worker threads hang: Once the watchdog detects that a worker thread has not progressed for sometime, it will send an IPI to that worker thread core to dump its call stack.

Along the way, it turns out watchdog comes very handy when we want to print various counters periodically.

The top level implementatin is in `managers/watchdog.c`. It is controlled by `CONFIG_SOFT_WATCHDOG` and `CONFIG_SOFT_WATCHDOG_INTERVAL_SEC`.

Processor's `watchdog_print` is a very simple print function. Memory's version does more: other than printing, it will also call `ht_check_worker()` to check if there are any workers hang.

Side note: if you are not satisfied with the default `CONFIG_SOFT_WATCHDOG_INTERVAL_SEC` range, just hardcode the preferrd number into `managers/watchdog.c`.