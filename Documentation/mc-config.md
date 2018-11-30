# Memory Manager Configurations

This file describes fine-tuning configurations of memory manager. For other generic configurations, please refer to [Profiling](https://github.com/WukLab/LegoOS/tree/master/Documentation/profile.md) and [Counters and Watchdog](https://github.com/WukLab/LegoOS/tree/master/Documentation/counters.md).

## Thread Pool

Memory manager is using a thread pool, or thpool, to handle all incoming messages. There are one or more network polling thread (controlled by `CONFIG_FIT_NR_RECVCQ_POLLING_THREADS`, default is 1), the polling threads will hand over new requests to `worker threads`.

The number of worker threads is controlled by `CONFIG_THPOOL_NR_WORKERS`, default is 1.
Each worker thread is identical.

We also have a fixed thpool buffers used to send replies. We have managed buffers because we want to a-sync send out network requests (by post to QP without poll CQ). So handlers can just return without worrying their buffer got corrupted.

The number of thpool buffer is defined by [`NR_THPOOL_BUFFER`](https://github.com/WukLab/LegoOS/blob/master/include/memory/thread_pool.h#L24).

There is no mapping between thpool worker and thpool buffer. Workers can use any buffer.

### Code

- [thpool_callback()](https://github.com/WukLab/LegoOS/blob/master/managers/memory/core.c#L429) is called when network polling threads get new request. This function will allocate a new thpool buffer, select a new worker thread, and enqueue the new job into its work queue.
- [thpool_worker_func()](https://github.com/WukLab/LegoOS/blob/master/managers/memory/core.c#L329) and [thpool_worker_handler()](https://github.com/WukLab/LegoOS/blob/master/managers/memory/core.c#L140) are the ultimate dispatch functions. There are a lot profiling code included.

## Replication

There are two options:
- `CONFIG_REPLICATION_VMA`: enable if you want to log VMA operations. The ops will be sent over to remote storage.
- `CONFIG_REPLICATION_MEMORY_BATCH_NR`: determines the number of log-structured batch flush size. Whenever this memory manager receives this amount of pcache flush from processor manager, this memory manager will performs a batch flush to remote storage.