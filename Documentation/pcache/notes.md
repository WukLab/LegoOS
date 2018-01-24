# General
Our pcache and victim cache are allocated and arranged as a big array. As for
pcache we look at it in a *cache set view*, which means consecutive pcache lines
are not relevant in natual. As for victim cache, we simply treat it as a big array
and walk through it one by one.

# Cache Allocation
The alloc/free of both pcache and victim cache are simple: each pcache line or
victim cache line has a `Allocated` bit to indicate if this line is free or not.
The `Allocated` bit is manipulated by atomic bit operations, thus SMP safe. This
further implies that we do not need another spinlock to guard allocation.

However, other activities such as explict eviction, background sweep may walk
through the cache lines at the same time of cache allocation, a single `Allocated`
bit is not enough. Because an allocated cache line will need some initial setup,
such as reset refcount, clear flags (prep_new_pcache),
thus there is a small time gap between Allocated bit being set and the cache line
being truly safe to use. Other activities must wait the cache line to be usable,
and then they can do further operations on this cache line.

To solve this race condition, there two possible solutions:
1) Add another bit: `Usable`, which is set once initial setup is done.
   In this case, functions excluding alloction code should always check if the `Usable`
   bit is set or not. a) If it is set, this means the cache line is safe for further operations
   b) If not, and `Allocated` bit is set, this means the cache line is under setup in another core,
   We should skip it.
   c) If not, and `Allocated` bit is not set, this means this cache line is simply free.
   We should skip it.

2) Add allocated cache lines to a list (such as LRU list), and functions excluding allocation
   code will only look into cache lines within this list. In other words, others will only
   look into surely usable cache lines.

Both solutions try to avoid others looking into *un-mature* cache lines in SMP envorinment.
The rule is simple: function should *NOT* look into data that is not supposed to be seen.
The cache line that has Allocated bit set but under setup is a typical case.

As an example, the physical page allocator, page reclaim, page cache in Linux are implemented with
the second solution. Pages freshly allocated will be added a LRU list or page cache own list.
And page reclaim code will only look into pages within the LRU list, it won't go through all
physical pages to do so. The reason for Linux to do so is simple: kernel can not scan the whole
physical pages to find out pages to operate.

`Pcache:` When it comes to pcache, the second solution also seems a better choice. Because in our envision,
pcache will have high-associativity such as 64 or 128. It will have bad performance if our eviction
algorithm or sweep thread need to go through every cache lines within a set to find out candidates,
while there might be only 1 or 2 allocated lines.

`Victim Cache:` When it comes to victim cache, the first solution seems a better choice. Because victim cache only
a few cache lines, e.g., 8 or 16. This means a whole victim cache line walk is fast. While the list
deletion and addtion seem may introduce some unnecessary overhead. It is all about trade-off.

These choices affect the usage of pcache and victim cache, mostly the eviction code.
