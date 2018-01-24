# General
Our pcache and victim cache are allocated and arranged as a big array. As for
pcache we look at it in a *cache set view*, which means consecutive pcache lines
are not relevant in natual. As for victim cache, we simply treat it as a big array
and walk through it one by one.

# Cache Allocation
The alloc/free of both pcache and victim cache are simple: each pcache line or
victim cache line has a Allocated bit to indicate if this line is free or not.
The Allocated bit is manipulated by atomic bit operations, thus SMP safe. This
further implies we do not need another spinlock to guard allocation.

However, other activities (explict eviction, background sweep, etc.)
may walk through the cache lines
at the same time of allocation, a single Allocated bit is not enough. Because
an allocated cache line will need some initial setup (prep_new_pcache: refcount),
thus there is a small time gap between allocated and usable.
Other activities must wait the cache line to be usable, and then do further things.

To solve this issue, there two possible solutions:
1) Add another bit: Usable, which is set once initial setup is done.
   In this case, functions excluding alloction code should always check if the Usable
   bit is set or not. If it is set, this means the cache line is safe for further operations
   If not, but with Allocated bit set, this means the cache line is under setup in another core.
   If not, and Allocated bit is not set, this means this cache line is simply free.

2) Add allocated cache lines to a list, and functions excluding allocation code will
   only look into cache lines within this list. In other words, others will only
   look into surely allocated cache lines.

Both solutions try to avoid others looking into unmature cache lines in SMP CPU.
The rule is simple: function should NOT look into data that is not supposed to be seen.
The cache line that has Allocated bit set but under setup is a typical example here.

Both pcache and victim cache need cache replacement, including algorithms and
mechanisms. Actually, if implemented in code, it is very similar to LRU code
in Linux (vmscan.c, swap.c, etc.). It 

