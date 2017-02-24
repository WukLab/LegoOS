#ifndef _LEGO_NET_H_
#define _LEGO_NET_H_

void init_lwip(void);

#ifdef CONFIG_INFINIBAND
extern int mad_got_one;
int lego_ib_init(void);
int ib_mad_init(void);
int ib_cache_setup(void);
#else
static inline int lego_ib_init(void) { return 0; }
static inline int ib_mad_init(void) { return 0; }
static inline int ib_cache_setup(void) { return 0; }
#endif

#endif
