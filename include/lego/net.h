#ifndef _LEGO_NET_H_
#define _LEGO_NET_H_

void init_lwip(void);

#ifdef CONFIG_INFINIBAND
int lego_ib_init(void);
#else
static inline int lego_ib_init(void) { return 0; }
#endif

#endif
