#include <net/lwip/netif.h>

struct jif_pkt {
        int jp_len;
	char *jp_data;
};

void	jif_input(struct netif *netif, void *va);
err_t	jif_init(struct netif *netif);
