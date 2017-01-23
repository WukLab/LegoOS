/*
 * Network server main loop -
 * serves IPC requests from other environments.
 */

//#include <lego/x86.h>
#include <lego/string.h>
#include <lego/kernel.h>
#include <lego/err.h>
#include <lego/types.h>
#include <lego/net.h>
#include <lego/mm.h>
#include <lego/pci.h>
//#include <lego/ns.h>
//#include <lego/lib.h>

//#include <arch/thread.h>
#include "net/lwip/init.h"
#include <net/lwip/sockets.h>
#include <net/lwip/netdb.h>
#include <net/lwip/netif.h>
#include <net/lwip/stats.h>
#include <net/lwip/sys.h>
#include <net/lwip/tcp.h>
#include <net/lwip/udp.h>
#include <net/lwip/dhcp.h>
#include <net/lwip/tcpip.h>
#include <net/lwip/stats.h>
#include <net/lwip/netbuf.h>
#include <net/netif/etharp.h>
#include "lwip/lego/jif/jif.h"

//#include "ns.h"

#define IP "10.0.2.15"
//#define IP "128.46.115.199"
#define MASK "255.255.255.0"
#define DEFAULT "10.0.2.2"
//#define DEFAULT "128.46.115.1"

struct netif nif;

#define debug 0

#if 0
static bool buse[QUEUE_SIZE];
static int next_i(int i) { return (i+1) % QUEUE_SIZE; }
static int prev_i(int i) { return (i ? i-1 : QUEUE_SIZE-1); }

static void *get_buffer(void) 
{
    void *va;

    int64_t i;
    for (i = 0; i < QUEUE_SIZE; i++)
        if (!buse[i]) break;

    if (i == QUEUE_SIZE) {
        panic("NS: buffer overflow");
        return 0;
    }

    va = (void *)(REQVA + i * PGSIZE);
    buse[i] = 1;

    return va;
}

static void put_buffer(void *va) 
{
    int64_t i = ((uint64_t)va - REQVA) / PGSIZE;
    buse[i] = 0;
}
#endif

static void lwip_init_local(struct netif *nif, void *if_state,
        uint32_t init_addr, uint32_t init_mask, uint32_t init_gw)
{
    struct ip_addr ipaddr, netmask, gateway;
    ipaddr.addr  = init_addr;
    netmask.addr = init_mask;
    gateway.addr = init_gw;

    if (0 == netif_add(nif, &ipaddr, &netmask, &gateway,
                if_state,
                jif_init,
                ip_input))
        panic("lwip_init: error in netif_add %p\n", nif);

	pr_debug("added netif %p\n", nif);
    netif_set_default(nif);
    netif_set_up(nif);
}

void serve_init(uint32_t ipaddr, uint32_t netmask, uint32_t gw)
{
    int r;

    lwip_init();
    //tcpip_init(NULL, NULL);
    
    //dhcp_init();

    lwip_init_local(&nif, NULL, ipaddr, netmask, gw);

    struct in_addr ia = {ipaddr};
    pr_debug("ns: %02x:%02x:%02x:%02x:%02x:%02x"
            " bound to static IP %s\n",
            nif.hwaddr[0], nif.hwaddr[1], nif.hwaddr[2],
            nif.hwaddr[3], nif.hwaddr[4], nif.hwaddr[5],
            inet_ntoa(ia));

    pr_debug("NS: TCP/IP initialized.\n");
}

#if 0
struct st_args {
    int32_t reqno;
    uint32_t whom;
    union Nsipc *req;
};

static void serve_thread(uint64_t a) 
{
    struct st_args *args = (struct st_args *)a;
    union Nsipc *req = args->req;
    int r;

    switch (args->reqno) {
        case NSREQ_ACCEPT:
            {
                struct Nsret_accept ret;
                r = lwip_accept(req->accept.req_s, &ret.ret_addr,
                        &ret.ret_addrlen);
                memmove(req, &ret, sizeof ret);
                break;
            }
        case NSREQ_BIND:
            r = lwip_bind(req->bind.req_s, &req->bind.req_name,
                    req->bind.req_namelen);
            break;
        case NSREQ_SHUTDOWN:
            r = lwip_shutdown(req->shutdown.req_s, req->shutdown.req_how);
            break;
        case NSREQ_CLOSE:
            r = lwip_close(req->close.req_s);
            break;
        case NSREQ_CONNECT:
            r = lwip_connect(req->connect.req_s, &req->connect.req_name,
                    req->connect.req_namelen);
            break;
        case NSREQ_LISTEN:
            r = lwip_listen(req->listen.req_s, req->listen.req_backlog);
            break;
        case NSREQ_RECV:
            // Note that we read the request fields before we
            // overwrite it with the response data.
            r = lwip_recv(req->recv.req_s, req->recvRet.ret_buf,
                    req->recv.req_len, req->recv.req_flags);
            break;
        case NSREQ_SEND:
            r = lwip_send(req->send.req_s, &req->send.req_buf,
                    req->send.req_size, req->send.req_flags);
            break;
        case NSREQ_SOCKET:
            r = lwip_socket(req->socket.req_domain, req->socket.req_type,
                    req->socket.req_protocol);
            break;
        case NSREQ_INPUT:
            jif_input(&nif, (void *)&req->pkt);
            r = 0;
            break;
        default:
            pr_debug("Invalid request code %d from %08x\n", args->whom, args->req);
            r = -E_INVAL;
            break;
    }

    if (r == -1) {
    	pr_debug("error %d\n", r);
    }

    put_buffer(args->req);
    //kfree(args);
}
#endif

#if !NO_SYS
int client(void)
{
	int sockfd, portno, n, i;
	struct sockaddr_in serv_addr;
	struct hostent *server;

	char buffer[256];

	for (i = 0; i < 256; i++) {
		buffer[i] = 'a';
	}

	portno = 6666;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) 
		pr_debug("ERROR opening socket");
	server = gethostbyname("128.46.115.144");
	if (server == NULL) {
		pr_debug("ERROR, no such host\n");
		return 0;
	}
	serv_addr.sin_family = AF_INET;
	memcpy((char *)server->h_addr, 
			(char *)&serv_addr.sin_addr.s_addr,
			server->h_length);
	serv_addr.sin_port = htons(portno);

	if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
		pr_debug("ERROR connecting");
	n = write(sockfd,buffer,10);
	if (n < 0) 
		pr_debug("ERROR writing to socket");
	n = read(sockfd,buffer,255);
	if (n < 0) 
		pr_debug("ERROR reading from socket");
	pr_debug("%s\n",buffer);
	close(sockfd);
	return 0;
}
#endif

#if 0
int server(void)
{
	int sockfd, newsockfd, portno;
	socklen_t clilen;
	char buffer[256];
	struct sockaddr_in serv_addr, cli_addr;
	int n;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) 
		error("ERROR opening socket");
	bzero((char *) &serv_addr, sizeof(serv_addr));
	portno = 6666;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);
	if (bind(sockfd, (struct sockaddr *) &serv_addr,
				sizeof(serv_addr)) < 0) 
		error("ERROR on binding");
	listen(sockfd,5);
	clilen = sizeof(cli_addr);
	newsockfd = accept(sockfd, 
			(struct sockaddr *) &cli_addr, 
			&clilen);
	if (newsockfd < 0) 
		error("ERROR on accept");
	bzero(buffer,256);
	n = read(newsockfd,buffer,255);
	if (n < 0) error("ERROR reading from socket");
	pr_debug("Here is the message: %s\n",buffer);
	n = write(newsockfd,"I got your message",18);
	if (n < 0) error("ERROR writing to socket");
	close(newsockfd);
	close(sockfd);
	return 0; 
}
#endif

static err_t tcp_connected_cb(void *arg, struct tcp_pcb *tpcb, err_t err)
{
	pr_debug("tcp_connected_cb %d\n", err);
}

static err_t tcp_sent_cb(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
	pr_debug("successfully sent %d bytes\n", len);
}

static test_tcp(void)
{
	struct tcp_pcb *tpcb;
	u16 port;
	struct ip_addr ipaddr;
	err_t ret;
	int i, length;
	char buf[256];
	char *buf1 = alloc_page();
	struct jif_pkt pkt;

	for (i = 0; i < 256; i++) {
		buf[i] = 'a';
	}

	ipaddr.addr = inet_addr("128.46.115.144");

	//while(1) {
#if 0
		/* Check link state, e.g. via MDIO communication with PHY */
		if(link_state_changed()) {
			if(link_is_up()) {
				netif_set_link_up(&nif);
			} else {
				netif_set_link_down(&nif);
			}
		}
		/* Check for received frames, feed them to lwIP */
		lock_interrupts();
		struct pbuf* p = queue_try_get(&queue);
		unlock_interrupts();
		if(p != NULL) {
			LINK_STATS_INC(link.recv);

			if(nif.input(p, &nif) != ERR_OK) {
				pbuf_free(p);
			}
		}
#endif
		tpcb = tcp_new();

		length = pci_receive_packet(buf1);
		pkt.jp_data = buf1;
		pkt.jp_len = length;
		pr_debug("pci received %d bytes pakcet\n", length);
		if (length > 0) {
			jif_input(&nif, (void *)(&pkt));
		}

		port = 6666;
		tcp_connect(tpcb, &ipaddr, port, tcp_connected_cb);
		pr_debug("after connect %p\n", tpcb);

	for (i = 0; i < 1; i++) {
		while (1) {
		length = pci_receive_packet(buf1);
		pkt.jp_data = buf1;
		pkt.jp_len = length;
		if (length > 0) {
			jif_input(&nif, (void *)(&pkt));
			break;
		}
		}

		//tcp_tmr();

		ret = tcp_write(tpcb, buf, 10, 0);
		pr_debug("tcp wrote %d\n", ret);

		length = pci_receive_packet(buf1);
		pkt.jp_data = buf1;
		pkt.jp_len = length;
		pr_debug("2 pci received %d bytes pakcet\n", length);
		if (length > 0) {
			jif_input(&nif, (void *)(&pkt));
		}

		ret = tcp_output(tpcb);
		pr_debug("tcp output %d\n", ret);

		length = pci_receive_packet(buf1);
		pkt.jp_data = buf1;
		pkt.jp_len = length;
		pr_debug("3 pci received %d bytes pakcet\n", length);
		if (length > 0) {
			jif_input(&nif, (void *)(&pkt));
		}

		tcp_sent(tpcb, tcp_sent_cb);
		/* Cyclic lwIP timers check */
	//	sys_check_timeouts();
		tcp_tmr();

		length = pci_receive_packet(buf1);
		pkt.jp_data = buf1;
		pkt.jp_len = length;
		pr_debug("4 pci received %d bytes pakcet\n", length);
		if (length > 0) {
			jif_input(&nif, (void *)(&pkt));
		}

	}
}

void init_lwip(void) 
{
	serve_init(inet_addr(IP),
			inet_addr(MASK),
			inet_addr(DEFAULT));
	test_tcp();
	//client();
	//serve();
}

#if 0
void umain(int argc, char **argv)
{
    envid_t ns_envid = sys_getenvid();

    binaryname = "ns";

    // fork off the input thread which will poll the NIC driver for input
    // packets
    input_envid = fork();
    if (input_envid < 0)
        panic("error forking");
    else if (input_envid == 0) {
        input(ns_envid);
        return;
    }

    // fork off the output thread that will send the packets to the NIC
    // driver
    output_envid = fork();
    if (output_envid < 0)
        panic("error forking");
    else if (output_envid == 0) {
        output(ns_envid);
        return;
    }

    // lwIP requires a user threading library; start the library and jump
    // into a thread to continue initialization.
    thread_init();
    thread_create(0, "main", tmain, 0);
    thread_yield();
    // never coming here!
	tmain(0);
}
#endif
