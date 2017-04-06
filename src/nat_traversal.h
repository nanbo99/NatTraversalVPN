/*
 * Nat traversal header.
 * liu-weifei@qq.com
 */

#ifndef _NAT_TRAVERSAL_BASE_
#define _NAT_TRAVERSAL_BASE_

/* struct sockaddr */
#include <netinet/in.h>

#define PROXY_SERVER_IP	"45.62.113.42"
#define LISTEN_PORT0    1024				/* common command. */
#define LISTEN_PORT1    1025				/* common command. */
#define LISTEN_PORT2    1026				/* TURN Relay Server. */

#define MAX_IP_SIZE    16

#define NAT_TIMEOUT     5

#define MAX_UDP_SOCKET_OPEN     10

#define log_out(s...) do {                           			\
	fprintf(stdout, s);                                         \
	fprintf(stdout, "\n");                                      \
	fflush(stdout);                                             \
} while (0)

enum ROLE {
    ROLE_Client,
    ROLE_Server,
    ROLE_Proxy,
    ROLE_MAX,
};

enum TRAVERSAL_COMM {
	/* Traversal command. */
	TRAVERSAL_GETNATTYPE,
	TRAVERSAL_GETSERVER,
	TRAVERSAL_REGISTER,			/* Register punch hole server. */
	TRAVERSAL_REGISTER_TURN,	/* Register turn server. */
	TRAVERSAL_PUNCHHOLE,
	TRAVERSAL_TURN,
	/* punch hole synchronous command. */
	TRAVERSAL_SYN,
	TRAVERSAL_SYNACK,
	TRAVERSAL_ACK,
	TRAVERSAL_MAX
};

int get_socket(void *buf, size_t len);
int nat_traversal(enum ROLE role, int sock, struct sockaddr_in *remote_sockaddr, int retrytimes);
int register_socket(enum ROLE role, int sockfd, int listen_port);

int nat_traversal_init(enum ROLE role, int ctrlfd);
int nat_traversal_deinit();


#endif /* _NAT_TRAVERSAL_BASE_ */
