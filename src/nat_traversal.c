/*
 * Nat traversal functions.
 * liu-weifei@qq.com
 */

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include "nat_traversal.h"
#include "nat_type.h"

#include "uthash.h"


const char *role_str[ROLE_MAX] = {
	"Client",
	"Server",
	"Proxy"
};

const char *cmd_str[TRAVERSAL_MAX] = {
	"GetNatType",
	"GetServer",
	"RegisterServer",
	"RegisterTURNServer",
	"Punchhole",
	"TURN",
	"SYN",
	"SYNACK",
	"ACK"
};

struct TraversalMsg {
    uint32_t role;
    uint32_t cmd;
    uint32_t port;
    char ip[MAX_IP_SIZE];
    char padding[4];
};

struct socket_data {
    int socket;						/* Key of hash table socket_hash_table. */
    int role;
    int port;						/* Key of hash table port_hash_table. */
    int need_relay;
    int timeout;
    pthread_mutex_t rlock, wlock;
    struct sockaddr_in dest_addr;
    UT_hash_handle hh;
};

/* time out thread id. */
static pthread_t client_thread_id = 0;
static pthread_t server_thread_id = 0;
static int nat_type = -NAT_TYPE_MAX;
static int app_role = ROLE_Client;
static struct socket_data *socket_hash_table = NULL;

int send_udp_package(int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen) {
    ssize_t ret;
    struct socket_data *sd = NULL;
    HASH_FIND_INT(socket_hash_table, &sockfd, sd);
    assert(sd != NULL);
    pthread_mutex_lock(&sd->wlock);
    sd->timeout = NAT_TIMEOUT;
    ret = sendto(sockfd, buf, len, flags, 
				 sd->role == ROLE_Client ? 
				 (struct sockaddr*)&sd->dest_addr : 
				 dest_addr, 
				 sd->role == ROLE_Client ? 
				 sizeof(sd->dest_addr) : 
				 addrlen);
    pthread_mutex_unlock(&sd->wlock);
    return ret;
}

int recv_udp_package(int sockfd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen) {
    ssize_t ret;
    struct socket_data *sd = NULL;
    HASH_FIND_INT(socket_hash_table, &sockfd, sd);
    assert(sd != NULL);
    pthread_mutex_lock(&sd->rlock);
    sd->timeout = NAT_TIMEOUT;
    ret = recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    pthread_mutex_unlock(&sd->rlock);
    return ret;
}

int sendmessage(int sock, struct sockaddr_in *remote_sockaddr, struct TraversalMsg *msg) {
	if(sendto(sock, msg, sizeof(struct TraversalMsg), 0, 
						(struct sockaddr *)remote_sockaddr, 
						sizeof(*remote_sockaddr)) < 0) {
		log_out("line %d, %s: sendto: %s\n", __LINE__, __FUNCTION__, strerror(errno));
		return -1;
	}
	return 0;
}

int recvmessage(int sock, struct sockaddr_in *remote_sockaddr, struct TraversalMsg *msg) {
	struct sockaddr_in sender_sockaddr;
	socklen_t addrlen = sizeof(sender_sockaddr);
	if(recvfrom(sock, msg, sizeof(struct TraversalMsg), 0, 
			(struct sockaddr *)&sender_sockaddr, &addrlen) < 0) {
		log_out("line %d, %s: recvfrom: %s\n", __LINE__, __FUNCTION__, strerror(errno));
		return -1;
	}
	if (sender_sockaddr.sin_addr.s_addr != remote_sockaddr->sin_addr.s_addr ||
		sender_sockaddr.sin_port != remote_sockaddr->sin_port) {
		log_out("line %d, recvfrom: recv data from different addr!\n", __LINE__);
		return -1;
	}
	return 0;
}

/*
handshake state  (Client			Server)
handshake state 0(reset state		reset state)
handshake state 1(SYN sent			SYN sent)
handshake state 2(SYN receivd		SYN receivd)
handshake state 3(SYNACK receivd	NULL)
handshake state 4(NULL				ACK receivd)
 */
int nat_traversal(enum ROLE role, int sock, struct sockaddr_in *remote_sockaddr, int retrytimes) {
	int times = 0, done = 0;
	struct TraversalMsg msg;
	struct timeval tv;
	if (role >= ROLE_MAX) return -1;
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(struct timeval));
	for(times = 0; times < retrytimes; times++) {
		int i;
		// 0. send SYN.
		msg.role = role;
		msg.cmd = TRAVERSAL_SYN;
		if (sendmessage(sock, remote_sockaddr, &msg) < 0) {
			log_out("line %d, sendmessage: error happend, will try again!\n", __LINE__);
			continue;
		}
		
		// 1. Server send SYNACK, and Client wait SYNACK.
		if (role == ROLE_Server) {
			msg.role = role;
			msg.cmd = TRAVERSAL_SYNACK;
			if(sendmessage(sock, remote_sockaddr, &msg) < 0) {
				log_out("line %d, sendmessage: error happend, will try again!\n", __LINE__);
				continue;
			}
		} else if (role == ROLE_Client) {
			if (recvmessage(sock, remote_sockaddr, &msg) < 0 || 
				(msg.cmd != TRAVERSAL_SYN && msg.cmd != TRAVERSAL_SYNACK)) {
				log_out("line %d, recvmessage: error happend, will try again!\n", __LINE__);
				continue;
			}
		}
		
		// 2. Client send ACK, and Server wait ACK.
		msg.role = role;
		msg.cmd = TRAVERSAL_ACK;
		if (role == ROLE_Client && sendmessage(sock, remote_sockaddr, &msg) < 0) {
			log_out("line %d, sendmessage: error happend, will try again!\n", __LINE__);
			continue;
		} else if (role == ROLE_Server) {
			if (recvmessage(sock, remote_sockaddr, &msg) < 0 || 
				(msg.cmd != TRAVERSAL_SYN && msg.cmd != TRAVERSAL_ACK)) {
				log_out("line %d, recvmessage: error happend, will try again!\n", __LINE__);
				continue;
			}
		}
		
		// All things done.
		done = 1;
		break;
	}
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(struct timeval));
	return done > 0 ? 0 : -1;
}


static const char fake_response[20];
void *nat_traversal_client_thread(void *param) {
	struct socket_data *sd = NULL;
    for(;;) {
        // send heart beat, bad package will dropped by shadowVPN.
        for(sd = socket_hash_table; sd != NULL && !sd->need_relay; sd = sd->hh.next) {
        	if(sd->timeout <= 0) {
	        	assert(sd->dest_addr.sin_port != 0);
			    send_udp_package(sd->socket, fake_response, sizeof(fake_response), 0, 
			    					(struct sockaddr*)&sd->dest_addr, sizeof(sd->dest_addr));
	        } else {
            	sd->timeout--;
		    }
    	}
    	sleep(1);
    }
}

void *nat_traversal_server_thread(void *param) {
	int ret, cbsock, sockopt = 1, flags;
	struct sockaddr_in remote_sockaddr, client_sockaddr;
	struct socket_data *sd = NULL;
	
	cbsock = socket(AF_INET, SOCK_STREAM, 0);
	
	memset(&remote_sockaddr, 0, sizeof(remote_sockaddr));
	remote_sockaddr.sin_family = AF_INET;
	remote_sockaddr.sin_port = htons(LISTEN_PORT0);
	inet_aton(PROXY_SERVER_IP, &remote_sockaddr.sin_addr);
	
	// 0. Server register in Proxy.
	if(setsockopt(cbsock, SOL_SOCKET, SO_KEEPALIVE, &sockopt, sizeof(sockopt)) < 0) {
		log_out("line %d, setsockopt, %s\n", __LINE__, strerror(errno));
		ret = -1;
		goto nat_traversal_server_thread_err_out;
	}
	
	log_out("connect to nat proxy(ip: %s, port: %d)\n", PROXY_SERVER_IP, LISTEN_PORT0);
	if(connect(cbsock, (struct sockaddr*)&remote_sockaddr, sizeof(remote_sockaddr)) < 0) {
		log_out("line %d, connect, %s\n", __LINE__, strerror(errno));
		ret = -1;
		goto nat_traversal_server_thread_err_out;
	}
	
	struct TraversalMsg msg;
	msg.role = ROLE_Server;
	msg.cmd = TRAVERSAL_REGISTER;
	
	// long live tcp connection register.
	send(cbsock, &msg, sizeof(msg), 0);
	
    for(;;) {
        if ((ret = recv(cbsock, &msg, sizeof(msg), 0)) < 0) {
			log_out("line %d, recv, %s\n", __LINE__, strerror(errno));
			continue;
		} else if(ret == 0) {
			log_out("line %d, recv, remote server closed!\n", __LINE__);
			break;
		}
		log_out("%s: role: %s, cmd: %s, ip: %s, port: %d\n", __FUNCTION__,
				role_str[msg.role], cmd_str[msg.cmd], msg.ip, msg.port);
		if(msg.role == ROLE_Proxy && msg.cmd == TRAVERSAL_PUNCHHOLE) {
			log_out("Recv punch hole request!\n");
			
			sd = socket_hash_table;
			//TODO: using the socket which port match with msg.port to do nat traversal
			// for ( ... ) {
			// 	   ...
			// }
			
			flags = fcntl(sd->socket, F_GETFL, 0);
			if (flags == -1 || -1 == fcntl(sd->socket, F_SETFL, (flags & ~O_NONBLOCK))) {
				printf("%s: fcntl: %s\n", __FUNCTION__, strerror(errno));
				continue;
			}
			
			memset(&client_sockaddr, 0, sizeof(client_sockaddr));
			client_sockaddr.sin_family = AF_INET;
			client_sockaddr.sin_port = htons(msg.port);
			inet_aton(msg.ip, &client_sockaddr.sin_addr);
			
			assert(sd != NULL);
			log_out("Punching hole...");
			
			if (nat_traversal(ROLE_Server, sd->socket, &client_sockaddr, 10) < 0) {
				log_out("failed!\n");
			} else {
				log_out("success!\n");
			}
			
			flags = fcntl(sd->socket, F_GETFL, 0);
			if (flags == -1 || -1 == fcntl(sd->socket, F_SETFL, flags | O_NONBLOCK)) {
				printf("%s: fcntl: %s\n", __FUNCTION__, strerror(errno));
			}
			
			// free all lock.
			pthread_mutex_unlock(&sd->rlock);
			pthread_mutex_unlock(&sd->wlock);
		} else if(msg.role == ROLE_Proxy && msg.cmd == TRAVERSAL_TURN) {
			// TODO: keep udp port connection with Nat Proxy Server.
			// Client send heart beat to nat proxy server, and proxy server relay it to Server.
		}
    }
    ret = 0;
nat_traversal_server_thread_err_out:
	close(cbsock);
	return (void*)ret;
}

int register_socket(enum ROLE role, int sockfd, int listen_port) {
    int ret, need_relay = 0;
    struct socket_data *sd;
    struct sockaddr_in remote_sockaddr, server_sockaddr;
    
    log_out("%s: enter, role: %d\n", __FUNCTION__, role);
    
    memset(&remote_sockaddr, 0, sizeof(remote_sockaddr));
	remote_sockaddr.sin_family = AF_INET;
	remote_sockaddr.sin_port = htons(LISTEN_PORT0);
	inet_aton(PROXY_SERVER_IP, &remote_sockaddr.sin_addr);
	
    if(role == ROLE_Client) {
    	struct TraversalMsg msg, reply;
		struct timeval tv;
		tv.tv_sec = 2;
		tv.tv_usec = 0;
		setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(struct timeval));
		
		log_out("Get Server Infomation from (%s:%d)!\n", PROXY_SERVER_IP, LISTEN_PORT0);
		msg.role = ROLE_Client;
		msg.cmd = TRAVERSAL_GETSERVER;
		msg.port = listen_port;
		if(sendmessage(sockfd, &remote_sockaddr, &msg) < 0 || 
			recvmessage(sockfd, &remote_sockaddr, &reply) < 0) {
			log_out("Error when get server addr!\n");
			return -1;
		}
		log_out("reply: role: %s, cmd: %s, ip: %s, port: %d\n", role_str[reply.role], 
				cmd_str[reply.cmd], reply.ip, reply.port);
		
		// for TURN, server_addr is Nat Proxy Server's addr
		// Nat Proxy Server Relay all udp package to true server.
		memset(&server_sockaddr, 0, sizeof(server_sockaddr));
		server_sockaddr.sin_family = AF_INET;
		server_sockaddr.sin_port = htons(reply.port);
		inet_aton(reply.ip, &server_sockaddr.sin_addr);
		
		// Setup udp connection with server.
		if(reply.cmd == TRAVERSAL_TURN) {
			// TODO: is there anything to do?
			need_relay = 1;
		} else {
			log_out("Punching hole...");
			nat_traversal(app_role, sockfd, &server_sockaddr, 10);
			if (nat_traversal(app_role, sockfd, &server_sockaddr, 10) < 0) {
				log_out("failed!\n");
			} else {
				log_out("success!\n");
			}
		}
		
		tv.tv_sec = 2;
		tv.tv_usec = 0;
		setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(struct timeval));
    } else if(role == ROLE_Server) {
    	// For Server, nat_type must get first, NAT_None don't need nat traverse.
		assert(nat_type >= 0 && nat_type < NAT_TYPE_MAX);
		if(nat_type == NAT_None)
			return 0;
    	// udp connection register.
    	struct TraversalMsg msg;
		msg.role = ROLE_Server;
		msg.cmd = nat_type == NAT_Symmetric ? TRAVERSAL_REGISTER_TURN : TRAVERSAL_REGISTER;
		msg.port = listen_port;
		if(sendmessage(sockfd, &remote_sockaddr, &msg) < 0) {
			log_out("Error when register server's udp connection!\n");
		}
    } else {
    	log_out("%s: Error, Bad role(%s)!\n", __FUNCTION__, role_str[role]);
		return -1;
    }
    
    // add to hash table.
    sd = calloc(1, sizeof(struct socket_data));
    if(sd < 0) return -1;
    sd->socket = sockfd;
    sd->role = role;
    sd->port = listen_port;
    sd->need_relay = need_relay;
    sd->timeout = NAT_TIMEOUT;
    if(role == ROLE_Client)
    	sd->dest_addr = server_sockaddr;
    pthread_mutex_init(&sd->rlock, NULL);
    pthread_mutex_init(&sd->wlock, NULL);
    
    HASH_ADD_INT(socket_hash_table, socket, sd);
    
    /*
     * Server's udp socket will be locked until punch hole is success.
     */
    if(role == ROLE_Server) {
    	pthread_mutex_lock(&sd->rlock);
    	pthread_mutex_lock(&sd->wlock);
    }
    
    return 0;
}

int nat_traversal_init(enum ROLE role) {
	int ret;
	nat_type = request_nat_type(PROXY_SERVER_IP, LISTEN_PORT0, LISTEN_PORT1);
	app_role = role;
	
	log_out("%s: %s's Nat type is: %s\n", __FUNCTION__, 
			role == ROLE_Server ? "Server" : "Client", nat_type2str(nat_type));
	
	if(nat_type < 0 || nat_type >= NAT_TYPE_MAX) return -1;
	
	// Client keep udp channel open.
	if(role == ROLE_Client && !client_thread_id) {
		ret = pthread_create(&client_thread_id, NULL, 
								nat_traversal_client_thread, NULL);
	}
	// Server keep connection with Nat Proxy Server.
	if(role == ROLE_Server && !server_thread_id) {
		ret = pthread_create(&server_thread_id, NULL, 
								nat_traversal_server_thread, NULL);
	}
	
	return 0;
}


