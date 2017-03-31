/*
 * Nat type check tool, for get nat type.
 * liu-weifei@qq.com
 */
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "nat_type.h"
#include "nat_traversal.h"

enum NAT_COMM {
    NAT_COMM_GET_ADDR,      /* Get addr from current socket. */
    NAT_COMM_GET_DFADDR,    /* Get addr from another socket. */
    NAT_COMM_RESPONSE,
    NAT_COMM_MAX,
};

struct NATMsg {
    uint32_t role;
    uint32_t cmd;
    uint32_t cmd2;
    uint32_t port;
    char ip[MAX_IP_SIZE];
};

const char *nat_type_str[NAT_TYPE_MAX] = {
    "No NAT",
    "Full Cone NAT",
    "Restricted Cone NAT",
    "Port Restricted Cone NAT",
    "Symmetric NAT"
};

const char *nat_type2str(int type) {
	if(type < 0 || type >= NAT_TYPE_MAX) return NULL;
	return nat_type_str[type];
}

/*
 * Proxy server: (ip0, port0)
 * Client : (local_ip, local_port)
 * Response of Proxy server(using (ip0, port1)): (outer_ip, outer_port)
 * 1. if recv response:
 *      1.1. if local_port == outer_port:
 *              NAT_None;
 *      1.2. else:
 *              NAT_Full_Cone/NAT_Restricted_Cone
 * 2. if recv nothing, then:
 *      Proxy server: (ip0, port0), (ip1, port1)
 *      Client : (local_ip, local_port)
 *      Response of Proxy server: (outer_ip0, outer_port0), (outer_ip1, outer_port1)
 *      2.1. if outer_port0 != outer_port1:
 *              NAT_Symmetric;
 *      2.2. else:
 *              NAT_Port_Restricted_Cone;
 *
 */
int request_nat_type_diff_port(int sock, char *remote_ip, uint32_t remote_port) {
    int ret, local_port;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    struct sockaddr_in local_sockaddr, remote_sockaddr, sender_sockaddr;
    struct NATMsg msg, reply;
    char local_ip[MAX_IP_SIZE];
    
    msg.cmd = TRAVERSAL_GETNATTYPE;
    msg.cmd2 = NAT_COMM_GET_DFADDR;
    msg.role = ROLE_Client;
    //msg.port = 0;
    //memset(msg.ip, 0, sizeof(msg.ip));
    
    memset(&remote_sockaddr, 0, sizeof(remote_sockaddr));
	remote_sockaddr.sin_family = AF_INET;
	remote_sockaddr.sin_port = htons(remote_port);
	inet_aton(remote_ip, &remote_sockaddr.sin_addr);
    // 1. send request to port0.
    if(sendto(sock, &msg, sizeof(msg), 0, (struct sockaddr*)&remote_sockaddr, 
    					sizeof(remote_sockaddr)) < 0) {
        log_out("%s: sendto: %s\n", __FUNCTION__, strerror(errno));
        ret = -NAT_TYPE_MAX;
        goto err_out;
    }
    
    // get local sock addr.
    if(getsockname(sock, (struct sockaddr*)&local_sockaddr, &addrlen) < 0) {
        log_out("%s: getsockname: %s\n", __FUNCTION__, strerror(errno));
        goto err_out;
    }
    local_port = ntohs(local_sockaddr.sin_port);
    snprintf(local_ip, MAX_IP_SIZE, "%s", inet_ntoa(local_sockaddr.sin_addr));
    
    // 2. recv response from port1, timeout: 2s.
    struct timeval tv;
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(struct timeval));
    if(recvfrom(sock, &reply, sizeof(reply), 0, (struct sockaddr*)&sender_sockaddr, 
    					&addrlen) >= 0) {
        /* response should return from another port. */
        //assert(remote_sockaddr.sin_port != sender_sockaddr.sin_port);
        log_out("%s: remote: (ip, port) = (%s, %d)\n", __FUNCTION__, 
        		inet_ntoa(remote_sockaddr.sin_addr), ntohs(remote_sockaddr.sin_port));
        log_out("%s: sender: (ip, port) = (%s, %d)\n", __FUNCTION__, 
        		inet_ntoa(sender_sockaddr.sin_addr), ntohs(sender_sockaddr.sin_port));
        
        log_out("%s: reply: (ip, port) = (%s, %d)\n", __FUNCTION__, reply.ip, reply.port);
        if(local_port == reply.port && strncmp(local_ip, reply.ip, MAX_IP_SIZE) == 0)
            ret = NAT_None;
        else
            ret = NAT_Restricted_Cone;  /* or NAT_Full_Cone */
    } else if(errno == EWOULDBLOCK) {
        /* recv nothing, then continue test Nat type. */
        ret = NAT_Port_Restricted_Cone; /* or NAT_Symmetric */
    } else {
        log_out("%s: recvfrom: %s\n", __FUNCTION__, strerror(errno));
        ret = -NAT_TYPE_MAX;
    }
	
err_out:
    tv.tv_sec = 0;
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(struct timeval));
    return ret;
}

int request_nat_type_multi_port(int sock, char *remote_ip, uint32_t remote_port0, 
								uint32_t remote_port1) {
    int ret, outer_port0, outer_port1;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    struct sockaddr_in local_sockaddr, remote_sockaddr, sender_sockaddr;
    struct NATMsg msg, reply;
    
    msg.cmd = TRAVERSAL_GETNATTYPE;
    msg.cmd2 = NAT_COMM_GET_ADDR;
    msg.role = ROLE_Client;
    //msg.port = 0;
    //memset(msg.ip, 0, sizeof(msg.ip));
    
    memset(&remote_sockaddr, 0, sizeof(remote_sockaddr));
	remote_sockaddr.sin_family = AF_INET;
	remote_sockaddr.sin_port = htons(remote_port0);
	inet_aton(remote_ip, &remote_sockaddr.sin_addr);
    
    // 1. send request to port0 and port1.
    // 2. recv response from port0 and port1.
    if(sendto(sock, &msg, sizeof(msg), 0, (struct sockaddr*)&remote_sockaddr, 
    					sizeof(remote_sockaddr)) < 0) {
        log_out("%s: sendto: %s\n", __FUNCTION__, strerror(errno));
        return -NAT_TYPE_MAX;
    }
    if(recvfrom(sock, &reply, sizeof(reply), 0, (struct sockaddr*)&sender_sockaddr, 
    					&addrlen) < 0) {
        log_out("%s: recvfrom: %s\n", __FUNCTION__, strerror(errno));
        return -NAT_TYPE_MAX;
    }
    outer_port0 = reply.port;
    
	remote_sockaddr.sin_port = htons(remote_port1);
    
    if(sendto(sock, &msg, sizeof(msg), 0, (struct sockaddr*)&remote_sockaddr, 
    					sizeof(remote_sockaddr)) < 0) {
        log_out("%s: sendto: %s\n", __FUNCTION__, strerror(errno));
        return -NAT_TYPE_MAX;
    }
    if(recvfrom(sock, &reply, sizeof(reply), 0, (struct sockaddr*)&sender_sockaddr, 
    					&addrlen) < 0) {
        log_out("%s: recvfrom: %s\n", __FUNCTION__, strerror(errno));
        return -NAT_TYPE_MAX;
    }
    outer_port1 = reply.port;
    
    // 3. compare two response's ip and port.
    if(outer_port0 != outer_port1) {
        ret = NAT_Symmetric;
    } else {
        ret = NAT_Port_Restricted_Cone;
    }
    return ret;
}

int request_nat_type(char *remote_ip, int port0, int port1) {
    struct sockaddr_in local_sockaddr, remote_sockaddr, sender_sockaddr;
    uint32_t outer_port0, outer_port1;
    socklen_t addrlen = sizeof(struct sockaddr);
    int ret, sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    if(sock < 0) return -NAT_TYPE_MAX;
    
    /*
     * Stage 1:
     *      can we recv response from diffrent port?
     */
    if ((ret = request_nat_type_diff_port(sock, remote_ip, port0)) < 0) {
        log_out("%s: request_nat_type_diff_port: %s\n", __FUNCTION__, "error!");
        goto err_out;
    } else if (ret < NAT_Port_Restricted_Cone) {
        goto request_nat_type_out;
    }
    
    /* continue to test Nat type. */
    
    /*
     * Stage 2:
     *      is this Symmetric nat?
     */
    
    if((ret = request_nat_type_multi_port(sock, remote_ip, port0, port1)) >= 0) {
        goto request_nat_type_out;
    } else {
        log_out("%s: request_nat_type_multi_port: %s\n", __FUNCTION__, "error!");
    }
    
err_out:
    ret = -NAT_TYPE_MAX;
request_nat_type_out:
    close(sock);
    return ret;
}




