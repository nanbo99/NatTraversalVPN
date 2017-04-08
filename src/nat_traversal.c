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
    int socket;                        /* Key of hash table socket_hash_table. */
    int role;
    int port;                        /* Key of hash table port_hash_table. */
    int need_relay;
    int timeout;
    int nat_traversed;
    struct sockaddr_in dest_addr;
    UT_hash_handle hh;
};

/* time out thread id. */
static pthread_t client_thread_id = 0;
static pthread_t server_thread_id = 0;
static int client_thread_running = 0;
static int server_thread_running = 0;
static int nat_type = -NAT_TYPE_MAX;
static int app_role = ROLE_Client;
static int ctrl_fd = -1;
static struct socket_data *socket_hash_table = NULL;

/*
 * send tcp message.
 */
ssize_t sendall(int sockfd, const void *buf, size_t len, int flags) {
    ssize_t sent, index = 0, left = len;
    while(left > 0) {
        sent = send(sockfd, (const char *)buf + index, left, flags);
        if(sent <= 0) {
            log_out("%s: send: %s\n", __FUNCTION__, strerror(errno));
            return sent;
        }
        index = index + sent;
        left = left - sent;
    }
    return index;
}

ssize_t recvall(int sockfd, void *buf, size_t len, int flags) {
    ssize_t recvd, index = 0, left = len;
    while(left > 0) {
        recvd = recv(sockfd, (char *)buf + index, left, flags);
        if(recvd <= 0) {
            log_out("%s: recv: %s\n", __FUNCTION__, strerror(errno));
            return recvd;
        }
        index = index + recvd;
        left = left - recvd;
    }
    return index;
}


/*
 * send udp message.
 */
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
handshake state  (Client            Server)
handshake state 0(reset state        reset state)
handshake state 1(SYN sent            SYN sent)
handshake state 2(SYN receivd        SYN receivd)
handshake state 3(SYNACK receivd    NULL)
handshake state 4(NULL                ACK receivd)
 */
int nat_traversal(enum ROLE role, int sock, struct sockaddr_in *remote_sockaddr, int retrytimes) {
    int times = 0, done = 0;
    struct TraversalMsg msg, reply;
    struct timeval tv;
    if (role >= ROLE_MAX) return -1;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(struct timeval));
    for(;;) {
        int i, ret;
        memset(&msg, 0, sizeof(msg));
        
        // 1. Client/Server send and wait SYN, punch hole.
        i = retrytimes;
        msg.role = role;
        msg.cmd = TRAVERSAL_SYN;
        while (--i) {
            memset(&reply, 0, sizeof(reply));
            if (sendmessage(sock, remote_sockaddr, &msg) < 0) {
                log_out("line %d, sendmessage: %s, will try again!\n", __LINE__, 
                        strerror(errno));
                continue;
            }
            ret = recvmessage(sock, remote_sockaddr, &reply);
            if (ret < 0) {
                log_out("line %d, recvmessage: %s, will try again!\n", __LINE__, 
                        strerror(errno));
                continue;
            }
            if (reply.cmd != TRAVERSAL_SYN) {
                log_out("line %d, recv %s, but SYN is expected!\n", __LINE__, 
                        cmd_str[reply.cmd]);
                continue;
            }
            break;
        }
        if (i <= 0) break;
        
        if (role == ROLE_Client) {
            // 2. Client wait SYNACK.
            i = retrytimes;
            while (--i) {
                memset(&reply, 0, sizeof(reply));
                ret = recvmessage(sock, remote_sockaddr, &reply);
                if (ret < 0) {
                    log_out("line %d, recvmessage: %s, will try again!\n", __LINE__, 
                            strerror(errno));
                    continue;
                }
                if (reply.cmd != TRAVERSAL_SYNACK) {
                    log_out("line %d, recv %s, but SYNACK is expected!\n", __LINE__, 
                            cmd_str[reply.cmd]);
                    continue;
                }
                break;
            }
            if(i <= 0) break;
            
            // 3. Client send ACK.
            i = retrytimes;
            msg.role = role;
            msg.cmd = TRAVERSAL_ACK;
            while (--i) {
                if (sendmessage(sock, remote_sockaddr, &msg) < 0) {
                    log_out("line %d, sendmessage: %s, will try again!\n", __LINE__, 
                            strerror(errno));
                    continue;
                }
                break;
            }
            if(i <= 0) break;
        } else if (role == ROLE_Server) {
            // 2. Server send SYNACK.
            i = retrytimes;
            msg.role = role;
            msg.cmd = TRAVERSAL_SYNACK;
            while (--i) {
                if (sendmessage(sock, remote_sockaddr, &msg) < 0) {
                    log_out("line %d, sendmessage: %s, will try again!\n", __LINE__, 
                            strerror(errno));
                    continue;
                }
                break;
            }
            if(i <= 0) break;
            
            // 3. Server wait ACK.
            i = retrytimes;
            while (--i) {
                memset(&reply, 0, sizeof(reply));
                ret = recvmessage(sock, remote_sockaddr, &reply);
                if (ret < 0) {
                    log_out("line %d, recvmessage: %s, will try again!\n", __LINE__, 
                            strerror(errno));
                    continue;
                }
                if (reply.cmd != TRAVERSAL_ACK) {
                    log_out("line %d, recv %s, but ACK is expected!\n", __LINE__, 
                            cmd_str[reply.cmd]);
                    continue;
                }
                break;
            }
            if(i <= 0) break;
        } else {
            break;
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
    while(client_thread_running) {
        // send heart beat, bad package will dropped by shadowVPN.
        /*
        for(sd = socket_hash_table; sd != NULL && !sd->need_relay; sd = sd->hh.next) {
            if(sd->timeout <= 0) {
                assert(sd->dest_addr.sin_port != 0);
                send_udp_package(sd->socket, fake_response, sizeof(fake_response), 0, 
                                    (struct sockaddr*)&sd->dest_addr, sizeof(sd->dest_addr));
            } else {
                sd->timeout--;
            }
        }
        */
        sleep(1);
    }
}

void *nat_traversal_server_thread(void *param) {
    int ret, cbsock, sockopt = 1;
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
        close(cbsock);
        return (void*)-1;
    }
    
    log_out("connect to nat proxy(ip: %s, port: %d)\n", PROXY_SERVER_IP, LISTEN_PORT0);
    if(connect(cbsock, (struct sockaddr*)&remote_sockaddr, sizeof(remote_sockaddr)) < 0) {
        log_out("line %d, connect, %s\n", __LINE__, strerror(errno));
        close(cbsock);
        return (void*)-1;
    }
    
    struct TraversalMsg msg;
    msg.role = ROLE_Server;
    msg.cmd = TRAVERSAL_REGISTER;
    
    // long live tcp connection register.
    send(cbsock, &msg, sizeof(msg), 0);
    
    while(server_thread_running) {
        // TODO: when stop server thread, make sure thread will not block at recv.
        if ((ret = recvall(cbsock, &msg, sizeof(msg), 0)) < 0) {
            log_out("line %d, recvall, %s\n", __LINE__, strerror(errno));
            continue;
        } else if(ret == 0) {
            log_out("line %d, recvall, remote server closed!\n", __LINE__);
            break;
        }
        
        log_out("%s: role: %s, cmd: %s, ip: %s, port: %d\n", __FUNCTION__,
                role_str[msg.role], cmd_str[msg.cmd], msg.ip, msg.port);
        
        if(msg.role == ROLE_Proxy && msg.cmd == TRAVERSAL_PUNCHHOLE) {
            log_out("Recv punch hole request!\n");
            
            sd = socket_hash_table;
            //TODO: using the socket which port match with msg.port to do nat traversal
            // for ( ... ) {
            //        ...
            // }
            
            memset(&client_sockaddr, 0, sizeof(client_sockaddr));
            client_sockaddr.sin_family = AF_INET;
            client_sockaddr.sin_port = htons(msg.port);
            inet_aton(msg.ip, &client_sockaddr.sin_addr);
            
            assert(sd != NULL);
            log_out("Punching hole...");
            
            if (nat_traversal(ROLE_Server, sd->socket, &client_sockaddr, 10) < 0) {
                sd->nat_traversed = 0;
                log_out("failed!\n");
            } else {
                sd->nat_traversed = 1;
                log_out("success!\n");
                // let vpn select this udp socket.
                if (-1 == write(ctrl_fd, &sd->socket, sizeof(int))) {
                    printf("%s: write: %s\n", __FUNCTION__, strerror(errno));
                }
            }
        } else if(msg.role == ROLE_Proxy && msg.cmd == TRAVERSAL_TURN) {
            // TODO: keep udp port connection with Nat Proxy Server.
            // Client send heart beat to nat proxy server, and proxy server relay it to Server.
        }
    }
    close(cbsock);
    return (void*)0;
}

int register_socket(enum ROLE role, int sockfd, int listen_port) {
    int ret, need_relay = 0, nat_traversed = 0;
    struct socket_data *sd;
    struct sockaddr_in remote_sockaddr, server_sockaddr;
    
    memset(&remote_sockaddr, 0, sizeof(remote_sockaddr));
    remote_sockaddr.sin_family = AF_INET;
    remote_sockaddr.sin_port = htons(LISTEN_PORT0);
    inet_aton(PROXY_SERVER_IP, &remote_sockaddr.sin_addr);
    
    if(role == ROLE_Client) {
        struct TraversalMsg msg, reply;
        struct timeval tv;
        char cmd[128];
        
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
            if (nat_traversal(app_role, sockfd, &server_sockaddr, 10) < 0) {
                nat_traversed = 0;
                log_out("failed!\n");
            } else {
                nat_traversed = 1;
                log_out("success!\n");
            }
        }
        
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(struct timeval));
        
        /*
         * Add route rule for client to server.
         */
        snprintf(cmd, 128, "ip route add %s via $(ip route show 0/0 | sed -e 's/.* via \\([^ ]*\\).*/\\1/')", reply.ip);
        system(cmd);
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
    sd->nat_traversed = nat_traversed;
    if(role == ROLE_Client)
        sd->dest_addr = server_sockaddr;
    
    HASH_ADD_INT(socket_hash_table, socket, sd);
    return 0;
}

int get_socket(void *buf, size_t len) {
    int *socks = buf, i;
    struct socket_data *sd = NULL;
    if ((len % sizeof(int)) != 0) return -1;
    for (sd = socket_hash_table, i = 0; 
         sd != NULL && i < len / sizeof(int); 
         sd = sd->hh.next) {
        if(sd->nat_traversed) {
            socks[i++] = sd->socket;
        }
    }
    return 0;
}

int get_socket_remote_addr(int sock, struct sockaddr *remote_sockaddr, 
                           socklen_t addrlen) {
    struct socket_data *sd = NULL;
    HASH_FIND_INT(socket_hash_table, &sock, sd);
    if (!sd || !remote_sockaddr || addrlen < sizeof(struct sockaddr_in))
        return -1;
    *(struct sockaddr_in*)remote_sockaddr = sd->dest_addr;
    return 0;
}

int nat_traversal_init(enum ROLE role, int ctrlfd) {
    int ret;
    nat_type = request_nat_type(PROXY_SERVER_IP, LISTEN_PORT0, LISTEN_PORT1);
    app_role = role;
    ctrl_fd = ctrlfd;
    
    log_out("%s: %s's Nat type is: %s\n", __FUNCTION__, 
            role == ROLE_Server ? "Server" : "Client", nat_type2str(nat_type));
    
    if(nat_type < 0 || nat_type >= NAT_TYPE_MAX) return -1;
    
    // Client keep udp channel open.
    if(role == ROLE_Client && !client_thread_id) {
        if((ret = pthread_create(&client_thread_id, NULL, nat_traversal_client_thread, NULL)) == 0) {
            client_thread_running = 1;
        } else {
            log_out("%s: pthread_create: %s\n", __FUNCTION__, strerror(ret));
        }
    }
    // Server keep connection with Nat Proxy Server.
    if(role == ROLE_Server && !server_thread_id) {
        if((ret = pthread_create(&server_thread_id, NULL, nat_traversal_server_thread, NULL)) == 0) {
            server_thread_running = 1;
        } else {
            log_out("%s: pthread_create: %s\n", __FUNCTION__, strerror(ret));
        }
    }
    
    return 0;
}

int nat_traversal_deinit() {
    int ret;
    char cmd[128];
    client_thread_running = 0;
    server_thread_running = 0;
    
    // Delete route rule, client always use a single server addr.
    snprintf(cmd, 128, "ip route del %s", inet_ntoa(socket_hash_table->dest_addr.sin_addr));
    ret = system(cmd);
    return ret ? -1 : 0;
}

