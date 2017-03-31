/*
 * Nat type check tool, for get nat type.
 * liu-weifei@qq.com
 */

#ifndef _NAT_TYPE_
#define _NAT_TYPE_

#include <netinet/in.h>

enum NAT_TYPE {
    NAT_None,
    NAT_Full_Cone,
    NAT_Restricted_Cone,
    NAT_Port_Restricted_Cone,
    NAT_Symmetric,
    NAT_TYPE_MAX
};

const char *nat_type2str(int type);
int request_nat_type(char *remote_ip, int port0, int port1);
//int response_nat_type(int sock, struct sockaddr_in *client_sockaddr, int cmd);

#endif /* _NAT_HELPER_ */
