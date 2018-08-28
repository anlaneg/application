/*
 * nl_socket.h
 *
 *  Created on: Aug 24, 2018
 *      Author: anlang
 */

#ifndef NL_SOCKET_H_
#define NL_SOCKET_H_

int nl_sock_mcmessage_process(evutil_socket_t listener, short event, void*arg);
int nl_sock_join_mcgroup(int fd, unsigned int multicast_group);

#endif /* NL_SOCKET_H_ */
