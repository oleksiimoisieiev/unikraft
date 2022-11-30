// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Authors: Oleksii Moisieiev <oleksii_moisieiev@epam.com>
 *
 * Copyright (c) 2022, EPAM Systems
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* Moved from linux kernel */

#ifndef __PVCALLS_FRONT_H__
#define __PVCALLS_FRONT_H__

#include <uk/socket.h>
#include <vfscore/eventpoll.h>

void *pvcalls_front_socket(struct posix_socket_driver *sock,
			  int family, int type, int protocol);
int pvcalls_front_connect(struct posix_socket_file *sock, struct sockaddr *addr,
			  int addr_len, int flags);
int pvcalls_front_bind(struct posix_socket_file *sock,
			  const struct sockaddr *addr, int addr_len);
int pvcalls_front_listen(struct posix_socket_file *sock, int backlog);
int pvcalls_front_accept(struct posix_socket_file *sock,
			  void **newmap, int flags);
int pvcalls_front_sendmsg(struct posix_socket_file *sock,
			  const struct msghdr *msg, size_t len);
int pvcalls_front_recvmsg(struct posix_socket_file *sock,
			  struct msghdr *msg, size_t len, int flags);
int pvcalls_front_poll(struct posix_socket_file *file, unsigned int *revents,
			  struct eventpoll_cb *ecb);
int pvcalls_front_release(struct posix_socket_file *sock);

#endif
