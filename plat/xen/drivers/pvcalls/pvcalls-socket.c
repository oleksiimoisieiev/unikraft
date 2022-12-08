/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Oleksii Moisieiev <oleksii_moisieiev@epam.com>
 *
 * Copyright (c) 2022, Epam Systems.
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

#include <uk/config.h>
#include <uk/assert.h>
#include <uk/essentials.h>
#include <uk/socket_driver.h>
#include <vfscore/eventpoll.h>

#include "pvcalls-front.h"

static void *pvcalls_socket_create(struct posix_socket_driver *d, int family,
								   int type, int protocol)
{
	return pvcalls_front_socket(d, family, type, protocol);
}

static void *pvcalls_socket_accept(struct posix_socket_file *sock,
								  struct sockaddr *restrict addr __unused,
								  socklen_t *restrict addr_len __unused,
								  int flags)
{
	void *newsock = NULL;

	int ret = pvcalls_front_accept(sock, &newsock, flags);
	if (ret)
		return NULL;
	return newsock;
}

static int pvcalls_socket_bind(struct posix_socket_file *sock,
							   const struct sockaddr *addr,
							   socklen_t addr_len)
{
	return pvcalls_front_bind(sock, addr, addr_len);
}

static int pvcalls_socket_listen(struct posix_socket_file *sock,
								 int backlog)
{
	return pvcalls_front_listen(sock, backlog);
}

static ssize_t pvcalls_socket_sendmsg(struct posix_socket_file *sock,
									  const struct msghdr *msg,
									  int flags __unused)
{
	return pvcalls_front_sendmsg(sock, msg, msg->msg_iovlen);
}

static ssize_t pvcalls_socket_recvmsg(struct posix_socket_file *sock,
								  	  struct msghdr *msg, int flags)
{
	return pvcalls_front_recvmsg(sock, msg, msg->msg_iovlen, flags);
}

static ssize_t pvcalls_socket_read(struct posix_socket_file *sock,
								   const struct iovec *iov, int iovcnt)
{
	struct msghdr msg;

	msg.msg_name = "pv_read";
	msg.msg_namelen = 7;
    msg.msg_iov = iov;
	msg.msg_iovlen = iovcnt;

	return pvcalls_front_recvmsg(sock, &msg, iovcnt, 0);
}

static ssize_t pvcalls_socket_write(struct posix_socket_file *sock,
									const struct iovec *iov, int iovcnt)
{
	struct msghdr msg;

	msg.msg_name = "pv_write";
	msg.msg_namelen = 8;
    msg.msg_iov = iov;
	msg.msg_iovlen = iovcnt;
	msg.msg_flags = 0;

	return pvcalls_front_sendmsg(sock, &msg, iovcnt);
}

static int pvcalls_socket_shutdown(struct posix_socket_file *sock,
								   int how __unused)
{
	return pvcalls_front_release(sock);
}

static int pvcalls_socket_close(struct posix_socket_file *sock)
{
	return 0;
}

static int pvcalls_socket_poll(struct posix_socket_file *sock,
	   unsigned int *revents, struct eventpoll_cb *ecb)
{
	return pvcalls_front_poll(sock, revents, ecb);
}

static struct posix_socket_ops pvcalls_socket_ops = {
    /* POSIX interfaces */
    .create = pvcalls_socket_create,
    .accept4 = pvcalls_socket_accept,
    .bind = pvcalls_socket_bind,
    .shutdown = pvcalls_socket_shutdown,
    /* .getpeername = lwip_posix_socket_getpeername, */
    /* .getsockname = lwip_posix_socket_getsockname, */
    /* .getsockopt = lwip_posix_socket_getsockopt, */
    /* .setsockopt = lwip_posix_socket_setsockopt, */
    /* .connect = lwip_posix_socket_connect, */
    .listen = pvcalls_socket_listen,
    /* .recvfrom = lwip_posix_socket_recvfrom, */
    .recvmsg = pvcalls_socket_recvmsg,
    .sendmsg = pvcalls_socket_sendmsg,
    /* .sendto = lwip_posix_socket_sendto, */
    /* vfscore ops */
    .read = pvcalls_socket_read,
    .write = pvcalls_socket_write,
    .close = pvcalls_socket_close,
    /* .ioctl = lwip_posix_socket_ioctl, */
    .poll = pvcalls_front_poll,
};

POSIX_SOCKET_FAMILY_REGISTER(AF_INET, &pvcalls_socket_ops);
