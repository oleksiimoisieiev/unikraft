// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Authors: Oleksii Moisieiev <oleksii_moisieiev@epam.com>
 *
 * Copyright (c) 2022, Epam Systems
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
- *
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
 * CONSEQUENTIAL DAMAGES (INCLUD


 ING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* Moved from linux kernel code */
/*
 * (c) 2017 Stefano Stabellini <stefano@aporeto.com>
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <uk/assert.h>
#include <uk/bitops.h>
#include <uk/print.h>
#include <uk/alloc.h>
#include <uk/list.h>
#include <uk/plat/spinlock.h>
#include <uk/refcount.h>
#include <uk/socket_driver.h>
#include <uk/mutex.h>
#if defined(__i386__) || defined(__x86_64__)
#include <xen-x86/mm.h>
#include <xen-x86/irq.h>
#elif defined(__aarch64__)
#include <xen-arm/mm.h>
#include <arm/irq.h>
#else
#error "Unsupported architecture"
#endif
#include <xenbus/xs.h>
#include <xenbus/xenbus.h>
#include <xenbus/client.h>
#include <xen/io/pvcalls.h>
#include <common/events.h>
#include <common/gnttab.h>

#include "pvcalls-front.h"

#define PVCALLS_INVALID_ID UINT_MAX
#define PVCALLS_RING_ORDER 4
#define PVCALLS_NR_RSP_PER_RING __CONST_RING_SIZE(xen_pvcalls, PAGE_SIZE)
#define PVCALLS_FRONT_MAX_SPIN 5000
#define IPPROTO_IP 0

#define MSG_CMSG_CLOEXEC 0x40000000 /* Set close_on_exec for file
		      descriptor received through
		      SCM_RIGHTS */
#define MSG_TRUNC 0x20
#define MSG_ERRQUEUE 0x2000 /* Fetch message from error queue */
#define MSG_OOB 1
#define MSG_PEEK 2
#define MSG_DONTROUTE 4
#define MSG_EOR 0x80 /* End of record */
#define MSG_CONFIRM 0x800 /* Confirm path validity */

#define O_NONBLOCK 04000
#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK O_NONBLOCK
#endif

static struct uk_alloc *drv_allocator;

#define PV_RING_SIZE __RING_SIZE((struct pvcalls_sring *)0, PAGE_SIZE)
#define XEN_PV_RING_SIZE __CONST_RING_SIZE(xen_pvcalls, PAGE_SIZE)

struct pvcalls_bedata {
	grant_ref_t ref;
	evtchn_port_t evtchn;
	struct uk_list_head socket_mappings;

	xen_pvcalls_front_ring_t ring;

	__spinlock socket_lock;

	struct uk_waitq inflight_req;
	struct xen_pvcalls_response rsp[PVCALLS_NR_RSP_PER_RING];
};

struct sock_mapping {
	bool active_socket;
	struct uk_list_head list;
	struct posix_socket_file *sock;
	__atomic refcount;
	union {
		struct {
			evtchn_port_t evtchn;
			grant_ref_t ref;
			struct pvcalls_data_intf *ring;
			struct pvcalls_data data;
			struct uk_mutex in_mutex;
			struct uk_mutex out_mutex;

			struct uk_waitq inflight_conn_req;
		} active;
		struct {
		/*
		 * Socket status, needs to be 64-bit aligned due to the
		 * test_and_* functions which have this requirement on arm64.
		 */
#define PVCALLS_STATUS_UNINITALIZED  0
#define PVCALLS_STATUS_BIND          1
#define PVCALLS_STATUS_LISTEN        2
			uint8_t status __attribute__((aligned(8)));
		/*
		 * Internal state-machine flags.
		 * Only one accept operation can be inflight for a socket.
		 * Only one poll operation can be inflight for a given socket.
		 * flags needs to be 64-bit aligned due to the test_and_*
		 * functions which have this requirement on arm64.
		 */
#define PVCALLS_FLAG_ACCEPT_INFLIGHT 0
#define PVCALLS_FLAG_POLL_INFLIGHT   1
#define PVCALLS_FLAG_POLL_RET        2
			uint8_t flags __attribute__((aligned(8)));
			uint32_t inflight_req_id;
			struct sock_mapping *accept_map;
			struct uk_waitq inflight_accept_req;
		} passive;
	};
	struct uk_mutex evp_lock;
	struct uk_list_head evp_list;
};

struct uk_pvdev {
	struct xenbus_device *xendev;
	struct pvcalls_bedata *data;
#if CONFIG_LIBUKSCHED
	struct uk_thread *st_thread;
	char *st_thread_name;
#endif

};

static struct uk_pvdev *pvcalls_front_dev = NULL;
static __atomic pvcalls_refcount;

static void pvcalls_file_event(struct sock_mapping *map,
				 unsigned int event)
{
	struct eventpoll_cb *ecb;
	struct uk_list_head *itr;

	UK_ASSERT(map);

	uk_mutex_lock(&map->evp_lock);
	uk_list_for_each(itr, &map->evp_list)
	{
		ecb = uk_list_entry(itr, struct eventpoll_cb, cb_link);

		UK_ASSERT(ecb->unregister);

		eventpoll_signal(ecb, event);
	}
	uk_mutex_unlock(&map->evp_lock);
}

static void pvcalls_map_init_evp(struct sock_mapping *map)
{
	UK_ASSERT(map);

	ukarch_spin_init(&map->evp_lock);
	UK_INIT_LIST_HEAD(&map->evp_list);
}

static int xs_read_backend_id(const char *nodename, domid_t *domid)
{
	char path[strlen(nodename) + sizeof("/backend-id")];
	int value, rc;

	snprintf(path, sizeof(path), "%s/backend-id", nodename);

	rc = xs_read_integer(XBT_NIL, path, &value);
	if (!rc)
		*domid = (domid_t)value;

	return rc;
}

/* first increment refcount, then proceed */
#define pvcalls_enter() {             \
	uk_refcount_acquire(&pvcalls_refcount);    \
}

/* first complete other operations, then decrement refcount */
#define pvcalls_exit() {               \
	uk_refcount_release(&pvcalls_refcount);     \
}

static int xs_read_int_value(xenbus_transaction_t xbt, const char *nodename,
			 const char *path, unsigned int *value)
{
	char fpath[strlen(nodename) + strlen(path) + 2];

	snprintf(fpath, sizeof(fpath), "%s/%s", nodename, path);

	return xs_read_integer(xbt, fpath, (int *)value);
}

static inline struct sock_mapping *pvcalls_enter_sock(struct posix_socket_file *sock)
{
	struct sock_mapping *map;

	if (!pvcalls_front_dev
	    || pvcalls_front_dev->data == NULL)
		return ERR2PTR(-ENOTCONN);

	map = (struct sock_mapping *)sock->sock_data;
	if (map == NULL)
		return ERR2PTR(-ENOTSOCK);

	pvcalls_enter();
	uk_refcount_acquire(&map->refcount);
	return map;
}

static inline void pvcalls_exit_sock(struct posix_socket_file *sock)
{
	struct sock_mapping *map;

	map = (struct sock_mapping *)sock->sock_data;
	uk_refcount_release(&map->refcount);
	pvcalls_exit();
}

static inline int get_request(struct pvcalls_bedata *bedata, unsigned int *req_id)
{
	*req_id = bedata->ring.req_prod_pvt & (RING_SIZE(&bedata->ring) - 1);
	if (RING_FULL(&bedata->ring)
	    || bedata->rsp[*req_id].req_id != PVCALLS_INVALID_ID)
		return -EAGAIN;
	return 0;
}

static bool pvcalls_front_write_todo(struct sock_mapping *map)
{
	struct pvcalls_data_intf *intf = map->active.ring;
	RING_IDX cons, prod, size = XEN_FLEX_RING_SIZE(PVCALLS_RING_ORDER);
	int32_t error;

	error = intf->out_error;
	if (error == -ENOTCONN)
		return false;
	if (error != 0)
		return true;

	cons = intf->out_cons;
	prod = intf->out_prod;
	return !!(size - pvcalls_queued(prod, cons, size));
}

static bool pvcalls_front_read_todo(struct sock_mapping *map)
{
	struct pvcalls_data_intf *intf = map->active.ring;
	RING_IDX cons, prod;
	int32_t error;

	cons = intf->in_cons;
	prod = intf->in_prod;
	error = intf->in_error;
	return (error != 0
		|| pvcalls_queued(prod, cons,
				  XEN_FLEX_RING_SIZE(PVCALLS_RING_ORDER))
		       != 0);
}

static void pvcalls_front_event_handler(
			evtchn_port_t evtchn __unused,
			struct __regs * regs __unused,
		    void *arg)
{
	struct xenbus_device *dev = arg;
	struct pvcalls_bedata *bedata;
	struct xen_pvcalls_response *rsp;
	uint8_t *src, *dst;
	int req_id = 0, more = 0, done = 0;

	if (dev == NULL)
		return;

	pvcalls_enter();
	bedata = pvcalls_front_dev->data;
	if (bedata == NULL) {
		pvcalls_exit();
		return;
	}

again:
	while (RING_HAS_UNCONSUMED_RESPONSES(&bedata->ring)) {
		rsp = RING_GET_RESPONSE(&bedata->ring, bedata->ring.rsp_cons);

		req_id = rsp->req_id;
		if (rsp->cmd == PVCALLS_POLL) {
			struct sock_mapping *map = (struct sock_mapping *)(uintptr_t)
						   rsp->u.poll.id;

			uk_clear_bit(PVCALLS_FLAG_POLL_INFLIGHT,
				  (void *)&map->passive.flags);
			/*
			 * clear INFLIGHT, then set RET. It pairs with
			 * the checks at the beginning of
			 * pvcalls_front_poll_passive.
			 */
			wmb();
			uk_set_bit(PVCALLS_FLAG_POLL_RET,
				(void *)&map->passive.flags);

			pvcalls_file_event(map, EPOLLIN | EPOLLRDNORM );
		} else {
			dst = (uint8_t *)&bedata->rsp[req_id] +
			      sizeof(rsp->req_id);
			src = (uint8_t *)rsp + sizeof(rsp->req_id);
			memcpy(dst, src, sizeof(*rsp) - sizeof(rsp->req_id));
			/*
			 * First copy the rest of the data, then req_id. It is
			 * paired with the barrier when accessing bedata->rsp.
			 */
			wmb();
			bedata->rsp[req_id].req_id = req_id;
		}

		done = 1;
		bedata->ring.rsp_cons++;
	}

	RING_FINAL_CHECK_FOR_RESPONSES(&bedata->ring, more);
	if (more)
		goto again;
	if (done)
		uk_waitq_wake_up(&bedata->inflight_req);

	pvcalls_exit();
}

static void pvcalls_front_free_map(struct pvcalls_bedata *bedata,
				   struct sock_mapping *map)
{
	int i;

	unbind_evtchn(map->active.evtchn);

	ukarch_spin_lock(&bedata->socket_lock);
	if (!uk_list_empty(&map->list))
		uk_list_del_init(&map->list);
	ukarch_spin_unlock(&bedata->socket_lock);

	for (i = 0; i < (1 << PVCALLS_RING_ORDER); i++)
		gnttab_end_access(map->active.ring->ref[i]);

	uk_pfree(drv_allocator, map->active.data.in,
		 1ul << (map->active.ring->ring_order + XEN_PAGE_SHIFT - PAGE_SHIFT));

	gnttab_end_access(map->active.ref);
	uk_pfree(drv_allocator, map->active.ring, 1);

	uk_free(drv_allocator, map);
}

static void pvcalls_front_conn_handler(evtchn_port_t port __unused,
				   struct __regs *regs __unused, void *sock_map)
{
	struct sock_mapping *map = sock_map;

	if (map == NULL)
		return;

	uk_waitq_wake_up(&map->active.inflight_conn_req);
	pvcalls_file_event(map, EPOLLIN | EPOLLRDNORM);
}

void *pvcalls_front_socket(struct posix_socket_driver *sock,
			   int family __unused, int type, int protocol __unused)
{
	struct pvcalls_bedata *bedata;
	struct sock_mapping *map = NULL;
	struct xen_pvcalls_request *req;
	int notify, ret;
	unsigned int req_id;

	/*
	 * PVCalls only supports domain AF_INET,
	 * type SOCK_STREAM and protocol 0 sockets for now.
	 *
	 * Check socket type here, AF_INET and protocol checks are done
	 * by the caller.
	 */
	if (type != SOCK_STREAM)
		return ERR2PTR(-EOPNOTSUPP);

	pvcalls_enter();
	if (!pvcalls_front_dev) {
		pvcalls_exit();
		return ERR2PTR(-EACCES);
	}
	bedata = pvcalls_front_dev->data;

	map = uk_zalloc(drv_allocator, sizeof(*map));
	if (map == NULL) {
		pvcalls_exit();
		return ERR2PTR(-ENOMEM);
	}

	uk_refcount_init(&map->refcount, 0);
	pvcalls_map_init_evp(map);
	ukarch_spin_lock(&bedata->socket_lock);

	ret = get_request(bedata, &req_id);
	if (ret < 0) {
		uk_free(drv_allocator, map);
		ukarch_spin_unlock(&bedata->socket_lock);
		pvcalls_exit();
		return ERR2PTR(ret);
	}

	uk_list_add_tail(&map->list, &bedata->socket_mappings);

	req = RING_GET_REQUEST(&bedata->ring, req_id);
	req->req_id = req_id;
	req->cmd = PVCALLS_SOCKET;
	req->u.socket.id = (uintptr_t) map;
	req->u.socket.domain = AF_INET;
	req->u.socket.type = SOCK_STREAM;
	req->u.socket.protocol = IPPROTO_IP;

	bedata->ring.req_prod_pvt++;
	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&bedata->ring, notify);
	ukarch_spin_unlock(&bedata->socket_lock);
	if (notify)
		notify_remote_via_evtchn(bedata->evtchn);

	uk_waitq_wait_event(&bedata->inflight_req,
			 UK_READ_ONCE(bedata->rsp[req_id].req_id) == (uint32_t)req_id);

	/* read req_id, then the content */
	rmb();
	ret = bedata->rsp[req_id].ret;
	bedata->rsp[req_id].req_id = PVCALLS_INVALID_ID;

	pvcalls_exit();
	return (void*)map;
}

static void free_active_ring(struct sock_mapping *map)
{
	if (!map->active.ring)
		return;

	uk_pfree(drv_allocator, map->active.data.in,
	   1ul << (map->active.ring->ring_order + XEN_PAGE_SHIFT - PAGE_SHIFT));
	uk_pfree(drv_allocator, map->active.ring, 1);
}

static int alloc_active_ring(struct sock_mapping *map)
{
	void *bytes;

	map->active.ring =
	    (struct pvcalls_data_intf *)uk_palloc(drv_allocator, 1);
	if (!map->active.ring)
		goto out;

	memset(map->active.ring, 0, PAGE_SIZE);
	map->active.ring->ring_order = PVCALLS_RING_ORDER;
	bytes = uk_palloc(drv_allocator, 1ul << (PVCALLS_RING_ORDER +
						  XEN_PAGE_SHIFT - PAGE_SHIFT));
	if (!bytes)
		goto out;
	/* memset(bytes, 0, 1 << PVCALLS_RING_ORDER); */
	memset(bytes, 0, XEN_FLEX_RING_SIZE(PVCALLS_RING_ORDER) * 2);

	map->active.data.in = bytes;
	map->active.data.out = bytes + XEN_FLEX_RING_SIZE(PVCALLS_RING_ORDER);

	return 0;

out:
	free_active_ring(map);
	return -ENOMEM;
}

static int create_active(struct sock_mapping *map, evtchn_port_t *evtchn)
{
	void *bytes;
	int ret, i;

	*evtchn = 0;
	uk_waitq_init(&map->active.inflight_conn_req);

	bytes = map->active.data.in;
	for (i = 0; i < (1 << PVCALLS_RING_ORDER); i++)
		map->active.ring->ref[i] = gnttab_grant_access(
			pvcalls_front_dev->xendev->otherend_id,
			virt_to_mfn(bytes) + i, 0);

	map->active.ref = gnttab_grant_access(
		pvcalls_front_dev->xendev->otherend_id,
		virt_to_mfn((void *)map->active.ring), 0);

	ret = evtchn_alloc_unbound(pvcalls_front_dev->xendev->otherend_id,
							   pvcalls_front_conn_handler,
							   map, evtchn);
	if (ret < 0) {
		goto out_error;
	}

	unmask_evtchn(*evtchn);
	map->active.evtchn = *evtchn;
	map->active_socket = true;
	uk_mutex_init(&map->active.in_mutex);
	uk_mutex_init(&map->active.out_mutex);

	return 0;

out_error:
	if (*evtchn > 0)
		unbind_evtchn(*evtchn);
	return ret;
}

int pvcalls_front_connect(struct posix_socket_file *sock, struct sockaddr *addr,
				int addr_len, int flags)
{
	struct pvcalls_bedata *bedata;
	struct sock_mapping *map = NULL;
	struct xen_pvcalls_request *req;
	int notify, ret;
	unsigned int req_id;
	evtchn_port_t evtchn;

	if (addr->sa_family != AF_INET || sock->type != SOCK_STREAM)
		return -EOPNOTSUPP;

	map = pvcalls_enter_sock(sock);
	if (PTRISERR(map))
		return PTR2ERR(map);

	bedata = pvcalls_front_dev->data;
	ret = alloc_active_ring(map);
	if (ret < 0) {
		pvcalls_exit_sock(sock);
		return ret;
	}

	ukarch_spin_lock(&bedata->socket_lock);
	ret = get_request(bedata, &req_id);
	if (ret < 0) {
		ukarch_spin_unlock(&bedata->socket_lock);
		free_active_ring(map);
		pvcalls_exit_sock(sock);
		return ret;
	}
	ret = create_active(map, &evtchn);
	if (ret < 0) {
		ukarch_spin_unlock(&bedata->socket_lock);
		free_active_ring(map);
		pvcalls_exit_sock(sock);
		return ret;
	}

	req = RING_GET_REQUEST(&bedata->ring, req_id);
	req->req_id = req_id;
	req->cmd = PVCALLS_CONNECT;
	req->u.connect.id = (uintptr_t)map;
	req->u.connect.len = addr_len;
	req->u.connect.flags = flags;
	req->u.connect.ref = map->active.ref;
	req->u.connect.evtchn = evtchn;
	memcpy(req->u.connect.addr, addr, sizeof(*addr));

	map->sock = sock;

	bedata->ring.req_prod_pvt++;
	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&bedata->ring, notify);
	ukarch_spin_unlock(&bedata->socket_lock);

	if (notify)
		notify_remote_via_evtchn(bedata->evtchn);

	uk_waitq_wait_event(&bedata->inflight_req,
			UK_READ_ONCE(bedata->rsp[req_id].req_id) == (uint32_t)req_id);

	/* read req_id, then the content */
	rmb();
	ret = bedata->rsp[req_id].ret;
	bedata->rsp[req_id].req_id = PVCALLS_INVALID_ID;
	pvcalls_exit_sock(sock);
	return ret;
}

static int __write_ring(struct pvcalls_data_intf *intf,
			struct pvcalls_data *data,
			void *mem, ssize_t len)
{
	RING_IDX cons, prod, size, masked_prod, masked_cons;
	RING_IDX array_size = XEN_FLEX_RING_SIZE(PVCALLS_RING_ORDER);
	int32_t error;

	error = intf->out_error;
	if (error < 0)
		return error;
	cons = intf->out_cons;
	prod = intf->out_prod;
	/* read indexes before continuing */
	mb();

	size = pvcalls_queued(prod, cons, array_size);
	if (size > array_size)
		return -EINVAL;
	if (size == array_size)
		return 0;
	if (len > array_size - size)
		len = array_size - size;

	masked_prod = pvcalls_mask(prod, array_size);
	masked_cons = pvcalls_mask(cons, array_size);

	if (masked_prod < masked_cons) {
		memcpy(data->out + masked_prod, mem,  len);
	} else {
		if (len > array_size - masked_prod) {
			int ret;
			memcpy(data->out + masked_prod, mem,
				       array_size - masked_prod);
			ret = array_size - masked_prod;
			memcpy(data->out, mem, len - ret);
			len += ret;
		} else {
			memcpy(data->out + masked_prod, mem, len);
		}
	}

	/* write to ring before updating pointer */
	wmb();
	intf->out_prod += len;

	return len;
}

int pvcalls_front_sendmsg(struct posix_socket_file *sock,
			   const struct msghdr *msg, size_t len)
{
	struct sock_mapping *map;
	int sent = 0, tot_sent = 0;
	int flags, i;

	flags = msg->msg_flags;
	if (flags & (MSG_CONFIRM | MSG_DONTROUTE | MSG_EOR | MSG_OOB))
		return -EOPNOTSUPP;

	map = pvcalls_enter_sock(sock);
	if (PTRISERR(map))
		return PTRISERR(map);

	uk_mutex_lock(&map->active.out_mutex);
	if ((flags & MSG_DONTWAIT) && !pvcalls_front_write_todo(map)) {
		uk_mutex_unlock(&map->active.out_mutex);
		pvcalls_exit_sock(sock);
		return -EAGAIN;
	}
	if (len > INT_MAX)
		len = INT_MAX;

	for (i = 0; i < msg->msg_iovlen; i++) {
		sent = __write_ring(map->active.ring, &map->active.data, msg->msg_iov[i].iov_base,
							msg->msg_iov[i].iov_len);
		if (sent > 0) {
			len -= sent;
			tot_sent += sent;
			notify_remote_via_evtchn(map->active.evtchn);
		}
		if (sent >= 0 && len > 0 && i < PVCALLS_FRONT_MAX_SPIN)
			continue;
		if (sent < 0)
			tot_sent = sent;
	}
	uk_mutex_unlock(&map->active.out_mutex);
	pvcalls_exit_sock(sock);
	return tot_sent;
}

static int __read_ring(struct pvcalls_data_intf *intf,
		       struct pvcalls_data *data,
		       void *mem, ssize_t len, int flags)
{
	RING_IDX cons, prod, size, masked_prod, masked_cons;
	RING_IDX array_size = XEN_FLEX_RING_SIZE(PVCALLS_RING_ORDER);
	int32_t error;

	cons = intf->in_cons;
	prod = intf->in_prod;
	error = intf->in_error;
	/* get pointers before reading from the ring */
	rmb();

	size = pvcalls_queued(prod, cons, array_size);
	masked_prod = pvcalls_mask(prod, array_size);
	masked_cons = pvcalls_mask(cons, array_size);

	if (size == 0)
		return error ?: size;

	if (len > size)
		len = size;

	if (masked_prod > masked_cons) {
		memcpy(mem, data->in + masked_cons, len);
	} else {
		if (len > (array_size - masked_cons)) {
			int ret;
			memcpy(mem, data->in + masked_cons,
				     array_size - masked_cons);
			ret = array_size - masked_cons;
			memcpy(mem, data->in, len - ret);
			len += ret;
		} else {
			memcpy(mem, data->in + masked_cons, len);
		}
	}

	/* read data from the ring before increasbing the index */
	mb();
	if (!(flags & MSG_PEEK))
		intf->in_cons += len;

	return len;
}

int pvcalls_front_recvmsg(struct posix_socket_file *sock,
						  struct msghdr *msg, size_t len,
						  int flags)
{
	int i;
	struct sock_mapping *map;
	ssize_t buflen = 0;

	if (len < msg->msg_iovlen)
		return -EOPNOTSUPP;

	if (flags & (MSG_CMSG_CLOEXEC | MSG_ERRQUEUE | MSG_OOB | MSG_TRUNC))
		return -EOPNOTSUPP;

	map = pvcalls_enter_sock(sock);
	if (PTRISERR(map))
		return PTRISERR(map);

	uk_mutex_lock(&map->active.in_mutex);
	if (len > XEN_FLEX_RING_SIZE(PVCALLS_RING_ORDER))
		len = XEN_FLEX_RING_SIZE(PVCALLS_RING_ORDER);

	while (!(flags & MSG_DONTWAIT) && !pvcalls_front_read_todo(map)) {
		uk_waitq_wait_event(&map->active.inflight_conn_req,
					 pvcalls_front_read_todo(map));
	}

	for (i = 0; i < msg->msg_iovlen; i++) {
		 ssize_t recvd_local = __read_ring(map->active.ring, &map->active.data,
						 msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len, flags);
		 if (recvd_local > 0)
			 buflen += recvd_local;
		 if ((recvd_local < 0)
		     || (recvd_local < (int)msg->msg_iov[i].iov_len)
		     || (flags & MSG_PEEK)) {
			 /* returned prematurely (or peeking, which might
			  * actually be limitated to the first iov) */
			 if (buflen <= 0) {
				 /* nothing received at all, propagate the error
				  */
				 buflen = recvd_local;
			 }
			 break;
		 }
	}

	if (buflen > 0)
		notify_remote_via_evtchn(map->active.evtchn);
	if (buflen == 0)
		buflen = (flags & MSG_DONTWAIT) ? -EAGAIN : 0;

	uk_mutex_unlock(&map->active.in_mutex);
	pvcalls_exit_sock(sock);
	return buflen;
}

int pvcalls_front_bind(struct posix_socket_file *sock,
					   const struct sockaddr *addr, int addr_len)
{
	struct pvcalls_bedata *bedata;
	struct sock_mapping *map = NULL;
	struct xen_pvcalls_request *req;
	int notify, ret;
	unsigned int req_id;

	if (addr->sa_family != AF_INET || sock->type != SOCK_STREAM)
		return -EOPNOTSUPP;

	map = pvcalls_enter_sock(sock);
	if (PTRISERR(map))
		return PTRISERR(map);
	bedata = pvcalls_front_dev->data;

	ukarch_spin_lock(&bedata->socket_lock);
	ret = get_request(bedata, &req_id);
	if (ret < 0) {
		ukarch_spin_unlock(&bedata->socket_lock);
		pvcalls_exit_sock(sock);
		return ret;
	}
	req = RING_GET_REQUEST(&bedata->ring, req_id);
	req->req_id = req_id;
	map->sock = sock;
	req->cmd = PVCALLS_BIND;
	req->u.bind.id = (uintptr_t)map;
	memcpy(req->u.bind.addr, addr, sizeof(*addr));
	req->u.bind.len = addr_len;

	uk_waitq_init(&map->passive.inflight_accept_req);

	map->active_socket = false;

	bedata->ring.req_prod_pvt++;
	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&bedata->ring, notify);
	ukarch_spin_unlock(&bedata->socket_lock);
	if (notify)
		notify_remote_via_evtchn(bedata->evtchn);

	uk_waitq_wait_event(&bedata->inflight_req,
			   UK_READ_ONCE(bedata->rsp[req_id].req_id) == (uint32_t)req_id);

	/* read req_id, then the content */
	rmb();
	ret = bedata->rsp[req_id].ret;
	bedata->rsp[req_id].req_id = PVCALLS_INVALID_ID;

	map->passive.status = PVCALLS_STATUS_BIND;
	pvcalls_exit_sock(sock);
	return 0;
}
int pvcalls_front_listen(struct posix_socket_file *sock, int backlog)
{
	struct pvcalls_bedata *bedata;
	struct sock_mapping *map;
	struct xen_pvcalls_request *req;
	int notify, ret;
	unsigned int req_id;

	map = pvcalls_enter_sock(sock);
	if (PTRISERR(map))
		return PTRISERR(map);
	bedata = pvcalls_front_dev->data;

	if (map->passive.status != PVCALLS_STATUS_BIND) {
		pvcalls_exit_sock(sock);
		return -EOPNOTSUPP;
	}

	ukarch_spin_lock(&bedata->socket_lock);
	ret = get_request(bedata, &req_id);
	if (ret < 0) {
		ukarch_spin_unlock(&bedata->socket_lock);
		pvcalls_exit_sock(sock);
		return ret;
	}
	req = RING_GET_REQUEST(&bedata->ring, req_id);
	req->req_id = req_id;
	req->cmd = PVCALLS_LISTEN;
	req->u.listen.id = (uintptr_t) map;
	req->u.listen.backlog = backlog;

	bedata->ring.req_prod_pvt++;
	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&bedata->ring, notify);
	ukarch_spin_unlock(&bedata->socket_lock);
	if (notify)
		notify_remote_via_evtchn(bedata->evtchn);

	uk_waitq_wait_event(&bedata->inflight_req,
		   UK_READ_ONCE(bedata->rsp[req_id].req_id)== (uint32_t)req_id);

	/* read req_id, then the content */
	rmb();
	ret = bedata->rsp[req_id].ret;
	bedata->rsp[req_id].req_id = PVCALLS_INVALID_ID;

	map->passive.status = PVCALLS_STATUS_LISTEN;
	pvcalls_exit_sock(sock);
	return ret;
}

int pvcalls_front_accept(struct posix_socket_file *sock,
						 void **newmap,
						 int flags)
{
	struct pvcalls_bedata *bedata;
	struct sock_mapping *map;
	struct sock_mapping *map2 = NULL;
	struct xen_pvcalls_request *req;
	int notify, ret, nonblock;
	unsigned int req_id;
	evtchn_port_t evtchn;

	map = pvcalls_enter_sock(sock);
	if (PTRISERR(map))
		return PTRISERR(map);
	bedata = pvcalls_front_dev->data;

	if (map->passive.status != PVCALLS_STATUS_LISTEN) {
		pvcalls_exit_sock(sock);
		return -EINVAL;
	}

	nonblock = flags & SOCK_NONBLOCK;
	/*
	 * Backend only supports 1 inflight accept request, will return
	 * errors for the others
	 */
	if (uk_test_and_set_bit(PVCALLS_FLAG_ACCEPT_INFLIGHT,
			     (void *)&map->passive.flags)) {
		req_id = UK_READ_ONCE(map->passive.inflight_req_id);
		if (req_id != PVCALLS_INVALID_ID &&
		    UK_READ_ONCE(bedata->rsp[req_id].req_id) == (uint32_t)req_id) {
			map2 = map->passive.accept_map;
			goto received;
		}
		if (nonblock) {
			pvcalls_exit_sock(sock);
			return -EAGAIN;
		}
		if (uk_waitq_wait_event(&map->passive.inflight_accept_req,
			!uk_test_and_set_bit(PVCALLS_FLAG_ACCEPT_INFLIGHT,
					  (void *)&map->passive.flags))) {
			pvcalls_exit_sock(sock);
			return -EINTR;
		}
	}

	map2 = uk_zalloc(drv_allocator, sizeof(*map2));
	if (map2 == NULL) {
		uk_clear_bit(PVCALLS_FLAG_ACCEPT_INFLIGHT,
			  (void *)&map->passive.flags);
		pvcalls_exit_sock(sock);
		return -ENOMEM;
	}

	uk_refcount_init(&map2->refcount, 0);
	pvcalls_map_init_evp(map2);

	ret = alloc_active_ring(map2);
	if (ret < 0) {
		uk_clear_bit(PVCALLS_FLAG_ACCEPT_INFLIGHT,
				(void *)&map->passive.flags);
		uk_free(drv_allocator, map2);
		pvcalls_exit_sock(sock);
		return ret;
	}
	ukarch_spin_lock(&bedata->socket_lock);
	ret = get_request(bedata, &req_id);
	if (ret < 0) {
		uk_clear_bit(PVCALLS_FLAG_ACCEPT_INFLIGHT,
			  (void *)&map->passive.flags);
		ukarch_spin_unlock(&bedata->socket_lock);
		free_active_ring(map2);
		uk_free(drv_allocator, map2);
		pvcalls_exit_sock(sock);
		return ret;
	}

	ret = create_active(map2, &evtchn);
	if (ret < 0) {
		free_active_ring(map2);
		uk_free(drv_allocator, map2);
		uk_clear_bit(PVCALLS_FLAG_ACCEPT_INFLIGHT,
			  (void *)&map->passive.flags);
		ukarch_spin_unlock(&bedata->socket_lock);
		pvcalls_exit_sock(sock);
		return ret;
	}
	uk_list_add_tail(&map2->list, &bedata->socket_mappings);

	req = RING_GET_REQUEST(&bedata->ring, req_id);
	req->req_id = req_id;
	req->cmd = PVCALLS_ACCEPT;
	req->u.accept.id = (uintptr_t) map;
	req->u.accept.ref = map2->active.ref;
	req->u.accept.id_new = (uintptr_t) map2;
	req->u.accept.evtchn = evtchn;
	map->passive.accept_map = map2;

	bedata->ring.req_prod_pvt++;
	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&bedata->ring, notify);
	ukarch_spin_unlock(&bedata->socket_lock);
	if (notify)
		notify_remote_via_evtchn(bedata->evtchn);
	/* We could check if we have received a response before returning. */
	if (nonblock) {
		UK_WRITE_ONCE(map->passive.inflight_req_id, req_id);
		pvcalls_exit_sock(sock);
		return -EAGAIN;
	}

	if (uk_waitq_wait_event(&bedata->inflight_req,
		    UK_READ_ONCE(bedata->rsp[req_id].req_id) == (uint32_t)req_id)) {
		pvcalls_exit_sock(sock);
		return -EINTR;
	}
	/* read req_id, then the content */
	rmb();

received:
	map2->sock = sock;
	*newmap = (void *)map2;

	ret = bedata->rsp[req_id].ret;
	bedata->rsp[req_id].req_id = PVCALLS_INVALID_ID;
	map->passive.inflight_req_id = PVCALLS_INVALID_ID;

	uk_clear_bit(PVCALLS_FLAG_ACCEPT_INFLIGHT, (void *)&map->passive.flags);
	uk_waitq_wake_up(&map->passive.inflight_accept_req);
	pvcalls_file_event(map, EPOLLIN | EPOLLRDNORM );

	pvcalls_exit_sock(sock);
	return ret;
}

static int pvcalls_front_poll_passive(struct posix_socket_file *file,
					       struct pvcalls_bedata *bedata,
					       struct sock_mapping *map)
{
	int notify, ret;
	unsigned int req_id;
	struct xen_pvcalls_request *req;

	if (uk_test_bit(PVCALLS_FLAG_ACCEPT_INFLIGHT,
		     (void *)&map->passive.flags)) {
		uint32_t req_id = UK_READ_ONCE(map->passive.inflight_req_id);

		if (req_id != PVCALLS_INVALID_ID &&
		    UK_READ_ONCE(bedata->rsp[req_id].req_id) == req_id)
			return EPOLLIN | EPOLLRDNORM;

		return 0;
	}

	if (uk_test_and_clear_bit(PVCALLS_FLAG_POLL_RET,
			       (void *)&map->passive.flags))
		return EPOLLIN | EPOLLRDNORM;

	/*
	 * First check RET, then INFLIGHT. No barriers necessary to
	 * ensure execution ordering because of the conditional
	 * instructions creating control dependencies.
	 */

	if (uk_test_and_set_bit(PVCALLS_FLAG_POLL_INFLIGHT,
			     (void *)&map->passive.flags))
		return 0;

	ukarch_spin_lock(&bedata->socket_lock);
	ret = get_request(bedata, &req_id);
	if (ret < 0) {
		ukarch_spin_unlock(&bedata->socket_lock);
		return ret;
	}
	req = RING_GET_REQUEST(&bedata->ring, req_id);
	req->req_id = req_id;
	req->cmd = PVCALLS_POLL;
	req->u.poll.id = (uintptr_t) map;

	bedata->ring.req_prod_pvt++;
	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&bedata->ring, notify);
	ukarch_spin_unlock(&bedata->socket_lock);
	if (notify)
		notify_remote_via_evtchn(bedata->evtchn);

	return 0;
}

static int pvcalls_front_poll_active(struct posix_socket_file *file,
					  struct pvcalls_bedata *bedata __unused,
					  struct sock_mapping *map)
{
	int mask = 0;
	int32_t in_error, out_error;
	struct pvcalls_data_intf *intf = map->active.ring;

	out_error = intf->out_error;
	in_error = intf->in_error;

	if (pvcalls_front_write_todo(map))
		mask |= EPOLLOUT | EPOLLWRNORM;
	if (pvcalls_front_read_todo(map))
		mask |= EPOLLIN | EPOLLRDNORM;
	if (in_error != 0 || out_error != 0)
		mask |= EPOLLERR;

	return mask;
}

static int pvcalls_front_get_events(struct posix_socket_file *sock)
{
	struct pvcalls_bedata *bedata;
	struct sock_mapping *map;
	int ret;

	map = pvcalls_enter_sock(sock);
	if (PTRISERR(map))
		return EINVAL;
	bedata = pvcalls_front_dev->data;

	if (map->active_socket)
		ret = pvcalls_front_poll_active(sock, bedata, map);
	else
		ret = pvcalls_front_poll_passive(sock, bedata, map);
	pvcalls_exit_sock(sock);
	return ret;
}

static void
pvcalls_front_unregister_eventpoll(struct eventpoll_cb *ecb)
{
	struct sock_mapping *map;

	UK_ASSERT(ecb);
	UK_ASSERT(ecb->data);

	map = ecb->data;

	uk_mutex_lock(&map->evp_lock);
	UK_ASSERT(!uk_list_empty(&ecb->cb_link));
	uk_list_del(&ecb->cb_link);

	ecb->data = NULL;
	ecb->unregister = NULL;
	uk_mutex_unlock(&map->evp_lock);
}


int pvcalls_front_poll(struct posix_socket_file *sock,
					   unsigned int *revents,
					   struct eventpoll_cb *ecb)
{
	struct sock_mapping *map;
	UK_ASSERT(revents);

	*revents = pvcalls_front_get_events(sock);

	map = pvcalls_enter_sock(sock);
	uk_mutex_lock(&map->evp_lock);
	if (!ecb->unregister) {
		UK_ASSERT(!ecb->data);
		uk_list_add_tail(&ecb->cb_link, &map->evp_list);

		ecb->data = map;
		ecb->unregister = pvcalls_front_unregister_eventpoll;
	}
	uk_mutex_unlock(&map->evp_lock);
	pvcalls_exit_sock(sock);
	return 0;
}

int pvcalls_front_release(struct posix_socket_file *sock)
{
	struct pvcalls_bedata *bedata;
	struct sock_mapping *map;
	int notify, ret;
	unsigned int req_id;
	struct xen_pvcalls_request *req;

	if (sock->sock_data == NULL)
		return 0;

	map = pvcalls_enter_sock(sock);
	if (PTRISERR(map)) {
		if (PTR2ERR(map) == -ENOTCONN)
			return -EIO;
		else
 			return 0;
	}
	bedata = pvcalls_front_dev->data;

	ukarch_spin_lock(&bedata->socket_lock);
	ret = get_request(bedata, &req_id);
	if (ret < 0) {
		ukarch_spin_unlock(&bedata->socket_lock);
		pvcalls_exit_sock(sock);
		return ret;
	}
	sock->sock_data = NULL;

	req = RING_GET_REQUEST(&bedata->ring, req_id);
	req->req_id = req_id;
	req->cmd = PVCALLS_RELEASE;
	req->u.release.id = (uintptr_t)map;

	bedata->ring.req_prod_pvt++;
	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&bedata->ring, notify);
	ukarch_spin_unlock(&bedata->socket_lock);
	if (notify)
		notify_remote_via_evtchn(bedata->evtchn);

	uk_waitq_wait_event(&bedata->inflight_req,
		   UK_READ_ONCE(bedata->rsp[req_id].req_id) == (uint32_t)req_id);

	if (map->active_socket) {
		/*
		 * Set in_error and wake up inflight_conn_req to force
		 * recvmsg waiters to exit.
		 */
		map->active.ring->in_error = -EBADF;
		uk_waitq_wake_up(&map->active.inflight_conn_req);
		pvcalls_file_event(map, EPOLLRDHUP);

		/*
		 * We need to make sure that sendmsg/recvmsg on this socket have
		 * not started before we've cleared sk_send_head here. The
		 * easiest way to guarantee this is to see that no pvcalls
		 * (other than us) is in progress on this socket.
		 */
		while (uk_refcount_read(&map->refcount) > 1)
			barrier();

		pvcalls_front_free_map(bedata, map);
	} else {
		uk_waitq_wake_up(&bedata->inflight_req);
		uk_waitq_wake_up(&map->passive.inflight_accept_req);
		pvcalls_file_event(map, EPOLLRDHUP);

		while (uk_refcount_read(&map->refcount) > 1)
			barrier();

		ukarch_spin_lock(&bedata->socket_lock);
		uk_list_del(&map->list);
		ukarch_spin_unlock(&bedata->socket_lock);
		if (UK_READ_ONCE(map->passive.inflight_req_id) != PVCALLS_INVALID_ID &&
			UK_READ_ONCE(map->passive.inflight_req_id) != 0) {
			pvcalls_front_free_map(bedata,
					       map->passive.accept_map);
		}
		uk_free(drv_allocator, map);
	}
	UK_WRITE_ONCE(bedata->rsp[req_id].req_id, PVCALLS_INVALID_ID);

	pvcalls_exit();
	return 0;
}

static int pvcalls_front_remove(struct xenbus_device *dev)
{
	struct pvcalls_bedata *bedata;
	struct sock_mapping *map = NULL, *n;

	bedata = pvcalls_front_dev->data;
	pvcalls_front_dev->data = NULL;
	unbind_evtchn(bedata->evtchn);

	uk_list_for_each_entry_safe(map, n, &bedata->socket_mappings, list) {
		map->sock->sock_data = NULL;
		if (map->active_socket) {
			map->active.ring->in_error = -EBADF;
			uk_waitq_wake_up(&map->active.inflight_conn_req);
			pvcalls_file_event(map, EPOLLRDHUP);
		}
	}

	mb();
	while (uk_refcount_read(&pvcalls_refcount) > 0)
		barrier();
	uk_list_for_each_entry_safe(map, n, &bedata->socket_mappings, list) {
		if (map->active_socket) {
			/* No need to lock, refcount is 0 */
			pvcalls_front_free_map(bedata, map);
		} else {
			uk_list_del(&map->list);
			uk_free(drv_allocator, map);
		}
	}
	if (bedata->ref != (grant_ref_t)-1)
		gnttab_end_access(bedata->ref);
	uk_free(drv_allocator, bedata->ring.sring);
	uk_free(drv_allocator, bedata);
	xenbus_switch_state(XBT_NIL, dev, XenbusStateClosed);
	return 0;
}

static int be_watch_start(struct xenbus_device *xendev, const char *path)
{
	struct xenbus_watch *watch;

	watch = xs_watch_path(XBT_NIL, path);
	if (PTRISERR(watch))
		return PTR2ERR(watch);

	xendev->otherend_watch = watch;

	return 0;
}

static int be_watch_stop(struct xenbus_device *xendev)
{
	return xs_unwatch(XBT_NIL, xendev->otherend_watch);
}

#define WAIT_BE_STATE_CHANGE_WHILE_COND(state_cond) \
	do { \
		rc = xs_read_integer(XBT_NIL, be_state_path, \
			(int *) &be_state); \
		if (rc) \
			goto out; \
		while (!rc && (state_cond)) \
			rc = xenbus_wait_for_state_change(be_state_path, \
				&be_state, xendev->otherend_watch); \
		if (rc) \
			goto out; \
	} while (0)

static int pvcalls_wait_be_connect(struct uk_pvdev *pvdev)
{
	struct xenbus_device *xendev = pvdev->xendev;
	char be_state_path[strlen(xendev->otherend) + sizeof("/state")];
	XenbusState be_state;
	int rc;

	sprintf(be_state_path, "%s/state", xendev->otherend);

	rc = be_watch_start(xendev, be_state_path);
	if (rc)
		goto out;

	WAIT_BE_STATE_CHANGE_WHILE_COND(be_state < XenbusStateConnected);

	if (be_state != XenbusStateConnected) {
		uk_pr_err("Backend not available, state=%s\n",
				xenbus_state_to_str(be_state));
		be_watch_stop(xendev);
		goto out;
	}

	rc = xenbus_switch_state(XBT_NIL, xendev, XenbusStateConnected);
	if (rc)
		goto out;

out:
	return rc;
}

static int pvcalls_front_probe(struct uk_pvdev *p)
{
	struct xenbus_device *xendev;
	int ret = -ENOMEM, i;
	char *versions;
	unsigned int max_page_order, function_calls;
	struct pvcalls_bedata *bedata = NULL;
	xenbus_transaction_t xbt;
	struct xen_pvcalls_sring *sring;

	UK_ASSERT(p != NULL);

	xendev = p->xendev;
	UK_ASSERT(xendev != NULL);
	UK_ASSERT(xendev->nodename != NULL);

	ret = xs_read_backend_id(xendev->nodename, &xendev->otherend_id);
	if (ret)
		return ret;

	/* read backend path */
	xendev->otherend = xs_read(XBT_NIL, xendev->nodename, "backend");
	if (PTRISERR(xendev->otherend)) {
		uk_pr_err("Error reading backend path.\n");
		ret = PTR2ERR(xendev->otherend);
		xendev->otherend = NULL;
		return ret;
	}

	versions = xs_read(XBT_NIL, xendev->otherend, "versions");
	if (PTRISERR(versions))
		return PTR2ERR(versions);
	if (strcmp(versions, "1")) {
		uk_free(drv_allocator, versions);
		return -EINVAL;
	}
	uk_free(drv_allocator, versions);

	ret = xs_read_int_value(XBT_NIL, xendev->otherend,
						 "max-page-order", &max_page_order);
	if (ret)
		return ret;

	if (max_page_order < PVCALLS_RING_ORDER)
		return -ENODEV;

	ret = xs_read_int_value(XBT_NIL, xendev->otherend,
					      "function-calls", &function_calls);
	if (ret)
		return ret;

	/* See XENBUS_FUNCTIONS_CALLS in pvcalls.h */
	if (function_calls != 1)
		return -ENODEV;

	bedata = uk_zalloc(drv_allocator, sizeof(struct pvcalls_bedata));
	if (!bedata)
		return -ENOMEM;

	p->data = bedata;
	UK_INIT_LIST_HEAD(&bedata->socket_mappings);
	ukarch_spin_init(&bedata->socket_lock);
	uk_refcount_init(&pvcalls_refcount, 0);
	bedata->ref = -1;

	for (i = 0; i < (int)PVCALLS_NR_RSP_PER_RING; i++)
		bedata->rsp[i].req_id = PVCALLS_INVALID_ID;

	sring = (struct xen_pvcalls_sring *) uk_palloc(drv_allocator, 1);
	if (!sring)
		goto error;
	memset(sring, 0, PAGE_SIZE);
	SHARED_RING_INIT(sring);
	FRONT_RING_INIT(&bedata->ring, sring, PAGE_SIZE);

	bedata->ref = gnttab_grant_access(xendev->otherend_id, virt_to_mfn(sring), 0);
	UK_ASSERT(bedata->ref != GRANT_INVALID_REF);

	uk_waitq_init(&bedata->inflight_req);

	ret = evtchn_alloc_unbound(xendev->otherend_id,
				       pvcalls_front_event_handler, xendev,
				       &bedata->evtchn);
	if (ret)
		goto error;

	unmask_evtchn(bedata->evtchn);
again:
	ret = xs_transaction_start(&xbt);
	if (ret) {
		uk_pr_err("starting transaction. Err: %d", ret);
		goto error;
	}

	ret = xs_printf(xbt, xendev->nodename, "version", "%u", 1);
	if (ret < 0)
		goto error_xenbus;

	ret = xs_printf(xbt, xendev->nodename, "ring-ref", "%d", bedata->ref);
	if (ret < 0)
		goto error_xenbus;
	ret = xs_printf(xbt, xendev->nodename, "port", "%u",
			    bedata->evtchn);
	if (ret < 0)
		goto error_xenbus;

	xenbus_switch_state(xbt, xendev, XenbusStateInitialised);

	ret = xs_transaction_end(xbt, 0);
	if (ret) {
		if (ret == -EAGAIN)
			goto again;
		uk_pr_err("completing transaction. Err: %d", ret);
		goto error;
	}

	ret = pvcalls_wait_be_connect(pvcalls_front_dev);
	if (ret)
		goto error;

	return 0;

 error_xenbus:
	xs_transaction_end(xbt, 1);
	uk_pr_err("Error writing xenstore: ret = %d\n", ret);
 error:
	pvcalls_front_remove(xendev);
	return ret;
}

static int pvcalls_add_dev(struct xenbus_device *xendev)
{
	int rc = 0;
	UK_ASSERT(xendev != NULL);
	if (pvcalls_front_dev) {
		uk_pr_err("Only one PV Calls connection supported\n");
		return -EINVAL;
	}

	pvcalls_front_dev = uk_calloc(drv_allocator, 1, sizeof(*pvcalls_front_dev));
	if (!pvcalls_front_dev) {
		rc = -ENOMEM;
		goto out;
	}
	pvcalls_front_dev->xendev = xendev;

	rc = pvcalls_front_probe(pvcalls_front_dev);
	if (rc)
		goto free;

	uk_pr_info("Initialized Xen pvcalls frontend driver\n");
	goto out;
free:
	uk_free(drv_allocator, pvcalls_front_dev);
out:
	return rc;
}

static int pvcalls_drv_init(struct uk_alloc *allocator)
{
	/* driver initialization */
	if (!allocator)
		return -EINVAL;

	drv_allocator = allocator;
	return 0;
}

static const xenbus_dev_type_t pvcalls_devtypes[] = {
	xenbus_dev_pvcalls,
};

static struct xenbus_driver pvcalls_driver = {
	.device_types = pvcalls_devtypes,
	.init = pvcalls_drv_init,
	.add_dev = pvcalls_add_dev,
};
XENBUS_REGISTER_DRIVER(&pvcalls_driver);
