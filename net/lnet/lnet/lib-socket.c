// SPDX-License-Identifier: GPL-2.0
/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Seagate, Inc.
 */
#define DEBUG_SUBSYSTEM S_LNET

#include <linux/if.h>
#include <linux/in.h>
#include <linux/net.h>
#include <linux/file.h>
#include <linux/pagemap.h>
/* For sys_open & sys_close */
#include <linux/syscalls.h>
#include <net/sock.h>
#include <linux/inetdevice.h>

#include <linux/lnet/lib-lnet.h>

int
lnet_sock_write(struct socket *sock, void *buffer, int nob, int timeout)
{
	int rc;
	long jiffies_left = timeout * HZ;
	unsigned long then;
	struct kvec iov = {
		.iov_base = buffer,
		.iov_len = nob
	};
	struct msghdr msg = { NULL, };

	LASSERT(nob > 0);
	/*
	 * Caller may pass a zero timeout if she thinks the socket buffer is
	 * empty enough to take the whole message immediately
	 */
	iov_iter_kvec(&msg.msg_iter, WRITE, &iov, 1, nob);
	for (;;) {
		msg.msg_flags = !timeout ? MSG_DONTWAIT : 0;
		if (timeout) {
			struct sock *sk = sock->sk;

			/* Set send timeout to remaining time */
			lock_sock(sk);
			sk->sk_sndtimeo = jiffies_left;
			release_sock(sk);
		}

		then = jiffies;
		rc = kernel_sendmsg(sock, &msg, &iov, 1, nob);
		jiffies_left -= jiffies - then;

		if (rc < 0)
			return rc;

		if (!rc) {
			CERROR("Unexpected zero rc\n");
			return -ECONNABORTED;
		}

		if (!msg_data_left(&msg))
			break;

		if (jiffies_left <= 0)
			return -EAGAIN;
	}
	return 0;
}
EXPORT_SYMBOL(lnet_sock_write);

int
lnet_sock_read(struct socket *sock, void *buffer, int nob, int timeout)
{
	int rc;
	long jiffies_left = timeout * HZ;
	unsigned long then;
	struct kvec iov = {
		.iov_base = buffer,
		.iov_len = nob
	};
	struct msghdr msg = {
		.msg_flags = 0
	};

	LASSERT(nob > 0);
	LASSERT(jiffies_left > 0);

	iov_iter_kvec(&msg.msg_iter, READ, &iov, 1, nob);

	for (;;) {
		struct sock *sk = sock->sk;

		/* Set receive timeout to remaining time */
		lock_sock(sk);
		sk->sk_rcvtimeo = jiffies_left;
		release_sock(sk);

		then = jiffies;
		rc = sock_recvmsg(sock, &msg, 0);
		jiffies_left -= jiffies - then;

		if (rc < 0)
			return rc;

		if (!rc)
			return -ECONNRESET;

		if (!msg_data_left(&msg))
			return 0;

		if (jiffies_left <= 0)
			return -ETIMEDOUT;
	}
}
EXPORT_SYMBOL(lnet_sock_read);

int choose_ipv4_src(__u32 *ret, int interface, __u32 dst_ipaddr, struct net *ns)
{
	struct net_device *dev;
	struct in_device *in_dev;
	int err;
	const struct in_ifaddr *ifa;

	rcu_read_lock();
	dev = dev_get_by_index_rcu(ns, interface);
	err = -EINVAL;
	if (!dev || !(dev->flags & IFF_UP))
		goto out;
	in_dev = __in_dev_get_rcu(dev);
	if (!in_dev)
		goto out;
	err = -ENOENT;
	in_dev_for_each_ifa_rcu(ifa, in_dev) {
		if (err == 0 ||
		    ((dst_ipaddr ^ ntohl(ifa->ifa_local)) &
		     ntohl(ifa->ifa_mask)) == 0) {
			/* This address at least as good as what we
			 * already have
			 */
			*ret = ntohl(ifa->ifa_local);
			err = 0;
		}
	}
out:
	rcu_read_unlock();
	return err;
}
EXPORT_SYMBOL(choose_ipv4_src);

static struct socket *
lnet_sock_create(int interface, struct sockaddr *remaddr,
		 int local_port, struct net *ns)
{
	struct socket *sock;
	int rc;
	int option;

	rc = sock_create_kern(ns, PF_INET, SOCK_STREAM, 0, &sock);
	if (rc) {
		CERROR("Can't create socket: %d\n", rc);
		return ERR_PTR(rc);
	}

	option = 1;
	rc = kernel_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
			       (char *)&option, sizeof(option));
	if (rc) {
		CERROR("Can't set SO_REUSEADDR for socket: %d\n", rc);
		goto failed;
	}

	if (interface >= 0 || local_port) {
		struct sockaddr_in locaddr = {};

		locaddr.sin_family = AF_INET;
		locaddr.sin_addr.s_addr = INADDR_ANY;
		if (interface >= 0) {
			struct sockaddr_in *sin = (void *)remaddr;
			u32 ip;

			rc = choose_ipv4_src(&ip,
					     interface,
					     ntohl(sin->sin_addr.s_addr),
					     ns);
			if (rc)
				goto failed;
			locaddr.sin_addr.s_addr = htonl(ip);
		}

		locaddr.sin_port = htons(local_port);

		rc = kernel_bind(sock, (struct sockaddr *)&locaddr,
				 sizeof(locaddr));
		if (rc == -EADDRINUSE) {
			CDEBUG(D_NET, "Port %d already in use\n", local_port);
			goto failed;
		}
		if (rc) {
			CERROR("Error trying to bind to port %d: %d\n",
			       local_port, rc);
			goto failed;
		}
	}
	return sock;

failed:
	sock_release(sock);
	return ERR_PTR(rc);
}

int
lnet_sock_setbuf(struct socket *sock, int txbufsize, int rxbufsize)
{
	int option;
	int rc;

	if (txbufsize) {
		option = txbufsize;
		rc = kernel_setsockopt(sock, SOL_SOCKET, SO_SNDBUF,
				       (char *)&option, sizeof(option));
		if (rc) {
			CERROR("Can't set send buffer %d: %d\n",
			       option, rc);
			return rc;
		}
	}

	if (rxbufsize) {
		option = rxbufsize;
		rc = kernel_setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
				       (char *)&option, sizeof(option));
		if (rc) {
			CERROR("Can't set receive buffer %d: %d\n",
			       option, rc);
			return rc;
		}
	}
	return 0;
}
EXPORT_SYMBOL(lnet_sock_setbuf);

int
lnet_sock_getaddr(struct socket *sock, bool remote, u32 *ip, int *port)
{
	struct sockaddr_in sin;
	int rc;

	if (remote)
		rc = kernel_getpeername(sock, (struct sockaddr *)&sin);
	else
		rc = kernel_getsockname(sock, (struct sockaddr *)&sin);
	if (rc < 0) {
		CERROR("Error %d getting sock %s IP/port\n",
		       rc, remote ? "peer" : "local");
		return rc;
	}

	if (ip)
		*ip = ntohl(sin.sin_addr.s_addr);

	if (port)
		*port = ntohs(sin.sin_port);

	return 0;
}
EXPORT_SYMBOL(lnet_sock_getaddr);

int
lnet_sock_getbuf(struct socket *sock, int *txbufsize, int *rxbufsize)
{
	if (txbufsize)
		*txbufsize = sock->sk->sk_sndbuf;

	if (rxbufsize)
		*rxbufsize = sock->sk->sk_rcvbuf;

	return 0;
}
EXPORT_SYMBOL(lnet_sock_getbuf);

struct socket *
lnet_sock_listen(int local_port, int backlog, struct net *ns)
{
	struct socket *sock;
	int rc;

	sock = lnet_sock_create(-1, NULL, local_port, ns);
	if (IS_ERR(sock)) {
		rc = PTR_ERR(sock);
		if (rc == -EADDRINUSE)
			CERROR("Can't create socket: port %d already in use\n",
			       local_port);
		return ERR_PTR(rc);
	}

	rc = kernel_listen(sock, backlog);
	if (!rc)
		return sock;

	CERROR("Can't set listen backlog %d: %d\n", backlog, rc);
	sock_release(sock);
	return ERR_PTR(rc);
}

struct socket *
lnet_sock_connect(int interface, int local_port,
		  struct sockaddr *peeraddr,
		  struct net *ns)
{
	struct socket *sock;
	int rc;

	sock = lnet_sock_create(interface, peeraddr, local_port, ns);
	if (IS_ERR(sock))
		return sock;

	rc = kernel_connect(sock, peeraddr, sizeof(struct sockaddr_in), 0);
	if (!rc)
		return sock;

	/*
	 * EADDRNOTAVAIL probably means we're already connected to the same
	 * peer/port on the same local port on a differently typed
	 * connection.  Let our caller retry with a different local
	 * port...
	 */
	CDEBUG_LIMIT(rc == -EADDRNOTAVAIL ? D_NET : D_NETERROR,
		     "Error %d connecting %d -> %pISp\n", rc,
		     local_port, peeraddr);

	sock_release(sock);
	return ERR_PTR(rc);
}
