/*
 * Copyright (c) 2016-2017 by Gaohang Wu, Xiaoye Meng.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/workqueue.h>
#include <net/sock.h>
#include <net/tcp.h>

/* FIXME */
struct server {
	struct workqueue_struct	*dispatcher, *worker;
	struct work_struct	work;
	struct socket		*sock;
};
struct client {
	struct work_struct	work;
	struct socket		*sock;
};

/* FIXME */
static unsigned short ktsdb_port = 55555;
struct server sv;

/* FIXME */
static int ktsdb_send(struct socket *sock, unsigned char *buf, int len) {
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
	struct kvec iov = { buf, len };

	return kernel_sendmsg(sock, &msg, &iov, 1, len);
}

/* FIXME */
static int ktsdb_recv(struct socket *sock, unsigned char *buf, int len) {
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
	struct kvec iov = { buf, len };

	return kernel_recvmsg(sock, &msg, &iov, 1, len, msg.msg_flags);
}

/* FIXME */
static void ktsdb_wk_data_ready(struct sock *sk, int unused) {
	printk(KERN_INFO "[%s] state = %d\n", __func__, sk->sk_state);
}

/* FIXME */
static void ktsdb_wk_write_space(struct sock *sk) {
	printk(KERN_INFO "[%s] state = %d\n", __func__, sk->sk_state);
}

/* FIXME */
static void ktsdb_wk_state_change(struct sock *sk) {
	printk(KERN_INFO "[%s] state = %d\n", __func__, sk->sk_state);
}

/* FIXME */
void ktsdb_conn_work(struct work_struct *work) {
}

/* FIXME */
static void set_wk_callbacks(struct socket *sock, struct client *c) {
	struct sock *sk = sock->sk;

	sk->sk_user_data    = (void *)c;
	sk->sk_data_ready   = ktsdb_wk_data_ready;
	sk->sk_write_space  = ktsdb_wk_write_space;
	sk->sk_state_change = ktsdb_wk_state_change;
}

static int ktsdb_accept_one(struct server *s) {
	struct socket *sock;
	struct sockaddr_in sa;
	int ret, len, one = 1;
	struct client *c;

	if ((ret = sock_create_lite(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock)) < 0) {
		printk(KERN_ERR "[%s] error creating client socket\n", __func__);
		return ret;
	}
	sock->type = s->sock->type;
	sock->ops  = s->sock->ops;
	if ((ret = s->sock->ops->accept(s->sock, sock, O_NONBLOCK)) < 0) {
		/* printk(KERN_ERR "[%s] error accepting client socket\n", __func__); */
		goto end;
	}
	if ((ret = s->sock->ops->getname(sock, (struct sockaddr *)&sa, &len, 1)) < 0) {
		printk(KERN_ERR "[%s] error getting peer name\n", __func__);
		sock->ops->shutdown(sock, SHUT_RDWR);
		goto end;
	}
	printk(KERN_INFO "Accepted client '%pI4:%u'\n", &sa.sin_addr, ntohs(sa.sin_port));
	if ((c = kmalloc(sizeof *c, GFP_KERNEL)) == NULL) {
		printk(KERN_ERR "[%s] error allocating new client\n", __func__);
		sock->ops->shutdown(sock, SHUT_RDWR);
		goto end;
	}
	INIT_WORK(&c->work, ktsdb_conn_work);
	c->sock = sock;
	/* FIXME */
	c->sock->sk->sk_allocation = GFP_ATOMIC;
	set_wk_callbacks(c->sock, c);
	kernel_setsockopt(c->sock, SOL_TCP, TCP_NODELAY, (char *)&one, sizeof one);
	return 0;

end:
	sock_release(sock);
	return ret;
}

/* FIXME */
static void ktsdb_dp_data_ready(struct sock *sk, int unused) {
	struct server *s = (struct server *)sk->sk_user_data;

	/* printk(KERN_INFO "[%s] state = %d\n", __func__, sk->sk_state); */
	if (sk->sk_state == TCP_LISTEN)
		queue_work(s->dispatcher, &s->work);
}

/* FIXME */
static void ktsdb_dp_write_space(struct sock *sk) {
	printk(KERN_INFO "[%s] state = %d\n", __func__, sk->sk_state);
}

/* FIXME */
static void ktsdb_dp_state_change(struct sock *sk) {
	/* printk(KERN_INFO "[%s] state = %d\n", __func__, sk->sk_state); */
}

/* FIXME */
static void ktsdb_listen_work(struct work_struct *work) {
	struct server *s = container_of(work, struct server, work);

	for (;;)
		if (ktsdb_accept_one(s))
			break;
}

/* FIXME */
static void set_dp_callbacks(struct socket *sock, struct server *s) {
	struct sock *sk = sock->sk;

	sk->sk_user_data    = (void *)s;
	sk->sk_data_ready   = ktsdb_dp_data_ready;
	sk->sk_write_space  = ktsdb_dp_write_space;
	sk->sk_state_change = ktsdb_dp_state_change;
}

static int __init ktsdb_init(void) {
	int one = 1;
	struct sockaddr_in sa;

	if ((sv.dispatcher = create_singlethread_workqueue("ktsdb_dp")) == NULL) {
		printk(KERN_ERR "[%s] error creating dispatcher thread\n", __func__);
		return -ENOMEM;
	}
	if ((sv.worker = create_workqueue("ktsdb_wk")) == NULL) {
		printk(KERN_ERR "[%s] error creating worker thread\n", __func__);
		destroy_workqueue(sv.dispatcher);
		return -ENOMEM;
	}
	INIT_WORK(&sv.work, ktsdb_listen_work);
	if (sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sv.sock) < 0) {
		printk(KERN_ERR "[%s] error creating server socket\n", __func__);
		destroy_workqueue(sv.dispatcher);
		destroy_workqueue(sv.worker);
		return -EIO;
	}
	/* FIXME */
	sv.sock->sk->sk_allocation = GFP_ATOMIC;
	set_dp_callbacks(sv.sock, &sv);
	kernel_setsockopt(sv.sock, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof one);
	kernel_setsockopt(sv.sock, SOL_TCP, TCP_NODELAY, (char *)&one, sizeof one);
	memset(&sa, '\0', sizeof sa);
	sa.sin_family      = AF_INET;
	sa.sin_addr.s_addr = INADDR_ANY;
	sa.sin_port        = htons(ktsdb_port);
	if (sv.sock->ops->bind(sv.sock, (struct sockaddr *)&sa, sizeof sa) < 0) {
		printk(KERN_ERR "[%s] error binding server socket\n", __func__);
		goto end;
	}
	/* FIXME */
	if (sv.sock->ops->listen(sv.sock, 511) < 0) {
		printk(KERN_ERR "[%s] error listening server socket\n", __func__);
		goto end;
	}
	printk(KERN_INFO "Server ktsdb started\n");
	return 0;

end:
	destroy_workqueue(sv.dispatcher);
	destroy_workqueue(sv.worker);
	sock_release(sv.sock);
	return -EIO;
}

/* FIXME */
static void __exit ktsdb_exit(void) {
	sock_release(sv.sock);
	destroy_workqueue(sv.worker);
	destroy_workqueue(sv.dispatcher);
	printk(KERN_INFO "ktsdb is now ready to exit, bye bye...\n");
}

module_init(ktsdb_init);
module_exit(ktsdb_exit);
MODULE_AUTHOR("Xiaoye Meng");
MODULE_LICENSE("GPL v2");

