/*
 * Copyright (c) 2014 Intel Corporation, Inc.  All rights reserved.
 * Copyright (c) 2017-2018 Hewlett Packard Enterprise Development LP.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <zhpe.h>

#define ZHPE_LOG_DBG(...) _ZHPE_LOG_DBG(FI_LOG_EP_CTRL, __VA_ARGS__)
#define ZHPE_LOG_ERROR(...) _ZHPE_LOG_ERROR(FI_LOG_EP_CTRL, __VA_ARGS__)

int zhpe_conn_map_init(struct zhpe_ep *ep, int init_size)
{
	struct zhpe_conn_map *map = &ep->attr->cmap;
	map->table = calloc(init_size, sizeof(*map->table));
	if (!map->table)
		return -FI_ENOMEM;

	mutex_init(&map->mutex, NULL);
	cond_init(&map->cond, NULL);
	map->used = 0;
	map->size = init_size;

	return 0;
}

#if 0
static int zhpe_conn_map_increase(struct zhpe_conn_map *map, int new_size)
{
	void *_table;

	_table = realloc(map->table, new_size * sizeof(*map->table));
	if (!_table) {
		ZHPE_LOG_ERROR("*** realloc failed, use FI_SOCKETS_DEF_CONN_MAP_SZ for"
			"specifying conn-map-size\n");
		return -FI_ENOMEM;
	}

	map->size = new_size;
	map->table = _table;
	return 0;
}
#endif

void zhpe_conn_map_destroy(struct zhpe_ep_attr *ep_attr)
{
	int			i;
	struct zhpe_conn_map	*cmap = &ep_attr->cmap;

	mutex_acquire(&cmap->mutex);
	for (i = 0; i < cmap->used; i++) {
		if (cmap->table[i].state != ZHPE_CONN_STATE_FREE)
			zhpe_conn_release_entry(ep_attr, &cmap->table[i]);
	}
	mutex_release(&cmap->mutex);

	free(cmap->table);
	cmap->table = NULL;
	cmap->used = cmap->size = 0;
	mutex_destroy(&cmap->mutex);
}

void zhpe_conn_release_entry(struct zhpe_ep_attr *ep_attr,
			     struct zhpe_conn *conn)
{
	/* ep_attr->cmap.mutex should be held, */
	zhpe_conn_z_free(conn);
        conn->state = ZHPE_CONN_STATE_FREE;
	if (conn->fi_addr != FI_ADDR_NOTAVAIL) {
		if (ofi_idm_lookup(&ep_attr->av_idm, conn->av_index) == conn)
			ofi_idm_clear(&ep_attr->av_idm, conn->av_index);
	}
	cond_broadcast(&ep_attr->cmap.cond);
}

static int zhpe_conn_get_next_index(struct zhpe_conn_map *map)
{
	int i;
	for (i = 0; i < map->size; i++) {
		if (!map->table[i].state == ZHPE_CONN_STATE_FREE)
			return i;
	}
	return -1;
}

struct zhpe_conn *zhpe_conn_map_insert(struct zhpe_ep_attr *ep_attr,
				       const union sockaddr_in46 *addr)
{
	int index;
	struct zhpe_conn_map *map = &ep_attr->cmap;

	if (map->size == map->used) {
		index = zhpe_conn_get_next_index(map);
		if (index < 0) {
			/* FIXME:This doesn't work because it will change the
			 * address of conns that are in use. Need chunky
			 * table. Maybe the IDM stuff?
			 */
			return NULL;
#if 0
			if (zhpe_conn_map_increase(map, map->size * 2))
				return NULL;
			index = map->used;
			map->used++;
#endif
		}
	} else {
		index = map->used;
		map->used++;
	}
	memset(&map->table[index], 0, sizeof(map->table[index]));
	map->table[index].fi_addr = FI_ADDR_NOTAVAIL;
	map->table[index].state = ZHPE_CONN_STATE_INIT;
	sockaddr_cpy(&map->table[index].addr, addr);
	map->table[index].ep_attr = ep_attr;
	map->table[index].zq_index = FI_ADDR_NOTAVAIL;

	return &map->table[index];
}

struct zhpe_conn *zhpe_conn_map_lookup(struct zhpe_ep_attr *ep_attr,
				       const union sockaddr_in46 *addr)
{
	struct zhpe_conn	*ret;
	int			i;

	for (i = 0; i < ep_attr->cmap.used; i++) {
		ret = &ep_attr->cmap.table[i];
		if (ret->state == ZHPE_CONN_STATE_FREE ||
		    ret->state == ZHPE_CONN_STATE_RACED)
			continue;

		if (!sockaddr_cmp(&ret->addr, addr))
			return ret;
	}

	return NULL;
}

int zhpe_set_sockopt_reuseaddr(int sock)
{
	int			ret = 0;
	int			optval = 1;

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval,
		       sizeof(optval)) == -1) {
		ret = -errno;
		ZHPE_LOG_ERROR("setsockopt reuseaddr failed:%s\n",
			       strerror(-ret));
	}
	return ret;
}

int zhpe_set_sockopt_nodelay(int sock)
{
	int			ret = 0;
	int			optval = 1;

	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &optval,
		       sizeof(optval)) == -1) {
		ret = -errno;
		ZHPE_LOG_ERROR("setsockopt tcp_nodelay failed:%s\n",
			       strerror(-ret));
	}

	return ret;
}

int zhpe_set_fd_cloexec(int fd)
{
	int			ret = 0;
	int			flags;

	flags = fcntl(fd, F_GETFL);
	if (flags == -1) {
		ret = -errno;
		ZHPE_LOG_ERROR("fcntl getfl failed:%s\n",
			       strerror(-ret));
		goto done;
	}
	if (fcntl(fd, F_SETFL, flags | O_CLOEXEC) == -1) {
		ret = -errno;
		ZHPE_LOG_ERROR("fcntl setfl cloexec failed:%s\n",
			       strerror(-ret));
	}
 done:
	return ret;
}

int zhpe_set_fd_nonblock(int fd)
{
	int			ret;

	ret = fi_fd_nonblock(fd);
	if (ret < 0)
		ZHPE_LOG_ERROR("fi_fd_nonblock() failed:%s\n",
			       fi_strerror(-ret));

	return ret;
}

int zhpe_set_sockopts_connect(int sock)
{
	int			ret;

	ret = zhpe_set_sockopt_reuseaddr(sock);
	if (ret < 0)
		goto done;
	ret = zhpe_set_sockopt_nodelay(sock);
	if (ret < 0)
		goto done;
	ret = zhpe_set_fd_cloexec(sock);
	if (ret < 0)
		goto done;
	ret = zhpe_set_fd_nonblock(sock);

 done:
	return ret;
}

int zhpe_set_sockopts_listen(int sock)
{
	int			ret;

	ret = zhpe_set_sockopt_reuseaddr(sock);
	if (ret < 0)
		goto done;
	ret = zhpe_set_fd_cloexec(sock);
 done:
	return ret;
}

int zhpe_set_sockopts_accept(int sock)
{
	int			ret;

	ret = zhpe_set_sockopt_nodelay(sock);
	if (ret < 0)
		goto done;
	ret = zhpe_set_fd_cloexec(sock);
 done:
	return ret;
}

static void *_zhpe_conn_listen(void *arg)
{
	int			rc;
	struct zhpe_ep_attr	*ep_attr = (struct zhpe_ep_attr *)arg;
	struct zhpe_conn_listener *listener = &ep_attr->listener;
	struct zhpe_conn_map	*map = &ep_attr->cmap;
	int			conn_fd = -1;
	union sockaddr_in46	local46;
	union sockaddr_in46	remote46;
	socklen_t		addr_len;
	char			tmp;
	struct pollfd		poll_fds[2];
	struct zhpe_conn	*conn;
	uint8_t			action;
#if ENABLE_DEBUG
	char			ntop[INET6_ADDRSTRLEN];
#endif

	poll_fds[0].fd = listener->sock;
	poll_fds[1].fd = listener->signal_fds[1];
	poll_fds[0].events = poll_fds[1].events = POLLIN;

	for (;;) {
		if (conn_fd >= 0)
			close(conn_fd);
		conn_fd = -1;
		if (!listener->do_listen)
			break;
		if (poll(poll_fds, 2, -1) > 0) {
			if (poll_fds[1].revents & POLLIN) {
				rc = ofi_read_socket(listener->signal_fds[1],
						      &tmp, 1);
				if (rc != 1) {
					ZHPE_LOG_ERROR("Invalid signal\n");
					goto err;
				}
				continue;
			}
		} else {
			goto err;
		}

		addr_len = sizeof(remote46);
		conn_fd = accept(listener->sock, (struct sockaddr *)&remote46,
				 &addr_len);
		ZHPE_LOG_DBG("CONN: accepted conn-req: %d\n", conn_fd);
		if (conn_fd == -1) {
			ZHPE_LOG_ERROR("failed to accept: %s\n",
				       strerror(errno));
			continue;
		}
		addr_len = sizeof(local46);
		rc = getsockname(conn_fd, (struct sockaddr *)&local46,
				 &addr_len);
		if (rc == -1) {
			ZHPE_LOG_ERROR("getsockname() failed: %s\n",
				       strerror(errno));
			continue;
		}
		ZHPE_LOG_DBG("ACCEPT: %s, %d\n",
			     sockaddr_ntop(&remote46, ntop, sizeof(ntop)),
			     ntohs(remote46.sin_port));
		/* Using loopback can cause identity problems, just don't. */
		if (ofi_is_loopback_addr((void *)&local46)) {
			rc = zhpe_gethostaddr(ep_attr->info.addr_format,
					      &local46);
			if (rc < 0)
				continue;
			sockaddr_cpy(&remote46, &local46);
		}

		rc = zhpe_set_sockopts_accept(conn_fd);
		if (rc < 0)
			continue;

		/* remote46 has ephermeral port, but we need listening port.
		 * connect() side will send it.
		 */
		rc = zhpe_recv_fixed_blob(conn_fd, &remote46.sin_port,
					  sizeof(remote46.sin_port));
		if (rc < 0)
			continue;

		action = ZHPE_CONN_ACTION_NEW;
		mutex_acquire(&map->mutex);
		/* We can only go forward with a conn we create;
		 * if we are racing, we need to break the tie and,
		 * if we win, mark the current conn as RACED.
		 */
		conn = zhpe_conn_map_lookup(ep_attr, &remote46);
		if (conn) {
			assert(conn->state == ZHPE_CONN_STATE_INIT);
			rc = sockaddr_cmp(&local46, &remote46);
			if (!rc)
				action = ZHPE_CONN_ACTION_SELF;
			else if (rc < 0)
				action = ZHPE_CONN_ACTION_DROP;
			if (action == ZHPE_CONN_ACTION_NEW) {
				conn->state = ZHPE_CONN_STATE_RACED;
				cond_broadcast(&ep_attr->cmap.cond);
			}
		}
		if (action == ZHPE_CONN_ACTION_NEW) {
			conn = zhpe_conn_map_insert(ep_attr, &remote46);
			if (!conn)
				action = ZHPE_CONN_ACTION_DROP;
		}
		mutex_release(&map->mutex);
		rc = zhpe_send_blob(conn_fd, &action, sizeof(action));
		if (rc < 0 || action != ZHPE_CONN_ACTION_NEW)
			continue;
		rc = zhpe_conn_z_setup(conn, conn_fd, action);
		if (rc >= 0)
			zhpe_pe_signal(ep_attr->domain->pe);
		else {
			mutex_acquire(&map->mutex);
			zhpe_conn_release_entry(ep_attr, conn);
			mutex_release(&map->mutex);
		}
	}

err:
	ofi_close_socket(listener->sock);
	ZHPE_LOG_DBG("Listener thread exited\n");
	return NULL;
}

int zhpe_listen(const struct fi_info *info,
		union sockaddr_in46 *ep_addr, int backlog)
{
	int			ret = 0;
	int			listen_fd = -1;
	socklen_t		addr_len;
	struct addrinfo		ai;
	struct addrinfo		*rai;
#if ENABLE_DEBUG
	char			ntop[INET6_ADDRSTRLEN];
#endif

	if (info->src_addr)
		sockaddr_cpy(ep_addr, info->src_addr);
	else {
		zhpe_getaddrinfo_hints_init(&ai, info->addr_format);
		ai.ai_flags |= AI_PASSIVE;
		ret = zhpe_getaddrinfo(NULL, "0", &ai, &rai);
		if (ret < 0)
			goto done;
		sockaddr_cpy(ep_addr, rai->ai_addr);
		freeaddrinfo(rai);
	}

	listen_fd = ofi_socket(ep_addr->sa_family,  SOCK_STREAM, IPPROTO_TCP);
	if (listen_fd == -1) {
		ret = -errno;
		ZHPE_LOG_ERROR("failed to create socket: %s\n",
			       strerror(-ret));
		goto done;
	}
	ret = zhpe_set_sockopts_listen(listen_fd);
	if (ret < 0)
		goto done;
	if (bind(listen_fd, (struct sockaddr *)ep_addr,
		 sizeof(*ep_addr)) == -1) {
		ret = -errno;
		ZHPE_LOG_ERROR("failed to bind socket: %s\n",
			       strerror(-ret));
		goto done;
	}
	/* Is there any platform where the ntohs() makes a difference, here? */
	if (!ntohs(ep_addr->sin_port)) {
		addr_len = sizeof(*ep_addr);
		if (getsockname(listen_fd, (struct sockaddr *)ep_addr,
				&addr_len) == -1) {
			ret = -errno;
			ZHPE_LOG_ERROR("getsockname failed: error %d:%s\n",
				       ret, strerror(-ret));
			goto done;
		}
		ZHPE_LOG_DBG("Bound to:%s:%u\n",
			     sockaddr_ntop(ep_addr, ntop, sizeof(ntop)),
			     ntohs(ep_addr->sin_port));
		/* If the address is a wildcard, get a real address. */
		if (sockaddr_wildcard(ep_addr)) {
			ret = zhpe_gethostaddr(info->addr_format, ep_addr);
			if (ret < 0)
				goto done;
		}
	}
	ret = zhpe_set_sockopts_listen(listen_fd);
	if (ret < 0)
		goto done;
	if (listen(listen_fd, backlog) == -1) {
		ret = -errno;
		ZHPE_LOG_ERROR("failed to listen socket: %s\n",
			       strerror(-ret));
		goto done;
	}
 done:
	if (ret >= 0)
		ret = listen_fd;
	else
		ofi_close_socket(listen_fd);

	return ret;
}

int zhpe_conn_listen(struct zhpe_ep_attr *ep_attr)
{
	int			ret;
	struct zhpe_conn_listener *listener = &ep_attr->listener;

	listener->sock = -1;
	ret = zhpe_listen(&ep_attr->info, &ep_attr->src_addr,
			  zhpe_cm_def_map_sz);
	if (ret < 0)
		goto done;
	listener->sock = ret;
	ep_attr->msg_src_port = ntohs(ep_attr->src_addr.sin_port);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, listener->signal_fds) == -1) {
		ret = -errno;
		ZHPE_LOG_ERROR("failed to create socketpair: %s\n",
			       strerror(-ret));
		goto done;
	}
	ret = zhpe_set_fd_nonblock(listener->signal_fds[1]);
	if (ret < 0)
		goto done;

	listener->do_listen = 1;

	ret = -pthread_create(&listener->listener_thread, 0,
			      _zhpe_conn_listen, ep_attr);
	if (ret < 0) {
		ZHPE_LOG_ERROR("failed to create conn listener thread:%s\n",
			       strerror(-ret));
		goto done;
	}
	listener->listener_thread_valid = true;
 done:
	if (ret < 0 && listener->sock != -1) {
		ofi_close_socket(listener->sock);
		listener->sock = -1;
	}

	return ret;
}

int zhpe_ep_connect(struct zhpe_ep_attr *ep_attr, struct zhpe_conn *conn)
{
	int			ret = 0;
	int			conn_fd = -1;
	union sockaddr_in46	addr;
	uint8_t			action;
#if ENABLE_DEBUG
	char			ntop[INET6_ADDRSTRLEN];
#endif

	if (ep_attr->ep_type == FI_EP_MSG) {
		/* Need to check that destination address has been
		   passed to endpoint */
		sockaddr_cpy(&addr, &ep_attr->dest_addr);
		addr.sin_port = htons(ep_attr->msg_dest_port);
	} else
		addr = ep_attr->av->table[conn->av_index].addr;

	conn_fd = ofi_socket(addr.sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (conn_fd == -1) {
		ZHPE_LOG_ERROR("failed to create conn_fd, errno: %d\n", errno);
		ret = -FI_EOTHER;
		goto done;
	}

	ZHPE_LOG_DBG("Connecting to: %s:%d\n",
		     sockaddr_ntop(&addr, ntop, sizeof(ntop)),
		     ntohs(addr.sin_port));
	ZHPE_LOG_DBG("Connecting using address:%s\n",
		     sockaddr_ntop(&ep_attr->src_addr, ntop, sizeof(ntop)));

	ret = connect(conn_fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret == -1) {
		ret = -errno;
		ZHPE_LOG_DBG("connect() erro - %s: %d\n",
			     strerror(-ret), conn_fd);
		ZHPE_LOG_DBG("Connecting to: %s:%d\n",
			     sockaddr_ntop(&addr, ntop, sizeof(ntop)),
			     ntohs(addr.sin_port));
		ZHPE_LOG_DBG("Connecting using address:%s\n",
			     sockaddr_ntop(&ep_attr->src_addr, ntop,
					   sizeof(ntop)));
		goto done;
	}

	/* Send the listening port to the other side. */
	ret = zhpe_send_blob(conn_fd, &ep_attr->src_addr.sin_port,
			     sizeof(ep_attr->src_addr.sin_port));
	if (ret < 0)
		goto done;
	ret = zhpe_recv_fixed_blob(conn_fd, &action, sizeof(action));
	if (ret < 0)
		goto done;
	if (action == ZHPE_CONN_ACTION_DROP) {
		ret = -FI_EAGAIN;
		goto done;
	}

	ret = zhpe_conn_z_setup(conn, conn_fd, action);
 done:
	if (conn_fd != -1)
		close(conn_fd);

	return ret;
}

struct addrinfo *zhpe_findaddrinfo(struct addrinfo *res, int family)
{
	for (; res; res = res->ai_next) {
		if (res->ai_family == family)
			return res;
	}

	return NULL;
}

void zhpe_getaddrinfo_hints_init(struct addrinfo *hints, uint32_t addr_format)
{
	memset(hints, 0, sizeof(*hints));
	hints->ai_socktype = SOCK_STREAM;
	hints->ai_flags = AI_ADDRCONFIG;
	if (addr_format == FI_SOCKADDR_IN6)
		hints->ai_family = AF_INET6;
	else
		hints->ai_family = AF_INET;
}

int zhpe_getaddrinfo(const char *node, const char *service,
		     struct addrinfo *hints, struct addrinfo **res)
{
	int			ret = 0;
	int			rc;

	rc = getaddrinfo(node, service, hints, res);
	if (rc) {
		if (rc == EAI_SYSTEM)
			ret = -errno;
	}

	switch (rc) {

	case 0:
	case EAI_SYSTEM:
		break;

	case EAI_ADDRFAMILY:
	case EAI_NODATA:
	case EAI_NONAME:
	case EAI_SERVICE:
		ret = -ENOENT;
		break;

	case EAI_AGAIN:
		ret = -EAGAIN;
		break;

	case EAI_FAIL:
		ret = -EIO;
		break;

	case EAI_MEMORY:
		ret = -ENOMEM;
		break;

	default:
		ret = -EINVAL;
		break;
	}

	if (ret < 0) {
		ZHPE_LOG_DBG("getaddrinfo(%s,%s) returned gai %d:%s,\n"
			     "    errno %d:%s\n",
			     node ?: "", service ?: "", rc, gai_strerror(rc),
			     -ret, (ret < 0 ? strerror(-ret) : ""));
		ZHPE_LOG_DBG("zhpe_getaddrinfo() returned %d:%s\n",
			     ret, strerror(-ret));
		*res = NULL;
	}

	return ret;
}

int zhpe_gethostaddr(uint32_t fi_addr_format, union sockaddr_in46 *addr)
{
	int			ret = 0;
	struct addrinfo		ai;
	struct addrinfo		*rai;
	in_port_t		port;
	char			hostname[HOST_NAME_MAX];

	/* FIXME: How to bulletproof this. */
	if (gethostname(hostname, sizeof(hostname)) == -1) {
		ret = -errno;
		ZHPE_LOG_ERROR("gethostname failed:error %d:%s\n",
			       ret, strerror(-ret));
		goto done;
	}
	zhpe_getaddrinfo_hints_init(&ai, fi_addr_format);
	ret = zhpe_getaddrinfo(hostname, NULL, &ai, &rai);
	if (ret < 0)
		goto done;
	/* Copy address, preserve port. */
	port = addr->sin_port;
	sockaddr_cpy(addr, rai->ai_addr);
	addr->sin_port = port;
	freeaddrinfo(rai);
 done:
	return ret;
}

