/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Copyright [2012] [Erik Nordström <erik.nordstrom@gmail.com>]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ddns/ddns.h>
#include <csocket/csocket.h>

extern struct ddns_proto_ops dyndns2_proto_ops;

static const struct ddns_proto_ops *protocols[] = {
    [DDNS_PROTO_DYNDNS2] = &dyndns2_proto_ops,
};

static const struct socket_ops *socket_ops[] = {
    [DDNS_INET_SOCKET] = &inet_stream_socket_ops,
    [DDNS_INET6_SOCKET] = &inet6_stream_socket_ops,
    [DDNS_SSL_SOCKET] = &ssl_socket_ops,
    //[DDNS_SSL6_SOCKET] = &ssl6_socket_ops,
};

int ddns_init(struct ddns *dd, enum ddns_socket_type socktype, 
              enum ddns_proto protocol)
{
    memset(dd, 0, sizeof(*dd));

    *dd = (struct ddns) {
        .sock = socket_create(socket_ops[socktype]),
        .ops = protocols[protocol],
        .protocol = protocol,
        .socktype = socktype,
    };

    if (!dd->sock)
        return -1;

    if (dd->ops->init(dd) < 0) {
        return -1;
    }

    return 0;
}

int ddns_connect(struct ddns *dd, const char *provider, const char *username, const char *password)
{
    char service[strlen(provider) + 6];
    
    if (socket_is_connected(dd->sock))
        return -1;
    
    strcpy(service, provider);

    if (dd->socktype == DDNS_SSL_SOCKET ||
        dd->socktype == DDNS_SSL6_SOCKET) {
        strcpy(service + strlen(provider), ":443");
    } else {
        strcpy(service + strlen(provider), ":80");
    }

    if (dd->username) {
        free(dd->username);
    }
    
    dd->username = malloc(strlen(username) + 1);

    if (!dd->username)
        return -1;

    strcpy(dd->username, username);

    if (dd->password) {
        free(dd->password);
    }
    
    dd->password = malloc(strlen(password) + 1);

    if (!dd->password)
        return -1;

    strcpy(dd->password, password);

    return socket_connect_service(dd->sock, service);
}

int ddns_update(struct ddns *dd, const char *name, const char *addr)
{
    return dd->ops->update(dd, name, addr);
}

void ddns_close(struct ddns *dd)
{
    socket_close(dd->sock);
}

void ddns_destroy(struct ddns *dd)
{
    return dd->ops->destroy(dd);
}
