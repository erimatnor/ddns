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
#ifndef __DDNS_H__
#define __DDNS_H__

#include <csocket/csocket.h>

enum ddns_proto {
    DDNS_PROTO_DYNDNS2,
    DDNS_PROTO_FREEDNS,
};

enum ddns_socket_type {
    DDNS_INET,
    DDNS_INET6,
    DDNS_SSL,
    DDNS_SSL6,
};

struct ddns_proto_ops;

struct ddns {
    struct socket *sock;
    const struct ddns_proto_ops *ops;
    enum ddns_proto protocol;
    enum ddns_socket_type socktype;
    void *private;
    char *username;
    char *password;
    const char *service;
};

struct ddns_proto_ops {
    //int (*connect(struct ddns *dd, const char *provider);
    int (*init)(struct ddns *dd);
    void (*destroy)(struct ddns *dd);
    int (*update)(struct ddns *dd, const char *name, const char *addr);
}; 

int ddns_init(struct ddns *dd, enum ddns_socket_type socktype, enum ddns_proto protocol);
int ddns_connect(struct ddns *dd, const char *provider, const char *username, const char *password);
int ddns_update(struct ddns *dd, const char *name, const char *addr);
void ddns_close(struct ddns *dd);
void ddns_destroy(struct ddns *dd);
const char *ddns_proto_name(enum ddns_proto proto);
/* void ddns_destroy(struct ddns *dd); */

#endif /* __DDNS_H__ */
