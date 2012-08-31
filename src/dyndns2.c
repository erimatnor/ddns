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
#include <ddns/ddns.h>
#include <config.h>
#include "http.h"
#include "config.h"

/* hostname, ip, wildcard, mx, backmx */
#define UPDATE_URL \
    "/nic/update?" \
    "hostname=%s&" \
    "myip=%s&"     \
    "wildcard=%s&" \
    "mx=%s&"       \
    "backmx=%s"

static const char *service = "members.dyndns.com";

int dyndns2_init(struct ddns *dd)
{
    dd->service = service;

    return 0;
}

void dyndns2_destroy(struct ddns *dd)
{

}

int dyndns2_update(struct ddns *dd, const char *name, const char *addr)
{
    struct http_request *req;
    struct http_response *rsp;
    char buf[512];
    int ret;

    snprintf(buf, sizeof(buf), UPDATE_URL, 
             name, addr, "NOCHG", "NOCHG", "NOCHG");
    
    req = http_request_alloc(HTTP_REQ_GET, buf);
    
    if (!req)
        return -1;

    http_request_add_field(req, HTTP_REQ_FIELD_HOST, dd->service, strlen(dd->service));
    http_request_add_field(req, HTTP_REQ_FIELD_AUTHORIZATION, 
                           "Basic base-64-authorization", 
                           strlen("Basic base-64-authorization"));
    http_request_add_field(req, HTTP_REQ_FIELD_USER_AGENT, 
                           PACKAGE_NAME " - " PACKAGE_VERSION,
                           strlen(PACKAGE_NAME " - " PACKAGE_VERSION));

    http_request_fprintf(stdout, req);

    http_request_send(dd->sock, req);
    
    ret = http_response_recv(dd->sock, &rsp, 2000);
    
    http_request_free(req);
    
    return 0;
}

struct ddns_proto_ops dyndns2_proto_ops = {
    .init = dyndns2_init,
    .destroy = dyndns2_destroy,
    .update = dyndns2_update,
};
